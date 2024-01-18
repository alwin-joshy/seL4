/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#ifdef CONFIG_HARDWARE_DEBUG_API

#include <string.h>
#include <util.h>
#include <arch/model/statedata.h>
#include <arch/machine/debug.h>
#include <arch/machine/debug_conf.h>
#include <arch/kernel/vspace.h>
#include <arch/machine/registerset.h>
#include <armv/debug.h>
#include <mode/machine/debug.h>
#include <sel4/constants.h> /* seL4_NumExclusiveBreakpoints/Watchpoints */

#define DBGDSCR_MDBGEN                (BIT(15))
#define DBGDSCR_HDBGEN                (BIT(14))
#define DBGDSCR_USER_ACCESS_DISABLE   (BIT(12))

/* This bit is always RAO */
#define DBGLSR_LOCK_IMPLEMENTED       (BIT(0))
#define DBGLSR_LOCK_ENABLED           (BIT(1))
#define DBGLAR_UNLOCK_VALUE           (0xC5ACCE55u)

#define DBGOSLAR_LOCK_VALUE           (0xC5ACCE55u)

#define DBGOSLSR_GET_OSLOCK_MODEL(v)  ((((v) >> 2u) & 0x2u) | ((v) & 0x1u))
#define DBGOSLSR_LOCK_MODEL_NO_OSLOCK (0u)
#define DBGOSLSR_LOCK_MODEL_OSLOCK_AND_OSSR (1u)
#define DBGOSLSR_LOCK_MODEL_OSLOCK_ONLY (2u)

#define DBGPRSR_OSLOCK                    (BIT(5))
#define DBGPRSR_OS_DLOCK                  (BIT(6))

#define DBGOSDLR_LOCK_ENABLE              (BIT(0))

#define DBGAUTHSTATUS_NSI_IMPLEMENTED (BIT(1))
#define DBGAUTHSTATUS_NSI_ENABLED     (BIT(0))
#define DBGAUTHSTATUS_SI_IMPLEMENTED (BIT(5))
#define DBGAUTHSTATUS_SI_ENABLED     (BIT(4))

#define DBGDRAR_VALID                (MASK(2))
#define DBGDSAR_VALID                (MASK(2))

#define DBGSDER_ENABLE_SECURE_USER_INVASIVE_DEBUG       (BIT(0))

/* ARMv7 Manuals, c3.3.1:
 *  "Breakpoint debug events are synchronous. That is, the debug event acts
 *  like an exception that cancels the breakpointed instruction."
 *
 * ARMv7 Manuals, c3.4.1:
 *  "Watchpoint debug events are precise and can be synchronous or asynchronous:
 *  a synchronous Watchpoint debug event acts like a synchronous abort
 *  exception on the memory access instruction itself. An asynchronous
 *  Watchpoint debug event acts like a precise asynchronous abort exception that
 *  cancels a later instruction."
 */

enum breakpoint_privilege /* BCR[2:1] */ {
    DBGBCR_PRIV_RESERVED = 0u,
    DBGBCR_PRIV_PRIVILEGED = 1u,
    DBGBCR_PRIV_USER = 2u,
    /* Use either when doing context linking, because the linked WVR or BVR that
     * specifies the vaddr, overrides the context-programmed BCR privilege.
     */
    DBGBCR_BCR_PRIV_EITHER = 3u
};

enum watchpoint_privilege /* WCR[2:1] */ {
    DBGWCR_PRIV_RESERVED = 0u,
    DBGWCR_PRIV_PRIVILEGED = 1u,
    DBGWCR_PRIV_USER = 2u,
    DBGWCR_PRIV_EITHER = 3u
};

/** Describes the availability and level of support for the debug features on
 * a particular CPU. Currently a static local singleton instance, but for
 * multiprocessor adaptation, just make it per-CPU.
 *
 * The majority of the writing to the debug coprocessor is done when a thread
 * is being context-switched to, so the code in this file always executes on
 * the target CPU. MP adaptation should come with few surprises.
 */
typedef struct debug_state {
    bool_t is_available, coprocessor_is_baseline_only, watchpoint_8b_supported,
           non_secure_invasive_unavailable, secure_invasive_unavailable,
           cpu_is_in_secure_mode, single_step_supported, breakpoints_supported,
           watchpoints_supported;
    uint8_t debug_armv;
    uint8_t didr_version, oem_variant, oem_revision;
} debug_state_t;
static debug_state_t dbg;

bool_t byte8WatchpointsSupported(void)
{
    return dbg.watchpoint_8b_supported;
}

#define SCR "p15, 0, %0, c1, c1, 0"
#define DBGDIDR "p14,0,%0,c0,c0,0"
/* Not guaranteed in v7, only v7.1+ */
#define DBGDRCR ""
#define DBGVCR "p15, 0, %0, c0, c7, 0"

#define DBGDRAR_32 "p14,0,%0,c1,c0,0"
#define DBGDRAR_64 "p14,0,%Q0,%R0,c1"
#define DBGDSAR_32 "p14,0,%0,c2,c0,0"
#define DBGDSAR_64 "p14,0,%Q0,%R0,c2"

/* ARMv7 manual C11.11.41:
 * "This register is required in all implementations."
 * "In v7.1 DBGPRSR is not visible in the CP14 interface."
 */
#define DBGPRSR "p14, 0, %0, c1, c5, 4"

#define DBGOSLAR "p14,0,%0,c1,c0,4"
/* ARMv7 manual: C11.11.32:
 * "In any implementation, software can read this register to detect whether
 * the OS Save and Restore mechanism is implemented. If it is not implemented
 * the read of DBGOSLSR.OSLM returns zero."
 */
#define DBGOSLSR "p14,0,%0,c1,c1,4"

/* ARMv7 manual: C11.11.30:
 * "This register is only visible in the CP14 interface."
 * "In v7 Debug, this register is not implemented."
 * "In v7.1 Debug, this register is required in all implementations."
 */
#define DBGOSDLR "p14, 0, %0, c1, c3, 4"

#define DBGDEVID2 "p14,0,%0,c7,c0,7"
#define DBGDEVID1 "p14,0,%0,c7,c1,7"
#define DBGDEVID "p14,0,%0,c7,c2,7"
#define DBGDEVTYPE ""

/* ARMv7 manual: C11.11.1: DBGAUTHSTATUS:
    * "This register is required in all implementations."
 * However, in v7, it is only visible in the memory mapped interface.
 * However, in the v6 manual, this register is not mentioned at all and doesn't
 * exist.
 */
#define DBGAUTHSTATUS "p14,0,%0,c7,c14,6"

#endif /* CONFIG_HARDWARE_DEBUG_API */


#ifdef CONFIG_HARDWARE_DEBUG_API

syscall_error_t Arch_decodeSetBreakpoint(tcb_t *t,
                                                       uint16_t bp_num, word_t vaddr, word_t type,
                                                       word_t size, word_t rw)
{
    syscall_error_t ret = {
        .type = seL4_NoError
    };

    bp_num = convertBpNumToArch(bp_num);

    if (type == seL4_DataBreakpoint) {
        if (bp_num >= seL4_NumExclusiveWatchpoints) {
            userError("Debug: invalid data-watchpoint number %u.", bp_num);
            ret.type = seL4_RangeError;
            ret.rangeErrorMin = 0;
            ret.rangeErrorMax = seL4_NumExclusiveBreakpoints - 1;
            return ret;
        }
    } else if (type == seL4_InstructionBreakpoint) {
        if (bp_num >= seL4_NumExclusiveBreakpoints) {
            userError("Debug: invalid instruction breakpoint nunber %u.", bp_num);
            ret.type = seL4_RangeError;
            ret.rangeErrorMin = 0;
            ret.rangeErrorMax = seL4_NumExclusiveWatchpoints - 1;
            return ret;
        }
    }

    if (size == 8 && !byte8WatchpointsSupported()) {
        userError("Debug: 8-byte watchpoints not supported on this CPU.");
        ret.type = seL4_InvalidArgument;
        ret.invalidArgumentNumber = 3;
        return ret;
    }
    if (size == 8 && type != seL4_DataBreakpoint) {
        userError("Debug: 8-byte sizes can only be used with watchpoints.");
        ret.type = seL4_InvalidArgument;
        ret.invalidArgumentNumber = 3;
        return ret;
    }

    return ret;
}

syscall_error_t Arch_decodeConfigureSingleStepping(tcb_t *t,
                                                   uint16_t bp_num,
                                                   word_t n_instr,
                                                   bool_t is_reply)
{
    word_t type;
    syscall_error_t ret = {
        .type = seL4_NoError
    };

    if (is_reply) {
        /* If this is a single-step fault reply, just default to the already-
         * configured bp_num. Of course, this assumes that a register had
         * already previously been configured for single-stepping.
         */
        if (!t->tcbArch.tcbContext.breakpointState.single_step_enabled) {
            userError("Debug: Single-step reply when single-stepping not "
                      "enabled.");
            ret.type = seL4_IllegalOperation;
            return ret;
        }

        type = seL4_InstructionBreakpoint;
        bp_num = t->tcbArch.tcbContext.breakpointState.single_step_hw_bp_num;
    } else {
        type = getTypeFromBpNum(bp_num);
        bp_num = convertBpNumToArch(bp_num);
    }

    if (type != seL4_InstructionBreakpoint || bp_num >= seL4_FirstWatchpoint) {
        /* Must use an instruction BP register */
        userError("Debug: Single-stepping can only be used with an instruction "
                  "breakpoint.");
        ret.type = seL4_InvalidArgument;
        ret.invalidArgumentNumber = 0;
        return ret;
    }
    if (t->tcbArch.tcbContext.breakpointState.single_step_enabled == true) {
        if (bp_num != t->tcbArch.tcbContext.breakpointState.single_step_hw_bp_num) {
            /* Can't configure more than one register for stepping. */
            userError("Debug: Only one register can be configured for "
                      "single-stepping at a time.");
            ret.type = seL4_InvalidArgument;
            ret.invalidArgumentNumber = 0;
            return ret;
        }
    }

    return ret;
}

// @alwin: Port comment to generic function
/* ARM allows watchpoint trigger on load, load-exclusive, and "swap" accesses.
 * store, store-exclusive and "swap" accesses. All accesses.
 *
 * The mask defines which bits are EXCLUDED from the comparison.
 * Always program the DBGDWVR with a WORD aligned address, and use the BAS to
 * state which bits form part of the match.
 *
 * It seems the BAS works as a bitmask of bytes to select in the range.
 *
 * To detect support for the 8-bit BAS field:
 *  * If the 8-bit BAS is unsupported, then BAS[7:4] is RAZ/WI.
 *
 * When using an 8-byte watchpoint that is not dword aligned, the result is
 * undefined. You should program it as the aligned base of the range, and select
 * only the relevant bytes then.
 *
 * You cannot do sparse byte selection: you either select a single byte in the
 * BAS or you select a contiguous range. ARM has deprecated sparse byte
 * selection.
 */

/** Convert a watchpoint size (0, 1, 2, 4 or 8 bytes) into the arch specific
 * register encoding.
 */
//static word_t convertSizeToArch(word_t size)
//{
//    switch (size) {
//    case 1:
//        return 0x1;
//    case 2:
//        return 0x3;
//    case 8:
//        return 0xFF;
//    default:
//        assert(size == 4);
//        return 0xF;
//    }
//}


/** Extracts the "Method of Entry" bits from DBGDSCR.
 *
 * Used to determine what type of debug exception has occurred.
 */
static inline word_t getMethodOfEntry(void)
{
    dbg_dscr_t dscr;

    dscr.words[0] = readDscrCp();
    return dbg_dscr_get_methodOfEntry(dscr);
}

/** Initiates or halts single-stepping on the target process.
 *
 * @param at arch_tcb_t for the target process to be configured.
 * @param bp_num The hardware ID of the breakpoint register to be used.
 * @param n_instr The number of instructions to step over.
 */
bool_t configureSingleStepping(tcb_t *t,
                               uint16_t bp_num,
                               word_t n_instr,
                               bool_t is_reply)
{

    if (is_reply) {
        bp_num = t->tcbArch.tcbContext.breakpointState.single_step_hw_bp_num;
    } else {
        bp_num = convertBpNumToArch(bp_num);
    }

    /* On ARM single-stepping is emulated using breakpoint mismatches. So you
     * would basically set the breakpoint to mismatch everything, and this will
     * cause an exception to be triggered on every instruction.
     *
     * We use NULL as the mismatch address since no code should be trying to
     * execute NULL, so it's a perfect address to use as the mismatch
     * criterion. An alternative might be to use an address in the kernel's
     * high vaddrspace, since that's an address that it's impossible for
     * userspace to be executing at.
     */
    dbg_bcr_t bcr;

    bcr.words[0] = readBcrContext(t, bp_num);

    /* If the user calls us with n_instr == 0, allow them to configure, but
     * leave it disabled.
     */
    if (n_instr > 0) {
        bcr = dbg_bcr_set_enabled(bcr, 1);
        t->tcbArch.tcbContext.breakpointState.single_step_enabled = true;
    } else {
        bcr = dbg_bcr_set_enabled(bcr, 0);
        t->tcbArch.tcbContext.breakpointState.single_step_enabled = false;
    }

    bcr = dbg_bcr_set_lbn(bcr, 0);
    bcr = dbg_bcr_set_ssc(bcr, DBGBCR_PRIV_USER);
    bcr = dbg_bcr_set_bas(bcr, convertSizeToArch(1));
    bcr = Arch_setupBcr(bcr, false);

    writeBvrContext(t, bp_num, 0);
    writeBcrContext(t, bp_num, bcr.words[0]);

    t->tcbArch.tcbContext.breakpointState.n_instructions = n_instr;
    t->tcbArch.tcbContext.breakpointState.single_step_hw_bp_num = bp_num;
    return true;
}

/** Using the DBGDIDR register, detects the debug architecture version, and
 * does a preliminary check for the level of support for our debug API.
 *
 * Reads DBGDIDR, which is guaranteed to be read safely. Then
 * determine whether or not we can or should proceed.
 *
 * The majority of the debug setup is concerned with trying to tell which
 * registers are safe to access on this CPU. The debug architecture is wildly
 * different across different CPUs and platforms, so genericity is fairly
 * challenging.
 */
BOOT_CODE static void initVersionInfo(void)
{
    dbg_didr_t didr;

    didr.words[0] = getDIDR();
    dbg.oem_revision = dbg_didr_get_revision(didr);
    dbg.oem_variant = dbg_didr_get_variant(didr);
    dbg.didr_version = dbg_didr_get_version(didr);
    dbg.coprocessor_is_baseline_only = true;
    dbg.breakpoints_supported = dbg.watchpoints_supported =
                                    dbg.single_step_supported = true;

    switch (dbg.didr_version) {
    case 0x1:
        dbg.debug_armv = 0x60;
        dbg.single_step_supported = false;
        break;
    case 0x2:
        dbg.debug_armv = 0x61;
        break;
    case 0x3:
        dbg.debug_armv = 0x70;
        dbg.coprocessor_is_baseline_only = false;
        break;
    case 0x4:
        dbg.debug_armv = 0x70;
        break;
    case 0x5:
        dbg.debug_armv = 0x71;
        dbg.coprocessor_is_baseline_only = false;
        break;
    case 0x6:
        dbg.debug_armv = 0x80;
        dbg.coprocessor_is_baseline_only = false;
        break;
    default:
        dbg.is_available = false;
        dbg.debug_armv = 0;
        return;
    }

    dbg.is_available = true;
}

/** Guides the debug hardware initialization sequence.
 *
 * In short, there is a small set of registers, the "baseline" registers, which
 * are guaranteed to be available on all ARM debug architecture implementations.
 * Aside from those, the rest are a *COMPLETE* toss-up, and detection is
 * difficult, because if you access any particular register which is
 * unavailable on an implementation, you trigger an #UNDEFINED exception. And
 * there is little uniformity or consistency.
 *
 * In addition, there are as many as 3 lock registers, all of which have
 * effects on which registers you can access...and only one of them is
 * consistently implemented. The others may or may not be implemented, and well,
 * you have to grope in the dark to determine whether or not they are...but
 * if they are implemented, their effect on software is still upheld, of course.
 *
 * Much of this sequence is catering for the different versions and determining
 * which registers and locks are implemented, and creating a common register
 * environment for the rest of the API code.
 *
 * There are several conditions which will cause the code to exit and give up.
 * For the most part, most implementations give you the baseline registers and
 * some others. When an implementation only supports the baseline registers and
 * nothing more, you're told so, and that basically means you can't do anything
 * with it because you have no reliable access to the debug registers.
 */
BOOT_CODE bool_t Arch_initHardwareBreakpoints(void)
{
    word_t dbgosdlr, dbgoslsr;

    /* The functioning of breakpoints on ARM requires that certain external
     * pin signals be enabled. If these are not enabled, there is nothing
     * that can be done from software. If these are enabled, we can then
     * select the debug-mode we want by programming the CP14 interface.
     *
     * Of the four modes available, we want monitor mode, because only monitor
     * mode delivers breakpoint and watchpoint events to the kernel as
     * exceptions. The other modes cause a break into "debug mode" or ignore
     * debug events.
     */
    memset(&dbg, 0, sizeof(dbg));

    initVersionInfo();
    if (dbg.is_available == false) {
        printf("Debug architecture not implemented.\n");
        return false;
    }

    printf("DIDRv: %x, armv %x, coproc baseline only? %s.\n",
           dbg.didr_version, dbg.debug_armv,
           ((dbg.coprocessor_is_baseline_only) ? "yes" : "no"));

    if (dbg.debug_armv > 0x61) {
        if (dbg.coprocessor_is_baseline_only) {
            printf("ARMDBG: No reliable access to DBG regs.\n");
            return dbg.is_available = false;
        }

        /* Interestingly, since the debug features have so many bits that
         * behave differently pending the state of secure-mode, ARM had to
         * expose a bit in the debug coprocessor that reveals whether or not the
         * CPU is in secure mode, or else it would be semi-impossible to program
         * this feature.
         */
        dbg.cpu_is_in_secure_mode = !(readDscrCp() & DBGDSCR_SECURE_MODE_DISABLED);
        if (dbg.cpu_is_in_secure_mode) {
            word_t sder;

            printf("CPU is in secure mode. Enabling debugging in secure user mode.\n");
            MRC(DBGSDER, sder);
            MCR(DBGSDER, sder
                | DBGSDER_ENABLE_SECURE_USER_INVASIVE_DEBUG);
        }

        /* Deal with OS Double-lock: */
        if (dbg.debug_armv == 0x71) {
            /* ARMv7 manuals, C11.11.30:
             * "In v7.1 Debug, this register is required in all implementations."
             */
            MRC(DBGOSDLR, dbgosdlr);
            MCR(DBGOSDLR, dbgosdlr & ~DBGOSDLR_LOCK_ENABLE);
        } else if (dbg.debug_armv == 0x70) {
            /* ARMv7 manuals, C11.11.30:
             * "In v7 Debug, this register is not implemented."
             *
             * So no need to do anything for debug v7.0.
             */
        }

        /* Now deal with OS lock: ARMv7 manual, C11.11.32:
         *  "In any implementation, software can read this register to detect
         *   whether the OS Save and Restore mechanism is implemented. If it is
         *   not implemented the read of DBGOSLSR.OSLM returns zero."
         */
        MRC(DBGOSLSR, dbgoslsr);
        if (DBGOSLSR_GET_OSLOCK_MODEL(dbgoslsr) != DBGOSLSR_LOCK_MODEL_NO_OSLOCK) {
            MCR(DBGOSLAR, ~DBGOSLAR_LOCK_VALUE);
        }

        disableAllBpsAndWps();
        if (!enableMonitorMode()) {
            return dbg.is_available = false;
        }
    } else {
        /* On v6 you have to enable monitor mode first. */
        if (!enableMonitorMode()) {
            return dbg.is_available = false;
        }
        disableAllBpsAndWps();
    }

    /* Finally, also pre-load some initial register state that can be used
     * for all new threads so that their initial saved debug register state
     * is valid when it's first loaded onto the CPU.
     */
    for (int i = 0; i < seL4_NumExclusiveBreakpoints; i++) {
        armKSNullBreakpointState.breakpoint[i].cr = readBcrCp(i) & ~DBGBCR_ENABLE;
    }
    for (int i = 0; i < seL4_NumExclusiveWatchpoints; i++) {
        armKSNullBreakpointState.watchpoint[i].cr = readWcrCp(i) & ~DBGWCR_ENABLE;
    }

    dbg.watchpoint_8b_supported = watchpoint8bSupported();
    return true;
}

/** Determines which breakpoint or watchpoint register caused the debug
 * exception to be triggered.
 *
 * Checks to see which hardware breakpoint was triggered, and saves
 * the ID of that breakpoint.
 * There is no short way to do this on ARM. On x86 there is a status
 * register that tells you which watchpoint has been triggered. On ARM
 * there is no such register, so you have to manually check each to see which
 * one was triggered.
 *
 * The arguments also work a bit differently from x86 as well. On x86 the
 * 2 arguments are dummy values, while on ARM, they contain useful information.
 *
 * @param vaddr The virtual address stored in the IFSR/DFSR register, which
 *              is either the watchpoint address or breakpoint address.
 * @param reason The presumed reason for the exception, which is based on
 *               whether it was a prefetch or data abort.
 * @return Struct with a member "bp_num", which is a positive integer if we
 *         successfully detected which debug register triggered the exception.
 *         "Bp_num" will be negative otherwise.
 */
static int getAndResetActiveBreakpoint(word_t vaddr, word_t reason)
{
    word_t align_mask;
    int i, ret = -1;

    // @alwin: convert this to generic
    if (reason == seL4_InstructionBreakpoint) {
        for (i = 0; i < seL4_NumExclusiveBreakpoints; i++) {
            dbg_bcr_t bcr;
            word_t bvr = readBvrCp(i);

            bcr.words[0] = readBcrCp(i);
            /* The actual trigger address may be an unaligned sub-byte of the
             * range, which means it's not guaranteed to match the aligned value
             * that was programmed into the address register.
             */
            align_mask = convertArchToSize(dbg_bcr_get_bas(bcr));
            align_mask = ~(align_mask - 1);

            if (bvr != (vaddr & align_mask) || !dbg_bcr_get_enabled(bcr)) {
                continue;
            }

            ret = i;
            return ret;
        }
    }

    if (reason == seL4_DataBreakpoint) {
        for (i = 0; i < seL4_NumExclusiveWatchpoints; i++) {
            dbg_wcr_t wcr;
            word_t wvr = readWvrCp(i);

            wcr.words[0] = readWcrCp(i);
            align_mask = convertArchToSize(dbg_wcr_get_bas(wcr));
            align_mask = ~(align_mask - 1);

            if (wvr != (vaddr & align_mask) || !dbg_wcr_get_enabled(wcr)) {
                continue;
            }

            ret = i;
            return ret;
        }
    }

    return ret;
}

/** Abstract wrapper around the IFSR/DFSR fault status values.
 *
 * Format of the FSR bits is different for long and short descriptors, so
 * extract the FSR bits and accompany them with a boolean.
 */
typedef struct fault_status {
    uint8_t status;
    bool_t is_long_desc_format;
} fault_status_t;

static fault_status_t getFaultStatus(word_t hsr_or_fsr)
{
    fault_status_t ret;

    /* Hyp mode uses the HSR, Hype syndrome register. */
#ifdef CONFIG_ARM_HYPERVISOR_SUPPORT
    /* the HSR only uses the long descriptor format. */
    ret.is_long_desc_format = true;
    /* FSR[5:0]. */
    ret.status = hsr_or_fsr & 0x3F;
#else
    /* Non-hyp uses IFSR/DFSR */
    if (hsr_or_fsr & BIT(FSR_LPAE_SHIFT)) {
        ret.is_long_desc_format = true;
        /* FSR[5:0] */
        ret.status = hsr_or_fsr & 0x3F;
    } else {
        ret.is_long_desc_format = false;
        /* FSR[10] | FSR[3:0]. */
        ret.status = (hsr_or_fsr & BIT(FSR_STATUS_BIT4_SHIFT)) >> FSR_STATUS_BIT4_SHIFT;
        ret.status <<= 4;
        ret.status = hsr_or_fsr & 0xF;
    }
#endif

    return ret;
}

/** Called to determine if an abort was a debug exception.
 *
 * The ARM debug exceptions look like Prefetch Aborts or Data Aborts, and you
 * have to examine some extra register state to determine whether or not the
 * abort you currently have on your hands is actually a debug exception.
 *
 * This routine takes care of the checks.
 * @param fs An abstraction of the DFSR/IFSR values, meant to make it irrelevant
 *           whether we're using the long/short descriptors. Bit positions and
 *           values change. This also makes the debug code forward compatible
 *           aarch64.
 */
bool_t isDebugFault(word_t hsr_or_fsr)
{
    fault_status_t fs;

    fs = getFaultStatus(hsr_or_fsr);
    if (fs.is_long_desc_format) {
        if (fs.status == FSR_LONGDESC_STATUS_DEBUG_EVENT) {
            return true;
        }
    } else {
        if (fs.status == FSR_SHORTDESC_STATUS_DEBUG_EVENT) {
            return true;
        }
    }

    if (getMethodOfEntry() == DEBUG_ENTRY_ASYNC_WATCHPOINT) {
        userError("Debug: Watchpoint delivered as async abort.");
        return true;
    }
    return false;
}

/** Called to process a debug exception.
 *
 * On x86, you're told which breakpoint register triggered the exception. On
 * ARM, you're told the virtual address that triggered the exception and what
 * type of access (data access vs instruction execution) triggered the exception
 * and you have to figure out which register triggered it.
 *
 * For watchpoints, it's not very complicated: just check to see which
 * register matches the virtual address.
 *
 * For breakpoints, it's a bit more complex: since both breakpoints and single-
 * stepping are configured using the same registers, we need to first detect
 * whether single-stepping is enabled. If not, then we check for a breakpoint.
 * @param fault_vaddr The instruction vaddr which triggered the exception, as
 *                    extracted by the kernel.
 */
seL4_Fault_t handleUserLevelDebugException(word_t fault_vaddr)
{
#ifdef TRACK_KERNEL_ENTRIES
    ksKernelEntry.path = Entry_DebugFault;
    ksKernelEntry.word = fault_vaddr;
#endif

    word_t method_of_entry = getMethodOfEntry();
    int i, active_bp;
    seL4_Fault_t ret;
    word_t bp_reason, bp_vaddr;

    switch (method_of_entry) {
    case DEBUG_ENTRY_BREAKPOINT:
        bp_reason = seL4_InstructionBreakpoint;
        bp_vaddr = fault_vaddr;

        /* Could have been triggered by:
         *  1. An actual breakpoint.
         *  2. A breakpoint configured in mismatch mode to emulate
         *  single-stepping.
         *
         * If the register is configured for mismatch, then it's a single-step
         * exception. If the register is configured for match, then it's a
         * normal breakpoint exception.
         */
        for (i = 0; i < seL4_NumExclusiveBreakpoints; i++) {
            dbg_bcr_t bcr;

            bcr.words[0] = readBcrCp(i);
            if (!dbg_bcr_get_enabled(bcr) || Arch_breakpointIsMismatch(bcr) != true) {
                continue;
            }
            /* Return the first BP enabled and configured for mismatch. */
            bp_reason = seL4_SingleStep;
            active_bp = i;
            break;
        }
        break;

    case DEBUG_ENTRY_SYNC_WATCHPOINT:
        bp_reason = seL4_DataBreakpoint;
#ifdef CONFIG_ARM_HYPERVISOR_SUPPORT
        /* Sync watchpoint sets the BP vaddr in HDFAR. */
        bp_vaddr = getHDFAR();
#else
        bp_vaddr = getFAR();
#endif
        break;

    case DEBUG_ENTRY_ASYNC_WATCHPOINT:
        bp_reason = seL4_DataBreakpoint;
        /* Async WP sets the WP vaddr in DBGWFAR for both hyp and non-hyp. */
        bp_vaddr = getWFAR();
        break;

    default: /* EXPLICIT_BKPT: BKPT instruction */
        assert(method_of_entry == DEBUG_ENTRY_EXPLICIT_BKPT);
        bp_reason = seL4_SoftwareBreakRequest;
        bp_vaddr = fault_vaddr;
        active_bp = 0;
    }

    if (method_of_entry != DEBUG_ENTRY_EXPLICIT_BKPT
        && bp_reason != seL4_SingleStep) {
        active_bp = getAndResetActiveBreakpoint(bp_vaddr,
                                                bp_reason);
        assert(active_bp >= 0);
    }

    /* There is no hardware register associated with BKPT instruction
     * triggers.
     */
    if (bp_reason != seL4_SoftwareBreakRequest) {
        /* Convert the hardware BP num back into an API-ID */
        active_bp = getBpNumFromType(active_bp, bp_reason);
    }
    ret = seL4_Fault_DebugException_new(bp_vaddr, active_bp, bp_reason);
    return ret;
}

#endif /* CONFIG_HARDWARE_DEBUG_API */

#ifdef ARM_BASE_CP14_SAVE_AND_RESTORE
#ifdef ARM_HYP_CP14_SAVE_AND_RESTORE_VCPU_THREADS
void Arch_debugAssociateVCPUTCB(tcb_t *t)
{
    /* Don't attempt to shift beyond end of word. */
    assert(seL4_NumHWBreakpoints < sizeof(word_t) * 8);

    /* Set all the bits to 1, so loadBreakpointState() will
     * restore all the debug regs unconditionally.
     */
    t->tcbArch.tcbContext.breakpointState.used_breakpoints_bf = MASK(seL4_NumHWBreakpoints);
}

void Arch_debugDissociateVCPUTCB(tcb_t *t)
{
    t->tcbArch.tcbContext.breakpointState.used_breakpoints_bf = 0;
}
#endif

/** Pops debug register context for a thread into the CPU.
 *
 * Mirrors the idea of restore_user_context.
 */
void restore_user_debug_context(tcb_t *target_thread)
{
    assert(target_thread != NULL);

    if (target_thread->tcbArch.tcbContext.breakpointState.used_breakpoints_bf == 0) {
        loadAllDisabledBreakpointState();
    } else {
        loadBreakpointState(target_thread);
    }

    /* ARMv7 manual, sec C3.7:
     * "Usually, an exception return sequence is a context change operation as
     * well as a context synchronization operation, in which case the context
     * change operation is guaranteed to take effect on the debug logic by the
     * end of that exception return sequence."
     *
     * So we don't need to execute ISB here because we're about to RFE.
     */
}

#endif /* ARM_BASE_CP14_SAVE_AND_RESTORE */
