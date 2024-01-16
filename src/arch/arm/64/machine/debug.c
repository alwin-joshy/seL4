/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#include <config.h>
#ifdef CONFIG_HARDWARE_DEBUG_API

#include <machine/debug.h>
#include <arch/kernel/vspace.h>
#include <arch/machine/debug.h>
#include <arch/machine/debug_conf.h>
#include <arch/machine/registerset.h>
#include <arch/model/statedata.h>
#include <armv/debug.h>
#include <mode/machine/debug.h>
#include <sel4/constants.h> /* seL4_NumExclusiveBreakpoints/Watchpoints */
#include <string.h>
#include <util.h>

#define MDSCR_MDE (BIT(15))
#define MDSCR_SS  (BIT(0))
#define SPSR_SS   (BIT(21))

#define ESR_EXCEPTION_CLASS_MASK 0xFC000000
#define ESR_EXCEPTION_CLASS_OFF 26

#define OSDLR_LOCK (BIT(0))
#define OSLAR_LOCK (BIT(0))

enum breakpoint_privilege /* BCR[2:1] */ {
  DBGBCR_PRIV_RESERVED = 0u,
  DBGBCR_PRIV_PRIVILEGED = 1u,
  DBGBCR_PRIV_USER = 2u,
  DBGBCR_BCR_PRIV_EITHER = 3u
};

enum watchpoint_privilege /* WCR[2:1] */ {
  DBGWCR_PRIV_RESERVED = 0u,
  DBGWCR_PRIV_PRIVILEGED = 1u,
  DBGWCR_PRIV_USER = 2u,
  DBGWCR_PRIV_EITHER = 3u
};



#endif /* CONFIG_HARDWARE_DEBUG_API */

#ifdef CONFIG_HARDWARE_DEBUG_API

/** Sets up the requested hardware breakpoint register.
 *
 * Acts as the backend for seL4_TCB_SetBreakpoint. Doesn't actually operate
 * on the hardware coprocessor, but just modifies the thread's debug register
 * context. The thread will pop off the updated register context when it is
 * popping its context the next time it runs.
 *
 * On ARM the hardware breakpoints are consumed by all operations, including
 * single-stepping, unlike x86, where single-stepping doesn't require the use
 * of an actual hardware breakpoint register (just uses the EFLAGS.TF bit).
 *
 * @param at arch_tcb_t that points to the register context of the thread we
 *           want to modify.
 * @param bp_num The hardware register we want to set up.
 * @params vaddr, type, size, rw: seL4 API values for seL4_TCB_SetBreakpoint.
 *         All documented in the seL4 API Manuals.
 */
void setBreakpoint(tcb_t *t, uint16_t bp_num, word_t vaddr, word_t type,
                   word_t size, word_t rw) {
  bp_num = convertBpNumToArch(bp_num);

  if (type == seL4_InstructionBreakpoint) {
    dbg_bcr_t bcr;

    writeBvrContext(t, bp_num, vaddr);

    /* Preserve reserved bits. */
    bcr.words[0] = readBcrContext(t, bp_num);
    bcr = dbg_bcr_set_enabled(bcr, 1);
    bcr = dbg_bcr_set_lbn(bcr, 0);
    bcr = dbg_bcr_set_pmc(bcr, DBGBCR_PRIV_USER);
    bcr = Arch_setupBcr(bcr, true);
    writeBcrContext(t, bp_num, bcr.words[0]);
  } else {
    dbg_wcr_t wcr;

    writeWvrContext(t, bp_num, vaddr);

    /* Preserve reserved bits */
    // @alwin: Move some of this stuff into Arch_setupWcr() eventually
    wcr.words[0] = readWcrContext(t, bp_num);
    wcr = dbg_wcr_set_enabled(wcr, 1);
    wcr = dbg_wcr_set_pac(wcr, DBGWCR_PRIV_USER);
    wcr = dbg_wcr_set_watchpointType(wcr, 0);
    wcr = dbg_wcr_set_bas(wcr, convertSizeToArch(size));
    wcr = dbg_wcr_set_addressMask(wcr, 0);
    wcr = dbg_wcr_set_lsc(wcr, convertAccessToArch(rw));
    wcr = dbg_wcr_set_lbn(wcr, 0);
    wcr = dbg_wcr_set_hmc(wcr, 0);
    wcr = dbg_wcr_set_ssc(wcr, 0);
    writeWcrContext(t, bp_num, wcr.words[0]);
  }
}

/** Retrieves the current configuration of a hardware breakpoint for a given
 * thread.
 *
 * Doesn't modify the configuration of that thread's breakpoints.
 *
 * @param at arch_tcb_t that holds the register context for the thread you wish
 *           to query.
 * @param bp_num Hardware breakpoint ID.
 * @return A struct describing the current configuration of the requested
 *         breakpoint.
 */
getBreakpoint_t getBreakpoint(tcb_t *t, uint16_t bp_num) {
  getBreakpoint_t ret;

  ret.type = getTypeFromBpNum(bp_num);
  bp_num = convertBpNumToArch(bp_num);

  if (ret.type == seL4_InstructionBreakpoint) {
    dbg_bcr_t bcr;

    bcr.words[0] = readBcrContext(t, bp_num);
    ret.size = 0;
    ret.rw = seL4_BreakOnRead;
    ret.vaddr = readBvrContext(t, bp_num);
    ret.is_enabled = dbg_bcr_get_enabled(bcr);
  } else {
    dbg_wcr_t wcr;

    wcr.words[0] = readWcrContext(t, bp_num);
    ret.size = convertArchToSize(dbg_wcr_get_bas(wcr));
    ret.rw = convertArchToAccess(dbg_wcr_get_lsc(wcr));
    ret.vaddr = readWvrContext(t, bp_num);
    ret.is_enabled = dbg_wcr_get_enabled(wcr);
  }
  return ret;
}

/** Disables and clears the configuration of a hardware breakpoint.
 *
 * @param at arch_tcb_t holding the reg context for the target thread.
 * @param bp_num The hardware breakpoint you want to disable+clear.
 */
void unsetBreakpoint(tcb_t *t, uint16_t bp_num) {
  word_t type;

  type = getTypeFromBpNum(bp_num);
  bp_num = convertBpNumToArch(bp_num);

  if (type == seL4_InstructionBreakpoint) {
    dbg_bcr_t bcr;

    bcr.words[0] = readBcrContext(t, bp_num);
    bcr = dbg_bcr_set_enabled(bcr, 0);
    writeBcrContext(t, bp_num, bcr.words[0]);
    writeBvrContext(t, bp_num, 0);
  } else {
    dbg_wcr_t wcr;

    wcr.words[0] = readWcrContext(t, bp_num);
    wcr = dbg_wcr_set_enabled(wcr, 0);
    writeWcrContext(t, bp_num, wcr.words[0]);
    writeWvrContext(t, bp_num, 0);
  }
}

/** Initiates or halts single-stepping on the target process.
 *
 * @param at arch_tcb_t for the target process to be configured.
 * @param bp_num The hardware ID of the breakpoint register to be used.
 * @param n_instr The number of instructions to step over.
 */
bool_t configureSingleStepping(tcb_t *t, uint16_t bp_num, word_t n_instr,
                               bool_t is_reply) {

    if (n_instr > 0) {
        /* Enable single stepping */
        t->tcbArch.tcbContext.breakpointState.single_step_enabled = true;
    } else {
        /* Disable single stepping */
        t->tcbArch.tcbContext.breakpointState.single_step_enabled = false;
    }

    t->tcbArch.tcbContext.breakpointState.n_instructions = n_instr;
    return true;
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
BOOT_CODE bool_t Arch_initHardwareBreakpoints(void) {

  /* Setup the general the debug control register */
  word_t mdscr = 0;
  MRS("MDSCR_EL1", mdscr);
  mdscr |= MDSCR_MDE;
  MSR("MDSCR_EL1", mdscr);

  /* Ensure that the OS double lock is unset */
  word_t osdlr = 0;
  MRS("osdlr_el1", osdlr);
  osdlr &= ~OSDLR_LOCK;
  MSR("osdlr_el1", osdlr);

  /* Ensure that the OS lock is unset */
  word_t oslar = 0;
  MSR("oslar_el1", oslar);

  // @alwin: why does the below not work? if anything the top one should not
  // work
  //    word_t oslar = 0;
  //    MRS("oslar_el1", oslar);
  //    oslar &= ~OSLAR_LOCK;
  //    MSR("oslar_el1", oslar);
  //
  /* Ensure that all the breakpoint and watchpoint registers are initially
  disabled */
  disableAllBpsAndWps();

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
static UNUSED int getAndResetActiveBreakpoint(word_t vaddr, word_t reason) {
  int i, ret = -1;

  if (reason == seL4_InstructionBreakpoint) {
    for (i = 0; i < seL4_NumExclusiveBreakpoints; i++) {
      dbg_bcr_t bcr;
      word_t bvr = readBvrCp(i);

      bcr.words[0] = readBcrCp(i);
      /* The actual trigger address may be an unaligned sub-byte of the
       * range, which means it's not guaranteed to match the aligned value
       * that was programmed into the address register.
       */

      if (bvr != vaddr || !dbg_bcr_get_enabled(bcr)) {
        continue;
      }

      ret = i;
      return ret;
    }
  } else {
    assert(reason == seL4_DataBreakpoint);

    for (i = 0; i < seL4_NumExclusiveWatchpoints; i++) {
      dbg_wcr_t wcr;
      word_t wvr = readWvrCp(i);

      wcr.words[0] = readWcrCp(i);
      word_t align_mask = convertArchToSize(dbg_wcr_get_bas(wcr));
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

// @alwin: update docs

/* Abstract wrapper around the ESR fault status value */

static word_t getFaultStatus(word_t esr) {
    return (esr & ESR_EXCEPTION_CLASS_MASK) >> ESR_EXCEPTION_CLASS_OFF;
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
bool_t isDebugFault(word_t esr) {
    word_t exception_class = getFaultStatus(esr);
    return (exception_class == DEBUG_ENTRY_BREAKPOINT ||
            exception_class == DEBUG_ENTRY_SINGLE_STEP ||
            exception_class == DEBUG_ENTRY_WATCHPOINT ||
            exception_class == DEBUG_ENTRY_EXPLICIT_BKPT);
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
seL4_Fault_t handleUserLevelDebugException(word_t esr, word_t fault_vaddr) {
  int active_bp;
  word_t bp_reason, bp_vaddr;
    word_t exception_class = getFaultStatus(esr);

#ifdef TRACK_KERNEL_ENTRIES
  ksKernelEntry.path = Entry_DebugFault;
  ksKernelEntry.word = exception_class;
#endif

  switch (exception_class) {
  case DEBUG_ENTRY_BREAKPOINT:
    bp_reason = seL4_InstructionBreakpoint;
    bp_vaddr = fault_vaddr;
    break;
  case DEBUG_ENTRY_WATCHPOINT:
    bp_reason = seL4_DataBreakpoint;
    // @alwin: aarch32 does something else in hypervisor mode
    bp_vaddr = getFAR();
    break;
  case DEBUG_ENTRY_SINGLE_STEP:
    bp_reason = seL4_SingleStep;
    bp_vaddr = fault_vaddr;
    active_bp = 0;
    break;
    //    case DEBUG_ENTRY_ASYNC_WATCHPOINT:
    // @alwin: necessary?
  default: /* EXPLICIT_BKPT: BKPT instruction */
    assert(exception_class == DEBUG_ENTRY_EXPLICIT_BKPT);
    bp_reason = seL4_SoftwareBreakRequest;
    bp_vaddr = fault_vaddr;
    active_bp = 0;
  }

    /* There is no hardware register associated with BKPT instruction
   * triggers or single stepping.
   */
  if (bp_reason != seL4_SoftwareBreakRequest && bp_reason != seL4_SingleStep) {
    active_bp = getAndResetActiveBreakpoint(bp_vaddr, bp_reason);
    active_bp = getBpNumFromType(active_bp, bp_reason);
    assert(active_bp >= 0);
  }

  if (bp_reason == seL4_SingleStep && !singleStepFaultCounterReady(NODE_STATE(ksCurThread))) {
    return seL4_Fault_NullFault_new();
}

  return seL4_Fault_DebugException_new(bp_vaddr, active_bp, bp_reason);
}

syscall_error_t Arch_decodeSetBreakpoint(tcb_t *t,
                                         uint16_t bp_num, word_t vaddr, word_t type,
                                         word_t size, word_t rw)
{
    syscall_error_t ret = {
        .type = seL4_NoError
    };

    // @alwin: Double check this
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

    if (size == 8 && type != seL4_DataBreakpoint) {
        userError("Debug: 8-byte sizes can only be used with watchpoints.");
        ret.type = seL4_InvalidArgument;
        ret.invalidArgumentNumber = 3;
        return ret;
    }

    return ret;
}


#endif /* CONFIG_HARDWARE_DEBUG_API */

#ifdef ARM_BASE_CP14_SAVE_AND_RESTORE

/** Pops debug register context for a thread into the CPU.
 *
 * Mirrors the idea of restore_user_context.
 */
void restore_user_debug_context(tcb_t *target_thread) {
    assert(target_thread != NULL);

    if (target_thread->tcbArch.tcbContext.breakpointState.used_breakpoints_bf ==
        0) {
        loadAllDisabledBreakpointState();
    } else {
        loadBreakpointState(target_thread);
    }

    /* Set/unset single stepping if applicable */
    word_t mdscr = 0, spsr = 0;
    MRS("MDSCR_EL1", mdscr);
    spsr = getRegister(target_thread, SPSR_EL1);
    if (target_thread->tcbArch.tcbContext.breakpointState.single_step_enabled) {
        /* Enable single stepping */
        mdscr |= MDSCR_SS;
        spsr |= SPSR_SS;
    } else {
        /* Disable single stepping */
        mdscr &= ~MDSCR_SS;
        spsr &= ~SPSR_SS;
    }
    MSR("MDSCR_EL1", mdscr);
    setRegister(target_thread, SPSR_EL1, spsr);

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
