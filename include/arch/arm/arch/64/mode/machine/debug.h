/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <util.h>
#include <api/types.h>
#include <arch/machine/debug_conf.h>
#include <sel4/plat/api/constants.h>
#include <armv/debug.h>

#define DBGBCR_ENABLE                 (BIT(0))
#define DBGWCR_ENABLE                 (BIT(0))


#ifdef CONFIG_HARDWARE_DEBUG_API

/** These next two functions are part of some state flags.
 *
 * A bitfield of all currently enabled breakpoints for a thread is kept in that
 * thread's TCB. These two functions here set and unset the bits in that
 * bitfield.
 */
static inline void setBreakpointUsedFlag(tcb_t *t, uint16_t bp_num)
{
    if (t != NULL) {
        t->tcbArch.tcbContext.breakpointState.used_breakpoints_bf |= BIT(bp_num);
    }
}

static inline void unsetBreakpointUsedFlag(tcb_t *t, uint16_t bp_num)
{
    if (t != NULL) {
        t->tcbArch.tcbContext.breakpointState.used_breakpoints_bf &= ~BIT(bp_num);
    }
}

static inline syscall_error_t Arch_decodeConfigureSingleStepping(tcb_t *t, uint16_t bp_num, word_t n_instr, bool_t is_reply)
{
    UNUSED word_t type;
    syscall_error_t ret = {
        .type = seL4_NoError
    };

    // if (is_reply) {
    //     /* If this is a single-step fault reply, just default to the already-
    //      * configured bp_num. Of course, this assumes that a register had
    //      * already previously been configured for single-stepping.
    //      */
    //     if (!t->tcbArch.tcbContext.breakpointState.single_step_enabled) {
    //         userError("Debug: Single-step reply when single-stepping not "
    //                   "enabled.");
    //         ret.type = seL4_IllegalOperation;
    //         return ret;
    //     }

    //     type = seL4_InstructionBreakpoint;
    //     bp_num = t->tcbArch.tcbContext.breakpointState.single_step_hw_bp_num;
    // } else {
    //     type = getTypeFromBpNum(bp_num);
    //     bp_num = convertBpNumToArch(bp_num);
    // }

    // if (type != seL4_InstructionBreakpoint || bp_num >= seL4_FirstWatchpoint) {
    //     /* Must use an instruction BP register */
    //     userError("Debug: Single-stepping can only be used with an instruction "
    //               "breakpoint.");
    //     ret.type = seL4_InvalidArgument;
    //     ret.invalidArgumentNumber = 0;
    //     return ret;
    // }
    // if (t->tcbArch.tcbContext.breakpointState.single_step_enabled == true) {
    //     if (bp_num != t->tcbArch.tcbContext.breakpointState.single_step_hw_bp_num) {
    //         /* Can't configure more than one register for stepping. */
    //         userError("Debug: Only one register can be configured for "
    //                   "single-stepping at a time.");
    //         ret.type = seL4_InvalidArgument;
    //         ret.invalidArgumentNumber = 0;
    //         return ret;
    //     }
    // }

    return ret;
}


static inline syscall_error_t Arch_decodeUnsetBreakpoint(tcb_t *t, uint16_t bp_num)
{
    syscall_error_t ret = {
        .type = seL4_NoError
    };

    if (bp_num >= seL4_FirstWatchpoint + seL4_NumExclusiveWatchpoints) {
        userError("Arch Debug: Invalid API bp_num %u.", bp_num);
        ret.type = seL4_NoError;
        return ret;
    }

    UNUSED word_t type;
    UNUSED dbg_bcr_t bcr;

    // type = getTypeFromBpNum(bp_num);
    // bp_num = convertBpNumToArch(bp_num);

    // bcr.words[0] = t->tcbArch.tcbContext.breakpointState.breakpoint[bp_num].cr;
    // if (type == seL4_InstructionBreakpoint) {
    //     if (Arch_breakpointIsMismatch(bcr) == true && dbg_bcr_get_enabled(bcr)) {
    //         userError("Rejecting call to unsetBreakpoint on breakpoint configured "
    //                   "for single-stepping (hwid %u).", bp_num);
    //         ret.type = seL4_IllegalOperation;
    //         return ret;
    //     }
    // }

    return ret;
}

#define MAKE_P14(crn, crm, opc2) "p14, 0, %0, c" #crn ", c" #crm ", " #opc2
#define MAKE_DBGBVR(num) MAKE_P14(0, num, 4)
#define MAKE_DBGBCR(num) MAKE_P14(0, num, 5)
#define MAKE_DBGWVR(num) MAKE_P14(0, num, 6)
#define MAKE_DBGWCR(num) MAKE_P14(0, num, 7)
#define MAKE_DBGXVR(num) MAKE_P14(1, num, 1)

/** Generates read functions for the CP14 control and value registers.
 */
#define DEBUG_GENERATE_READ_FN(_name, _reg) \
static inline word_t \
_name(uint16_t bp_num) \
{ \
    word_t ret; \
 \
    switch (bp_num) { \
    case 1: \
        MRS(MAKE_ ## _reg(1), ret); \
        return ret; \
    case 2: \
        MRS(MAKE_ ## _reg(2), ret); \
        return ret; \
    case 3: \
        MRS(MAKE_ ## _reg(3), ret); \
        return ret; \
    case 4: \
        MRS(MAKE_ ## _reg(4), ret); \
        return ret; \
    case 5: \
        MRS(MAKE_ ## _reg(5), ret); \
        return ret; \
    case 6: \
        MRS(MAKE_ ## _reg(6), ret); \
        return ret; \
    case 7: \
        MRS(MAKE_ ## _reg(7), ret); \
        return ret; \
    case 8: \
        MRS(MAKE_ ## _reg(8), ret); \
        return ret; \
    case 9: \
        MRS(MAKE_ ## _reg(9), ret); \
        return ret; \
    case 10: \
        MRS(MAKE_ ## _reg(10), ret); \
        return ret; \
    case 11: \
        MRS(MAKE_ ## _reg(11), ret); \
        return ret; \
    case 12: \
        MRS(MAKE_ ## _reg(12), ret); \
        return ret; \
    case 13: \
        MRS(MAKE_ ## _reg(13), ret); \
        return ret; \
    case 14: \
        MRS(MAKE_ ## _reg(14), ret); \
        return ret; \
    case 15: \
        MRS(MAKE_ ## _reg(15), ret); \
        return ret; \
    default: \
        assert(bp_num == 0); \
        MRS(MAKE_ ## _reg(0), ret); \
        return ret; \
    } \
}

/** Generates write functions for the CP14 control and value registers.
 */
#define DEBUG_GENERATE_WRITE_FN(_name, _reg)  \
static inline void \
_name(uint16_t bp_num, word_t val) \
{ \
    switch (bp_num) { \
    case 1: \
        MSR(MAKE_ ## _reg(1), val); \
        return; \
    case 2: \
        MSR(MAKE_ ## _reg(2), val); \
        return; \
    case 3: \
        MSR(MAKE_ ## _reg(3), val); \
        return; \
    case 4: \
        MSR(MAKE_ ## _reg(4), val); \
        return; \
    case 5: \
        MSR(MAKE_ ## _reg(5), val); \
        return; \
    case 6: \
        MSR(MAKE_ ## _reg(6), val); \
        return; \
    case 7: \
        MSR(MAKE_ ## _reg(7), val); \
        return; \
    case 8: \
        MSR(MAKE_ ## _reg(8), val); \
        return; \
    case 9: \
        MSR(MAKE_ ## _reg(9), val); \
        return; \
    case 10: \
        MSR(MAKE_ ## _reg(10), val); \
        return; \
    case 11: \
        MSR(MAKE_ ## _reg(11), val); \
        return; \
    case 12: \
        MSR(MAKE_ ## _reg(12), val); \
        return; \
    case 13: \
        MSR(MAKE_ ## _reg(13), val); \
        return; \
    case 14: \
        MSR(MAKE_ ## _reg(14), val); \
        return; \
    case 15: \
        MSR(MAKE_ ## _reg(15), val); \
        return; \
    default: \
        assert(bp_num == 0); \
        MSR(MAKE_ ## _reg(0), val); \
        return; \
    } \
}

DEBUG_GENERATE_READ_FN(readBcrCp, DBGBCR)
DEBUG_GENERATE_READ_FN(readBvrCp, DBGBVR)
DEBUG_GENERATE_READ_FN(readWcrCp, DBGWCR)
DEBUG_GENERATE_READ_FN(readWvrCp, DBGWVR)
DEBUG_GENERATE_WRITE_FN(writeBcrCp, DBGBCR)
DEBUG_GENERATE_WRITE_FN(writeBvrCp, DBGBVR)
DEBUG_GENERATE_WRITE_FN(writeWcrCp, DBGWCR)
DEBUG_GENERATE_WRITE_FN(writeWvrCp, DBGWVR)


#endif /* CONFIG_HARDWARE_DEBUG_API */
