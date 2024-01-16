/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <config.h>

#ifdef ARM_BASE_CP14_SAVE_AND_RESTORE

#define MAKE_DBGBVR(num) "DBGBVR" #num "_EL1"
#define MAKE_DBGBCR(num) "DBGBCR" #num "_EL1"
#define MAKE_DBGWVR(num) "DBGWVR" #num "_EL1"
#define MAKE_DBGWCR(num) "DBGWCR" #num "_EL1"

#endif /* ARM_BASE_CP14_SAVE_AND_RESTORE */

// @alwin: For now, only define the breakpoints that come from lower exception levels
#define DEBUG_ENTRY_BREAKPOINT      0x30
#define DEBUG_ENTRY_SINGLE_STEP     0x32
#define DEBUG_ENTRY_WATCHPOINT      0x34
#define DEBUG_ENTRY_EXPLICIT_BKPT   0x3C

#ifdef CONFIG_HARDWARE_DEBUG_API

enum watchpoint_access /* WCR[4:3] */ {
  DBGWCR_ACCESS_RESERVED = 0u,
  DBGWCR_ACCESS_LOAD = 1u,
  DBGWCR_ACCESS_STORE = 2u,
  DBGWCR_ACCESS_EITHER = 3u
};

/** Determines whether or not a Prefetch Abort or Data Abort was really a debug
 * exception.
 *
 * Examines the FSR bits, looking for the "Debug event" value, and also examines
 * DBGDSCR looking for the "Async watchpoint abort" value, since async
 * watchpoints behave differently.
 */
bool_t isDebugFault(word_t hsr_or_fsr);

/** Determines and carries out what needs to be done for a debug exception.
 *
 * This could be handling a single-stepping exception, or a breakpoint or
 * watchpoint.
 */
seL4_Fault_t handleUserLevelDebugException(word_t exception_class, word_t fault_vaddr);

#endif /* CONFIG_HARDWARE_DEBUG_API */

#ifdef ARM_BASE_CP14_SAVE_AND_RESTORE
void restore_user_debug_context(tcb_t *target_thread);
void saveAllBreakpointState(tcb_t *t);
void loadAllDisabledBreakpointState(void);
#endif

#ifdef CONFIG_HARDWARE_DEBUG_API

static inline syscall_error_t Arch_decodeConfigureSingleStepping(tcb_t *t,
                                                                 uint16_t bp_num,
                                                                 word_t n_instr,
                                                                 bool_t is_reply)
{
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

    }

    return ret;
}

syscall_error_t Arch_decodeSetBreakpoint(tcb_t *t,
                                         uint16_t bp_num, word_t vaddr, word_t type,
                                         word_t size, word_t rw);


#endif /* CONFIG_HARDWARE_DEBUG_API */
