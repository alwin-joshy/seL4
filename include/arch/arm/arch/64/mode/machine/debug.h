/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <config.h>

#ifdef ARM_BASE_CP14_SAVE_AND_RESTORE

/** Generates read functions for the CP14 control and value registers.
 */
#define DEBUG_GENERATE_READ_FN(_name, _reg)                                    \
  static word_t _name(uint16_t bp_num) {                                       \
    word_t ret;                                                                \
                                                                               \
    switch (bp_num) {                                                          \
    case 1:                                                                    \
      MRS(MAKE_##_reg(1), ret);                                                \
      return ret;                                                              \
    case 2:                                                                    \
      MRS(MAKE_##_reg(2), ret);                                                \
      return ret;                                                              \
    case 3:                                                                    \
      MRS(MAKE_##_reg(3), ret);                                                \
      return ret;                                                              \
    case 4:                                                                    \
      MRS(MAKE_##_reg(4), ret);                                                \
      return ret;                                                              \
    case 5:                                                                    \
      MRS(MAKE_##_reg(5), ret);                                                \
      return ret;                                                              \
    case 6:                                                                    \
      MRS(MAKE_##_reg(6), ret);                                                \
      return ret;                                                              \
    case 7:                                                                    \
      MRS(MAKE_##_reg(7), ret);                                                \
      return ret;                                                              \
    case 8:                                                                    \
      MRS(MAKE_##_reg(8), ret);                                                \
      return ret;                                                              \
    case 9:                                                                    \
      MRS(MAKE_##_reg(9), ret);                                                \
      return ret;                                                              \
    case 10:                                                                   \
      MRS(MAKE_##_reg(10), ret);                                               \
      return ret;                                                              \
    case 11:                                                                   \
      MRS(MAKE_##_reg(11), ret);                                               \
      return ret;                                                              \
    case 12:                                                                   \
      MRS(MAKE_##_reg(12), ret);                                               \
      return ret;                                                              \
    case 13:                                                                   \
      MRS(MAKE_##_reg(13), ret);                                               \
      return ret;                                                              \
    case 14:                                                                   \
      MRS(MAKE_##_reg(14), ret);                                               \
      return ret;                                                              \
    case 15:                                                                   \
      MRS(MAKE_##_reg(15), ret);                                               \
      return ret;                                                              \
    default:                                                                   \
      assert(bp_num == 0);                                                     \
      MRS(MAKE_##_reg(0), ret);                                                \
      return ret;                                                              \
    }                                                                          \
  }

/** Generates write functions for the CP14 control and value registers.
 */
#define DEBUG_GENERATE_WRITE_FN(_name, _reg)                                   \
  static void _name(uint16_t bp_num, word_t val) {                             \
    switch (bp_num) {                                                          \
    case 1:                                                                    \
      MSR(MAKE_##_reg(1), val);                                                \
      return;                                                                  \
    case 2:                                                                    \
      MSR(MAKE_##_reg(2), val);                                                \
      return;                                                                  \
    case 3:                                                                    \
      MSR(MAKE_##_reg(3), val);                                                \
      return;                                                                  \
    case 4:                                                                    \
      MSR(MAKE_##_reg(4), val);                                                \
      return;                                                                  \
    case 5:                                                                    \
      MSR(MAKE_##_reg(5), val);                                                \
      return;                                                                  \
    case 6:                                                                    \
      MSR(MAKE_##_reg(6), val);                                                \
      return;                                                                  \
    case 7:                                                                    \
      MSR(MAKE_##_reg(7), val);                                                \
      return;                                                                  \
    case 8:                                                                    \
      MSR(MAKE_##_reg(8), val);                                                \
      return;                                                                  \
    case 9:                                                                    \
      MSR(MAKE_##_reg(9), val);                                                \
      return;                                                                  \
    case 10:                                                                   \
      MSR(MAKE_##_reg(10), val);                                               \
      return;                                                                  \
    case 11:                                                                   \
      MSR(MAKE_##_reg(11), val);                                               \
      return;                                                                  \
    case 12:                                                                   \
      MSR(MAKE_##_reg(12), val);                                               \
      return;                                                                  \
    case 13:                                                                   \
      MSR(MAKE_##_reg(13), val);                                               \
      return;                                                                  \
    case 14:                                                                   \
      MSR(MAKE_##_reg(14), val);                                               \
      return;                                                                  \
    case 15:                                                                   \
      MSR(MAKE_##_reg(15), val);                                               \
      return;                                                                  \
    default:                                                                   \
      assert(bp_num == 0);                                                     \
      MSR(MAKE_##_reg(0), val);                                                \
      return;                                                                  \
    }                                                                          \
  }

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



/** Determines whether or not a Prefetch Abort or Data Abort was really a debug
 * exception.
 *
 * Examines the FSR bits, looking for the "Debug event" value, and also examines
 * DBGDSCR looking for the "Async watchpoint abort" value, since async
 * watchpoints behave differently.
 */
bool_t isDebugFault(word_t esr);

/** Determines and carries out what needs to be done for a debug exception.
 *
 * This could be handling a single-stepping exception, or a breakpoint or
 * watchpoint.
 */
seL4_Fault_t handleUserLevelDebugException(word_t exception_class, word_t fault_vaddr);

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

#endif /* CONFIG_HARDWARE_DEBUG_API */
