/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#ifdef CONFIG_HARDWARE_DEBUG_API

#endif

#include <mode/machine/debug.h>

#ifdef CONFIG_HARDWARE_DEBUG_API

enum watchpoint_access /* WCR[4:3] */ {
  DBGWCR_ACCESS_RESERVED = 0u,
  DBGWCR_ACCESS_LOAD = 1u,
  DBGWCR_ACCESS_STORE = 2u,
  DBGWCR_ACCESS_EITHER = 3u
};

/* These next few functions (read*Context()/write*Context()) read from TCB
 * context and not from the hardware registers.
 */
static inline word_t readBcrContext(tcb_t *t, uint16_t index) {
  assert(index < seL4_NumExclusiveBreakpoints);
  return t->tcbArch.tcbContext.breakpointState.breakpoint[index].cr;
}

static inline word_t readBvrContext(tcb_t *t, uint16_t index) {
  assert(index < seL4_NumExclusiveBreakpoints);
  return t->tcbArch.tcbContext.breakpointState.breakpoint[index].vr;
}

static inline word_t readWcrContext(tcb_t *t, uint16_t index) {
  assert(index < seL4_NumExclusiveWatchpoints);
  return t->tcbArch.tcbContext.breakpointState.watchpoint[index].cr;
}

static inline word_t readWvrContext(tcb_t *t, uint16_t index) {
  assert(index < seL4_NumExclusiveWatchpoints);
  return t->tcbArch.tcbContext.breakpointState.watchpoint[index].vr;
}

static inline void writeBcrContext(tcb_t *t, uint16_t index, word_t val) {
  assert(index < seL4_NumExclusiveBreakpoints);
  t->tcbArch.tcbContext.breakpointState.breakpoint[index].cr = val;
}

static inline void writeBvrContext(tcb_t *t, uint16_t index, word_t val) {
  assert(index < seL4_NumExclusiveBreakpoints);
  t->tcbArch.tcbContext.breakpointState.breakpoint[index].vr = val;
}

static inline void writeWcrContext(tcb_t *t, uint16_t index, word_t val) {
  assert(index < seL4_NumExclusiveWatchpoints);
  t->tcbArch.tcbContext.breakpointState.watchpoint[index].cr = val;
}

static inline void writeWvrContext(tcb_t *t, uint16_t index, word_t val) {
  assert(index < seL4_NumExclusiveWatchpoints);
  t->tcbArch.tcbContext.breakpointState.watchpoint[index].vr = val;
}

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

#endif /* CONFIG_HARDWARE_DEBUG_API */

#ifdef ARM_BASE_CP14_SAVE_AND_RESTORE

#define DBGBCR_ENABLE (BIT(0))
#define DBGWCR_ENABLE (BIT(0))

void restore_user_debug_context(tcb_t *target_thread);
void saveAllBreakpointState(tcb_t *t);
void loadAllDisabledBreakpointState(void);



DEBUG_GENERATE_READ_FN(readBcrCp, DBGBCR)
DEBUG_GENERATE_READ_FN(readBvrCp, DBGBVR)
DEBUG_GENERATE_READ_FN(readWcrCp, DBGWCR)
DEBUG_GENERATE_READ_FN(readWvrCp, DBGWVR)
DEBUG_GENERATE_WRITE_FN(writeBcrCp, DBGBCR)
DEBUG_GENERATE_WRITE_FN(writeBvrCp, DBGBVR)
DEBUG_GENERATE_WRITE_FN(writeWcrCp, DBGWCR)
DEBUG_GENERATE_WRITE_FN(writeWvrCp, DBGWVR)

/** For debugging: prints out the debug register pair values as returned by the
 * coprocessor.
 *
 * @param nBp Number of breakpoint reg pairs to print, starting at BP #0.
 * @param nBp Number of watchpoint reg pairs to print, starting at WP #0.
 */
UNUSED static inline void dumpBpsAndWpsCp(int nBp, int nWp) {
  int i;

  for (i = 0; i < nBp; i++) {
    userError("CP BP %d: Bcr %lx, Bvr %lx", i, readBcrCp(i), readBvrCp(i));
  }

  for (i = 0; i < nWp; i++) {
    userError("CP WP %d: Wcr %lx, Wvr %lx", i, readWcrCp(i), readWvrCp(i));
  }
}

/** Print a thread's saved debug context. For debugging. This differs from
 * dumpBpsAndWpsCp in that it reads from a thread's saved register context, and
 * not from the hardware coprocessor registers.
 *
 * @param at arch_tcb_t where the thread's reg context is stored.
 * @param nBp Number of BP regs to print, beginning at BP #0.
 * @param mWp Number of WP regs to print, beginning at WP #0.
 */
UNUSED static void dumpBpsAndWpsContext(tcb_t *t, int nBp, int nWp) {
  int i;

  for (i = 0; i < nBp; i++) {
    userError("Ctxt BP %d: Bcr %lx, Bvr %lx", i, readBcrContext(t, i),
              readBvrContext(t, i));
  }

  for (i = 0; i < nWp; i++) {
    userError("Ctxt WP %d: Wcr %lx, Wvr %lx", i, readWcrContext(t, i),
              readWvrContext(t, i));
  }
}

static inline uint16_t convertBpNumToArch(uint16_t bp_num)
{
    if (bp_num >= seL4_NumExclusiveBreakpoints) {
        bp_num -= seL4_NumExclusiveBreakpoints;
    }
    return bp_num;
}

static inline word_t getTypeFromBpNum(uint16_t bp_num)
{
    return (bp_num >= seL4_NumExclusiveBreakpoints)
           ? seL4_DataBreakpoint
           : seL4_InstructionBreakpoint;
}

static inline syscall_error_t Arch_decodeGetBreakpoint(tcb_t *t, uint16_t bp_num)
{
    syscall_error_t ret = {
        .type = seL4_NoError
    };

    if (bp_num >= seL4_FirstWatchpoint + seL4_NumExclusiveWatchpoints) {
        userError("Arch Debug: Invalid API bp_num %u.", bp_num);
        ret.type = seL4_NoError;
        return ret;
    }
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

    return ret;
}

syscall_error_t Arch_decodeSetBreakpoint(tcb_t *t,
                                         uint16_t bp_num, word_t vaddr, word_t type,
                                         word_t size, word_t rw);
syscall_error_t Arch_decodeConfigureSingleStepping(tcb_t *t,
                                                   uint16_t bp_num,
                                                   word_t n_instr,
                                                   bool_t is_reply);

#endif /* ARM_BASE_CP14_SAVE_AND_RESTORE */

#ifdef CONFIG_HARDWARE_DEBUG_API



/** Convert an arch specific encoded watchpoint size back into a simple integer
 * representation.
 */
static inline word_t convertArchToSize(word_t archsize) {
  switch (archsize) {
  case 0x1:
    return 1;
  case 0x3:
    return 2;
  case 0xFF:
    return 8;
  default:
    assert(archsize == 0xF);
    return 4;
  }
}

/** Convert an access perms API value (seL4_BreakOnRead, etc) into the register
 * encoding that matches it.
 */
static inline word_t convertAccessToArch(word_t access) {
  switch (access) {
  case seL4_BreakOnRead:
    return DBGWCR_ACCESS_LOAD;
  case seL4_BreakOnWrite:
    return DBGWCR_ACCESS_STORE;
  default:
    assert(access == seL4_BreakOnReadWrite);
    return DBGWCR_ACCESS_EITHER;
  }
}

/** Convert an arch-specific register encoding back into an API access perms
 * value.
 */
static inline word_t convertArchToAccess(word_t archaccess) {
  switch (archaccess) {
  case DBGWCR_ACCESS_LOAD:
    return seL4_BreakOnRead;
  case DBGWCR_ACCESS_STORE:
    return seL4_BreakOnWrite;
  default:
    assert(archaccess == DBGWCR_ACCESS_EITHER);
    return seL4_BreakOnReadWrite;
  }
}

static inline uint16_t getBpNumFromType(uint16_t bp_num, word_t type) {
  assert(type == seL4_InstructionBreakpoint || type == seL4_DataBreakpoint ||
         type == seL4_SingleStep);

  switch (type) {
  case seL4_InstructionBreakpoint:
  case seL4_SingleStep:
    return bp_num;
  default: /* seL4_DataBreakpoint: */
    assert(type == seL4_DataBreakpoint);
    return bp_num + seL4_NumExclusiveBreakpoints;
  }
}

/** Load an initial, all-disabled setup state for the registers.
 */
BOOT_CODE static void disableAllBpsAndWps(void) {
  int i;

  for (i = 0; i < seL4_NumExclusiveBreakpoints; i++) {
    writeBvrCp(i, 0);
    writeBcrCp(i, readBcrCp(i) & ~DBGBCR_ENABLE);
  }
  for (i = 0; i < seL4_NumExclusiveWatchpoints; i++) {
    writeWvrCp(i, 0);
    writeWcrCp(i, readWcrCp(i) & ~DBGWCR_ENABLE);
  }

  isb();
}
#endif /* CONFIG_HARDWARE_DEBUG_API */

#ifdef ARM_BASE_CP14_SAVE_AND_RESTORE



static void loadBreakpointState(tcb_t *t) {
  int i;

  assert(t != NULL);

  for (i = 0; i < seL4_NumExclusiveBreakpoints; i++) {
    if (t->tcbArch.tcbContext.breakpointState.used_breakpoints_bf & BIT(i)) {
      writeBvrCp(i, readBvrContext(t, i));
      writeBcrCp(i, readBcrContext(t, i));
    } else {
      /* If the thread isn't using the BP, then just load
       * a default "disabled" state.
       */
      writeBcrCp(i, readBcrCp(i) & ~DBGBCR_ENABLE);
    }
  }

  for (i = 0; i < seL4_NumExclusiveWatchpoints; i++) {
    if (t->tcbArch.tcbContext.breakpointState.used_breakpoints_bf &
        BIT(i + seL4_NumExclusiveBreakpoints)) {
      writeWvrCp(i, readWvrContext(t, i));
      writeWcrCp(i, readWcrContext(t, i));
    } else {
      writeWcrCp(i, readWcrCp(i) & ~DBGWCR_ENABLE);
    }
  }
}

#endif