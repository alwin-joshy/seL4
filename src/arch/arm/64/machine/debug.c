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

#define DBGDSCR_MDBGEN (BIT(15))
#define DBGDSCR_HDBGEN (BIT(14))
#define DBGDSCR_USER_ACCESS_DISABLE (BIT(12))

/* This bit is always RAO */
#define DBGLSR_LOCK_IMPLEMENTED (BIT(0))
#define DBGLSR_LOCK_ENABLED (BIT(1))
#define DBGLAR_UNLOCK_VALUE (0xC5ACCE55u)

#define DBGOSLAR_LOCK_VALUE (0xC5ACCE55u)

#define DBGOSLSR_GET_OSLOCK_MODEL(v) ((((v) >> 2u) & 0x2u) | ((v) & 0x1u))
#define DBGOSLSR_LOCK_MODEL_NO_OSLOCK (0u)
#define DBGOSLSR_LOCK_MODEL_OSLOCK_AND_OSSR (1u)
#define DBGOSLSR_LOCK_MODEL_OSLOCK_ONLY (2u)

#define DBGPRSR_OSLOCK (BIT(5))
#define DBGPRSR_OS_DLOCK (BIT(6))

#define DBGOSDLR_LOCK_ENABLE (BIT(0))

#define DBGAUTHSTATUS_NSI_IMPLEMENTED (BIT(1))
#define DBGAUTHSTATUS_NSI_ENABLED (BIT(0))
#define DBGAUTHSTATUS_SI_IMPLEMENTED (BIT(5))
#define DBGAUTHSTATUS_SI_ENABLED (BIT(4))

#define DBGDRAR_VALID (MASK(2))
#define DBGDSAR_VALID (MASK(2))

#define DBGSDER_ENABLE_SECURE_USER_INVASIVE_DEBUG (BIT(0))

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

enum watchpoint_access /* WCR[4:3] */ {
  DBGWCR_ACCESS_RESERVED = 0u,
  DBGWCR_ACCESS_LOAD = 1u,
  DBGWCR_ACCESS_STORE = 2u,
  DBGWCR_ACCESS_EITHER = 3u
};

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

#ifdef ARM_BASE_CP14_SAVE_AND_RESTORE

#define DBGBCR_ENABLE (BIT(0))

#define DBGWCR_ENABLE (BIT(0))

#define MAKE_DBGBVR(num) "DBGBVR" #num "_EL1"
#define MAKE_DBGBCR(num) "DBGBCR" #num "_EL1"
#define MAKE_DBGWVR(num) "DBGWVR" #num "_EL1"
#define MAKE_DBGWCR(num) "DBGWCR" #num "_EL1"
// #define MAKE_DBGXVR(num) MAKE_P14(1, num, 1)

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

DEBUG_GENERATE_READ_FN(readBcrCp, DBGBCR)
DEBUG_GENERATE_READ_FN(readBvrCp, DBGBVR)
DEBUG_GENERATE_READ_FN(readWcrCp, DBGWCR)
DEBUG_GENERATE_READ_FN(readWvrCp, DBGWVR)
DEBUG_GENERATE_WRITE_FN(writeBcrCp, DBGBCR)
DEBUG_GENERATE_WRITE_FN(writeBvrCp, DBGBVR)
DEBUG_GENERATE_WRITE_FN(writeWcrCp, DBGWCR)
DEBUG_GENERATE_WRITE_FN(writeWvrCp, DBGWVR)

/* These next few functions (read*Context()/write*Context()) read from TCB
 * context and not from the hardware registers.
 */
static word_t readBcrContext(tcb_t *t, uint16_t index) {
  assert(index < seL4_NumExclusiveBreakpoints);
  return t->tcbArch.tcbContext.breakpointState.breakpoint[index].cr;
}

static word_t readBvrContext(tcb_t *t, uint16_t index) {
  assert(index < seL4_NumExclusiveBreakpoints);
  return t->tcbArch.tcbContext.breakpointState.breakpoint[index].vr;
}

static word_t readWcrContext(tcb_t *t, uint16_t index) {
  assert(index < seL4_NumExclusiveWatchpoints);
  return t->tcbArch.tcbContext.breakpointState.watchpoint[index].cr;
}

static word_t readWvrContext(tcb_t *t, uint16_t index) {
  assert(index < seL4_NumExclusiveWatchpoints);
  return t->tcbArch.tcbContext.breakpointState.watchpoint[index].vr;
}

static void writeBcrContext(tcb_t *t, uint16_t index, word_t val) {
  assert(index < seL4_NumExclusiveBreakpoints);
  t->tcbArch.tcbContext.breakpointState.breakpoint[index].cr = val;
}

static void writeBvrContext(tcb_t *t, uint16_t index, word_t val) {
  assert(index < seL4_NumExclusiveBreakpoints);
  t->tcbArch.tcbContext.breakpointState.breakpoint[index].vr = val;
}

static void writeWcrContext(tcb_t *t, uint16_t index, word_t val) {
  assert(index < seL4_NumExclusiveWatchpoints);
  t->tcbArch.tcbContext.breakpointState.watchpoint[index].cr = val;
}

static void writeWvrContext(tcb_t *t, uint16_t index, word_t val) {
  assert(index < seL4_NumExclusiveWatchpoints);
  t->tcbArch.tcbContext.breakpointState.watchpoint[index].vr = val;
}

#endif /* ARM_BASE_CP14_SAVE_AND_RESTORE */

#ifdef CONFIG_HARDWARE_DEBUG_API

/** For debugging: prints out the debug register pair values as returned by the
 * coprocessor.
 *
 * @param nBp Number of breakpoint reg pairs to print, starting at BP #0.
 * @param nBp Number of watchpoint reg pairs to print, starting at WP #0.
 */
UNUSED static void dumpBpsAndWpsCp(int nBp, int nWp) {
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
static UNUSED word_t convertSizeToArch(word_t size) {
  switch (size) {
  case 1:
    return 0x1;
  case 2:
    return 0x3;
  case 8:
    return 0xFF;
  default:
    assert(size == 4);
    return 0xF;
  }
}

/** Convert an arch specific encoded watchpoint size back into a simple integer
 * representation.
 */
static word_t convertArchToSize(word_t archsize) {
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
static word_t convertAccessToArch(word_t access) {
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
static word_t convertArchToAccess(word_t archaccess) {
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

static UNUSED uint16_t getBpNumFromType(uint16_t bp_num, word_t type) {
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

/** Extracts the "Method of Entry" bits from DBGDSCR.
 *
 * Used to determine what type of debug exception has occurred.
 */
static inline word_t getMethodOfEntry(void) {
  return 0;
  // @alwin: Port this to aarch64
  //    dbg_dscr_t dscr;

  //    dscr.words[0] = readDscrCp();
  //    return dbg_dscr_get_methodOfEntry(dscr);
}

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
        userError("Enabling!");
        t->tcbArch.tcbContext.breakpointState.single_step_enabled = true;
    } else {
        /* Disable single stepping */
        t->tcbArch.tcbContext.breakpointState.single_step_enabled = false;
    }

    t->tcbArch.tcbContext.breakpointState.n_instructions = n_instr;
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
BOOT_CODE UNUSED static void initVersionInfo(void) {
  //    dbg_didr_t didr;
  //
  //    didr.words[0] = getDIDR();
  //    dbg.oem_revision = dbg_didr_get_revision(didr);
  //    dbg.oem_variant = dbg_didr_get_variant(didr);
  //    dbg.didr_version = dbg_didr_get_version(didr);
  //    dbg.coprocessor_is_baseline_only = true;
  //    dbg.breakpoints_supported = dbg.watchpoints_supported =
  //                                    dbg.single_step_supported = true;
  //
  //    switch (dbg.didr_version) {
  //    case 0x1:
  //        dbg.debug_armv = 0x60;
  //        dbg.single_step_supported = false;
  //        break;
  //    case 0x2:
  //        dbg.debug_armv = 0x61;
  //        break;
  //    case 0x3:
  //        dbg.debug_armv = 0x70;
  //        dbg.coprocessor_is_baseline_only = false;
  //        break;
  //    case 0x4:
  //        dbg.debug_armv = 0x70;
  //        break;
  //    case 0x5:
  //        dbg.debug_armv = 0x71;
  //        dbg.coprocessor_is_baseline_only = false;
  //        break;
  //    case 0x6:
  //        dbg.debug_armv = 0x80;
  //        dbg.coprocessor_is_baseline_only = false;
  //        break;
  //    default:
  //        dbg.is_available = false;
  //        dbg.debug_armv = 0;
  //        return;
  //    }
  //
  //    dbg.is_available = true;
}

/** Load an initial, all-disabled setup state for the registers.
 */
BOOT_CODE UNUSED static void disableAllBpsAndWps(void) {
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
  //    /* Ensure that all the breakpoint and watchpoint registers are initially
  //    disabled */
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

  // @alwin: Port this to aarch64
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

/** Abstract wrapper around the IFSR/DFSR fault status values.
 *
 * Format of the FSR bits is different for long and short descriptors, so
 * extract the FSR bits and accompany them with a boolean.
 */

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

#endif /* CONFIG_HARDWARE_DEBUG_API */

#ifdef ARM_BASE_CP14_SAVE_AND_RESTORE

/** Mirrors Arch_initFpuContext.
 *
 * Zeroes out the BVR thread context and preloads reserved bit values from the
 * control regs into the thread context so we can operate solely on the values
 * cached in RAM in API calls, rather than retrieving the values from the
 * coprocessor.
 */
void Arch_initBreakpointContext(user_context_t *uc) {
  uc->breakpointState = armKSNullBreakpointState;
}

void loadAllDisabledBreakpointState(void) {
  int i;

  /* We basically just want to read-modify-write each reg to ensure its
   * "ENABLE" bit is clear. We did preload the register context with the
   * reserved values from the control registers, so we can read our
   * initial values from either the coprocessor or the thread's register
   * context.
   *
   * Both are perfectly fine, and the only discriminant factor is performance.
   * I suspect that reading from RAM is faster than reading from the
   * coprocessor, but I can't be sure.
   */
  for (i = 0; i < seL4_NumExclusiveBreakpoints; i++) {
    writeBcrCp(i, readBcrCp(i) & ~DBGBCR_ENABLE);
  }
  for (i = 0; i < seL4_NumExclusiveWatchpoints; i++) {
    writeWcrCp(i, readWcrCp(i) & ~DBGWCR_ENABLE);
  }
}

/* We only need to save the breakpoint state in the hypervisor
 * build, and only for threads that have an associated VCPU.
 *
 * When the normal kernel is running with the debug API, all
 * changes to the debug regs are done through the debug API.
 * In the hypervisor build, the guest VM has full access to the
 * debug regs in PL1, so we need to save its values on vmexit.
 *
 * When saving the debug regs we will always save all of them.
 * When restoring, we will restore only those that have been used
 * for native threads; and we will restore all of them
 * unconditionally for VCPUs (because we don't know which of
 * them have been changed by the guest).
 *
 * To ensure that all the debug regs are restored unconditionally,
 * we just set the "used_breakpoints_bf" bitfield to all 1s in
 * associateVcpu.
 */
void saveAllBreakpointState(tcb_t *t) {
  int i;

  assert(t != NULL);

  for (i = 0; i < seL4_NumExclusiveBreakpoints; i++) {
    writeBvrContext(t, i, readBvrCp(i));
    writeBcrContext(t, i, readBcrCp(i));
  }

  for (i = 0; i < seL4_NumExclusiveWatchpoints; i++) {
    writeWvrContext(t, i, readWvrCp(i));
    writeWcrContext(t, i, readWcrCp(i));
  }
}

#ifdef ARM_HYP_CP14_SAVE_AND_RESTORE_VCPU_THREADS
void Arch_debugAssociateVCPUTCB(tcb_t *t) {
  /* Don't attempt to shift beyond end of word. */
  assert(seL4_NumHWBreakpoints < sizeof(word_t) * 8);

  /* Set all the bits to 1, so loadBreakpointState() will
   * restore all the debug regs unconditionally.
   */
  t->tcbArch.tcbContext.breakpointState.used_breakpoints_bf =
      MASK(seL4_NumHWBreakpoints);
}

void Arch_debugDissociateVCPUTCB(tcb_t *t) {
  t->tcbArch.tcbContext.breakpointState.used_breakpoints_bf = 0;
}
#endif

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
