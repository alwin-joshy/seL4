/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

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

#endif /* ARM_BASE_CP14_SAVE_AND_RESTORE */

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
    wcr.words[0] = readWcrContext(t, bp_num);
    wcr = dbg_wcr_set_enabled(wcr, 1);
    wcr = dbg_wcr_set_pac(wcr, DBGWCR_PRIV_USER);
    wcr = dbg_wcr_set_bas(wcr, convertSizeToArch(size));
    wcr = dbg_wcr_set_lsc(wcr, convertAccessToArch(rw));
    wcr = dbg_wcr_set_watchpointType(wcr, 0);
    wcr = dbg_wcr_set_lbn(wcr, 0);
    wcr = dbg_wcr_set_addressMask(wcr, 0);
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
#ifdef CONFIG_ARCH_AARCH32
    if (Arch_breakpointIsMismatch(bcr) == true) {
        ret.type = seL4_SingleStep;
    };
#endif
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

#endif /* CONFIG_HARDWARE_DEBUG_API */
