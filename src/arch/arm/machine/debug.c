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

#endif /* ARM_BASE_CP14_SAVE_AND_RESTORE */
