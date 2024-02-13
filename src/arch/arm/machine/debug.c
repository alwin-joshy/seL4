#ifdef ARM_BASE_CP14_SAVE_AND_RESTORE

/** Mirrors Arch_initFpuContext.
 *
 * Zeroes out the BVR thread context and preloads reserved bit values from the
 * control regs into the thread context so we can operate solely on the values
 * cached in RAM in API calls, rather than retrieving the values from the
 * coprocessor.
 */
void Arch_initBreakpointContext(user_context_t *uc)
{
    uc->breakpointState = armKSNullBreakpointState;
}

void loadAllDisabledBreakpointState(void)
{
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
void saveAllBreakpointState(tcb_t *t)
{
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

static void loadBreakpointState(tcb_t *t)
{
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
