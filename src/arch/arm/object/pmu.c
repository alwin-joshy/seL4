#include <config.h>

#include <arch/object/pmu.h>

#define ISB asm volatile("isb")

static exception_t decodePMUControl_ReadEventCounter(word_t length, cap_t cap, word_t *buffer, word_t badge)
{
    seL4_Word counter = getSyscallArg(0, buffer);

    // @kwinter: Hardcoding max size of counter to 6. Have this info generalised,
    // maybe per platform in the hardware.yml files?
    if (counter > 6) {
        userError("PMUControl_ReadEventCounter: Invalid counter.");
        current_syscall_error.type = seL4_RangeError;
        return EXCEPTION_SYSCALL_ERROR;
    }

    seL4_Word counter_value = 0;
    switch(counter) {
        case EVENT_CTR_0:
            MRS(PMU_EVENT_CTR0, counter_value);
            break;
        case EVENT_CTR_1:
            MRS(PMU_EVENT_CTR1, counter_value);
            break;
        case EVENT_CTR_2:
            MRS(PMU_EVENT_CTR2, counter_value);
            break;
        case EVENT_CTR_3:
            MRS(PMU_EVENT_CTR3, counter_value);
            break;
        case EVENT_CTR_4:
            MRS(PMU_EVENT_CTR4, counter_value);
            break;
        case EVENT_CTR_5:
            MRS(PMU_EVENT_CTR5, counter_value);
            break;
        case CYCLE_CTR:
            MRS(PMU_CYCLE_CTR, counter_value);
            break;
        default:
            printf("Not a valid counter!\n");
    }

    setRegister(NODE_STATE(ksCurThread), msgRegisters[0], counter_value);
    return EXCEPTION_NONE;
}

static exception_t decodePMUControl_WriteEventCounter(word_t length, cap_t cap, word_t *buffer, word_t badge)
{
    seL4_Word counter = getSyscallArg(0, buffer);
    seL4_Word value = getSyscallArg(1, buffer);
    seL4_Word event = getSyscallArg(2, buffer);

    // @kwinter: Hardcoding max size of counter to 6. Have this info generalised,
    // maybe per platform in the hardware.yml files?
    if (counter > 6) {
        userError("PMUControl_WriteEventCounter: Invalid counter.");
        current_syscall_error.type = seL4_RangeError;
        return EXCEPTION_SYSCALL_ERROR;
    }

        switch(counter) {
        case EVENT_CTR_0:
            MSR(PMU_EVENT_CTR0, value);
            MSR(PMU_EVENT_TYP0, event);
            break;
        case EVENT_CTR_1:
            MSR(PMU_EVENT_CTR1, value);
            MSR(PMU_EVENT_TYP1, event);
            break;
        case EVENT_CTR_2:
            MSR(PMU_EVENT_CTR2, value);
            MSR(PMU_EVENT_TYP2, event);
            break;
        case EVENT_CTR_3:
            MSR(PMU_EVENT_CTR3, value);
            MSR(PMU_EVENT_TYP3, event);
            break;
        case EVENT_CTR_4:
            MSR(PMU_EVENT_CTR4, value);
            MSR(PMU_EVENT_TYP4, event);
            break;
        case EVENT_CTR_5:
            MSR(PMU_EVENT_CTR5, value);
            MSR(PMU_EVENT_TYP5, event);
            break;
        case CYCLE_CTR:
            MSR(PMU_CYCLE_CTR, value);
            break;
        default:
            printf("Not a valid counter!\n");
    }

    return EXCEPTION_NONE;
}

static exception_t decodePMUControl_CounterControl(word_t length, cap_t cap, word_t *buffer, word_t badge)
{
    seL4_Word cntl_val = getSyscallArg(0, buffer);

    if (cntl_val > 2) {
        userError("PMUControl_CounterControl: Invalid control value. Must be 0, 1 or 2.");
        current_syscall_error.type = seL4_InvalidArgument;
        return EXCEPTION_SYSCALL_ERROR;
    }

    switch(cntl_val) {
        case 0: {
            uint32_t value = 0;
            uint32_t mask = 0;

            /* Disable Performance Counter */
            MRS(PMCR_EL0, value);
            mask = 0;
            mask |= (1 << 0); /* Enable */
            mask |= (1 << 1); /* Cycle counter reset */
            mask |= (1 << 2); /* Reset all counters */
            MSR(PMCR_EL0, (value & ~mask));

            /* Disable cycle counter register */
            MRS(PMCNTENSET_EL0, value);
            mask = 0;
            mask |= (1 << 31);
            MSR(PMCNTENSET_EL0, (value & ~mask));
            break;
        }
        case 1: {
            uint32_t val;
            MRS(PMCR_EL0, val);
            val |= BIT(0);
            ISB;
            MSR(PMCR_EL0, val);
            MSR(PMCNTENSET_EL0, (BIT(31)));
            break;
        }
        case 2: {
            uint32_t value = 0;
            uint32_t mask = 0;
            MRS(PMCR_EL0, value);
            mask = 0;
            mask |= (1 << 1); /* Cycle counter reset */
            mask |= (1 << 2); /* Reset all counters */
            MSR(PMCR_EL0, (value & ~mask));
            break;
        }
        default:
            break;
    }

    return EXCEPTION_NONE;
}

static exception_t decodePMUControl_InterruptValue(word_t length, cap_t cap, word_t *buffer, word_t badge)
{
    // Get the interrupt flag from the PMU
    uint32_t irqFlag = 0;
    MRS(PMOVSCLR_EL0, irqFlag);

    // Clear the interrupt flag
    uint32_t val = BIT(31);
    MSR(PMOVSCLR_EL0, val);

    setRegister(NODE_STATE(ksCurThread), msgRegisters[0], irqFlag);

    return EXCEPTION_NONE;
}

exception_t decodePMUControlInvocation(word_t label, unsigned int length, cptr_t cptr,
                                          cte_t *srcSlot, cap_t cap, bool_t call, word_t *buffer)
{
    word_t badge = cap_pmu_control_cap_get_capPMUBadge(cap);

    switch(label) {
        case PMUReadEventCounter:
            return decodePMUControl_ReadEventCounter(length, cap, buffer, badge);
        case PMUWriteEventCounter:
            return decodePMUControl_WriteEventCounter(length, cap, buffer, badge);
        case PMUCounterControl:
            return decodePMUControl_CounterControl(length, cap, buffer, badge);
        case PMUInterruptValue:
            return decodePMUControl_InterruptValue(length, cap, buffer, badge);
        default:
            userError("PMUControl invocation: Illegal operation attempted.");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
    }
}
