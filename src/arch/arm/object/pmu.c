#include <config.h>

#include <arch/object/pmu.h>

#define ISB asm volatile("isb")

// @kwinter: The following functions are tagged with which ARM extension impelments the features.

/* FEAT_PMUv3_EXT */
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
        // @kwinter: The spec can support up to 30 counters. We will need to extend this to support a MAX of 30.
        // Maybe add definitions in per board to state how many counters and what extensions are actually supported.
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

/* FEAT_PMUv3_EXT */
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

/* FEAT_PMUv3_EXT */
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

/* FEAT_PMUv3_EXT */
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

// Read from any specified PMU regsiter as defined by the regsiter defintion enum
static exception_t decodePMUControl_Read(word_t length, cap_t cap, word_t *buffer, word_t badge)
{
    seL4_Word register_num = getSyscallArg(0, buffer);

    // @kwinter: Add error checking here
    seL4_Word register_value = 0;

    switch(register_num) {
        case pmevcntr0:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR0_EL0", register_value);
            break;
            #endif
        case pmevcntr1:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR1_EL0", register_value);
            break;
            #endif
        case pmevcntr2:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR2_EL0", register_value);
            break;
            #endif
        case pmevcntr3:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR3_EL0", register_value);
            break;
            #endif
        case pmevcntr4:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR4_EL0", register_value);
            break;
            #endif
        case pmevcntr5:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR5_EL0", register_value);
            break;
            #endif
        case pmevcntr6:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR6_EL0", register_value);
            break;
            #endif
        case pmevcntr7:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR7_EL0", register_value);
            break;
            #endif
        case pmevcntr8:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR8_EL0", register_value);
            break;
            #endif
        case pmevcntr9:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR9_EL0", register_value);
            break;
            #endif
        case pmevcntr10:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR10_EL0", register_value);
            break;
            #endif
        case pmevcntr11:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR11_EL0", register_value);
            break;
            #endif
        case pmevcntr12:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR12_EL0", register_value);
            break;
            #endif
        case pmevcntr13:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR13_EL0", register_value);
            break;
            #endif
        case pmevcntr14:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR14_EL0", register_value);
            break;
            #endif
        case pmevcntr15:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR15_EL0", register_value);
            break;
            #endif
        case pmevcntr16:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR16_EL0", register_value);
            break;
            #endif
        case pmevcntr17:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR17_EL0", register_value);
            break;
            #endif
        case pmevcntr18:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR18_EL0", register_value);
            break;
            #endif
        case pmevcntr19:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR19_EL0", register_value);
            break;
            #endif
        case pmevcntr20:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR20_EL0", register_value);
            break;
            #endif
        case pmevcntr21:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR21_EL0", register_value);
            break;
            #endif
        case pmevcntr22:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR22_EL0", register_value);
            break;
            #endif
        case pmevcntr23:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR23_EL0", register_value);
            break;
            #endif
        case pmevcntr24:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR24_EL0", register_value);
            break;
            #endif
        case pmevcntr25:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR25_EL0", register_value);
            break;
            #endif
        case pmevcntr26:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR26_EL0", register_value);
            break;
            #endif
        case pmevcntr27:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR27_EL0", register_value);
            break;
            #endif
        case pmevcntr28:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR28_EL0", register_value);
            break;
            #endif
        case pmevcntr29:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR29_EL0", register_value);
            break;
            #endif
        case pmevcntr30:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVCNTR30_EL0", register_value);
            break;
            #endif
        case pmccntr:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMCCNTR_EL0", register_value);
            break;
            #endif
        case pmicntr:
            #ifdef CONFIG_FEAT_PMUv3_ICNTR
            MRS("PMICNTR_EL0", register_value);
            break;
            #endif
        case pmevtyper0:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER0_EL0", register_value);
            break;
            #endif
        case pmevtyper1:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER1_EL0", register_value);
            break;
            #endif
        case pmevtyper2:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER2_EL0", register_value);
            break;
            #endif
        case pmevtyper3:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER3_EL0", register_value);
            break;
            #endif
        case pmevtyper4:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER4_EL0", register_value);
            break;
            #endif
        case pmevtyper5:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER5_EL0", register_value);
            break;
            #endif
        case pmevtyper6:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER6_EL0", register_value);
            break;
            #endif
        case pmevtyper7:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER7_EL0", register_value);
            break;
            #endif
        case pmevtyper8:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER8_EL0", register_value);
            break;
            #endif
        case pmevtyper9:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER9_EL0", register_value);
            break;
            #endif
        case pmevtyper10:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER10_EL0", register_value);
            break;
            #endif
        case pmevtyper11:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER11_EL0", register_value);
            break;
            #endif
        case pmevtyper12:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER12_EL0", register_value);
            break;
            #endif
        case pmevtyper13:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER13_EL0", register_value);
            break;
            #endif
        case pmevtyper14:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER14_EL0", register_value);
            break;
            #endif
        case pmevtyper15:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER15_EL0", register_value);
            break;
            #endif
        case pmevtyper16:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER16_EL0", register_value);
            break;
            #endif
        case pmevtyper17:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER17_EL0", register_value);
            break;
            #endif
        case pmevtyper18:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER18_EL0", register_value);
            break;
            #endif
        case pmevtyper19:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER19_EL0", register_value);
            break;
            #endif
        case pmevtyper20:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER20_EL0", register_value);
            break;
            #endif
        case pmevtyper21:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER21_EL0", register_value);
            break;
            #endif
        case pmevtyper22:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER22_EL0", register_value);
            break;
            #endif
        case pmevtyper23:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER23_EL0", register_value);
            break;
            #endif
        case pmevtyper24:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER24_EL0", register_value);
            break;
            #endif
        case pmevtyper25:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER25_EL0", register_value);
            break;
            #endif
        case pmevtyper26:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER26_EL0", register_value);
            break;
            #endif
        case pmevtyper27:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER27_EL0", register_value);
            break;
            #endif
        case pmevtyper28:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER28_EL0", register_value);
            break;
            #endif
        case pmevtyper29:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER29_EL0", register_value);
            break;
            #endif
        case pmevtyper30:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMEVTYPER30_EL0", register_value);
            break;
            #endif
        case pmicfiltr:
            #ifdef CONFIG_FEAT_PMUv3_ICNTR
            MRS("PMCCFILTR_EL0", register_value);
            break;
            #endif
        case pmcntenset:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMCNTENSET_EL0", register_value);
            break;
            #endif
        case pmcntenclr:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMCNTENCLR_EL0", register_value);
            break;
            #endif
        case pmovsclr:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMOVSCLR_EL0", register_value);
            break;
            #endif
        case pmzr:
            #if defined(CONFIG_FEAT_PMUv3_EXT) && defined(CONFIG_FEAT_PMUv3p9)
            MRS("PMZR_EL0", register_value);
            break;
            #endif
        case pmovsset:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMOVSSET_EL0", register_value);
            break;
            #endif
        case pmcr:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMCR_EL0", register_value);
            break;
            #endif
        case pmintenset:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMINTENSET_EL1", register_value);
            break;
            #endif
        case pmintenclr:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MRS("PMINTENCLR_EL1", register_value);
            break;
            #endif
        default:
             printf("Not a valid register: %ld!\n", register_num);
             // @kwinter: Return an execption here. Either it was not a
             // valid register, or no PMU features where enabled.
    }

    setRegister(NODE_STATE(ksCurThread), msgRegisters[0], register_value);
    return EXCEPTION_NONE;
}

// Write to any specified PMU register as defined by the register definition enumß.
static exception_t decodePMUControl_Write(word_t length, cap_t cap, word_t *buffer, word_t badge)
{
    seL4_Word register_num = getSyscallArg(0, buffer);
    UNUSED seL4_Word register_value = getSyscallArg(1, buffer);

     // @kwinter: Add error checking here
    switch(register_num) {
        case pmevcntr0:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR0_EL0", register_value);
            break;
            #endif
        case pmevcntr1:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR1_EL0", register_value);
            break;
            #endif
        case pmevcntr2:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR2_EL0", register_value);
            break;
            #endif
        case pmevcntr3:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR3_EL0", register_value);
            break;
            #endif
        case pmevcntr4:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR4_EL0", register_value);
            break;
            #endif
        case pmevcntr5:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR5_EL0", register_value);
            break;
            #endif
        case pmevcntr6:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR6_EL0", register_value);
            break;
            #endif
        case pmevcntr7:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR7_EL0", register_value);
            break;
            #endif
        case pmevcntr8:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR8_EL0", register_value);
            break;
            #endif
        case pmevcntr9:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR9_EL0", register_value);
            break;
            #endif
        case pmevcntr10:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR10_EL0", register_value);
            break;
            #endif
        case pmevcntr11:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR11_EL0", register_value);
            break;
            #endif
        case pmevcntr12:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR12_EL0", register_value);
            break;
            #endif
        case pmevcntr13:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR13_EL0", register_value);
            break;
            #endif
        case pmevcntr14:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR14_EL0", register_value);
            break;
            #endif
        case pmevcntr15:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR15_EL0", register_value);
            break;
            #endif
        case pmevcntr16:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR16_EL0", register_value);
            break;
            #endif
        case pmevcntr17:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR17_EL0", register_value);
            break;
            #endif
        case pmevcntr18:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR18_EL0", register_value);
            break;
            #endif
        case pmevcntr19:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR19_EL0", register_value);
            break;
            #endif
        case pmevcntr20:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR20_EL0", register_value);
            break;
            #endif
        case pmevcntr21:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR21_EL0", register_value);
            break;
            #endif
        case pmevcntr22:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR22_EL0", register_value);
            break;
            #endif
        case pmevcntr23:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR23_EL0", register_value);
            break;
            #endif
        case pmevcntr24:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR24_EL0", register_value);
            break;
            #endif
        case pmevcntr25:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR25_EL0", register_value);
            break;
            #endif
        case pmevcntr26:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR26_EL0", register_value);
            break;
            #endif
        case pmevcntr27:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR27_EL0", register_value);
            break;
            #endif
        case pmevcntr28:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR28_EL0", register_value);
            break;
            #endif
        case pmevcntr29:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR29_EL0", register_value);
            break;
            #endif
        case pmevcntr30:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVCNTR30_EL0", register_value);
            break;
            #endif
        case pmccntr:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMCCNTR_EL0", register_value);
            break;
            #endif
        case pmicntr:
            #ifdef FEAT_PMUv3_ICNTR
            MSR("PMICNTR_EL0", register_value);
            break;
            #endif
        case pmevtyper0:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER0_EL0", register_value);
            break;
            #endif
        case pmevtyper1:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER1_EL0", register_value);
            break;
            #endif
        case pmevtyper2:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER2_EL0", register_value);
            break;
            #endif
        case pmevtyper3:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER3_EL0", register_value);
            break;
            #endif
        case pmevtyper4:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER4_EL0", register_value);
            break;
            #endif
        case pmevtyper5:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER5_EL0", register_value);
            break;
            #endif
        case pmevtyper6:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER6_EL0", register_value);
            break;
            #endif
        case pmevtyper7:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER7_EL0", register_value);
            break;
            #endif
        case pmevtyper8:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER8_EL0", register_value);
            break;
            #endif
        case pmevtyper9:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER9_EL0", register_value);
            break;
            #endif
        case pmevtyper10:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER10_EL0", register_value);
            break;
            #endif
        case pmevtyper11:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER11_EL0", register_value);
            break;
            #endif
        case pmevtyper12:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER12_EL0", register_value);
            break;
            #endif
        case pmevtyper13:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER13_EL0", register_value);
            break;
            #endif
        case pmevtyper14:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER14_EL0", register_value);
            break;
            #endif
        case pmevtyper15:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER15_EL0", register_value);
            break;
            #endif
        case pmevtyper16:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER16_EL0", register_value);
            break;
            #endif
        case pmevtyper17:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER17_EL0", register_value);
            break;
            #endif
        case pmevtyper18:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER18_EL0", register_value);
            break;
            #endif
        case pmevtyper19:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER19_EL0", register_value);
            break;
            #endif
        case pmevtyper20:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER20_EL0", register_value);
            break;
            #endif
        case pmevtyper21:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER21_EL0", register_value);
            break;
            #endif
        case pmevtyper22:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER22_EL0", register_value);
            break;
            #endif
        case pmevtyper23:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER23_EL0", register_value);
            break;
            #endif
        case pmevtyper24:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER24_EL0", register_value);
            break;
            #endif
        case pmevtyper25:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER25_EL0", register_value);
            break;
            #endif
        case pmevtyper26:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER26_EL0", register_value);
            break;
            #endif
        case pmevtyper27:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER27_EL0", register_value);
            break;
            #endif
        case pmevtyper28:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER28_EL0", register_value);
            break;
            #endif
        case pmevtyper29:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER29_EL0", register_value);
            break;
            #endif
        case pmevtyper30:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMEVTYPER30_EL0", register_value);
            break;
            #endif
        case pmicfiltr:
            #ifdef CONFIG_FEAT_PMUv3_ICNTR
            MSR("PMCCFILTR_EL0", register_value);
            break;
            #endif
        case pmcntenset:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMCNTENSET_EL0", register_value);
            break;
            #endif
        case pmcntenclr:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMCNTENCLR_EL0", register_value);
            break;
            #endif
        case pmovsclr:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMOVSCLR_EL0", register_value);
            break;
            #endif
        case pmzr:
            #if defined(CONFIG_FEAT_PMUv3_EXT) && defined(CONFIG_FEAT_PMUv3p9)
            MSR("PMZR_EL0", register_value);
            break;
            #endif
        case pmovsset:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMOVSSET_EL0", register_value);
            break;
            #endif
        case pmcr:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMCR_EL0", register_value);
            break;
            #endif
        case pmintenset:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMINTENSET_EL1", register_value);
            break;
            #endif
        case pmintenclr:
            #ifdef CONFIG_FEAT_PMUv3_EXT
            MSR("PMINTENCLR_EL1", register_value);
            break;
            #endif
        default:
             printf("Not a valid register: %ld!\n", register_num);
    }

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
        case PMURead:
            return decodePMUControl_Read(length, cap, buffer, badge);
        case PMUWrite:
            return decodePMUControl_Write(length, cap, buffer, badge);
        default:
            userError("PMUControl invocation: Illegal operation attempted.");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
    }
}
