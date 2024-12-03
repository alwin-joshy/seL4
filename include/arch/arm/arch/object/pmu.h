/* This is an intial header file to add the PMU cap to AARCH64 based systems. */

#pragma once

#include <types.h>
#include <api/failures.h>
#include <object/structures.h>

// @kwinter: This following enum only contains the registers that would normally be exported
// to EL0. Discuss if we also want to provide access to the privelleged EL1 registers.
// Also this is for FEAT_PMUv3_EXT64
// enum pmu_register {
//     // FEAT_PMUv3_EXT
//     pmevcntr0,
//     pmevcntr1,
//     pmevcntr2,
//     pmevcntr3,
//     pmevcntr4,
//     pmevcntr5,
//     pmevcntr6,
//     pmevcntr7,
//     pmevcntr8,
//     pmevcntr9,
//     pmevcntr10,
//     pmevcntr11,
//     pmevcntr12,
//     pmevcntr13,
//     pmevcntr14,
//     pmevcntr15,
//     pmevcntr16,
//     pmevcntr17,
//     pmevcntr18,
//     pmevcntr19,
//     pmevcntr20,
//     pmevcntr21,
//     pmevcntr22,
//     pmevcntr23,
//     pmevcntr24,
//     pmevcntr25,
//     pmevcntr26,
//     pmevcntr27,
//     pmevcntr28,
//     pmevcntr29,
//     pmevcntr30,
//     // FEAT_PMUv3_EXT
//     pmccntr,
//     // FEAT_PMUv3_ICNTR
//     pmicntr,
//     // FEAT_PMUv3_EXT and FEAT_PCSRv8p2
//     pmpcsr,
//     pmvcidsr,
//     pmcid1sr,
//     pmpcsr,
//     // FEAT_PMUv3_EXT and FEAT_PCSRv8p2 and EL2 is implemented
//     pmvidsr,
//     // FEAT_PMUv3_EXT
//     pmccidsr,
//     pmcid1sr,
//     pmevtyper0,
//     pmevtyper1,
//     pmevtyper2,
//     pmevtyper3,
//     pmevtyper4,
//     pmevtyper5,
//     pmevtyper6,
//     pmevtyper7,
//     pmevtyper8,
//     pmevtyper9,
//     pmevtyper10,
//     pmevtyper11,
//     pmevtyper12,
//     pmevtyper13,
//     pmevtyper14,
//     pmevtyper15,
//     pmevtyper16,
//     pmevtyper17,
//     pmevtyper18,
//     pmevtyper19,
//     pmevtyper20,
//     pmevtyper21,
//     pmevtyper22,
//     pmevtyper23,
//     pmevtyper24,
//     pmevtyper25,
//     pmevtyper26,
//     pmevtyper27,
//     pmevtyper28,
//     pmevtyper29,
//     pmevtyper30,
//     // @kwinter: add back the FEAT_PMUv3_SS features that are supposed to be here.
//     pmccfiltr,
//     // FEAT_PMUv3_ICNTR
//     pmicfiltr,

// };


enum pmu_register_el0 {
    // FEAT_PMUv3_EXT
    pmevcntr0,
    pmevcntr1,
    pmevcntr2,
    pmevcntr3,
    pmevcntr4,
    pmevcntr5,
    pmevcntr6,
    pmevcntr7,
    pmevcntr8,
    pmevcntr9,
    pmevcntr10,
    pmevcntr11,
    pmevcntr12,
    pmevcntr13,
    pmevcntr14,
    pmevcntr15,
    pmevcntr16,
    pmevcntr17,
    pmevcntr18,
    pmevcntr19,
    pmevcntr20,
    pmevcntr21,
    pmevcntr22,
    pmevcntr23,
    pmevcntr24,
    pmevcntr25,
    pmevcntr26,
    pmevcntr27,
    pmevcntr28,
    pmevcntr29,
    pmevcntr30,
    // FEAT_PMUv3_EXT
    pmccntr,
    // FEAT_PMUv3_ICNTR
    pmicntr,
    // FEAT_PMUv3_EXT
    pmevtyper0,
    pmevtyper1,
    pmevtyper2,
    pmevtyper3,
    pmevtyper4,
    pmevtyper5,
    pmevtyper6,
    pmevtyper7,
    pmevtyper8,
    pmevtyper9,
    pmevtyper10,
    pmevtyper11,
    pmevtyper12,
    pmevtyper13,
    pmevtyper14,
    pmevtyper15,
    pmevtyper16,
    pmevtyper17,
    pmevtyper18,
    pmevtyper19,
    pmevtyper20,
    pmevtyper21,
    pmevtyper22,
    pmevtyper23,
    pmevtyper24,
    pmevtyper25,
    pmevtyper26,
    pmevtyper27,
    pmevtyper28,
    pmevtyper29,
    pmevtyper30,
    pmccfiltr,
    // FEAT_PMUv3_ICNTR
    pmicfiltr,
    // FEAT_PMUv3_EXT
    pmcntenset,
    pmcntenclr,
    pmovsclr,
    // FEAT_PMUv3_EXT AND FEAT_PMUv3p9
    pmzr,
    // FEAT_PMUv3_EXT
    pmovsset,
    pmcr,
    // The following registers allow us to enable/disable interrupts.
    pmintenset,
    pmintenclr,
};

// Definitions of counters available on PMU
#define EVENT_CTR_0 0
#define EVENT_CTR_1 1
#define EVENT_CTR_2 2
#define EVENT_CTR_3 3
#define EVENT_CTR_4 4
#define EVENT_CTR_5 5
#define CYCLE_CTR 6

/* PMU Register Names */
#define PMU_EVENT_CTR0 "pmevcntr0_el0"
#define PMU_EVENT_TYP0 "pmevtyper0_el0"
#define PMU_EVENT_CTR1 "pmevcntr1_el0"
#define PMU_EVENT_TYP1 "pmevtyper1_el0"
#define PMU_EVENT_CTR2 "pmevcntr2_el0"
#define PMU_EVENT_TYP2 "pmevtyper2_el0"
#define PMU_EVENT_CTR3 "pmevcntr3_el0"
#define PMU_EVENT_TYP3 "pmevtyper3_el0"
#define PMU_EVENT_CTR4 "pmevcntr4_el0"
#define PMU_EVENT_TYP4 "pmevtyper4_el0"
#define PMU_EVENT_CTR5 "pmevcntr5_el0"
#define PMU_EVENT_TYP5 "pmevtyper5_el0"
#define PMU_CYCLE_CTR "pmccntr_el0"
#define PMCR_EL0 "pmcr_el0"
#define PMCNTENSET_EL0 "pmcntenset_el0"
#define PMOVSCLR_EL0 "pmovsclr_el0"

exception_t decodePMUControlInvocation(word_t label, unsigned int length, cptr_t cptr,
                                         cte_t *srcSlot, cap_t cap,
                                         bool_t call, word_t *buffer);