/* This is an intial header file to add the PMU cap to AARCH64 based systems. */

#pragma once

#include <types.h>
#include <api/failures.h>
#include <object/structures.h>

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