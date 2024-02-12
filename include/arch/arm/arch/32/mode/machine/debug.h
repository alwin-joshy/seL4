/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <config.h>

#define DBGDSCR_int "p14,0,%0,c0,c1,0"
/* Not guaranteed in v7, only v7.1+ */
#define DBGDSCR_ext "p14, 0, %0, c0, c2, 2"
#define DBGSDER "p15, 0, %0, c1, c1, 1"

#define DBGWFAR "p14,0,%0,c0,c6,0"
#define DFAR "p15,0,%0,c6,c0,0"

#define DBGDSCR_SECURE_MODE_DISABLED  (BIT(18))

#define DBGSDER_ENABLE_SECURE_USER_NON_INVASIVE_DEBUG   (BIT(1))

#if defined(CONFIG_DEBUG_BUILD) || defined (CONFIG_HARDWARE_DEBUG_API)

#ifndef __ASSEMBLER__
#include <stdint.h>
#include <arch/machine/registerset.h>

void debug_init(void) VISIBLE;

typedef void (*break_handler_t)(user_context_t *context);

void software_breakpoint(uint32_t va, user_context_t *context) VISIBLE;
void breakpoint_multiplexer(uint32_t va, user_context_t *context) VISIBLE;

int set_breakpoint(uint32_t va, break_handler_t handler) VISIBLE;
void clear_breakpoint(uint32_t va) VISIBLE;

enum vector_ids {
    VECTOR_RESET =          0,
    VECTOR_UNDEFINED =      1,
    VECTOR_SWI =            2,
    VECTOR_PREFETCH_ABORT = 3,
    VECTOR_DATA_ABORT =     4,
    VECTOR_IRQ =            6,
    VECTOR_FIQ =            7
};
typedef uint32_t vector_t;

typedef void (*catch_handler_t)(user_context_t *context, vector_t vector);

void set_catch_handler(catch_handler_t handler) VISIBLE;
void catch_vector(vector_t vector) VISIBLE;
void uncatch_vector(vector_t vector) VISIBLE;
#endif /* !__ASSEMBLER__ */

/*********************************/
/*** cp14 register definitions ***/
/*********************************/

/* Debug ID Register */
#define DIDR_BRP_OFFSET             24
#define DIDR_BRP_SIZE                4
#define DIDR_VERSION_OFFSET         16
#define DIDR_VERSION_SIZE            4
#define DIDR_VARIANT_OFFSET          4
#define DIDR_VARIANT_SIZE            4
#define DIDR_REVISION_OFFSET         0
#define DIDR_REVISION_SIZE           4

#ifndef __ASSEMBLER__
static inline uint32_t getDIDR(void)
{
    uint32_t x;

    asm volatile("mrc p14, 0, %0, c0, c0, 0" : "=r"(x));

    return x;
}

#ifdef CONFIG_HARDWARE_DEBUG_API

#define DEBUG_REPLY_N_REQUIRED_REGISTERS        (1)

/* Get Watchpoint Fault Address register value (for async watchpoints). */
static inline word_t getWFAR(void)
{
    word_t ret;

    MRC(DBGWFAR, ret);
    return ret;
}
#endif
#endif /* !__ASSEMBLER__ */

/* Debug Status and Control Register */
#define DSCR_MONITOR_MODE_ENABLE     15
#define DSCR_MODE_SELECT             14
#define DSCR_ENTRY_OFFSET             2
#define DSCR_ENTRY_SIZE               4

#define DEBUG_ENTRY_DBGTAP_HALT       0
#define DEBUG_ENTRY_BREAKPOINT        1
#define DEBUG_ENTRY_ASYNC_WATCHPOINT  2
#define DEBUG_ENTRY_EXPLICIT_BKPT     3
#define DEBUG_ENTRY_EDBGRQ            4
#define DEBUG_ENTRY_VECTOR_CATCH      5
#define DEBUG_ENTRY_DATA_ABORT        6
#define DEBUG_ENTRY_INSTRUCTION_ABORT 7
#define DEBUG_ENTRY_SYNC_WATCHPOINT   (0xA)

/* Vector Catch Register */
#define VCR_FIQ      7
#define VCR_IRQ      6
#define VCR_DATA     4
#define VCR_PREFETCH 3
#define VCR_SWI      2
#define VCR_UNDEF    1
#define VCR_RESET    0

#ifndef __ASSEMBLER__
static inline uint32_t getVCR(void)
{
    uint32_t x;

    asm volatile("mrc p14, 0, %0, c0, c7, 0" : "=r"(x));

    return x;
}

static inline void setVCR(uint32_t x)
{
    asm volatile("mcr p14, 0, %0, c0, c7, 0" : : "r"(x));
}

#endif /* !__ASSEMBLER__ */

/* Breakpoint Control Registers */
#define BCR_MEANING            21
#define BCR_ENABLE_LINKING     20
#define BCR_LINKED_BRP         16
#define BCR_BYTE_SELECT         5
#define BCR_SUPERVISOR          1
#define BCR_ENABLE              0

#define FSR_SHORTDESC_STATUS_DEBUG_EVENT       (0x2)
#define FSR_LONGDESC_STATUS_DEBUG_EVENT        (0x22)
#define FSR_LPAE_SHIFT                         (9)
#define FSR_STATUS_BIT4_SHIFT                  (10)

#ifndef __ASSEMBLER__

#ifdef CONFIG_HARDWARE_DEBUG_API
/** Determines whether or not a Prefetch Abort or Data Abort was really a debug
 * exception.
 *
 * Examines the FSR bits, looking for the "Debug event" value, and also examines
 * DBGDSCR looking for the "Async watchpoint abort" value, since async
 * watchpoints behave differently.
 */
bool_t isDebugFault(word_t hsr_or_fsr);

/** Determines and carries out what needs to be done for a debug exception.
 *
 * This could be handling a single-stepping exception, or a breakpoint or
 * watchpoint.
 */
seL4_Fault_t handleUserLevelDebugException(word_t fault_vaddr);

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

#endif /* !__ASSEMBLER__ */

#endif /* defined(CONFIG_DEBUG_BUILD) || defined (CONFIG_HARDWARE_DEBUG_API) */

#ifdef ARM_HYP_TRAP_CP14
/* Those of these that trap NS accesses trap all NS accesses; we can't cause the
 * processor to only trap NS-PL0 or NS-PL1, but if we want to trap the accesses,
 * we get both (PL0 and PL1) non-secure modes' accesses.
 */
#define ARM_CP15_HDCR "p15, 4, %0, c1, c1, 1"
#define HDCR_DEBUG_TDRA_SHIFT     (11) /* Trap debug ROM access from non-secure world */
#define HDCR_DEBUG_TDOSA_SHIFT    (10) /* Trap debug OS related access from NS world */
#define HDCR_DEBUG_TDA_SHIFT      (9)  /* Trap debug CP14 register access from NS world */
#define HDCR_DEBUG_TDE_SHIFT      (8)  /* Trap debug exceptions taken from NS world */
#define HDCR_PERFMON_HPME_SHIFT   (7)  /* Enable the hyp-mode perfmon counters. */
#define HDCR_PERFMON_TPM_SHIFT    (6)  /* Trap NS PM accesses */
#define HDCR_PERFMON_TPMCR_SHIFT  (5)  /* Trap NS PMCR reg access */

/** When running seL4 as a hypervisor, if we're building with support for the
 * hardware debug API, we have a case of indirection that we need to handle.
 *
 * For native PL0 user threads in the hypervisor seL4 build, if a debug
 * exception is triggered in one of them, the CPU will raise the exception and
 * naturally, it will attempt to deliver it to a PL1 exception vector table --
 * but no such table exists for native hypervisor-seL4 threads, so the CPU will
 * end up encountering a VM fault while trying to vector into the vector table.
 *
 * For this reason, for native hypervisor-seL4 threads, we need to trap the
 * debug exception DIRECTLY into the hypervisor-seL4 instance, and handle it
 * directly. So we need to SET HDCR.TDE for this case.
 *
 * For the Guest VM, if it programs the CPU to trigger breakpoints, and a
 * debug exception gets triggered, we don't want to catch those debug exceptions
 * since we can let the Guest VM handle them on its own. So we need to UNSET
 * HDCR.TDE for this case.
 *
 * This function encapsulates the setting/unsetting, and it is called when we
 * are about to enable/disable a VCPU.
 *
 * If we are enabling a vcpu (vcpu_enable) we UNSET HDCR.TDE.
 * If we are disabling a vcpu (vcpu_disable) we SET HDCR.TDE.
 */
static inline void setHDCRTrapDebugExceptionState(bool_t enable_trapping)
{
    word_t hdcr;
#ifdef CONFIG_ARCH_AARCH64
    MRS("mdcr_el2", hdcr);
#else
    MRC(ARM_CP15_HDCR, hdcr);
#endif
    if (enable_trapping) {
        /* Trap and redirect debug faults that occur in PL0 native threads by
         * setting HDCR.TDE (trap debug exceptions).
         */
        hdcr |= (BIT(HDCR_DEBUG_TDE_SHIFT)
                 | BIT(HDCR_DEBUG_TDA_SHIFT)
                 | BIT(HDCR_DEBUG_TDRA_SHIFT)
                 | BIT(HDCR_DEBUG_TDOSA_SHIFT));
    } else {
        /* Let the PL1 Guest VM handle debug events on its own */
        hdcr &= ~(BIT(HDCR_DEBUG_TDE_SHIFT)
                  | BIT(HDCR_DEBUG_TDA_SHIFT)
                  | BIT(HDCR_DEBUG_TDRA_SHIFT)
                  | BIT(HDCR_DEBUG_TDOSA_SHIFT));
    }
#ifdef CONFIG_ARCH_AARCH64
    MSR("mdcr_el2", hdcr);
#else
    MCR(ARM_CP15_HDCR, hdcr);
#endif
}

static inline void initHDCR(void)
{
    /* By default at boot, we SET HDCR.TDE to catch and redirect native threads'
     * PL0 debug exceptions.
     *
     * Unfortunately, this is complicated a bit by ARM's strange requirement that
     * if you set HDCR.TDE, you must also set TDA, TDOSA, and TDRA:
     *  ARMv7 archref manual: section B1.8.9:
     *      "When HDCR.TDE is set to 1, the HDCR.{TDRA, TDOSA, TDA} bits must all
     *      be set to 1, otherwise behavior is UNPREDICTABLE"
     *
     * Subsequently on calls to vcpu_enable/disable, we will modify HDCR.TDE
     * as needed.
     */
    setHDCRTrapDebugExceptionState(true);
}
#endif /* ARM_HYP_TRAP_CP14 */
