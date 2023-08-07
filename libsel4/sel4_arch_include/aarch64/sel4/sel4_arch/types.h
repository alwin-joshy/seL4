/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: BSD-2-Clause
 */

#pragma once

#include <sel4/simple_types.h>

typedef seL4_CPtr seL4_ARM_PageUpperDirectory;
typedef seL4_CPtr seL4_ARM_PageGlobalDirectory;
/* whether the VSpace refers to a PageUpperDirectory or PageGlobalDirectory directly
 * depends on the physical address size */
typedef seL4_CPtr seL4_ARM_VSpace;

typedef struct seL4_UserContext_ {
    /* frame registers */
    seL4_Word pc, sp, spsr, x0, x1, x2, x3, x4, x5, x6, x7, x8, x16, x17, x18, x29, x30;
    /* other integer registers */
    seL4_Word x9, x10, x11, x12, x13, x14, x15, x19, x20, x21, x22, x23, x24, x25, x26, x27, x28;
    /* Thread ID registers */
    seL4_Word tpidr_el0, tpidrro_el0;
} seL4_UserContext;

typedef struct seL4_CapSet_ {
    /* cptrs */
    seL4_Word c0, c1, c2, c3, c4, c5, c6, c7, c8, c9, c10, c11, c12, c13, c14, c15, c16, c17, c18,
              c19, c20, c21, c22, c23, c24, c25, c26, c27, c28, c29, c30, c31;

    /* Number of capabilities passed in */
    seL4_Word num;
} seL4_CapSet;