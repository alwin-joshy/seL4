/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

#include <config.h>

#ifdef CONFIG_HARDWARE_DEBUG_API

#define DBGBCR_BAS_A64 0xF

enum v8_breakpoint_type {
    DBGBCR_TYPE_UNLINKED_INSTRUCTION_MATCH = 0u,
    DBGBCR_TYPE_LINKED_INSTRUCTION_MATCH = 0x1u,

    DBGBCR_TYPE_UNLINKED_CONTEXT_ID_MATCH = 0x2u,
    DBGBCR_TYPE_LINKED_CONTEXT_ID_MATCH = 0x3u,

    DBGBCR_TYPE_UNLINKED_CONTEXTIDR_EL1_MATCH = 0x6u,
    DBGBCR_TYPE_LINKED_CONTEXTIDR_EL1_MATCH = 0x7u,

    DBGBCR_TYPE_UNLINKED_VMID_MATCH = 0x8u,
    DBGBCR_TYPE_LINKED_VMID_MATCH = 0x9u,

    DBGBCR_TYPE_UNLINKED_CONTEXT_ID_AND_VMID_MATCH = 0xAu,
    DBGBCR_TYPE_LINKED_CONTEXT_ID_AND_VMID_MATCH = 0xBu,

    DBGBCR_TYPE_UNLINKED_CONTEXTIDR_EL2_MATCH = 0xCu,
    DBGBCR_TYPE_LINKED_CONTEXTIDR_EL2_MATCH = 0xDu,

    DBGBCR_TYPE_UNLINKED_FULL_CONTEXT_ID_MATCH = 0xEu,
    DBGBCR_TYPE_LINKED_FULL_CONTEXT_ID_MATCH = 0xFu,
};

static inline dbg_bcr_t Arch_setupBcr(dbg_bcr_t in_val, UNUSED bool_t is_match)
{
    dbg_bcr_t bcr = dbg_bcr_set_hmc(in_val, 0);
    bcr = dbg_bcr_set_ssc(bcr, 0);
    bcr = dbg_bcr_set_bas(bcr, DBGBCR_BAS_A64);
    bcr = dbg_bcr_set_breakpointType(bcr, DBGBCR_TYPE_UNLINKED_INSTRUCTION_MATCH);
    return bcr;
}

/** Convert a watchpoint size (0, 1, 2, 4 or 8 bytes) into the arch specific
 * register encoding.
 */
static inline word_t convertSizeToArch(word_t size) {
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

#endif /* CONFIG_HARDWARE_DEBUG_API */

