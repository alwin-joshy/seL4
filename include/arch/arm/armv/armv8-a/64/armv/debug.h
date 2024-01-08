/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

static inline dbg_bcr_t Arch_setupBcr(dbg_bcr_t in_val, bool_t is_match)
{
    dbg_bcr_t bcr = in_val;

    // bcr = dbg_bcr_set_addressMask(in_val, 0);
    // bcr = dbg_bcr_set_hypeModeControl(bcr, 0);
    // bcr = dbg_bcr_set_secureStateControl(bcr, 0);
    // bcr = dbg_bcr_set_byteAddressSelect(bcr, convertSizeToArch(4));
    // if (is_match) {
    //     bcr = dbg_bcr_set_breakpointType(bcr, DBGBCR_TYPE_UNLINKED_INSTRUCTION_MATCH);
    // } else {
    //     bcr = dbg_bcr_set_breakpointType(bcr, DBGBCR_TYPE_UNLINKED_INSTRUCTION_MISMATCH);
    // }
    return bcr;
}

