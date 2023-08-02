/*
 * Copyright 2020, Data61, CSIRO (ABN 41 687 119 230)
 *
 * SPDX-License-Identifier: GPL-2.0-only
 */

#pragma once

/** Determines whether or not a Prefetch Abort or Data Abort was really a debug
 * exception.
 *
 * Examines the FSR bits, looking for the "Debug event" value, and also examines
 * DBGDSCR looking for the "Async watchpoint abort" value, since async
 * watchpoints behave differently.
 */
bool_t isDebugFault(word_t hsr_or_fsr);

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

