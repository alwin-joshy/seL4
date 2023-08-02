#pragma once

#include <mode/kernel/kgdb.h>
#include <types.h>

#define NUM_REGS 34
#define NUM_REGS64 (NUM_REGS - 1)

typedef struct register_set {
    uint64_t registers_64[NUM_REGS - 1];
    uint32_t cpsr;
} register_set_t;

void kgdb_handler(void);
void kgdb_handle_debug_fault(seL4_Word vaddr);