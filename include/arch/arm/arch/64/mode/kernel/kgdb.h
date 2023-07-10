#pragma once

#include <mode/kernel/kgdb.h>
#define NUM_REGS 34
#define NUM_REGS64 (NUM_REGS - 1)


typedef struct register_set {
    uint64_t registers_64[NUM_REGS - 1];
    uint32_t cpsr; 
} register_set_t;

void kgdb_handler(void);
