#pragma once

#ifdef CONFIG_GDB

#include <types.h>

#define NUM_REGS 34
#define NUM_REGS64 (NUM_REGS - 1)
#define MAX_SW_BREAKS 50

typedef struct register_set {
    uint64_t registers_64[NUM_REGS - 1];
    uint32_t cpsr;
} register_set_t;

void regs2buf(register_set_t *regs);
void buf2regs(register_set_t *regs);
char *regs_buf2hex(register_set_t *regs, char *buf);
bool_t set_software_breakpoint(seL4_Word addr);
bool_t unset_software_breakpoint(seL4_Word addr);
bool_t set_hardware_breakpoint(seL4_Word addr);
bool_t unset_hardware_breakpoint(seL4_Word addr);
bool_t enable_single_step(void);
bool_t disable_single_step(void);

#endif /* CONFIG_GDB */
