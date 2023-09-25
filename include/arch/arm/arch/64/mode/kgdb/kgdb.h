#pragma once

#ifdef CONFIG_GDB

#include <types.h>

#define NUM_REGS 34
#define NUM_REGS64 (NUM_REGS - 1)
#define MAX_SW_BREAKS 50

#define INSTR_SIZE 4

typedef struct register_set {
    uint64_t registers_64[NUM_REGS - 1];
    uint32_t cpsr;
} register_set_t;

typedef struct sw_breakpoint {
    uint64_t addr;
    uint32_t orig_instr;
} sw_break_t;

typedef struct thread_info {
    tcb_t *tcb;
    sw_break_t software_breakpoints[MAX_SW_BREAKS];
} thread_info_t;

int hex(unsigned char c);
void regs2buf(tcb_t *thread, register_set_t *regs);
void buf2regs(tcb_t *thread, register_set_t *regs);
char *regs_buf2hex(register_set_t *regs, char *buf);
bool_t set_software_breakpoint(thread_info_t *thread_info, seL4_Word addr);
bool_t unset_software_breakpoint(thread_info_t *thread_info, seL4_Word addr);
bool_t set_hardware_breakpoint(seL4_Word addr);
bool_t unset_hardware_breakpoint(seL4_Word addr);
bool_t enable_single_step(void);
bool_t disable_single_step(void);

#endif /* CONFIG_GDB */
