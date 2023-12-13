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

/* Bookkeeping for software breakpoints */
typedef struct sw_breakpoint {
    uint64_t addr;
    uint32_t orig_instr;
} sw_break_t;

/* Bookkeeping for hardware breakpoints */
typedef struct hw_breakpoint {
    uint64_t addr;
    uint32_t orig_instr;
} hw_break_t;

/* Different types of watchpoints */
typedef enum watchpoint_type {
    WATCHPOINT_INVALID = 0,
    WATCHPOINT_READ = 1,
    WATCHPOINT_WRITE = 2,
    WATCHPOINT_ACCESS = 3,
} watch_type_t;

/* Bookkeeping for watchpoints */
typedef struct watchpoint {
    uint64_t addr;
    watch_type_t type;
} watch_t;

/* Thread bookkeeping */
typedef struct thread_info {
    tcb_t *tcb;
    sw_break_t software_breakpoints[MAX_SW_BREAKS];
    hw_break_t hardware_breakpoints[seL4_NumExclusiveBreakpoints];
    watch_t watchpoints[seL4_NumExclusiveWatchpoints];
    bool_t single_step;
} thread_info_t;

int hex(unsigned char c);
void regs2buf(tcb_t *thread, register_set_t *regs);
void buf2regs(tcb_t *thread, register_set_t *regs);
char *regs_buf2hex(register_set_t *regs, char *buf);
bool_t set_software_breakpoint(thread_info_t *thread_info, seL4_Word addr);
bool_t unset_software_breakpoint(thread_info_t *thread_info, seL4_Word addr);
bool_t set_hardware_breakpoint(thread_info_t *thread_info, seL4_Word addr);
bool_t unset_hardware_breakpoint(thread_info_t *thread_info, seL4_Word addr);
bool_t set_watchpoint(thread_info_t *thread_info, seL4_Word addr, watch_type_t type);
bool_t unset_watchpoint(thread_info_t *thread_info, seL4_Word addr);
bool_t enable_single_step(void);
bool_t disable_single_step(void);
void arch_switch_thread(thread_info_t *curr_thread, thread_info_t *new_thread);
watch_type_t get_watchpoint_type(thread_info_t *thread_info, seL4_Word addr);
seL4_Word arch_to_big_endian(seL4_Word vaddr);

#endif /* CONFIG_GDB */
