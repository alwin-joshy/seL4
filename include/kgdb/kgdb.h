#pragma once

#ifdef CONFIG_GDB

typedef enum debug_exception {
    DEBUG_SW_BREAK = 0,
    DEBUG_HW_BREAK = 1,
    DEBUG_SS = 2,
    DEBUG_WP = 3
} debug_exception_t;

void kgdb_handler(void);
void kgdb_handle_debug_fault(debug_exception_t type, seL4_Word vaddr, bool_t was_write);
void kgdb_send_debug_packet(char *buf, int len);
void kgdb_start_thread(tcb_t *tcb);
int kgdb_register_initial_thread(void);
void kgdb_switch_thread(tcb_t *old_tcb, tcb_t *new_tcb);

#endif /* CONFIG_GDB */