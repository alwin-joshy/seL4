#pragma once

#ifdef CONFIG_GDB

typedef enum debug_exception {
    DEBUG_SW_BREAK = 0,
    DEBUG_HW_BREAK = 1,
    DEBUG_SS = 3
} debug_exception_t;

void kgdb_handler(void);
void kgdb_handle_debug_fault(debug_exception_t type, seL4_Word vaddr);
void kgdb_send_debug_packet(char *buf, int len);

#endif /* CONFIG_GDB */