#ifdef CONFIG_GDB

#include <string.h>
#include <mode/kgdb/kgdb.h>
#include <kgdb/kgdb.h>

#define BUFSIZE 1024
#define MONITOR_POSITION 1
#define MAX_THREADS 64

/* Input buffer */
static char kgdb_in[BUFSIZE];

/* Output buffer */
static char kgdb_out[BUFSIZE];

extern thread_info_t threads[MAX_THREADS];
extern thread_info_t *target_thread;
extern int num_threads; 

/* Output a character to serial */
static void gdb_putChar(char c)
{
    kernel_putDebugChar(c);
}

/* Read a character from serial */
static char gdb_getChar(void)
{
    char c =  kernel_getDebugChar();
    return c;
}

static char *kgdb_get_packet(void)
{
    char c;
    int count;
    /* Checksum and expected checksum */
    unsigned char cksum, xcksum;
    char *buf = kgdb_in;
    (void) buf;

    while (1) {
        /* Wait for the start character - ignoring all other characters */
        while ((c = gdb_getChar()) != '$')
#ifndef DEBUG_PRINTS
            ;
#else
        {
            gdb_putChar(c);
        }
        gdb_putChar(c);
#endif
retry:
        /* Initialize cksum variables */
        cksum = 0;
        xcksum = -1;
        count = 0;
        (void) xcksum;

        /* Read until we see a # or the buffer is full */
        while (count < BUFSIZE - 1) {
            c = gdb_getChar();
#ifdef DEBUG_PRINTS
            gdb_putChar(c);
#endif
            if (c == '$') {
                goto retry;
            } else if (c == '#') {
                break;
            }
            cksum += c;
            buf[count++] = c;
        }

        /* Null terminate the string */
        buf[count] = 0;

#ifdef DEBUG_PRINTS
        printf("\nThe value of the command so far is %s. The checksum you should enter is %x\n", buf, cksum);
#endif

        if (c == '#') {
            c = gdb_getChar();
            xcksum = hex(c) << 4;
            c = gdb_getChar();
            xcksum += hex(c);

            if (cksum != xcksum) {
                gdb_putChar('-');   /* checksum failed */
            } else {
                gdb_putChar('+');   /* checksum success, ack*/

                if (buf[2] == ':') {
                    gdb_putChar(buf[0]);
                    gdb_putChar(buf[1]);

                    return &buf[3];
                }

                return buf;
            }
        }
    }

    return NULL;
}


/*
 * Send a packet, computing it's checksum, waiting for it's acknoledge.
 * If there is not ack, packet will be resent.
 */
static void kgdb_put_packet(char *buf)
{
    uint8_t cksum;
    //kprintf("<- [%s]\n", buf);
    for (;;) {
        gdb_putChar('$');
        for (cksum = 0; *buf; buf++) {
            cksum += *buf;
            gdb_putChar(*buf);
        }
        gdb_putChar('#');
        gdb_putChar(hexchars[cksum >> 4]);
        gdb_putChar(hexchars[cksum % 16]);
        if (gdb_getChar() == '+') {
            break;
        }
    }
}

void kgdb_send_debug_packet(char *buf, int len) {
    strlcpy(kgdb_out, buf, len);
    kgdb_put_packet(kgdb_out);
}


int kgdb_register_initial_thread() {
    if (threads[num_threads].tcb != NULL) {
        return -1;
    }

    threads[num_threads].tcb = NODE_STATE(ksCurThread);
    target_thread = &threads[num_threads];
    num_threads++;
    return 0;
}

void kgdb_start_thread(tcb_t *tcb) {
    /* We use k_hex2mem for kernel virtual addresses */

    char exec_name[256];
    uint8_t thread_id = num_threads++;

    /* @alwin: Doing it like this so gdb doesn't freak out that the child is different to the parent.
               Is this the best way? */

    threads[thread_id].tcb = threads[MONITOR_POSITION].tcb;
    strlcpy(kgdb_out, "T05fork:p", sizeof(kgdb_out));
    char *buf = k_mem2hex((char *) &thread_id, kgdb_out + strnlen(kgdb_out, sizeof(kgdb_out)), sizeof(uint8_t));
    strlcpy(buf, ".1;", sizeof(kgdb_out));
    kgdb_put_packet(kgdb_out);
    kgdb_handler();

    strlcpy(kgdb_out, "T05exec:", sizeof(kgdb_out));
    snprintf(exec_name, 256, "./%s.elf", TCB_PTR_DEBUG_PTR(tcb)->tcbName);
    buf = k_mem2hex(exec_name, kgdb_out + strnlen(kgdb_out, sizeof(kgdb_out)), strnlen(exec_name, sizeof(exec_name)));
    *buf++ = ';';
    *buf = 0;
    threads[thread_id].tcb = tcb;
    kgdb_put_packet(kgdb_out);
    kgdb_handler();
}

static char *hex2regs_buf(char *buf, register_set_t *regs)
{
    /* We use k_hex2mem for kernel virtual addresses  */
    k_hex2mem(buf, (char *) regs->registers_64, NUM_REGS64 * sizeof(seL4_Word));
    
    /* 2 hex characters per byte*/
    return k_hex2mem(buf + 2 * NUM_REGS64 * sizeof(seL4_Word), (char *) &regs->cpsr, sizeof(seL4_Word) / 2);
}

static char *hex2int(char *hex_str, int max_bytes, seL4_Word *val)
{
    int curr_bytes = 0;
    while (*hex_str && curr_bytes < max_bytes) {
        uint8_t byte = *hex_str;
        byte = hex(byte);
        if (byte == (uint8_t) -1) {
            return hex_str;
        }
        *val = (*val << 4) | (byte & 0xF);
        curr_bytes++;
        hex_str++;
    }
    return hex_str;
}

/* Expected string is of the form [Mm][a-fA-F0-9]{sizeof(seL4_Word) * 2},[a-fA-F0-9] +*/
static bool_t parse_mem_format(char *ptr, seL4_Word *addr, seL4_Word *size)
{
    *addr = 0;
    *size = 0;
    bool_t is_read = true;

    /* Are we dealing with a memory read or a memory write */
    if (*ptr++ == 'M') {
        is_read = false;
    }

    /* Parse the address */
    ptr = hex2int(ptr, sizeof(seL4_Word) * 2, addr);
    if (*ptr++ != ',') {
        return false;
    }

    /* Parse the size */
    ptr = hex2int(ptr, sizeof(seL4_Word) * 2, size);

    /* Check that we have reached the end of the string */
    if (is_read) {
        // strlcpy(kgdb_out, "E01", 4);
        return (*ptr == 0);
    } else {
        return (*ptr == 0 || *ptr == ':');
    }
}


static bool_t parse_breakpoint_format(char *ptr, seL4_Word *addr, seL4_Word *kind)
{
    /* Parse the first three characters */
    assert (*ptr == 'Z' || *ptr == 'z');
    ptr++;
    assert (*ptr >= '0' && *ptr <= '4');
    ptr++;
    assert(*ptr++ == ',');

    /* Parse the addr and kind */

    *addr = 0;
    *kind = 0;

    ptr = hex2int(ptr, sizeof(seL4_Word) * 2, addr);
    if (*ptr++ != ',') {
        return false;
    }

    ptr = hex2int(ptr, sizeof(seL4_Word) * 2, kind);
    if (*kind != 4) {
        return false;
    }

    return true;
}


void kgdb_handle_debug_fault(debug_exception_t type, seL4_Word vaddr)
{
    if (type == DEBUG_SW_BREAK) {
        strlcpy(kgdb_out, "T05thread:p", sizeof(kgdb_out));
        uint8_t i = 0;
        for (i = 0; i < MAX_THREADS; i++) {
            if (threads[i].tcb == NODE_STATE(ksCurThread)) {
                break;
            }
        }
        assert(i != MAX_THREADS);

        /* @alwin: This is ugly, fix it */
        char *ptr = k_mem2hex((char *) &i, kgdb_out + strnlen(kgdb_out, sizeof(kgdb_out)), sizeof(uint8_t));
        strlcpy(ptr, ".1;swbreak:;", sizeof(kgdb_out));
        kgdb_put_packet(kgdb_out);
    } else if (type == DEBUG_HW_BREAK || type == DEBUG_SS) {
        strlcpy(kgdb_out, "T05hwbreak:;", sizeof(kgdb_out));
        kgdb_put_packet(kgdb_out);
    }
}

static void handle_read_regs(void) {
    register_set_t regs;
    regs2buf(target_thread->tcb, &regs);
    regs_buf2hex(&regs, kgdb_out);
}

static void handle_write_regs(char *ptr) {
    register_set_t regs;
    hex2regs_buf(++ptr, &regs);
    buf2regs(target_thread->tcb, &regs);
    strlcpy(kgdb_out, "OK", sizeof(kgdb_out));
}

static void handle_read_mem(char *ptr) {
    seL4_Word addr, size;

    if (!parse_mem_format(ptr, &addr, &size)) {
        /* Error parsing input */
        strlcpy(kgdb_out, "E01", sizeof(kgdb_out));
    } else if (size * 2 > sizeof(kgdb_in) - 1) {
        /* Buffer too big? Don't really get this */
        strlcpy(kgdb_out, "E01", sizeof(kgdb_out));
    } else {
        if (mem2hex(target_thread->tcb, addr, kgdb_out, size) == NULL) {
            /* Failed to read the memory at the location */
            strlcpy(kgdb_out, "E04", sizeof(kgdb_out));
        }
    }
}

static void handle_write_mem(char *ptr) {
    seL4_Word addr, size;

    if (!parse_mem_format(ptr, &addr, &size)) {
        strlcpy(kgdb_out, "E02", sizeof(kgdb_out));
    } else {
        if ((ptr = memchr(kgdb_in, ':', BUFSIZE))) {
            ptr++;
            if (hex2mem(target_thread->tcb, ptr, addr, size) == 0) {
                strlcpy(kgdb_out, "E03", sizeof(kgdb_out));
            } else {
                strlcpy(kgdb_out, "OK", sizeof(kgdb_out));
            }
        }
    }
}

static void handle_query(char *ptr) {
    if (strncmp(ptr, "qSupported", 10) == 0) {
        /* TODO: This may eventually support more features */
        snprintf(kgdb_out, sizeof(kgdb_out),
                 "qSupported:PacketSize=%lx;QThreadEvents+;swbreak+;hwbreak+;vContSupported+;fork-events+;exec-events+;multiprocess+;", sizeof(kgdb_in));
    } else if (strncmp(ptr, "qfThreadInfo", 12) == 0) {
        char *out_ptr = kgdb_out;
        *out_ptr++ = 'm';
        for (uint8_t i = 1; i < 64; i++) {
            if (i == 2 && threads[i].tcb != NULL) {
            }
            if (threads[i].tcb != NULL) {
                if (i != 1) {
                    *out_ptr++ = ',';
                }
                *out_ptr++ = 'p';
                out_ptr = k_mem2hex((char *) &i, out_ptr, sizeof(uint8_t));
                strlcpy(out_ptr, ".1", 3);
                /* @alwin: this is stupid, be better */
                out_ptr += 2;
            } else {
                break;
            }
        }
    } else if (strncmp(ptr, "qsThreadInfo", 12) == 0) {
        strlcpy(kgdb_out, "l", sizeof(kgdb_out));
    } else if (strncmp(ptr, "qC", 2) == 0) {
        strlcpy(kgdb_out, "QCp1.1", sizeof(kgdb_out));
    } else if (strncmp(ptr, "qSymbol", 7) == 0) {
        strlcpy(kgdb_out, "OK", sizeof(kgdb_out));
    } else if (strncmp(ptr, "qTStatus", 8) == 0) {
        /* TODO: THis should eventually work in the non startup case */
        strlcpy(kgdb_out, "T0", sizeof(kgdb_out));
    } else if (strncmp(ptr, "qAttached", 9) == 0) {
        strlcpy(kgdb_out, "1", sizeof(kgdb_out));
    }
}

static void handle_configure_debug_events(char *ptr) {
    seL4_Word addr, size;

    /* Breakpoints and watchpoints */
    if (strncmp(ptr, "Z0", 2) == 0) {
        /* Set a software breakpoint using binary rewriting */
        if (!parse_breakpoint_format(ptr, &addr, &size)) {
            strlcpy(kgdb_out, "E01", sizeof(kgdb_out));
            return;
        }
        if (!set_software_breakpoint(target_thread, addr)) {
            strlcpy(kgdb_out, "E01", sizeof(kgdb_out));
        } else {
            strlcpy(kgdb_out, "OK", sizeof(kgdb_out));
        }
    } else if (strncmp(ptr, "z0", 2) == 0) {
        /* Unset a software breakpoint */
        if (!parse_breakpoint_format(ptr, &addr, &size)) {
            strlcpy(kgdb_out, "E01", sizeof(kgdb_out));
            return;
        }
        if (!unset_software_breakpoint(target_thread, addr)) {
            strlcpy(kgdb_out, "E01", sizeof(kgdb_out));
        } else {
            strlcpy(kgdb_out, "OK", sizeof(kgdb_out));
        }
    } else if (strncmp(ptr, "Z1", 2) == 0) {
        /* Set a hardware breakpoint */
        if (!parse_breakpoint_format(ptr, &addr, &size)) {
            strlcpy(kgdb_out, "E01", sizeof(kgdb_out));
            return;
        }
        if (!set_hardware_breakpoint(addr)) {
            strlcpy(kgdb_out, "E01", sizeof(kgdb_out));
        } else {
            strlcpy(kgdb_out, "OK", sizeof(kgdb_out));
        }
    } else if (strncmp(ptr, "z1", 2) == 0) {
        /* Unset a hardware breakpoint */
        if (!parse_breakpoint_format(ptr, &addr, &size)) {
            strlcpy(kgdb_out, "E01", sizeof(kgdb_out));
            return;
        }
        if (!unset_hardware_breakpoint(addr)) {
            strlcpy(kgdb_out, "E01", sizeof(kgdb_out));
        } else {
            strlcpy(kgdb_out, "OK", sizeof(kgdb_out));
        }
    }
}

static int parse_thread_id(char *ptr, int *proc_id) {
    int size = 0;
    if (*ptr++ != 'p') {
        return -1;
    }

    char *ptr_tmp = ptr;
    if (strncmp(ptr, "-1", 3) == 0) {
        *proc_id = -1;
        return 0;
    }

    while (*ptr_tmp++ != '.') {
        size++;
    }

    /* 2 hex chars per byte */
    size /= 2;

    if (size == 0) {
        *proc_id = hex(*ptr);
    } else {
        k_hex2mem(ptr, (char *) proc_id, size);
    }

    ptr = ptr_tmp;
    if (*ptr != '0' && *ptr != '1') {
        return -1;
    }

    return 0;
}

static void handle_set_thread(char *ptr) {
    int proc_id = 0;

    assert(*ptr++ = 'H');

    if (*ptr != 'g' && *ptr != 'c') {
        strlcpy(kgdb_out, "E01", sizeof(kgdb_out));
        return;
    }
    ptr++;

    if (parse_thread_id(ptr, &proc_id) == -1) {
        strlcpy(kgdb_out, "E01", sizeof(kgdb_out));
        return;
    }

    // char c[2];
    // c[0] = proc_id + '0';
    // c[1] = '\0';
    // kgdb_send_debug_packet(c, 2);


    if (proc_id != -1 && proc_id != 0) {
        target_thread = &threads[proc_id];
    }

    /* @alwin : figure out what to do when proc_id is 0 */

    if (target_thread->tcb == NULL) {
        /* @alwin: todo, figure this out */
        (void) proc_id;
    }

    strlcpy(kgdb_out, "OK", sizeof(kgdb_out));
}

void kgdb_handler(void)
{
    // printf("Entering KGDB stub\n");
    char *ptr;
    while (1) {
        ptr = kgdb_get_packet();
        kgdb_out[0] = 0;
        if (*ptr == 'g') {
            handle_read_regs();
        } else if (*ptr == 'G') {
            handle_write_regs(ptr);
        } else if (*ptr == 'm') {
            handle_read_mem(ptr);
        } else if (*ptr == 'M') {
            handle_write_mem(ptr);
        } else if (*ptr == 'c' || *ptr == 's') {
            // seL4_Word addr;
            int stepping = *ptr == 's' ? 1 : 0;
            ptr++;

            if (stepping) {
                enable_single_step();
            } else {
                disable_single_step();
            }
            /* TODO: Support continue from an address and single step */
            break;
        } else if (*ptr == 'q') {
            handle_query(ptr);
        } else if (*ptr == 'H') {
            handle_set_thread(ptr);
        } else if (*ptr == '?') {
            /* TODO: This should eventually report more reasons than swbreak */
            strlcpy(kgdb_out, "T05swbreak:;", sizeof(kgdb_out));
        } else if (*ptr == 'v') {
            if (strncmp(ptr, "vCont?", 7) == 0) {
                strlcpy(kgdb_out, "vCont;c", sizeof(kgdb_out));
            } else if (strncmp(ptr, "vCont;c", 7) == 0) {
                break;
            }
        } else if (*ptr == 'z' || *ptr == 'Z') {
            handle_configure_debug_events(ptr);
        }

        kgdb_put_packet(kgdb_out);
    }
}

#endif  /* CONFIG_GDB */
