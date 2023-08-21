#ifdef CONFIG_GDB

#include <string.h>
#include <mode/kgdb/kgdb.h>
#include <kgdb/kgdb.h>

#define BUFSIZE 1024

/* Input buffer */
static char kgdb_in[BUFSIZE];

/* Output buffer */
static char kgdb_out[BUFSIZE];

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

static void mystrcpy(char *dest, char *src, int num)
{
    (void) num;
    int i = -1;
    do {
        i++;
        dest[i] = src[i];
    } while (src[i] != '\0');
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
    mystrcpy(kgdb_out, buf, len);
    kgdb_put_packet(kgdb_out);
}

static char *hex2regs_buf(char *buf, register_set_t *regs)
{
    hex2mem(buf, (char *) regs->registers_64, NUM_REGS64 * sizeof(seL4_Word));
    /* 2 hex characters per byte*/
    return hex2mem(buf + 2 * NUM_REGS64 * sizeof(seL4_Word), (char *) &regs->cpsr, sizeof(seL4_Word) / 2);
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
        // mystrcpy(kgdb_out, "E01", 4);
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
        mystrcpy(kgdb_out, "T05swbreak:;", 13);
        kgdb_put_packet(kgdb_out);
    } else if (type == DEBUG_HW_BREAK || type == DEBUG_SS) {
        mystrcpy(kgdb_out, "T05hwbreak:;", 13);
        kgdb_put_packet(kgdb_out);
    }
}

static void handle_read_regs(void) {
    register_set_t regs;
    regs2buf(&regs);
    regs_buf2hex(&regs, kgdb_out);
}

static void handle_write_regs(char *ptr) {
    register_set_t regs;
    hex2regs_buf(++ptr, &regs);
    buf2regs(&regs);
    mystrcpy(kgdb_out, "OK", 3);
}

static void handle_read_mem(char *ptr) {
    seL4_Word addr, size;

    if (!parse_mem_format(ptr, &addr, &size)) {
        /* Error parsing input */
        mystrcpy(kgdb_out, "E01", 4);
    } else if (size * 2 > sizeof(kgdb_in) - 1) {
        /* Buffer too big? Don't really get this */
        mystrcpy(kgdb_out, "E01", 4);
    } else {
        if (mem2hex((char *) addr, kgdb_out, size) == NULL) {
            /* Failed to read the memory at the location */
            mystrcpy(kgdb_out, "E04", 4);
        }
    }
}

static void handle_write_mem(char *ptr) {
    seL4_Word addr, size;

    if (!parse_mem_format(ptr, &addr, &size)) {
        mystrcpy(kgdb_out, "E02", 4);
    } else {
        if ((ptr = memchr(kgdb_in, ':', BUFSIZE))) {
            ptr++;
            if (hex2mem(ptr, (char *) addr, size) == NULL) {
                mystrcpy(kgdb_out, "E03", 4);
            } else {
                mystrcpy(kgdb_out, "OK", 3);
            }
        }
    }
}

static void handle_query(char *ptr) {
    if (strncmp(ptr, "qSupported", 10) == 0) {
        /* TODO: This may eventually support more features */
        snprintf(kgdb_out, sizeof(kgdb_out),
                 "qSupported:PacketSize=%lx;QThreadEvents+;swbreak+;hwbreak+;vContSupported+;", sizeof(kgdb_in));
    } else if (strncmp(ptr, "qfThreadInfo", 12) == 0) {
        /* This should eventually get an actual list of thread IDs */
        mystrcpy(kgdb_out, "m1", 3);
    } else if (strncmp(ptr, "qsThreadInfo", 12) == 0) {
        mystrcpy(kgdb_out, "l", 2);
    } else if (strncmp(ptr, "qC", 2) == 0) {
        mystrcpy(kgdb_out, "QC1", 4);
    } else if (strncmp(ptr, "qSymbol", 7) == 0) {
        mystrcpy(kgdb_out, "OK", 3);
    } else if (strncmp(ptr, "qTStatus", 8) == 0) {
        /* TODO: THis should eventually work in the non startup case */
        mystrcpy(kgdb_out, "T0", 3);
    }
}

static void handle_configure_debug_events(char *ptr) {
    seL4_Word addr, size;

    /* Breakpoints and watchpoints */
    if (strncmp(ptr, "Z0", 2) == 0) {
        /* Set a software breakpoint using binary rewriting */
        if (!parse_breakpoint_format(ptr, &addr, &size)) {
            mystrcpy(kgdb_out, "E01", 4);
        }
        if (!set_software_breakpoint(addr)) {
            mystrcpy(kgdb_out, "E01", 4);
        } else {
            mystrcpy(kgdb_out, "OK", 3);
        }
    } else if (strncmp(ptr, "z0", 2) == 0) {
        /* Unset a software breakpoint */
        if (!parse_breakpoint_format(ptr, &addr, &size)) {
            mystrcpy(kgdb_out, "E01", 4);
        }
        if (!unset_software_breakpoint(addr)) {
            mystrcpy(kgdb_out, "E01", 4);
        } else {
            mystrcpy(kgdb_out, "OK", 3);
        }
    } else if (strncmp(ptr, "Z1", 2) == 0) {
        /* Set a hardware breakpoint */
        if (!parse_breakpoint_format(ptr, &addr, &size)) {
            mystrcpy(kgdb_out, "E01", 4);
        }
        if (!set_hardware_breakpoint(addr)) {
            mystrcpy(kgdb_out, "E01", 4);
        } else {
            mystrcpy(kgdb_out, "OK", 3);
        }
    } else if (strncmp(ptr, "z1", 2) == 0) {
        /* Unset a hardware breakpoint */
        if (!parse_breakpoint_format(ptr, &addr, &size)) {
            mystrcpy(kgdb_out, "E01", 4);
        }
        if (!unset_hardware_breakpoint(addr)) {
            mystrcpy(kgdb_out, "E01", 4);
        } else {
            mystrcpy(kgdb_out, "OK", 3);
        }
    }
}

void kgdb_handler(void)
{
    printf("Entering KGDB stub\n");
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
            (void) stepping;

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
            /* TODO: THis should eventually do something */
            mystrcpy(kgdb_out, "OK", 3);
        } else if (*ptr == '?') {
            /* TODO: This should eventually report more reasons than swbreak */
            mystrcpy(kgdb_out, "T05swbreak:;", 13);
        } else if (*ptr == 'v') {
            if (strncmp(ptr, "vCont?", 7) == 0) {
                mystrcpy(kgdb_out, "vCont;c", 8);
            } else if (strncmp(ptr, "vCont;c", 7) == 0) {
                break;
            }
        } else if (*ptr == 'z' || *ptr == 'Z') {
            handle_configure_debug_events(ptr);
        }

        kgdb_put_packet(kgdb_out);
    }
}

#endif /* CONFIG_GDB */
