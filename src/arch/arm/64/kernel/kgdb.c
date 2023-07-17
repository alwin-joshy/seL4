// #include <machine/io.h>
#include <mode/kernel/kgdb.h>
#include <mode/machine/registerset.h>
#include <mode/kernel/vspace.h>
#include <string.h>

#define BUFSIZE 1024
#define UART2_PPTR (KDEV_BASE + 0x84c0)
#define UART_WFIFO  0x0
#define UART_RFIFO  0x4
#define UART_STATUS 0xC
#define UART_TX_FULL        BIT(21)
#define UART_REG2(x) ((volatile uint32_t *)(UART2_PPTR + (x)))

// #define DEBUG_PRINTS

/*
ssh tftp, ssh consoles, console odroid-c2, ctrl shift e o to takr control, ctrl shift e . to disconnect
*/

/* Input buffer */
static char kgdb_in[BUFSIZE];

/* Output buffer */
static char kgdb_out[BUFSIZE];

/* Hex characters */
static char hexchars[] = "0123456789abcdef";

/* Output a character to serial */
static void gdb_putChar(char c)
{
	kernel_putDebugChar(c);
}

// /* Read a character from serial */
static char gdb_getChar(void)
{
	char c =  kernel_getDebugChar();
	return c;
}

static void mystrcpy(char *dest, char *src, int num) {
	(void) num;
	int i = -1;
	do {
		i++;
		dest[i] = src[i];
	} while (src[i] != '\0');
}

// static void uart2_putchar(char c) {
//     while ((*UART_REG2(UART_STATUS) & UART_TX_FULL));

//     /* Add character to the buffer. */
//     *UART_REG2(UART_WFIFO) = c;
// }

// static inline void gdb_putChar2(
//     unsigned char c)
// {
//     /* UART console requires printing a '\r' (CR) before any '\n' (LF) */
//     if (c == '\n') {
//         uart2_putchar('\r');
//     }
//     uart2_putchar(c);
// }

/* Convert a character (representing a hexadecimal) to its integer equivalent */
static int hex (unsigned char c) {
	if (c >= 'a' && c <= 'f') {
		return c - 'a' + 10;
	} else if (c >= 'A' && c <= 'F') {
		return c - 'A' + 10;
	} else if (c >= '0' && c <= '9') {
		return c - '0';
	}
	return -1; 
}

static char *kgdb_get_packet(void) {
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
				gdb_putChar('-'); 	/* checksum failed */
			} else {
				gdb_putChar('+');	/* checksum success, ack*/

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
        if (gdb_getChar() == '+')
            break;
    }
}

/**
 * Translates from registers to a registers buffer that gdb expects.
 */
static void regs2buf(register_set_t *regs) {
	int i = 0;
	for (i = 0; i <= X30; i++) {
		regs->registers_64[i] = getRegister(NODE_STATE(ksCurThread), i);
	}
	regs->registers_64[i++] = getRegister(NODE_STATE(ksCurThread), SP_EL0);
	regs->registers_64[i++] = getRegister(NODE_STATE(ksCurThread), NextIP);
	regs->cpsr = getRegister(NODE_STATE(ksCurThread), SPSR_EL1) & 0xffffffff;
}

/**
 * Translates from gdb registers buffer to registers
 */
static void buf2regs(register_set_t *regs) {
	int i; 
	for (i = 0; i <= X30; i++) {
		setRegister(NODE_STATE(ksCurThread), i, regs->registers_64[i]);
	}
	setRegister(NODE_STATE(ksCurThread), SP_EL0, regs->registers_64[i++]);
	setRegister(NODE_STATE(ksCurThread), NextIP, regs->registers_64[i++]);
	setRegister(NODE_STATE(ksCurThread), SPSR_EL1, regs->cpsr);
}

/**
 * Returns a ptr to last char put in buf or NULL on error (cannot read memory)
 */

static bool_t is_mapped(vptr_t vaddr) {
    cap_t vspaceRootCap = TCB_PTR_CTE_PTR(NODE_STATE(ksCurThread), tcbVTable)->cap;
	return vaddrIsMapped(vspaceRootCap, vaddr);
}

static char *mem2hex(char *mem, char *buf, int size)
{
    int i;
    unsigned char c;

    for (i = 0; i < size; i++, mem++) {
         if (!is_mapped((vptr_t) mem & ~0xFFF))
            return NULL;
       	c = *mem;
        *buf++ = hexchars[c >> 4];
        *buf++ = hexchars[c % 16];
    }
    *buf = 0;
    return buf;
}

static char *regs_buf2hex(register_set_t *regs, char *buf) {
    /* First we handle the 64-bit registers */
    buf = mem2hex((char *) regs->registers_64, buf, NUM_REGS64 * sizeof(seL4_Word));
    return mem2hex((char *) &regs->cpsr, buf, sizeof(seL4_Word) / 2);
}

/**
 * Returns a ptr to the char after last memory byte written
 *  or NULL on error (cannot write memory)
 */
static char *hex2mem(char *buf, char *mem, int size)
{
    int i;
    unsigned char c;

    for (i = 0; i < size; i++, mem++) {
        if (!is_mapped((vptr_t) mem & ~0xFFF))
           return NULL;
        c = hex(*buf++) << 4;
        c += hex(*buf++);
        *mem = c;
    }
    return mem;
}

static char *hex2regs_buf(char *buf, register_set_t *regs) {
    hex2mem(buf, (char *) regs->registers_64, NUM_REGS64 * sizeof(seL4_Word));
    /* 2 hex characters per byte*/
    return hex2mem(buf + 2 * NUM_REGS64 * sizeof(seL4_Word), (char *) &regs->cpsr, sizeof(seL4_Word)/2);
}

static char * hex2int(char *hex_str, int max_bytes, seL4_Word *val) {
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

/* Expected string is of the form [Mm][a-fA-F0-9]{16},[a-fA-F0-9]+*/
static bool_t parse_mem_format(char* ptr, seL4_Word *addr, seL4_Word *size) {
	*addr = 0;
	*size = 0;
	bool_t is_read = true; 

	/* Are we dealing with a memory read or a memory write */
	if (*ptr++ == 'M') {
		is_read = false;
	}

	/* Parse the address */
	ptr = hex2int(ptr, 16, addr);
	if (*ptr++ != ',') {
		return false; 
	}

	/* Parse the size */
	ptr = hex2int(ptr, 16, size);

	/* Check that we have reached the end of the string */
	if (is_read) {
		// mystrcpy(kgdb_out, "E01", 4);		
		return (*ptr == 0);
	} else {
		return (*ptr == 0 || *ptr == ':');
	}
}

void kgdb_handler(void) {
	char *ptr;
	register_set_t regs;
	seL4_Word addr, size;
	int test = 25;
	printf("The address of test is ==> %p\n", &test);

	while (1) {
		ptr = kgdb_get_packet();
#ifdef DEBUG_PRINTS
		printf("\n\nHi. The first message I received was: %s\n\n", ptr);
#endif
        kgdb_out[0] = 0;
		
		if (*ptr == 'g') {
			regs2buf(&regs);
            regs_buf2hex(&regs, kgdb_out);
		} else if (*ptr == 'G') {
            hex2regs_buf(++ptr, &regs);
			buf2regs(&regs);
			mystrcpy(kgdb_out, "OK", 3);
		} else if (*ptr == 'm') {
            if (!parse_mem_format(ptr, &addr, &size)) {
                /* Error parsing input */
				mystrcpy(kgdb_out, "E01", 4);
            } else if (size * 2 > sizeof(kgdb_in) - 1) {
                /* Buffer too big? Don't really get this */
				mystrcpy(kgdb_out, "E01", 4);
            } else {
                if (addr == 0xfffffffffffffff7) {
                    mystrcpy(kgdb_out, "E05", 4);
                }
                if (mem2hex((char *) addr, kgdb_out, size) == NULL) {
                    /* Failed to read the memory at the location */
					mystrcpy(kgdb_out, "E04", 4);
                }
            }
		} else if (*ptr == 'M') {
			if (!parse_mem_format(kgdb_in , &addr, &size)) {
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
		} else if (*ptr == 'c' || *ptr == 's') {
			// seL4_Word addr; 
			int stepping = *ptr == 's' ? 1 : 0;
			ptr++;
			(void) stepping;

			/* TODO: Support continue from an address and single step */
            // if (sscanf(ptr, "%x", &addr))
                // current_task->regs.eip = addr;
            // if (stepping)
                // current_task->regs.eflags |= 0x100; /* Set trap flag. */
            // else
                // current_task->regs.eflags &= ~0x100; /* Clear trap flag */
            

            // TODO: Maybe need to flush i-cache?
            break;
		} else if (*ptr == 'q') {
			if (strncmp(ptr, "qSupported", 10) == 0) {
                /* TODO: This may eventually support more features */
                snprintf(kgdb_out, sizeof(kgdb_out), 
                    "qSupported:PacketSize=%lx;QThreadEvents+;swbreak+", sizeof(kgdb_in));
            } else if (strncmp(ptr, "qfThreadInfo", 12) == 0) { 
                /* This should eventually get an actual list of thread IDs */
                mystrcpy(kgdb_out, "m1", 3);
            } else if (strncmp(ptr, "qsThreadInfo", 12) == 0) {
                mystrcpy(kgdb_out, "l", 2);
            } else if (strncmp(ptr, "qC", 2) == 0) {
                mystrcpy(kgdb_out, "QC1", 4);
            } else if (strncmp(ptr, "qSymbol", 7) == 0) {
                mystrcpy(kgdb_out, "OK", 3);
            }
		} else if (*ptr == 'H') {
            /* TODO: THis should eventually do something */
            mystrcpy(kgdb_out, "OK", 3);
        } else if (strncmp(ptr, "qTStatus", 8) == 0) {
            /* TODO: THis should eventually work in the non startup case */
            mystrcpy(kgdb_out, "T0", 3);
        } else if (*ptr == '?') {
            /* TODO: This should eventually report more reasons than swbreak */
            mystrcpy(kgdb_out, "T05swbreak:;", 3);
        }

        kgdb_put_packet(kgdb_out);
	}
}
