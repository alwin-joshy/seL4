// #include <machine/io.h>
// #include <string.h>
#include <mode/kernel/kgdb.h>
#include <mode/machine/registerset.h>

#define BUFSIZE 1024
#define UART2_PPTR (KDEV_BASE + 0x84c0)
#define UART_WFIFO  0x0
#define UART_RFIFO  0x4
#define UART_STATUS 0xC
#define UART_TX_FULL        BIT(21)
#define UART_REG2(x) ((volatile uint32_t *)(UART2_PPTR + (x)))

#define DEBUG_PRINTS

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

static void uart2_putchar(char c) {
    while ((*UART_REG2(UART_STATUS) & UART_TX_FULL));

    /* Add character to the buffer. */
    *UART_REG2(UART_WFIFO) = c;
}

static inline void gdb_putChar2(
    unsigned char c)
{
    /* UART console requires printing a '\r' (CR) before any '\n' (LF) */
    if (c == '\n') {
        uart2_putchar('\r');
    }
    uart2_putchar(c);
}

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
static void regs2buf(seL4_Word *regs) {
	for (int i = 0; i < n_contextRegisters; i++) {
		regs[i] = getRegister(NODE_STATE(ksCurThread), i);
	}
}

/**
 * Translates from gdb registers buffer to registers
 */
static void buf2regs(seL4_Word *regs) {
	for (int i = 0; i < n_contextRegisters; i++) {
		setRegister(NODE_STATE(ksCurThread), i, regs[i]);
	}
}

/**
 * Returns a ptr to last char put in buf or NULL on error (cannot read memory)
 */
static char *mem2hex(char *mem, char *buf, int size)
{
    int i;
    unsigned char c;

    for (i = 0; i < size; i++, mem++) {
        //if (!is_mapped((virt_t)mem & ~0xFFF))
        //    return NULL;
       	c = *mem;
       	*buf++ = hexchars[c >> 4];
        *buf++ = hexchars[c % 16];
    }
    *buf = 0;
    return buf;
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
        // if (!is_mapped((virt_t)mem & ~0xFFF)) {
        //     kprintf("not mapped %x\n", mem);
        //     return NULL;
        // }
        c = hex(*buf++) << 4;
        c += hex(*buf++);
        *mem = c;
    }
    return mem;
}

static void mystrcpy(char *dest, char *src) {
	int i = -1;
	do {
		i++;
		dest[i] = src[i];
	} while (src[i] != '\0');
}


void kgdb_handler(void) {
	char *ptr;
	seL4_Word regs[n_contextRegisters];

	gdb_putChar2('a');

	while (1) {
		ptr = kgdb_get_packet();
		printf("\n\nHi. The first message I received was: %s\n\n", ptr);
        kgdb_out[0] = 0;

		if (*ptr == 'g') {
			regs2buf(regs);
			mem2hex((char *) regs, kgdb_out, n_contextRegisters*sizeof(seL4_Word));
		} else if (*ptr == 'G') {
			hex2mem(++ptr, (char *) regs, n_contextRegisters*sizeof(seL4_Word));
			buf2regs(regs);
			mystrcpy(kgdb_out, "OK");
		} else if (*ptr == 'c' || *ptr == 's') {
			// seL4_Word addr; 
			bool_t stepping = *ptr == 's' ? 1 : 0;
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
			if (strncmp(ptr, "qSupported", 9) == 0) {
                snprintf(kgdb_out, sizeof(kgdb_out), 
                    "qSupported:PacketSize=%lx", sizeof(kgdb_in));
            }
		}

        kgdb_put_packet(kgdb_out);
	}
}
