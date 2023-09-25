#ifdef CONFIG_GDB

#include <mode/kgdb/kgdb.h>
#include <mode/machine/registerset.h>
#include <mode/kernel/vspace.h>
#include <api/faults.h>
#include <string.h>

/* Software breakpoint related stuff */
#define AARCH64_BREAK_MON   0xd4200000
#define KGDB_DYN_DBG_BRK_IMM        0x400
#define AARCH64_BREAK_KGDB_DYN_DBG  \
    (AARCH64_BREAK_MON | (KGDB_DYN_DBG_BRK_IMM << 5))

thread_info_t threads[64] = {0};
thread_info_t *target_thread = NULL;
int num_threads = 1; 

/* Hardware breapoint related stuff */

typedef struct hw_breakpoint {
    uint64_t addr;
} hw_break_t;

hw_break_t hardware_breakpoints[seL4_NumExclusiveBreakpoints] = {0};

/* Hex characters */
static char hexchars[] = "0123456789abcdef";

/* Debug register manipulation */
#define DBGBCR_BT 0xF00000
#define DBGBCR_EN 0x1
#define DBGBCR_BAS 0x1E0
#define DBGBCR_PMC 0x6

#define DBGBVR_RESS 0xFFE0000000000000
#define DBGBVR_VA   0x1FFFFFFFFFFFC

#define MDSCR_MDE   (1 << 15)
#define MDSCR_SS   (1)

#define SPSR_SS (1 << 21)

/* Convert a character (representing a hexadecimal) to its integer equivalent */
int hex(unsigned char c)
{
    if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
    } else if (c >= 'A' && c <= 'F') {
        return c - 'A' + 10;
    } else if (c >= '0' && c <= '9') {
        return c - '0';
    }
    return -1;
}


// static bool_t is_mapped(tcb_t *thread, vptr_t vaddr)
// {
//     cap_t vspaceRootCap = TCB_PTR_CTE_PTR(thread, tcbVTable)->cap;
//     return vaddrIsMapped(vspaceRootCap, vaddr);
// }

/**
 * Returns a ptr to last char put in buf or NULL on error (cannot read memory)
 */


static char *mem2hex(tcb_t *thread, word_t mem, char *buf, int size)
{
    int i;
    unsigned char c;
    cap_t vspaceRootCap = TCB_PTR_CTE_PTR(thread, tcbVTable)->cap;

    word_t curr_word = 0;
    for (i = 0; i < size; i++) {
        if (i % INSTR_SIZE == 0) {
            readHalfWordFromVSpace_ret_t ret = readHalfWordFromVSpace(vspaceRootCap, mem);
            if (ret.status != EXCEPTION_NONE) {
                return NULL;
            }

            curr_word = ret.value;
            mem += INSTR_SIZE;
        }

        c = *(((char *) &curr_word) + (i % INSTR_SIZE));
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
static word_t hex2mem(tcb_t *thread, char *buf, word_t mem, int size)
{
    int i;
    unsigned char c;
    cap_t vspaceRootCap = TCB_PTR_CTE_PTR(thread, tcbVTable)->cap;

    word_t curr_word = 0;
    for (i = 0; i < size; i++, mem++) {
        if (i % INSTR_SIZE == 0) {            
            readHalfWordFromVSpace_ret_t ret = readHalfWordFromVSpace(vspaceRootCap, mem);
            if (ret.status != EXCEPTION_NONE) {
                return 0;
                // return NULL;
            }

            curr_word = ret.value;
        }

        c = hex(*buf++) << 4;
        c += hex(*buf++);
        *(((char *) &curr_word) + (i % INSTR_SIZE)) = c;

        if (i % INSTR_SIZE == INSTR_SIZE - 1 || i == size - 1) {
            writeHalfWordToVSpace(vspaceRootCap, mem + (i/INSTR_SIZE), curr_word);
            mem += INSTR_SIZE;
        }
    }

    return (mem + i);
}

/*
ssh tftp, ssh consoles, console odroid-c2, ctrl shift e o to takr control, ctrl shift e . to disconnect
*/

static char *k_mem2hex(char *mem, char *buf, int size)
{
    /* @alwin: This check should be better */
    assert(mem >= (char *) USER_TOP);

    int i;
    unsigned char c;
    for (i = 0; i < size; i++, mem++) {
        c = *mem;
        *buf++ = hexchars[c >> 4];
        *buf++ = hexchars[c % 16];
    }
    *buf = 0;
    return buf;
}

static char *k_hex2mem(char *buf, char *mem, int size)
{
    /* @alwin: This check should be better */
    assert(mem >= (char *) USER_TOP);

    int i;
    unsigned char c;

    for (i = 0; i < size; i++, mem++) {
        c = hex(*buf++) << 4;
        c += hex(*buf++);
        *mem = c;
    }
    return mem;
}

char *regs_buf2hex(register_set_t *regs, char *buf)
{

    /* We use k_mem2hex for kernel virtual addresses */

    /* First we handle the 64-bit registers */
    buf = k_mem2hex((char *) regs->registers_64, buf, NUM_REGS64 * sizeof(seL4_Word));
    return k_mem2hex((char *) &regs->cpsr, buf, sizeof(seL4_Word) / 2);
}

/**
 * Translates from registers to a registers buffer that gdb expects.
 */
void regs2buf(tcb_t *thread, register_set_t *regs)
{
    int i = 0;
    for (i = 0; i <= X30; i++) {
        regs->registers_64[i] = getRegister(thread, i);
    }
    regs->registers_64[i++] = getRegister(thread, SP_EL0);
    regs->registers_64[i++] = getRegister(thread, NextIP);
    regs->cpsr = getRegister(thread, SPSR_EL1) & 0xffffffff;
}

/**
 * Translates from gdb registers buffer to registers
 */
void buf2regs(tcb_t *thread, register_set_t *regs)
{
    int i;
    for (i = 0; i <= X30; i++) {
        setRegister(thread, i, regs->registers_64[i]);
    }
    setRegister(thread, SP_EL0, regs->registers_64[i++]);
    setRegister(thread, NextIP, regs->registers_64[i++]);
    setRegister(thread, SPSR_EL1, regs->cpsr);
}

static bool_t instruction_read(tcb_t *thread, seL4_Word addr, uint32_t *instr)
{
    cap_t vspaceRootCap = TCB_PTR_CTE_PTR(thread, tcbVTable)->cap;
    readHalfWordFromVSpace_ret_t ret = readHalfWordFromVSpace(vspaceRootCap, addr);
    if (ret.status) {
        return false;
    }
    *instr = ret.value;
    return true;
}

static bool_t instruction_write(tcb_t *thread, seL4_Word addr, uint32_t instr)
{
    cap_t vspaceRootCap = TCB_PTR_CTE_PTR(thread, tcbVTable)->cap;
    writeHalfWordToVSpace_ret_t ret = writeHalfWordToVSpace(vspaceRootCap, addr, instr);
    if (ret.status) {
        return false;
    }
    return true;
}

bool_t set_software_breakpoint(thread_info_t *thread_info, seL4_Word addr)
{
    sw_break_t tmp;
    tmp.addr = addr;

    if (!instruction_read(thread_info->tcb, addr, &tmp.orig_instr)) {
        return false;
    }

    if (!instruction_write(thread_info->tcb, addr, AARCH64_BREAK_KGDB_DYN_DBG)) {
        return false;
    }


    int i;
    for (i = 0; i < MAX_SW_BREAKS; i++) {
        if (thread_info->software_breakpoints[i].addr == 0) {
            thread_info->software_breakpoints[i] = tmp;
            return true;
        }
    }

    instruction_write(thread_info->tcb, addr, tmp.orig_instr);
    return false;
}

bool_t unset_software_breakpoint(thread_info_t *thread_info, seL4_Word addr) {
    int i = 0;
    for (i = 0; i < MAX_SW_BREAKS; i++) {
        if (thread_info->software_breakpoints[i].addr == addr) {
            break;
        }
    }

    /* @alwin: which is the right behaviour here? */
    if (i == MAX_SW_BREAKS) {
        // return false; 
        return true; 
    }

    if (!instruction_write(thread_info->tcb, addr, thread_info->software_breakpoints[i].orig_instr)) {
        return false; 
    }

    return true; 
}



static void set_dbgbcr(int breakpoint_num) {
    word_t dbgbcr_val = 0;

    switch (breakpoint_num) {
        case 0 : MRS("DBGBCR0_EL1", dbgbcr_val); break;
        case 1 : MRS("DBGBCR1_EL1", dbgbcr_val); break;
        case 2 : MRS("DBGBCR2_EL1", dbgbcr_val); break;
        case 3 : MRS("DBGBCR3_EL1", dbgbcr_val); break;
        case 4 : MRS("DBGBCR4_EL1", dbgbcr_val); break;
        case 5 : MRS("DBGBCR5_EL1", dbgbcr_val); break;
        default : assert(0);
    }

    /* Set the breakpoint type */
    dbgbcr_val = (dbgbcr_val & ~DBGBCR_BT) | (0x0 & DBGBCR_BT);
    /* Set the behaviour of the breakpoint  */
    dbgbcr_val = (dbgbcr_val & ~DBGBCR_PMC) | ((0x2 << 1) & DBGBCR_PMC);
    /* Enable the breakpoint */
    dbgbcr_val = dbgbcr_val | DBGBCR_EN;


    switch (breakpoint_num) {
        case 0 : MSR("DBGBCR0_EL1", dbgbcr_val); break;
        case 1 : MSR("DBGBCR1_EL1", dbgbcr_val); break;
        case 2 : MSR("DBGBCR2_EL1", dbgbcr_val); break;
        case 3 : MSR("DBGBCR3_EL1", dbgbcr_val); break;
        case 4 : MSR("DBGBCR4_EL1", dbgbcr_val); break;
        case 5 : MSR("DBGBCR5_EL1", dbgbcr_val); break;
        default : assert(0);
    }
}

static void unset_dbgbcr(int breakpoint_num) {
    word_t dbgbcr_val = 0;

    switch (breakpoint_num) {
        case 0 : MRS("DBGBCR0_EL1", dbgbcr_val); break;
        case 1 : MRS("DBGBCR1_EL1", dbgbcr_val); break;
        case 2 : MRS("DBGBCR2_EL1", dbgbcr_val); break;
        case 3 : MRS("DBGBCR3_EL1", dbgbcr_val); break;
        case 4 : MRS("DBGBCR4_EL1", dbgbcr_val); break;
        case 5 : MRS("DBGBCR5_EL1", dbgbcr_val); break;
        default : assert(0);
    }

    /* Disable the breakpoint */
    dbgbcr_val = dbgbcr_val & ~DBGBCR_EN;

    switch (breakpoint_num) {
        case 0 : MSR("DBGBCR0_EL1", dbgbcr_val); break;
        case 1 : MSR("DBGBCR1_EL1", dbgbcr_val); break;
        case 2 : MSR("DBGBCR2_EL1", dbgbcr_val); break;
        case 3 : MSR("DBGBCR3_EL1", dbgbcr_val); break;
        case 4 : MSR("DBGBCR4_EL1", dbgbcr_val); break;
        case 5 : MSR("DBGBCR5_EL1", dbgbcr_val); break;
        default : assert(0);
    }
}


static void set_dbgbvr(int breakpoint_num, seL4_Word addr) {
    word_t dbgbvr_val = 0;

    switch (breakpoint_num) {
        case 0 : MRS("DBGBVR0_EL1", dbgbvr_val); break;
        case 1 : MRS("DBGBVR1_EL1", dbgbvr_val); break;
        case 2 : MRS("DBGBVR2_EL1", dbgbvr_val); break;
        case 3 : MRS("DBGBVR3_EL1", dbgbvr_val); break;
        case 4 : MRS("DBGBVR4_EL1", dbgbvr_val); break;
        case 5 : MRS("DBGBVR5_EL1", dbgbvr_val); break;
        default : assert(0);
    }

    dbgbvr_val = (dbgbvr_val & ~DBGBVR_VA) | (addr & DBGBVR_VA);
    if ((addr >> 48) & 0x1) {
        dbgbvr_val = (dbgbvr_val & ~DBGBVR_RESS) | DBGBVR_RESS;
    } else {
        dbgbvr_val = (dbgbvr_val & ~DBGBVR_RESS);
    }

    switch (breakpoint_num) {
        case 0 : MSR("DBGBVR0_EL1", dbgbvr_val); break;
        case 1 : MSR("DBGBVR1_EL1", dbgbvr_val); break;
        case 2 : MSR("DBGBVR2_EL1", dbgbvr_val); break;
        case 3 : MSR("DBGBVR3_EL1", dbgbvr_val); break;
        case 4 : MSR("DBGBVR4_EL1", dbgbvr_val); break;
        case 5 : MSR("DBGBVR5_EL1", dbgbvr_val); break;
        default : assert(0);
    }
}

bool_t set_hardware_breakpoint(seL4_Word addr) {

    int i = 0; 
    for (i = 0; i < seL4_NumExclusiveBreakpoints; i++) {
        if (!hardware_breakpoints[i].addr) break;
    }

    if (i == seL4_NumExclusiveBreakpoints) return false ;

    /* set the debug control register for this breakpoint number */
    set_dbgbcr(i);
    
    /* Set the debug value register for this breakpoint number */
    set_dbgbvr(i, addr);

    /* Setup the general the debug control register */
    word_t mdscr = 0;
    MRS("MDSCR_EL1", mdscr);
    /* Enable breakpoint exceptions. Ideally, this should only have to be done once */
    mdscr = (mdscr | MDSCR_MDE);
    MSR("MDSCR_EL1", mdscr);

    /* Ensure that OS lock and double lock are unset */
    word_t osdlar = 0;
    MSR("osdlr_el1", osdlar);
    word_t oslar = 0;
    MSR("oslar_el1", oslar);
    return true;
}

bool_t unset_hardware_breakpoint(seL4_Word addr) {
    int i = 0;
    for (i = 0; i < seL4_NumExclusiveBreakpoints; i++) {
        if (hardware_breakpoints[i].addr == addr) break;
    }

    if (i == seL4_NumExclusiveBreakpoints) return false;

    unset_dbgbcr(i);

    return true;
}

bool_t enable_single_step(void) {
    word_t mdscr = 0;
    MRS("MDSCR_EL1", mdscr);
    mdscr = (mdscr | MDSCR_MDE);
    mdscr = (mdscr | MDSCR_SS);
    MSR("MDSCR_EL1", mdscr);

    /* Ensure that OS lock and double lock are unset */
    word_t osdlar = 0;
    MSR("osdlr_el1", osdlar);
    word_t oslar = 0;
    MSR("oslar_el1", oslar);

    seL4_Word reg = getRegister(NODE_STATE(ksCurThread), SPSR_EL1);
    reg = reg | SPSR_SS;
    setRegister(NODE_STATE(ksCurThread), SPSR_EL1, reg);

    return true; 
}

bool_t disable_single_step(void) {
    word_t mdscr = 0;
    MRS("MDSCR_EL1", mdscr);
    mdscr = (mdscr & ~MDSCR_SS);
    MSR("MDSCR_EL1", mdscr);

    seL4_Word reg = getRegister(NODE_STATE(ksCurThread), SPSR_EL1);
    reg = (reg & ~SPSR_SS);
    setRegister(NODE_STATE(ksCurThread), SPSR_EL1, reg);
    return true; 
}

#endif /* CONFIG_GDB */

