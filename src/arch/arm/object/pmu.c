#include <config.h>

#include <arch/object/pmu.h>

static exception_t decodePMUControl_ReadEventCounter(word_t length, cap_t cap, word_t *buffer)
{
    seL4_Word counter = getSyscallArg(0, buffer);

    // @kwinter: Hardcoding max size of counter to 6. Have this info generalised,
    // maybe per platform in the hardware.yml files?
    if (counter > 6) {
        userError("PMUControl_ReadEventCounter: Invalid counter.");
        current_syscall_error.type = seL4_RangeError;
        return EXCEPTION_SYSCALL_ERROR;
    }

    printf("We are getting to decodePMUControl_ReadEventCounter. This was value of counter: %lu\n", counter);

    setRegister(NODE_STATE(ksCurThread), msgRegisters[0], 6);
    return EXCEPTION_NONE;
}

static exception_t decodePMUControl_WriteEventCounter(word_t length, cap_t cap, word_t *buffer)
{
    seL4_Word counter = getSyscallArg(0, buffer);
    // seL4_Word value = getSyscallArg(1, buffer);
    // seL4_Word event = getSyscallArg(2, buffer);

    // @kwinter: Hardcoding max size of counter to 6. Have this info generalised,
    // maybe per platform in the hardware.yml files?
    if (counter > 6) {
        userError("PMUControl_WriteEventCounter: Invalid counter.");
        current_syscall_error.type = seL4_RangeError;
        return EXCEPTION_SYSCALL_ERROR;
    }

    printf("We are getting to decodePMUControl_WriteEventCounter. This was value of counter: %lu\n", counter);

    return EXCEPTION_NONE;
}

static exception_t decodePMUControl_CounterControl(word_t length, cap_t cap, word_t *buffer)
{
    // @kwinter: Need to handle the error cases here for length etc...
    // Also, do we really need to pass through cap_t cap?
    seL4_Word counter = getSyscallArg(0, buffer);
    // seL4_Word cntl_val = getSyscallArg(1, buffer);

    // @kwinter: Hardcoding max size of counter to 6. Have this info generalised,
    // maybe per platform in the hardware.yml files?
    if (counter > 6) {
        userError("PMUControl_CounterControl: Invalid counter.");
        current_syscall_error.type = seL4_RangeError;
        return EXCEPTION_SYSCALL_ERROR;
    }

    printf("We got to decodePMUControl_CounterControl. This is value of counter: %lu\n", counter);

    return EXCEPTION_NONE;
}

exception_t decodePMUControlInvocation(word_t label, unsigned int length, cptr_t cptr,
                                          cte_t *srcSlot, cap_t cap, bool_t call, word_t *buffer)
{

    switch(label) {
        case PMUReadEventCounter:
            return decodePMUControl_ReadEventCounter(length, cap, buffer);
        case PMUWriteEventCounter:
            return decodePMUControl_WriteEventCounter(length, cap, buffer);
        case PMUCounterControl:
            return decodePMUControl_CounterControl(length, cap, buffer);
        default:
            userError("PMUControl invocation: Illegal operation attempted.");
            current_syscall_error.type = seL4_IllegalOperation;
            return EXCEPTION_SYSCALL_ERROR;
    }
}
