/* This is an intial header file to add the PMU cap to AARCH64 based systems. */

#pragma once

#include <types.h>
#include <api/failures.h>
#include <object/structures.h>

exception_t decodePMUControlInvocation(word_t label, unsigned int length, cptr_t cptr,
                                         cte_t *srcSlot, cap_t cap,
                                         bool_t call, word_t *buffer);