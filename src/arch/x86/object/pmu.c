#include <arch/object/pmu.h>

static uint32_t pmu_architecture_version = 0;
static uint32_t pmu_num_counters = 0;
static uint32_t pmu_counter_bit_width = 0;
static uint32_t supported_events = 0;

#define PMC_BASE_ADDR 0x0C1
#define PERFEVTSEL_BASE_ADDR 0x186

enum EventType {
	UnhaltedCoreCycles = 0,
	InstructionRetired,
	UnhaltedReferenceCycles,
	LLCReference,
	LLCMisses,
	BranchInstructionRetired,
	BranchMissesRetired,
	TopdownSlots,
	TopdownBackendBound,
	TopdownBadSpeculation,
	TopdownFrontendBound,
	TopdownRetiring,
	LBRInserts,
	EventTypeMax,
};

static uint8_t event_umask[EventTypeMax] = 	{0x00, 0x00, 0x01, 0x4f, 0x41, 0x00, 0x00, 0x01, 0x02, 0x00, 0x01, 0x02, 0x01};
static uint8_t event_sel[EventTypeMax] = 	{0x3c, 0xc0, 0x3c, 0x2e, 0x2e, 0xc4, 0xc5, 0xa4, 0xa4, 0x73, 0x9c, 0xc2, 0xe4};

enum CounterControlCommand {
	CounterControlStop = 0,
	CounterControlStart,
	CounterControlReset,
};


static void decodePMUControl_ReadEventCounter(word_t length, int cap, word_t *buffer, word_t badge);
static void decodePMUControl_SetEventCounter(word_t length, int cap, word_t *buffer, word_t badge);
static void decodePMUControl_ToggleEventCounter(word_t lengt, int cap, word_t *buffer, word_t badge);

void profiler_init()
{
	uint32_t pmu_val_eax = x86_cpuid_eax(0xa, 0);
	uint32_t pmu_val_ebx = x86_cpuid_ebx(0xa, 0);

	pmu_architecture_version = pmu_val_eax & (BIT(8) - 1);
	pmu_num_counters = (pmu_val_eax >> 8) & (BIT(8) - 1);
	pmu_counter_bit_width = (pmu_val_eax >> 16) & (BIT(8) - 1);
	uint32_t ebx_bitvec_length = (pmu_val_eax >> 24) & (BIT(8) - 1);

    printf("CPUID: Architecture version %u\n", pmu_architecture_version);
    printf("CPUID: Number of counters %u\n", pmu_num_counters);
    printf("CPUID: bit width %u\n", pmu_num_counters);
    printf("CPUID: ebx bit vector length %u\n", ebx_bitvec_length);

    for (int i = 0; i < ebx_bitvec_length; i++) {
    	if ((pmu_val_ebx & BIT(i)) == 0) {
    		supported_events |= BIT(i);
    	}
    }

    if (pmu_architecture_version == 0) {
    	printf("Warning: This processor does not support performance monitoring\n");
    	return;
    }
}

static void decodePMUControl_ReadEventCounter(word_t length, int cap, word_t *buffer, word_t badge)
{
	seL4_Word counter = getSyscallArg(0, buffer);

	if (counter > pmu_num_counters) {
		userError("PMUControl_SetEventCounter: Invalid counter.");
		return;
	}

	seL4_Word value = x86_rdmsr(PMC_BASE_ADDR + (counter * sizeof(seL4_Word)));

	printf("Got value %lu\n", value);

	volatile int i = 0;
	while (true) {
		i++;
	}
}

static void decodePMUControl_SetEventCounter(word_t length, int cap, word_t *buffer,
													  word_t badge)
{

	seL4_Word counter = getSyscallArg(0, buffer);
	seL4_Word value = getSyscallArg(1, buffer);
	seL4_Word event = getSyscallArg(2, buffer);

	if (counter > pmu_num_counters) {
		userError("PMUControl_SetEventCounter: Invalid counter.");
		return;
	}

	if (event > EventTypeMax) {
		userError("PMUControl_SetEventCounter: Invalid event.");
		return;
	}

	if ((supported_events & BIT(event)) == 0) {
		userError("PMUControl_SetEventCounter: This event is not supported.");
		return;
	}

	seL4_Word perfevtsel = x86_rdmsr(PERFEVTSEL_BASE_ADDR + (counter * sizeof(seL4_Word)));
	if (perfevtsel & BIT(22)) {
		userError("PMUControl_SetEventCounter: Cannot modify event counters while enabled.");
		return;
	}

	perfevtsel |= event_sel[event]; // Set EVENT_SELECT
	perfevtsel |= (event_umask[event] << 8); // SET UMASK
	x86_wrmsr(PERFEVTSEL_BASE_ADDR + (counter * sizeof(seL4_Word)), perfevtsel);
	x86_wrmsr(PMC_BASE_ADDR + (counter * sizeof(seL4_Word)), value);
}

static void decodePMUControl_ToggleEventCounter(word_t lengt, int cap, word_t *buffer,
													   word_t badge)
{
	seL4_Word counter = getSyscallArg(0, buffer);
	seL4_Word enable = getSyscallArg(1, buffer);

	if (counter > pmu_num_counters) {
		userError("PMUControl_ToggleEventCounter: Invalid counter");
	}

	seL4_Word perfevtsel = x86_rdmsr(PERFEVTSEL_BASE_ADDR + (counter * sizeof(seL4_Word)));

	printf("perfevtsel is %lu\n", perfevtsel);

	perfevtsel |= BIT(16); 	// Count userspace cycles
	perfevtsel |= BIT(17); 	// Count kernel cycles
	perfevtsel &= ~BIT(18);	// Disable edge detection
	perfevtsel &= ~BIT(19);	// Disable pin control
	perfevtsel |= BIT(20);	// Enable overflow interrupt
	if (enable) {
		perfevtsel |= BIT(22);
	} else {
		perfevtsel &= ~BIT(22);
	}
	perfevtsel &= 0xffffff; // Unset CMASK

	printf("perfevtsel is %lu\n", perfevtsel);

	x86_wrmsr(PERFEVTSEL_BASE_ADDR + (counter * sizeof(seL4_Word)), perfevtsel);
}

// static exception_t decodePMUControl_CounterControl(word_t length, cap_t cap, word_t *buffer,
// 												   word_t badge)
// {
// 	seL4_Word cntl_val = getSyscallArg(0, buffer);

// 	if (cntl_val > CounterControlReset) {
// 		userError("PMUControl_CounterControl: Invalid control value. Must be 0, 1 or 2.");
//         current_syscall_error.type = seL4_InvalidArgument;
//         return EXCEPTION_SYSCALL_ERROR;
// 	}

// 	switch (cntl_val) {

// 	}
// }