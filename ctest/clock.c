#include "clock.h"

#include <csp/arch/csp_time.h>

static uint32_t now_ms = CTEST_CLOCK_EPOCH_MS;

void ctest_clock_set(uint32_t ms) {
	now_ms = ms;
}

void ctest_clock_advance(uint32_t ms) {
	now_ms += ms;
}

uint32_t ctest_clock_now(void) {
	return now_ms;
}

uint32_t csp_get_ms(void) {
	return now_ms;
}

uint32_t csp_get_ms_isr(void) {
	return now_ms;
}

uint32_t csp_get_s(void) {
	return now_ms / 1000u;
}

uint32_t csp_get_s_isr(void) {
	return now_ms / 1000u;
}
