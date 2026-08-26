#include "hooks.h"

#include <csp/csp.h>
#include <csp/csp_hooks.h>

#include <stdint.h>
#include <string.h>

#define CTEST_MEMFREE_DEFAULT 0x00100000u

static bool rebooted;
static bool shut_down;
static uint32_t memfree = CTEST_MEMFREE_DEFAULT;
static unsigned int ps_entries;

bool ctest_rebooted(void) {
	return rebooted;
}

bool ctest_shut_down(void) {
	return shut_down;
}

void ctest_set_memfree(uint32_t bytes) {
	memfree = bytes;
}

void ctest_set_ps_entries(unsigned int entries) {
	ps_entries = entries;
}

void ctest_hooks_reset(void) {
	rebooted = false;
	shut_down = false;
	memfree = CTEST_MEMFREE_DEFAULT;
	ps_entries = 0;
}

void csp_output_hook(const csp_id_t * idout, csp_packet_t * packet, csp_iface_t * iface, uint16_t via, int from_me) {
	(void)idout;
	(void)packet;
	(void)iface;
	(void)via;
	(void)from_me;
}

void csp_input_hook(csp_iface_t * iface, csp_packet_t * packet) {
	(void)iface;
	(void)packet;
}

/* The real hook is expected not to return. Recording instead is what lets a test
 * assert that the reboot service was reached *and* that the magic word gates it. */
void csp_reboot_hook(void) {
	rebooted = true;
}

void csp_shutdown_hook(void) {
	shut_down = true;
}

uint32_t csp_memfree_hook(void) {
	return memfree;
}

unsigned int csp_ps_hook(csp_packet_t * packet) {
	(void)packet;
	return ps_entries;
}

static uint8_t peek_region[CTEST_PEEK_REGION_LEN];

uint8_t * ctest_peek_region(void) {
	return peek_region;
}

/* Overrides the `__weak` default in src/cmp/csp_cmp_mem.c, which is a bare memcpy — so a
 * node built with CMP answers a PEEK from any address and a POKE to any address, with no
 * validation at all.
 *
 * Here exactly one window is reachable. `addr` arrives already cast to a pointer by the
 * handler, so the check is on the pointer value: anything inside
 * [CTEST_PEEK_BASE, CTEST_PEEK_BASE + CTEST_PEEK_REGION_LEN) is an offset into the region,
 * and everything else is refused. Refusing makes the handler return non-zero, which means
 * the node sends no reply — which is itself a thing worth testing. */
static bool in_window(uintptr_t p, size_t size) {
	return (p >= CTEST_PEEK_BASE) && (size <= CTEST_PEEK_REGION_LEN) &&
		   ((p - CTEST_PEEK_BASE) <= (CTEST_PEEK_REGION_LEN - size));
}

int csp_cmp_memcpy(csp_memptr_t to, csp_const_memptr_t from, size_t size) {
	uintptr_t dst = (uintptr_t)to;
	uintptr_t src = (uintptr_t)from;

	if (in_window(src, size)) {
		memcpy((void *)to, peek_region + (src - CTEST_PEEK_BASE), size);
		return CSP_ERR_NONE;
	}
	if (in_window(dst, size)) {
		memcpy(peek_region + (dst - CTEST_PEEK_BASE), (const void *)from, size);
		return CSP_ERR_NONE;
	}
	return CSP_ERR_INVAL;
}

/* csp_if_kiss.c serialises its transmit path through these. There is one thread
 * here, so they have nothing to do. */
void csp_usart_lock(void * driver_data) {
	(void)driver_data;
}

void csp_usart_unlock(void * driver_data) {
	(void)driver_data;
}

/* --- clock -------------------------------------------------------------------------- */

static int clock_accepts = 1;
static csp_timestamp_t clock_now;

void ctest_clock_set_accepts(int accept) {
	clock_accepts = accept;
}

csp_timestamp_t ctest_clock_last_set(void) {
	return clock_now;
}

/* Overrides the __weak posix implementation, which reads the real wall clock and would put
   a different number in the corpus on every run. */
void csp_clock_get_time(csp_timestamp_t * time) {
	*time = clock_now;
}

int csp_clock_set_time(const csp_timestamp_t * time) {
	if (!clock_accepts) {
		return CSP_ERR_INVAL;
	}
	clock_now = *time;
	return CSP_ERR_NONE;
}
