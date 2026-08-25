#include "hooks.h"

#include <csp/csp_hooks.h>

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

/* csp_if_kiss.c serialises its transmit path through these. There is one thread
 * here, so they have nothing to do. */
void csp_usart_lock(void * driver_data) {
	(void)driver_data;
}

void csp_usart_unlock(void * driver_data) {
	(void)driver_data;
}
