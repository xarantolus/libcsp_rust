/* The application half of libcsp: the hooks in csp/csp_hooks.h that the library
 * declares and never defines, plus the two USART locks csp_if_kiss.c calls.
 *
 * Providing them here rather than linking libcsp's Linux driver keeps the oracle free
 * of real I/O, and puts the reboot/shutdown/memfree/ps answers under the test's
 * control so a service reply can be asserted against a known value.
 */
#pragma once

#include <stdbool.h>
#include <inttypes.h>

/** True once csp_reboot_hook() has been called. Cleared by ctest_hooks_reset(). */
bool ctest_rebooted(void);

/** True once csp_shutdown_hook() has been called. */
bool ctest_shut_down(void);

/** What csp_memfree_hook() reports. */
void ctest_set_memfree(uint32_t bytes);

/** How many entries csp_ps_hook() claims to have written. */
void ctest_set_ps_entries(unsigned int entries);

/** Forget the reboot/shutdown flags and restore the default answers. */
void ctest_hooks_reset(void);

/* --- the memory window PEEK and POKE are allowed to touch ---
 *
 * libcsp's default `csp_cmp_memcpy` is a bare `memcpy`, so a PEEK reads and a POKE writes
 * any address a packet names. It is `__weak`, and this overrides it with a bounds-checked
 * stub: the only thing reachable is `ctest_peek_region`, addressed as an offset from
 * `CTEST_PEEK_BASE`. Anything else is refused.
 *
 * The indirection is not only for safety — `csp_cmp_peek_msg.addr` is a `uint32_t`, so on a
 * 64-bit host a real pointer does not survive the round trip anyway.
 */

/** Base address the test region appears at, as seen on the wire. */
#define CTEST_PEEK_BASE 0x1000u

/** Bytes in the test region. */
#define CTEST_PEEK_REGION_LEN 256

/** Fill the region with a known pattern and return a pointer to it. */
uint8_t * ctest_peek_region(void);
