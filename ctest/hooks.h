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
