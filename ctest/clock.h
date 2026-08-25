/* A clock the test drives, replacing libcsp's src/arch/posix/csp_time.c.
 *
 * libcsp reads time through four plain (non-weak) functions, so substituting them is
 * a matter of leaving that one file out of the build — see CMakeLists.txt. Every
 * timing-dependent behaviour in the library then becomes a function of what the test
 * assigns here:
 *
 *   - RDP retransmission and connection timeouts are driven by csp_conn_check_timeouts()
 *     reading csp_get_ms(), so advancing the clock replaces sleeping. libcsp's own
 *     suite needs tcase_set_timeout(..., 60) for two tests because of this.
 *   - The RDP initial send sequence number is rand_r() over a seed that is
 *     re-initialised from csp_get_ms() on every SYN (csp_rdp.c:548), so it is fully
 *     determined by the clock rather than being random at all.
 *   - csp_dedup.c ages its entries against csp_get_ms(), so the 32-bit millisecond
 *     wrap at 49.7 days is reachable by assignment.
 */
#pragma once

#include <inttypes.h>

/* Where every test starts, unless it says otherwise.
 *
 * Not zero: RDP compares `now` against `timestamp + timeout` using wrapping
 * arithmetic, so starting at zero would put half of the tests' arithmetic on the far
 * side of a wrap and hide ordinary bugs behind an unusual case. Tests that want the
 * wrap ask for it explicitly. */
#define CTEST_CLOCK_EPOCH_MS 100000u

/** Set the clock to an absolute millisecond value. */
void ctest_clock_set(uint32_t ms);

/** Move the clock forward. Wraps at 2^32 like the real one. */
void ctest_clock_advance(uint32_t ms);

/** What csp_get_ms() would return right now. */
uint32_t ctest_clock_now(void);
