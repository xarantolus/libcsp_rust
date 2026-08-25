/* Records what the C did, as one JSON Lines record per test.
 *
 * The Rust side reads these back with serde and replays each case, so this file is the
 * schema. Three rules make it safe to write by hand:
 *
 *   1. **Every value is an integer, a `[a-z0-9_]+` identifier, or lowercase hex.** None of
 *      them can contain a quote, a backslash or a control character, so there is nothing
 *      to escape and no way to emit invalid JSON. Identifiers are checked at runtime and
 *      abort the test rather than being silently mangled.
 *   2. **One write(2) per record.** The runner forks per test, so several processes share
 *      the output file descriptor. A single write under PIPE_BUF is atomic; two writes are
 *      not, and would interleave two tests' records into one corrupt line.
 *   3. **A record is only written if the test passes.** A failing assertion means the
 *      harness misunderstood the C, and recording that would enshrine the mistake.
 *
 * Records are emitted only when --trace is given, so `just ctest` stays a plain test run.
 */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <inttypes.h>

/** Largest record. One write(2) has to carry it, so it stays under PIPE_BUF. */
#define CTEST_TRACE_MAX 4000

/** Open the trace file. NULL disables tracing. Called once from main(). */
void ctest_trace_open(const char * path);

/** Is anything listening? Lets a test skip building a record it cannot emit. */
bool ctest_tracing(void);

/**
 * Start a record.
 *
 * @param suite   suite name, an identifier.
 * @param name    test name, an identifier — the Rust replay is found by this name.
 * @param verdict "must_match", "diverges" or "c_only".
 */
void ctest_trace_begin(const char * suite, const char * name, const char * verdict);

/** Finish the record and write it. Does nothing if no record is open. */
void ctest_trace_end(void);

/* --- values --- */

void ctest_trace_int(const char * key, int64_t value);
void ctest_trace_bool(const char * key, bool value);

/** A `[a-z0-9_]+` identifier — an enum name, not free text. */
void ctest_trace_ident(const char * key, const char * value);

/** Bytes, as a lowercase hex string. */
void ctest_trace_hex(const char * key, const uint8_t * data, size_t len);

/* --- structure ---
 *
 * `key` is NULL for an element inside an array, and a name inside an object. */

void ctest_trace_obj_begin(const char * key);
void ctest_trace_obj_end(void);
void ctest_trace_arr_begin(const char * key);
void ctest_trace_arr_end(void);
