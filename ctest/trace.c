#include "trace.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int trace_fd = -1;

/* Built up here and written once. `open` distinguishes "no record in progress" from "a
 * record with nothing in it yet", which is what tells the value writers whether to emit a
 * separating comma. */
static char buf[CTEST_TRACE_MAX];
static size_t len;
static bool open_record;
static bool need_comma;

/* A record that did not fit is a record the Rust side would read as truncated JSON, so
 * overflow ends the process rather than emitting it. */
static void die(const char * why) {
	fprintf(stderr, "ctest trace: %s\n", why);
	abort();
}

static void put(const char * s) {
	size_t n = strlen(s);
	if (len + n >= sizeof(buf)) {
		die("record exceeds CTEST_TRACE_MAX");
	}
	memcpy(buf + len, s, n);
	len += n;
}

static void put_char(char c) {
	if (len + 1 >= sizeof(buf)) {
		die("record exceeds CTEST_TRACE_MAX");
	}
	buf[len++] = c;
}

/* The whole reason no escaping is needed. Anything outside this alphabet is a bug in the
 * caller, not something to encode around. */
static void put_ident(const char * s) {
	if ((s == NULL) || (*s == '\0')) {
		die("empty identifier");
	}
	for (const char * p = s; *p != '\0'; p++) {
		bool ok = ((*p >= 'a') && (*p <= 'z')) || ((*p >= '0') && (*p <= '9')) || (*p == '_');
		if (!ok) {
			fprintf(stderr, "ctest trace: %s is not [a-z0-9_]+\n", s);
			abort();
		}
	}
	put_char('"');
	put(s);
	put_char('"');
}

static void separate(void) {
	if (need_comma) {
		put_char(',');
	}
	need_comma = true;
}

static void key(const char * k) {
	separate();
	if (k != NULL) {
		put_ident(k);
		put_char(':');
	}
}

void ctest_trace_open(const char * path) {
	if (path == NULL) {
		return;
	}
	trace_fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_APPEND, 0644);
	if (trace_fd < 0) {
		perror("ctest trace: open");
		exit(EXIT_FAILURE);
	}
}

bool ctest_tracing(void) {
	return trace_fd >= 0;
}

void ctest_trace_begin(const char * suite, const char * name, const char * verdict) {
	if (!ctest_tracing()) {
		return;
	}
	len = 0;
	need_comma = false;
	open_record = true;
	put_char('{');
	ctest_trace_ident("suite", suite);
	ctest_trace_ident("case", name);
	ctest_trace_ident("verdict", verdict);
}

void ctest_trace_end(void) {
	if (!open_record) {
		return;
	}
	put_char('}');
	put_char('\n');
	open_record = false;

	/* One write, so records from concurrently forked tests cannot interleave. A short
	 * write would do exactly what the single write is there to prevent. */
	ssize_t written = write(trace_fd, buf, len);
	if ((written < 0) || ((size_t)written != len)) {
		perror("ctest trace: write");
		abort();
	}
	len = 0;
}

void ctest_trace_int(const char * k, int64_t value) {
	if (!open_record) {
		return;
	}
	char n[32];
	snprintf(n, sizeof(n), "%" PRId64, value);
	key(k);
	put(n);
}

void ctest_trace_bool(const char * k, bool value) {
	if (!open_record) {
		return;
	}
	key(k);
	put(value ? "true" : "false");
}

void ctest_trace_ident(const char * k, const char * value) {
	if (!open_record) {
		return;
	}
	key(k);
	put_ident(value);
}

void ctest_trace_hex(const char * k, const uint8_t * data, size_t n) {
	if (!open_record) {
		return;
	}
	static const char digits[] = "0123456789abcdef";
	key(k);
	put_char('"');
	for (size_t i = 0; i < n; i++) {
		put_char(digits[data[i] >> 4]);
		put_char(digits[data[i] & 0x0f]);
	}
	put_char('"');
}

void ctest_trace_obj_begin(const char * k) {
	if (!open_record) {
		return;
	}
	key(k);
	put_char('{');
	need_comma = false;
}

void ctest_trace_obj_end(void) {
	if (!open_record) {
		return;
	}
	put_char('}');
	need_comma = true;
}

void ctest_trace_arr_begin(const char * k) {
	if (!open_record) {
		return;
	}
	key(k);
	put_char('[');
	need_comma = false;
}

void ctest_trace_arr_end(void) {
	if (!open_record) {
		return;
	}
	put_char(']');
	need_comma = true;
}
