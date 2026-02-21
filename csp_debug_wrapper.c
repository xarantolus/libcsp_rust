/*
 * C wrapper for CSP debug hook that handles va_list formatting
 * This allows Rust to receive pre-formatted strings instead of dealing with va_list
 */

#include <stdio.h>
#include <stdarg.h>
#include <csp/csp_debug.h>

// Function pointer for Rust callback
typedef void (*rust_debug_callback_t)(unsigned int level, const char *message);
static rust_debug_callback_t rust_callback = NULL;

// Set the Rust callback
void csp_debug_set_rust_callback(rust_debug_callback_t callback) {
    rust_callback = callback;
}

// C debug hook that formats the message and calls Rust
void csp_debug_hook_wrapper(unsigned int level, const char *format, va_list args) {
    if (rust_callback != NULL) {
        char buffer[1024];
        vsnprintf(buffer, sizeof(buffer), format, args);
        rust_callback(level, buffer);
    }
}

// Helper function to install the wrapper as the CSP debug hook
void csp_debug_hook_install_wrapper(void) {
    csp_debug_hook_set(csp_debug_hook_wrapper);
}

// Helper function to clear the CSP debug hook
void csp_debug_hook_clear(void) {
    csp_debug_hook_set(NULL);
}
