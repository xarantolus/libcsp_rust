/*
 * Wrapper to provide sscanf() by calling mini-scanf's c_sscanf().
 * mini-scanf uses c_sscanf to avoid name conflicts, but libcsp expects sscanf.
 */

extern int c_sscanf(const char* buff, char* format, ...);

int sscanf(const char* buff, const char* format, ...) {
    __builtin_va_list args;
    __builtin_va_start(args, format);

    // Forward to c_sscanf
    // Note: This is a simplified wrapper that works for libcsp's usage patterns
    int result = c_sscanf(buff, (char*)format, args);

    __builtin_va_end(args);
    return result;
}
