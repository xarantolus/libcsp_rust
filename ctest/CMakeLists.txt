# The C oracle: real libcsp, driven by libcheck, with a clock the test controls.
#
# libcsp's own suite is built from libcsp/unittests/CMakeLists.txt against the library
# target. This builds the sources directly instead, for two reasons that are the whole
# point of the exercise:
#
#   1. src/arch/posix/csp_time.c is left out and ctest/clock.c takes its place, so time
#      is an input. See clock.h.
#   2. autoconfig.h is generated here rather than by the submodule's CMake, so a second
#      build directory can vary CSP_USE_HMAC (and the rest) without touching libcsp.
#
# The submodule stays at its pinned commit and needs nothing added to it.

cmake_minimum_required(VERSION 3.16)
project(csp_ctest C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(LIBCSP ${CMAKE_CURRENT_SOURCE_DIR}/../libcsp)

if(NOT EXISTS ${LIBCSP}/src/csp_io.c)
  message(FATAL_ERROR "libcsp submodule is not checked out at ${LIBCSP}")
endif()

# Build configuration. Varying these is how the "feature compiled out" paths become
# reachable; suite_security.c needs a CTEST_USE_HMAC=0 build to reach the gate in
# csp_route.c that refuses a packet asking for HMAC on a node without it.
set(CTEST_USE_RDP 1 CACHE STRING "CSP_USE_RDP")
set(CTEST_USE_HMAC 1 CACHE STRING "CSP_USE_HMAC")
set(CTEST_USE_PROMISC 1 CACHE STRING "CSP_USE_PROMISC")
set(CTEST_USE_RTABLE 1 CACHE STRING "CSP_USE_RTABLE")

configure_file(autoconfig.h.in ${CMAKE_CURRENT_BINARY_DIR}/gen/csp/autoconfig.h @ONLY)

find_package(PkgConfig REQUIRED)
pkg_check_modules(CHECK REQUIRED check)

add_executable(ctest)

target_sources(ctest PRIVATE
  clock.c
  hooks.c
  trace.c
  main.c
  suite_queue.c
  suite_buffer.c
  suite_hmac.c
  suite_rdp.c
  suite_promisc.c
  suite_dedup.c
  suite_security.c
)

target_sources(ctest PRIVATE
  ${LIBCSP}/src/csp_id.c
  ${LIBCSP}/src/csp_crc32.c
  ${LIBCSP}/src/csp_init.c
  ${LIBCSP}/src/csp_debug.c
  ${LIBCSP}/src/csp_buffer.c
  ${LIBCSP}/src/csp_io.c
  ${LIBCSP}/src/csp_conn.c
  ${LIBCSP}/src/csp_port.c
  ${LIBCSP}/src/csp_qfifo.c
  ${LIBCSP}/src/csp_route.c
  ${LIBCSP}/src/csp_promisc.c
  ${LIBCSP}/src/csp_dedup.c
  ${LIBCSP}/src/csp_services.c
  ${LIBCSP}/src/csp_service_handler.c
  ${LIBCSP}/src/cmp/csp_cmp_dispatch.c
  ${LIBCSP}/src/cmp/csp_cmp_ident.c
  ${LIBCSP}/src/cmp/csp_cmp_if_stats.c
  ${LIBCSP}/src/cmp/csp_cmp_route.c
  ${LIBCSP}/src/cmp/csp_cmp_mem.c
  ${LIBCSP}/src/cmp/csp_cmp_peek_poke.c
  ${LIBCSP}/src/cmp/csp_cmp_clock.c
  # csp_clock_get_time is __weak here, so suite_cmp.c can override it and make the
  # CLOCK service answer a value the test chose.
  ${LIBCSP}/src/arch/posix/csp_clock.c
  ${LIBCSP}/src/csp_sfp.c
  ${LIBCSP}/src/csp_rdp.c
  ${LIBCSP}/src/csp_rdp_queue.c
  ${LIBCSP}/src/csp_hex_dump.c
  ${LIBCSP}/src/csp_iflist.c
  ${LIBCSP}/src/csp_rtable_cidr.c
  ${LIBCSP}/src/csp_rtable_stdio.c
  ${LIBCSP}/src/crypto/csp_sha1.c
  ${LIBCSP}/src/crypto/csp_hmac.c
  ${LIBCSP}/src/interfaces/csp_if_lo.c
  ${LIBCSP}/src/interfaces/csp_if_kiss.c
  # csp_buffer.c and csp_conn.c reach the OS through these.
  ${LIBCSP}/src/arch/posix/csp_queue.c
  ${LIBCSP}/src/arch/posix/pthread_queue.c
  ${LIBCSP}/src/arch/posix/csp_semaphore.c
  # Deliberately absent: src/arch/posix/csp_time.c — clock.c provides those four
  # symbols instead. Adding it back produces a duplicate-symbol link error rather
  # than silently restoring wall-clock time, which is the failure mode worth having.
)

target_include_directories(ctest PRIVATE
  ${LIBCSP}/include
  ${LIBCSP}/src
  ${CMAKE_CURRENT_BINARY_DIR}/gen
  ${CHECK_INCLUDE_DIRS}
)

target_compile_options(ctest PRIVATE
  -Wall -Wextra
  -Wno-unused-parameter
  -Wno-sign-compare
  -Wno-gnu-zero-variadic-macro-arguments
  ${CHECK_CFLAGS_OTHER}
)

target_link_libraries(ctest PRIVATE ${CHECK_LIBRARIES} pthread)
target_link_directories(ctest PRIVATE ${CHECK_LIBRARY_DIRS})
