# Task runner for the port. `just` with no target lists everything.
default:
    @just --list

# ---------------------------------------------------------------------------
# The C oracle (ctest/)
# ---------------------------------------------------------------------------

# Configure + build the C oracle.
ctest-build:
    cmake -S ctest -B build/ctest -G Ninja -DCMAKE_BUILD_TYPE=Debug
    cmake --build build/ctest

# Run the C oracle. Pass a suite name to run just one: `just ctest RDP`
ctest suite="": ctest-build
    #!/usr/bin/env bash
    set -euo pipefail
    if [ -n "{{suite}}" ]; then export CK_RUN_SUITE="{{suite}}"; fi
    ./build/ctest/ctest

# Run the C oracle under AddressSanitizer.
#
# suite_eth is excluded: libcsp has known out-of-bounds reads in the Ethernet
# receive path, and ASan aborts on them rather than letting the test record what
# the C did. Those cases are covered by assertions on the counters instead.
ctest-asan suite="":
    #!/usr/bin/env bash
    set -euo pipefail
    cmake -S ctest -B build/ctest-asan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS="-fsanitize=address,undefined -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=address,undefined"
    cmake --build build/ctest-asan
    if [ -n "{{suite}}" ]; then export CK_RUN_SUITE="{{suite}}"; fi
    ./build/ctest-asan/ctest

# ---------------------------------------------------------------------------
# libcsp itself
# ---------------------------------------------------------------------------

# Configure the canonical libcsp build that difftest/build.rs and oracle/ expect.
canonical:
    cmake -S libcsp -B build/canonical -G Ninja \
        -DCSP_USE_RDP=ON -DCSP_USE_HMAC=ON -DCSP_USE_PROMISC=ON -DCSP_USE_RTABLE=ON
    cmake --build build/canonical

# ---------------------------------------------------------------------------
# Rust
# ---------------------------------------------------------------------------

test:
    cargo test --workspace --all-features

# The full pre-commit gate.
check: canonical
    cargo test --workspace --all-features
    cargo clippy --workspace --all-features --tests -- -D warnings
    cargo fmt --all --check
    cargo build -p csp-core -p csp --target thumbv7em-none-eabihf --no-default-features
    cargo build -p csp-core -p csp --target thumbv7em-none-eabihf --all-features

fmt:
    cargo fmt --all
