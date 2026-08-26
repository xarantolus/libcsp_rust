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

# The C oracle with the packet pool NOT zeroed on allocation, which is what a build that
# cares about cycles does. Reaches the branches the canonical config hides.
ctest-noclear:
    #!/usr/bin/env bash
    set -euo pipefail
    cmake -S ctest -B build/ctest-noclear -G Ninja -DCMAKE_BUILD_TYPE=Debug \
        -DCTEST_BUFFER_ZERO_CLEAR=0
    cmake --build build/ctest-noclear
    ./build/ctest-noclear/ctest

# The C oracle under UndefinedBehaviorSanitizer.
#
# Separate from ctest-asan: ASan aborts on libcsp's out-of-bounds reads in the Ethernet
# path before a test can record what the C did, while UBSan reports and continues. This is
# what catches csp_if_eth.c:46 shifting a promoted uint16_t into the sign bit of an int.
ctest-ubsan suite="":
    #!/usr/bin/env bash
    set -euo pipefail
    cmake -S ctest -B build/ctest-ubsan -G Ninja -DCMAKE_BUILD_TYPE=Debug \
        -DCMAKE_C_FLAGS="-fsanitize=undefined -fno-omit-frame-pointer" \
        -DCMAKE_EXE_LINKER_FLAGS="-fsanitize=undefined"
    cmake --build build/ctest-ubsan
    if [ -n "{{suite}}" ]; then export CK_RUN_SUITE="{{suite}}"; fi
    ./build/ctest-ubsan/ctest

# Line/region coverage over the shipped crates.
#
# Not a score to admire: what it is for is the *uncovered* half. The crypto hooks defaulting
# to "encrypted" on plaintext sat behind hooks.rs having the lowest function coverage in the
# crate, and nothing else had pointed at it.
cov:
    cargo llvm-cov --workspace --all-features --summary-only

# Mutation-test the corpus: break each guard, count which records notice.
#
# A mutation nothing notices is a hole. See ctest/tools/mutants.py for why counting
# records is not the same as measuring anything.
mutants:
    python3 ctest/tools/mutants.py

# Regenerate the corpus: what the C did, for the Rust side to replay.
#
# Byte-stable across runs by construction — every source of non-determinism in libcsp
# reachable from here is driven by clock.c. `git diff --stat corpus/` on an unchanged tree
# is the check that it stayed that way.
corpus: ctest-build
    mkdir -p corpus
    ./build/ctest/ctest --trace corpus/ctest.jsonl

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

# The size of the C API, four ways, so the denominator in SCOPE.md is reproducible
# rather than remembered. Needs `just canonical` first.
api-surface:
    #!/usr/bin/env bash
    set -euo pipefail
    lib=build/canonical/libcsp.so.2.2
    [ -f "$lib" ] || { echo "run 'just canonical' first"; exit 1; }
    nm -D --defined-only "$lib" | awk '$2=="T" && $3 ~ /^csp_/ {print $3}' | sort -u > /tmp/api-exported
    grep -rhoE '^[a-zA-Z_][a-zA-Z0-9_ *]*\b(csp_[a-z0-9_]+)\s*\(' libcsp/include/csp/ --include=*.h \
        | grep -oE 'csp_[a-z0-9_]+\s*\($' | tr -d ' (' | sort -u > /tmp/api-declared
    printf 'exported from the canonical build   %s\n' "$(wc -l < /tmp/api-exported)"
    printf 'declared in include/csp/**.h        %s\n' "$(wc -l < /tmp/api-declared)"
    printf '  both                              %s\n' "$(comm -12 /tmp/api-declared /tmp/api-exported | wc -l)"
    printf '  declared, not in this build       %s\n' "$(comm -23 /tmp/api-declared /tmp/api-exported | wc -l)"
    printf '  exported, not a public header     %s\n' "$(comm -13 /tmp/api-declared /tmp/api-exported | wc -l)"

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
