"""Every `START_TEST` in a suite must be handed to `tcase_add_test`.

libcheck makes a defined-but-unregistered test invisible: `START_TEST(x)` expands to a
function definition, so the file compiles, the suite runs, and the count goes up by nothing.
Nothing fails. The test simply never executes, and if it also writes a corpus record, that
record never appears and the Rust replay has nothing to disagree with -- the whole chain
stays green while the case is not being run at all.

That has happened twice here, both times from an edit whose anchor did not match. This is
the check that turns it into a build failure. It is deliberately textual: parsing C properly
would be worse, and the two forms are unambiguous in these files.

Usage: `python3 ctest/tools/registered.py`. Exit 1 lists the unregistered tests.
"""

import pathlib
import re
import sys

SUITES = sorted((pathlib.Path(__file__).resolve().parents[1]).glob("suite_*.c"))

DEFINED = re.compile(r"^START_TEST\((\w+)\)", re.M)
ADDED = re.compile(r"tcase_add_test\(\s*\w+\s*,\s*(\w+)\s*\)")

# Sets, not counts: `suite_rdp.c` defines the same names twice under `#if (CSP_USE_RDP)`
# and its `#else`, only one of which compiles. Some registrations are themselves
# conditional -- the `CSP_BUFFER_ZERO_CLEAR` case runs only in the `ctest-noclear` build --
# so a name registered anywhere in the file counts as registered.
missing = []
for path in SUITES:
    text = path.read_text()
    defined = set(DEFINED.findall(text))
    added = set(ADDED.findall(text))
    for name in sorted(defined - added):
        missing.append(f"{path.name}: {name}")
    # The reverse is a compile error, not something to check for here.

if missing:
    print("tests defined but never registered -- these do not run:")
    for m in missing:
        print(f"    {m}")
    sys.exit(1)

total = sum(len(set(DEFINED.findall(p.read_text()))) for p in SUITES)
print(f"all {total} ctest cases are registered")
