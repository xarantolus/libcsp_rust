"""Measure the size figures COMPARISON.md quotes, on whichever branch this runs.

COMPARISON.md's scoreboard carried `50 translation units, 8 527 lines of C`, a Rust
implementation figure of `8 353`, a test figure of `7 568`, and a ratio of `0.89x`. None of
the four was reproducible: no script, no definition and no commit was recorded anywhere for
any of them, so there was no way to tell a stale number from a wrong one. The ratio was in
fact wrong on the table's own arithmetic -- 8 353 / 8 527 is 0.98, and the row above it
divides by the same denominator correctly.

So the definitions live here, in one place, and `just numbers` checks the document against
them:

* **C** -- every `.c` under `libcsp/src` at the pinned submodule commit. The whole library,
  not a subset, because any subset needs a rule and the rule is what goes missing.
* **Rust implementation** -- every `.rs` under `csp-core/src` and `csp/src`, up to the first
  `#[cfg(test)]` in each file.
* **Rust tests** -- the remainder of those files, plus `csp/tests` and `csp-core/tests`.
  `difftest/` is excluded: it links the C library and is a harness, not part of the port.
* **`transpiled/`**, on the c2rust branches only -- `unsafe` blocks and functions,
  `static mut`, `extern "C"`, and raw-pointer types, counted textually.

Line counts are plain newline counts. Blank and comment lines are included, in both
languages, because "excluding comments" is another rule that has to be written down and
agreed to, and this comparison is not sensitive to it.

Usage: `python3 ctest/tools/loc.py` prints the figures for the current branch.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]

C_ROOT = ROOT / "libcsp" / "src"
IMPL_ROOTS = ("csp-core/src", "csp/src")
TEST_ROOTS = ("csp/tests", "csp-core/tests")


def lines(path):
    return path.read_text(errors="ignore").count("\n")


def c_source():
    """Translation units and lines under `libcsp/src`."""
    files = sorted(C_ROOT.rglob("*.c"))
    return len(files), sum(lines(f) for f in files)


def rust_source():
    """(implementation, tests) for the port, split at the first `#[cfg(test)]`."""
    impl = tests = 0
    for root in IMPL_ROOTS:
        for f in sorted((ROOT / root).rglob("*.rs")):
            text = f.read_text(errors="ignore")
            cut = text.find("#[cfg(test)]")
            if cut < 0:
                impl += text.count("\n")
            else:
                impl += text[:cut].count("\n")
                tests += text[cut:].count("\n")
    for root in TEST_ROOTS:
        d = ROOT / root
        if d.exists():
            tests += sum(lines(f) for f in sorted(d.rglob("*.rs")))
    return impl, tests


def transpiled():
    """c2rust's output, or None on a branch that has none."""
    d = ROOT / "transpiled"
    if not d.exists():
        return None
    text = "\n".join(f.read_text(errors="ignore") for f in sorted(d.rglob("*.rs")))
    return {
        "lines": text.count("\n"),
        "unsafe": len(re.findall(r"\bunsafe\b", text)),
        "static mut": len(re.findall(r"\bstatic\s+mut\b", text)),
        'extern "C"': len(re.findall(r'\bextern\s+"C"', text)),
        "raw pointers": len(re.findall(r"\*\s*(?:const|mut)\s", text)),
    }


def ratio(rust, c):
    """The multiplier as the document prints it: two decimals, one trailing digit dropped."""
    return f"{rust / c:.2f}"


def main():
    units, c_lines = c_source()
    impl, tests = rust_source()
    print(f"C translation units    {units}")
    print(f"C lines                {c_lines}")
    print(f"Rust implementation    {impl}  ({ratio(impl, c_lines)}x the C)")
    print(f"Rust tests             {tests}")
    t = transpiled()
    if t:
        print("transpiled/ (this branch):")
        for k, v in t.items():
            print(f"  {k:16s} {v}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
