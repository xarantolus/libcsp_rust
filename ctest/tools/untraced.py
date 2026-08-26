"""C tests that assert against a real libcsp node and record nothing.

A test in `ctest/` that has no `ctest_trace_*` call still runs, still passes, and still says
nothing about the port -- the oracle measured something and threw the answer away. That is
not a hypothetical: it is where the last three defects came from.

  - `suite_dedup.c` had seven tests and four records; the three that traced nothing were the
    window boundary, so the port's dedup window was compared to no oracle at all.
  - `suite_rdp.c` had 21 tests and 11 records; five of the untraced covered SYN option-block
    validation, and one of those turned out to be a malformed SYN that got an RST *and* an
    accepted connection, plus a table slot a peer could exhaust.
  - the same measurement then found the negotiated window never bounding `ack_delay_count`.

So this prints the gap per suite and names the tests. It is deliberately *not* wired into
`just check`: an untraced test is a lead, not a defect, and several are legitimate (libcsp
internals with no port equivalent, like the promiscuous queue-sizing pair). Run it when
looking for the next thing to verify.

A test counts as recording if its body calls `ctest_trace_begin` **or** any static helper in
the same file whose own body does -- `suite_dedup.c` and `suite_rdp.c` both record through
helpers, and an earlier version of this that only looked for the literal call reported two
already-covered tests as gaps.

Usage: `just untraced`.
"""

import collections
import json
import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
SUITES = sorted((ROOT / "ctest").glob("suite_*.c"))
CORPUS = ROOT / "corpus" / "ctest.jsonl"

TEST = re.compile(r"^START_TEST\((\w+)\)", re.M)
HELPER = re.compile(r"^static\s+[\w \t\*]+?(\w+)\s*\([^;]*?\)\s*\{", re.M)


def live_source(text):
    """Only the branch that compiles. `suite_rdp.c` defines its tests twice."""
    marker = "#else /* !CSP_USE_RDP */"
    return text[: text.index(marker)] if marker in text else text


def recorders(src):
    """`ctest_trace_begin` plus every static helper that reaches it."""
    found = {"ctest_trace_begin"}
    for m in HELPER.finditer(src):
        end = src.find("\n}", m.end())
        if end != -1 and "ctest_trace_begin" in src[m.end() : end]:
            found.add(m.group(1))
    return found


def main():
    per_suite = collections.Counter()
    if CORPUS.exists():
        for line in CORPUS.read_text().splitlines():
            if line.strip():
                per_suite[json.loads(line)["suite"]] += 1

    total_tests = total_recorded = 0
    gaps = []
    for path in SUITES:
        src = live_source(path.read_text())
        names = TEST.findall(src)
        rec = recorders(src)
        untraced = []
        for name in names:
            begin = src.index(f"START_TEST({name})")
            end = src.index("END_TEST", begin)
            body = src[begin:end]
            if not any(f"{r}(" in body for r in rec):
                untraced.append(name)
        total_tests += len(names)
        total_recorded += len(names) - len(untraced)
        if untraced:
            gaps.append((path.name, untraced))

    for suite, names in gaps:
        print(f"{suite}: {len(names)} test(s) record nothing")
        for n in names:
            print(f"    {n}")
    print()
    print(f"{total_recorded}/{total_tests} C tests record something")
    print(f"{sum(per_suite.values())} corpus records across {len(per_suite)} suites")
    return 0


if __name__ == "__main__":
    sys.exit(main())
