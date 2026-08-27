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

So this prints the gap per suite and names the tests. An untraced test is a lead, not a
defect, and several are legitimate (libcsp internals with no port equivalent, like the
promiscuous queue-sizing pair) -- so the gap itself does not fail. What *does* fail is an
untraced test with no written justification: `SCOPE.md` carries a table giving the basis for
each one, and this checks that the table and the code still describe the same set.

That check exists because the prose around the table said "each is justified in SCOPE.md"
for several cycles with nothing verifying it, and the table's headline ratio silently went
stale as tests were added. A justification nobody checks decays into the same hand-wave as
no justification at all.

A test counts as recording if its body calls `ctest_trace_begin` **or** any static helper in
the same file whose own body does -- `suite_dedup.c` and `suite_rdp.c` both record through
helpers, and an earlier version of this that only looked for the literal call reported two
already-covered tests as gaps.

Every test the current run reports is justified one by one in `SCOPE.md` -- covered
elsewhere, structurally inapplicable, or a named gap. A count alone invites exactly the
hand-wave this exists to prevent, so check that table before concluding the remainder is
fine.

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
SCOPE = ROOT / "SCOPE.md"

# A justification row: | `suite::name` | basis |. Other tables in SCOPE.md use the same
# shape for Rust paths (`Node::resolve`), so the suite has to be one that exists.
SUITE_NAMES = {p.stem.removeprefix("suite_") for p in SUITES}
JUSTIFIED = re.compile(
    r"^\|\s*`(" + "|".join(sorted(SUITE_NAMES)) + r")::(\w+)`\s*\|", re.M
)

TEST = re.compile(r"^START_TEST\((\w+)\)", re.M)
HELPER = re.compile(r"^static\s+[\w \t\*]+?(\w+)\s*\([^;]*?\)\s*\{", re.M)


def live_source(text):
    """Only the branch that compiles. `suite_rdp.c` defines its tests twice."""
    marker = "#else /* !CSP_USE_RDP */"
    return text[: text.index(marker)] if marker in text else text


def recorders(src):
    """`ctest_trace_begin` plus every static helper that reaches it, transitively.

    To a fixed point, not one level. `suite_hmac.c` records through
    `hmac_record` -> `hmac_record_hdr` -> `ctest_trace_begin`, and a single pass called a
    test that does record a test that does not -- which is the same mistake this tool exists
    to catch, made by the tool.
    """
    bodies = {}
    for m in HELPER.finditer(src):
        end = src.find("\n}", m.end())
        if end != -1:
            bodies[m.group(1)] = src[m.end() : end]

    found = {"ctest_trace_begin"}
    changed = True
    while changed:
        changed = False
        for name, body in bodies.items():
            if name in found:
                continue
            if any(f"{r}(" in body for r in found):
                found.add(name)
                changed = True
    return found


def justified():
    """`suite::name` keys from SCOPE.md's untraced-justification table.

    Matched by shape, not by position: *any* SCOPE.md table row whose first cell is a bare
    `` `suite::name` `` counts. So an unrelated table that happens to name a record in its
    first column reads as a justification for it, and this run fails with "justification rows
    for tests that are not untraced". That has happened once; the fix is to move the name out
    of column one, not to weaken the match, which is what makes a stale row impossible to
    leave lying about.
    """
    if not SCOPE.exists():
        return set()
    return {f"{s}::{n}" for s, n in JUSTIFIED.findall(SCOPE.read_text())}


def keys_for(suite, test):
    """The names a justification row may use for this test.

    A test is `test_<name>` in `suite_<suite>.c`, and the table writes it as
    `<suite>::<name>` -- but where the function name already repeats the suite
    (`test_promisc_disabled_consumes_nothing`) the row drops the repeat. Both spellings are
    in the table today, so both are accepted rather than churning the rows.
    """
    name = test.removeprefix("test_")
    out = {f"{suite}::{name}"}
    if name.startswith(f"{suite}_"):
        out.add(f"{suite}::{name.removeprefix(suite + '_')}")
    return out


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

    have = justified()
    unjustified = []
    claimed = set()
    for path, names in gaps:
        suite = path.removeprefix("suite_").removesuffix(".c")
        for n in names:
            keys = keys_for(suite, n)
            hit = keys & have
            if hit:
                claimed |= hit
            else:
                # Report every spelling a row could use, so the fix is copy-pasteable.
                unjustified.append(" or ".join(sorted(keys)))

    # A row for a test that now records, or that no longer exists, is a justification for
    # nothing -- and left in place it inflates the table into looking more complete than it is.
    stale = sorted(have - claimed)

    if unjustified or stale:
        print()
        if unjustified:
            print("untraced with no basis in SCOPE.md's justification table:")
            for u in sorted(unjustified):
                print(f"    {u}")
        if stale:
            print("justification rows for tests that are not untraced:")
            for s in stale:
                print(f"    {s}")
        return 1

    print(f"all {len(unjustified) + len(claimed)} untraced tests have a basis in SCOPE.md")
    return 0


if __name__ == "__main__":
    sys.exit(main())
