"""Every `csp_foo.c:NNN` the port cites, checked against the line it points at.

Three findings in a row were a **claim about libcsp** that read plausibly and had never been
executed: `csp_rtable_save` mapped to a one-route formatter, the `fixup_cspv1` rows mapped to
a codec that byte-reverses the header, and a doc comment asserting `csp_init` calls
`csp_iflist_check_dfl` when nothing in libcsp calls it. Citations are the machine-checkable
part of that class. The submodule is pinned at `13a8c841`, so a cited line number is fixed
forever: a wrong one was always wrong and never drifted.

Two checks, both deterministic:

1. **The file and the line exist.**
2. **The cited line has substance** — it is not blank and not a lone `{`, `}` or `};`. A
   citation landing on a closing brace is pointing at the end of *something*, and which
   something is exactly what the reader cannot tell. All four errors this tool found on its
   first run were of that shape: `csp_port.c:54` is the closing brace of the function
   *before* `csp_port_get_socket`, and `csp_port.c:150` is a brace eight lines above the
   `csp_buffer_free` two comments attributed to it.

**What was tried and rejected:** requiring the citing comment and the cited line to share an
identifier. It is tunable to catch the four real errors *or* to pass the correct citations,
not both — with a small context window it flagged five correct ones (`irq`, `RDP_EAK` and
other short identifiers), and with a large one it stopped flagging `csp_port.c:54` because
the comment happened to say "returns NULL" and the brace has a `return NULL;` above it.
A threshold fitted until the list looks right is not a check. Left out rather than shipped.

Usage: `python3 ctest/tools/cites.py`, and `just check`.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
LIBCSP = ROOT / "libcsp"

#: Everything that cites the pinned tree, and is as able to be wrong about it.
SOURCES = [
    ROOT / "csp" / "src",
    ROOT / "csp-core" / "src",
    ROOT / "difftest" / "tests",
    ROOT / "difftest" / "src",
]
DOCS = [ROOT / "SCOPE.md", ROOT / "AUDIT.md", ROOT / "COMPARISON.md"]

CITE = re.compile(r"((?:csp_|pthread_)[\w/]*\.[ch]):(\d+)")
#: A line that is only structure. `#endif` and `*/` close things too, and say as little.
HOLLOW = {"", "{", "}", "};", "*/", "#endif", "#else", "*", "};/*"}


def files():
    for d in SOURCES:
        if d.exists():
            yield from sorted(p for p in d.rglob("*.rs"))
            yield from sorted(p for p in d.rglob("*.c"))
    for f in DOCS:
        if f.exists():
            yield f


def resolve(name):
    for sub in ("src", "include", "examples"):
        hits = sorted(LIBCSP.glob(f"{sub}/**/{name}"))
        if hits:
            return hits[0]
    return None


def main():
    problems = []
    total = 0
    for f in files():
        lines = f.read_text(errors="ignore").splitlines()
        for n, line in enumerate(lines, 1):
            for m in CITE.finditer(line):
                total += 1
                name, ln = m.group(1), int(m.group(2))
                where = f"{f.relative_to(ROOT)}:{n}"
                target = resolve(name)
                if target is None:
                    problems.append(f"{where}: cites {name}, which is not in the pinned tree")
                    continue
                clines = target.read_text(errors="ignore").splitlines()
                if ln > len(clines):
                    problems.append(
                        f"{where}: cites {name}:{ln}, but that file has {len(clines)} lines"
                    )
                    continue
                if clines[ln - 1].strip() in HOLLOW:
                    problems.append(
                        f"{where}: cites {name}:{ln}, which is {clines[ln - 1].strip()!r} — "
                        f"a citation has to point at something"
                    )

    print(f"{total} citations of the pinned libcsp tree")
    for p in problems:
        print(f"  {p}")
    if problems:
        print(f"{len(problems)} citation(s) that point at nothing")
        return 1
    print("every one resolves to a line with something on it")
    return 0


if __name__ == "__main__":
    sys.exit(main())
