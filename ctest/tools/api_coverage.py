"""Every public libcsp function is accounted for, or this fails.

The first "the port is complete" claim in this project compared *module names* and missed
about thirty-five functions, the whole socket API among them. Counting modules cannot catch
that; only an inventory at function granularity can, and only if the inventory is checked
rather than trusted.

So `api_map.tsv` maps every `csp_*` function declared in `libcsp/include/csp/**.h` to one of:

    ported       <rust path>    the port implements it; the path must exist
    out-of-scope <reason>       SCOPE.md excludes it (arch shims, drivers, zmqhub, ...)
    deferred     <reason>       in scope, deliberately not done yet, named in SCOPE.md

and this script checks three things that together make the map hard to lie with:

  1. every declared C function appears in the map        -- catches silent omission
  2. every map entry names a function that still exists  -- catches stale rows after a bump
  3. every `ported` row names a Rust item that exists    -- catches a mapping to nothing

**What this does NOT establish.** That a Rust item exists under a name is not evidence it
behaves like the C. A grep proves spelling. Behavioural equivalence is what the corpus
records, the golden vectors and the difftest suite are for, and `deferred`/`out-of-scope`
rows carry no behavioural claim at all. Read a green run as "nothing is unaccounted for",
never as "everything is correct".

Usage: `just api`. Exit 1 lists every discrepancy.
"""

import pathlib
import re
import sys

ROOT = pathlib.Path(__file__).resolve().parents[2]
HEADERS = ROOT / "libcsp" / "include" / "csp"
MAP = pathlib.Path(__file__).resolve().parent / "api_map.tsv"
RUST_DIRS = [ROOT / "csp" / "src", ROOT / "csp-core" / "src"]

DECL = re.compile(r"^\s*(?!typedef)([A-Za-z_][\w \t\*]*?)\b(csp_\w+)\s*\(", re.M)


def declared():
    """Every `csp_*` function declared in a public header, comments stripped first."""
    out = {}
    for h in sorted(HEADERS.rglob("*.h")):
        text = h.read_text(errors="ignore")
        text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
        text = re.sub(r"//.*", "", text)
        for m in DECL.finditer(text):
            out.setdefault(m.group(2), str(h.relative_to(HEADERS)))
    return out


def rust_symbols():
    """Item names defined anywhere in the shipped crates."""
    # Two patterns, because one `const` alternative swallows the `fn` of `pub const fn foo`
    # and reports the item as missing -- which it did for `Id::is_broadcast` and
    # `sfp::max_mtu`, both of which exist.
    items = re.compile(
        r"\b(?:const\s+|async\s+|unsafe\s+|extern\s+\"C\"\s+)*"
        r"(?:fn|struct|enum|trait|type|mod|union|macro_rules!)\s+(\w+)"
    )
    consts = re.compile(r"\bconst\s+(?!fn\b)(\w+)\s*:")
    names = set()
    for d in RUST_DIRS:
        for f in d.rglob("*.rs"):
            text = f.read_text(errors="ignore")
            names.update(items.findall(text))
            names.update(consts.findall(text))
            # A file is a module, whether or not any `mod` line names it here.
            names.add(f.stem)
    return names


def load_map():
    rows = {}
    if not MAP.exists():
        return rows
    for n, line in enumerate(MAP.read_text().splitlines(), 1):
        if not line.strip() or line.startswith("#"):
            continue
        parts = line.split("\t")
        if len(parts) < 3:
            print(f"{MAP.name}:{n}: expected three tab-separated fields", file=sys.stderr)
            sys.exit(2)
        rows[parts[0].strip()] = (parts[1].strip(), parts[2].strip())
    return rows


def main():
    c_funcs = declared()
    rows = load_map()
    syms = rust_symbols()
    problems = []

    for fn, hdr in sorted(c_funcs.items()):
        if fn not in rows:
            problems.append(f"unmapped: {fn}  (declared in {hdr})")

    for fn in sorted(rows):
        if fn not in c_funcs:
            problems.append(f"stale: {fn} is in the map but no header declares it")

    for fn, (status, detail) in sorted(rows.items()):
        if status not in {"ported", "out-of-scope", "deferred"}:
            problems.append(f"bad status for {fn}: {status}")
        elif status == "ported":
            # The last path segment is the item; `csp::conn::Table::find` -> `find`.
            item = detail.replace("()", "").split("::")[-1].strip()
            if item and item not in syms:
                problems.append(f"{fn} -> {detail}: no Rust item named `{item}` exists")

    counts = {}
    for status, _ in rows.values():
        counts[status] = counts.get(status, 0) + 1

    if problems:
        print(f"{len(problems)} problem(s):")
        for p in problems:
            print(f"    {p}")
        return 1

    total = len(c_funcs)
    print(f"all {total} declared csp_* functions are accounted for")
    for k in ("ported", "out-of-scope", "deferred"):
        if counts.get(k):
            print(f"  {counts[k]:4} {k}")
    print("(accounted for, not verified equivalent -- see this file's docstring)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
