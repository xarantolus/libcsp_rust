"""Every public libcsp function is accounted for, or this fails.

The first "the port is complete" claim in this project compared *module names* and missed
about thirty-five functions, the whole socket API among them. Counting modules cannot catch
that; only an inventory at function granularity can, and only if the inventory is checked
rather than trusted.

So `api_map.tsv` maps every `csp_*` function declared in `libcsp/include/csp/**.h` to one of:

    ported       <rust path>    the port implements it; the path must exist
    out-of-scope <reason>       SCOPE.md excludes it (arch shims, drivers, zmqhub, ...)
    deferred     <reason>       in scope, deliberately not done yet, named in SCOPE.md

and this script checks five things that together make the map hard to lie with:

  1. every declared C function appears in the map        -- catches silent omission
  2. every map entry names a function that still exists  -- catches stale rows after a bump
  3. every `ported` row names a Rust item that exists    -- catches a mapping to nothing
  4. every `ported` row names a *function*               -- catches a row that stops short
  5. that function is defined in the module the row names -- catches a row that only spells

Checks 4 and 5 are what keep the first three honest, and both were added late. With only 1-3,
152 `ported` rows resolved to 28 distinct Rust names, because a row could name the type that
holds the method and pass for as long as the struct existed. With 4 but not 5, 57 of the rows
named a function that exists in several modules -- `new` in nineteen of them -- so a row would
still survive its real target being deleted. See `rust_functions` and `defines` below.

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


def rust_functions():
    """Function names defined anywhere in the shipped crates, tests excluded.

    Separate from `rust_symbols` because a `ported` row that resolves to a *type* proves
    almost nothing: `csp_iflist_get_by_broadcast` -> `csp::iflist::IfList` passes as long as
    the struct exists, whatever became of the method. Measured 2026-08-27: 152 `ported` rows
    resolved to 28 distinct names, 148 of them shared with another row. That is module
    granularity wearing a function-shaped map -- the exact failure this file was written to
    stop, re-formed inside it.
    """
    fn = re.compile(r"\bfn\s+(\w+)")
    names = set()
    for d in RUST_DIRS:
        for f in d.rglob("*.rs"):
            text = f.read_text(errors="ignore")
            i = text.find("\n#[cfg(test)]")
            if i != -1:
                text = text[:i]
            names.update(fn.findall(text))
    return names


def defines(path):
    """Does the module named by a `ported` path define the function the path ends in?

    Name-only lookup is looser than it reads: 57 of the 148 `ported` rows name a function
    that exists in more than one module, and `new` is defined in 19. So a row could keep
    passing after its real target was deleted, on the strength of an unrelated same-named
    `fn` elsewhere -- the same failure as naming a type, one level down again. Resolving the
    path makes a row a pointer rather than a name.

    Returns None if the path names no module file, which is itself a failure worth reporting.
    """
    segs = path.replace("()", "").split("::")
    src = ROOT / ("csp" if segs[0] == "csp" else "csp-core") / "src"
    item = segs[-1]
    # Longest module prefix that is a file; a crate-root path lands on lib.rs.
    for k in range(len(segs) - 1, 1, -1):
        f = src.joinpath(*segs[1:k]).with_suffix(".rs")
        if f.exists():
            break
    else:
        f = src / "lib.rs"
    if not f.exists():
        return None
    return bool(re.search(r"\bfn\s+" + re.escape(item) + r"\b", f.read_text(errors="ignore")))


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
    fns = rust_functions()
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
            elif item and item not in fns:
                problems.append(
                    f"{fn} -> {detail}: `{item}` is not a function. A row that stops at a "
                    f"type or module cannot notice the function going away, which is the "
                    f"failure this map exists to catch -- name the item that does the work"
                )
            elif item:
                found = defines(detail)
                if found is None:
                    problems.append(f"{fn} -> {detail}: names no module that exists")
                elif not found:
                    problems.append(
                        f"{fn} -> {detail}: `{item}` is a function somewhere, but not in the "
                        f"module this path names -- the row would survive its real target "
                        f"being deleted"
                    )

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
