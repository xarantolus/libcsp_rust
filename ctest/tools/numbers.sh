#!/usr/bin/env bash
# Every *live* number docs/API.md and COMPARISON.md quote, plus the one figure in SCOPE.md
# that tracks the tree, measured rather than remembered.
#
# AUDIT.md is deliberately not checked, and this header used to name it as though it were.
# Its numbers -- and all of SCOPE.md's except the "record something today" line -- are dated
# records of what was true on the day they were written ("All 465 tests as they stood at the
# time of this audit"). Making those track the tree would destroy the thing they are for.
#
# Three figures had drifted before this existed -- "449 tests" against 487,
# "922 golden vectors" against 510 lines, "19 differential tests" against 33 -- and a
# stale count is exactly the shape of the coverage claim that hid a third of the library.
set -uo pipefail
cd "$(dirname "$0")/../.."

out=$(cargo test --workspace --all-features --no-fail-fast 2>&1)
if [ "$(echo "$out" | grep -c FAILED)" -ne 0 ]; then
  echo "tests are FAILING -- every count below would be from a partial run" >&2
  exit 1
fi

printf 'rust tests           %s across %s binaries (--all-features)\n' \
  "$(echo "$out" | grep -E '^test result' | awk '{s+=$4} END {print s}')" \
  "$(echo "$out" | grep -cE '^test result')"
printf 'golden vector lines  %s (vectors/v{1,2}.tsv, comments and blanks excluded)\n' \
  "$(cat vectors/v1.tsv vectors/v2.tsv | grep -vcE '^#|^$')"
printf 'difftest tests       %s (#[test] in difftest/tests/)\n' \
  "$(grep -hcE '^[[:space:]]*#\[test\]' difftest/tests/*.rs | paste -sd+ - | python3 -c 'import sys; print(eval(sys.stdin.read()))')"
printf 'C oracle checks      %s (just ctest)\n' \
  "$(just ctest 2>&1 | grep -oE 'Checks: [0-9]+' | grep -oE '[0-9]+')"
printf 'corpus records       %s\n' "$(wc -l < corpus/ctest.jsonl)"

# Printing them is not enough. "487 tests" drifted to 492 while sitting three lines under
# a paragraph promising every number here is measured, and I corrected the record and check
# counts in the same edit without noticing it. `just numbers check` fails on a mismatch, so
# the promise is enforced rather than repeated.
if [ "${1:-}" = "check" ]; then
  fail=0
  # The scoreboard writes thousands with a space (`11 692`), so every extractor reads a
  # normalised copy in which digit groups are joined. Without it `[0-9]+` matches `11` and
  # the check fails -- or worse, passes -- for a typographic reason.
  _norm() { sed -E ':a;s/([0-9]) ([0-9])/\1\2/g;ta' "$1"; }
  expect() {  # expect <what> <measured> <regex> [file, default docs/API.md]
    file=${4:-docs/API.md}
    doc=$(_norm "$file" | grep -oE "$3" | grep -oE '[0-9]+' | head -1)
    _expect_cmp "$1" "$2" "$doc" "$file"
  }
  # The last cell of a table row, for a figure the port column does not bold.
  expect_last() {  # expect_last <what> <measured> <row regex> <file>
    doc=$(_norm "$4" | grep -E "$3" | grep -oE '[0-9]+' | tail -1)
    _expect_cmp "$1" "$2" "$doc" "$4"
  }
  # A row of the COMPARISON.md table has three cells; the port's is the bolded one. Taking
  # the first number on the line compares against c2rust's `0` and passes for the wrong
  # reason -- which it did, until this run printed "= 0, measured 533".
  # The **last** bolded number on the row, not the first: the port is the rightmost column,
  # and a cell like `16 954 (**1.45x the C**)` puts a bolded ratio to its left. Taking the
  # first read `1` and reported a mismatch against 11 095.
  expect_bold() {  # expect_bold <what> <measured> <row regex> <file>
    doc=$(_norm "$4" | grep -E "$3" | grep -oE '\*\*[0-9]+' | grep -oE '[0-9]+' | tail -1)
    _expect_cmp "$1" "$2" "$doc" "$4"
  }
  _expect_cmp() {
    if [ "$3" != "$2" ]; then
      echo "$4 says $1 = ${3:-<missing>}, measured $2" >&2
      fail=1
    fi
  }
  expect "rust tests"     "$(echo "$out" | grep -E '^test result' | awk '{s+=$4} END {print s}')" '\*\*[0-9]+ tests\*\* across the crates'
  expect "corpus records" "$(wc -l < corpus/ctest.jsonl)" '\*\*[0-9]+ corpus records\*\*'
  expect "C oracle checks" "$(just ctest 2>&1 | grep -oE 'Checks: [0-9]+' | grep -oE '[0-9]+')" '\*\*[0-9]+ checks\*\*'
  expect "golden vector lines" "$(cat vectors/v1.tsv vectors/v2.tsv | grep -vcE '^#|^$')" '\*\*[0-9]+ golden vector lines\*\*'
  expect "difftest tests" "$(grep -hcE '^[[:space:]]*#\[test\]' difftest/tests/*.rs | paste -sd+ - | python3 -c 'import sys; print(eval(sys.stdin.read()))')" '\*\*[0-9]+ differential tests\*\*'
  # The binary count sat in the same sentence as the test count, printed by this script and
  # checked by nothing -- so it read 10 against a measured 22 for as long as nobody counted.
  # Half a sentence being enforced is what let it drift under a paragraph promising it was not.
  expect "test binaries" "$(echo "$out" | grep -cE '^test result')" 'in [0-9]+ binaries'
  # COMPARISON.md was checked by nothing, and drifted: its three-branch table still claimed
  # 451 tests and 19 differential tests against 533 and 66, and it counted 923 golden
  # vectors -- 412 of which lived in `vectors/vectors.tsv`, a superseded single-file format
  # that `csp-core/tests/vectors.rs` does not load. A tool that guards one of four documents
  # guards the one that was already being watched.
  expect_bold "comparison: tests" "$(echo "$out" | grep -E '^test result' | awk '{s+=$4} END {print s}')" \
    '^\| Tests passing \|' COMPARISON.md
  expect_bold "comparison: differential tests" \
    "$(grep -hcE '^[[:space:]]*#\[test\]' difftest/tests/*.rs | paste -sd+ - | python3 -c 'import sys; print(eval(sys.stdin.read()))')" \
    '^\| Differential tests vs the C \|' COMPARISON.md
  expect "comparison: golden vectors" "$(cat vectors/v1.tsv vectors/v2.tsv | grep -vcE '^#|^$')" \
    '[0-9]+ vectors captured from the running C' COMPARISON.md

  # COMPARISON.md's size figures. `50 translation units, 8 527 lines of C`, `8 353` and
  # `7 568` were reproducible by no definition at all -- no script, no commit, no rule was
  # recorded for any of them, and the ratio printed beside the implementation figure
  # (`0.89x`) did not even follow from the table's own two numbers. What makes that a
  # measurement failure rather than a broken measuring stick: the same textual method
  # reproduces the four c2rust figures in the same table exactly (441, 90, 486, 2 709).
  # `ctest/tools/loc.py` owns the definitions now, and these four lines make the document
  # track them.
  loc=$(python3 ctest/tools/loc.py)
  loc_field() { echo "$loc" | grep -E "^$1" | grep -oE '[0-9]+' | head -1; }
  expect "comparison: C translation units" "$(loc_field 'C translation units')" \
    '\*\*[0-9]+ translation units' COMPARISON.md
  expect "comparison: C lines" "$(loc_field 'C lines')" \
    '[0-9]+ lines of C\*\*' COMPARISON.md
  expect_bold "comparison: rust implementation" "$(loc_field 'Rust implementation')" \
    '^\| Rust LOC \(implementation\) \|' COMPARISON.md
  expect_last "comparison: rust tests" "$(loc_field 'Rust tests')" \
    '^\| Rust LOC \(tests\) \|' COMPARISON.md
  # The multiplier, which is the figure that was actually wrong: the row said `0.89x` where
  # its own two numbers give 0.98, while the row above divided by the same denominator
  # correctly. A derived number nobody recomputes is the easiest kind to get wrong.
  doc_ratio=$(_norm COMPARISON.md | grep -E '^\| Rust LOC \(implementation\) \|' \
    | grep -oE '[0-9]+\.[0-9]+' | tail -1)
  loc_ratio=$(echo "$loc" | grep -E '^Rust implementation' | grep -oE '[0-9]+\.[0-9]+')
  _expect_cmp "comparison: implementation ratio" "$loc_ratio" "$doc_ratio" COMPARISON.md

  # The API breakdown COMPARISON.md states in the present tense. `just api` measures it and
  # the paragraph quoted it, and the two were free to drift -- which is how the same document
  # spent months saying "All 186 are now accounted for" after SCOPE.md had recorded that 186
  # was not reproducible. Three rows moved from `ported` to `out-of-scope` the moment their
  # mapping was measured, so this is not a hypothetical.
  api_out=$(python3 ctest/tools/api_coverage.py)
  api_field() { echo "$api_out" | grep -E "^ +[0-9]+ $1\$" | grep -oE '[0-9]+'; }
  expect "comparison: api ported" "$(api_field ported)" \
    '[0-9]+ ported' COMPARISON.md
  expect "comparison: api out of scope" "$(api_field out-of-scope)" \
    '[0-9]+ out of scope' COMPARISON.md
  expect "comparison: api deferred" "$(api_field deferred)" \
    '[0-9]+ deferred by an explicit decision' COMPARISON.md
  expect "comparison: api total" "$(echo "$api_out" | grep -oE 'all [0-9]+ declared' | grep -oE '[0-9]+')" \
    'All \*\*[0-9]+\*\* `csp_\*` functions' COMPARISON.md

  # SCOPE.md's "record something today" is the one figure in that file that moves whenever a
  # C test is added, which is most cycles. It read 125 of 144 against a measured 148 of 165.
  # The rest of SCOPE.md's numbers are historical measurements and must NOT track the tree.
  untraced_line=$(python3 ctest/tools/untraced.py 2>/dev/null | grep -oE '[0-9]+/[0-9]+ C tests record something')
  expect "scope: tests that record" "${untraced_line%%/*}" \
    '[0-9]+ of [0-9]+ record something today' SCOPE.md
  scope_total=$(grep -oE '[0-9]+ of [0-9]+ record something today' SCOPE.md | grep -oE '[0-9]+' | sed -n 2p)
  measured_total=$(echo "$untraced_line" | grep -oE '/[0-9]+' | tr -d '/')
  if [ "$scope_total" != "$measured_total" ]; then
    echo "SCOPE.md says scope: C tests total = ${scope_total:-<missing>}, measured $measured_total" >&2
    fail=1
  fi

  [ "$fail" -eq 0 ] && echo "docs/API.md, COMPARISON.md and SCOPE.md match the measurement"
  exit "$fail"
fi
python3 - <<'PY'
import json, collections
c = collections.Counter()
for line in open('corpus/ctest.jsonl'):
    c[json.loads(line)['suite']] += 1
print('  per suite          ' + ', '.join(f'{k} {v}' for k, v in sorted(c.items())))
PY
