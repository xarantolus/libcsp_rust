#!/usr/bin/env bash
# Every number docs/API.md, COMPARISON.md and AUDIT.md quote, measured rather than
# remembered. Three of them had drifted before this existed -- "449 tests" against 487,
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
  expect() {  # expect <what> <measured> <regex capturing the figure in docs/API.md>
    doc=$(grep -oE "$3" docs/API.md | grep -oE '[0-9]+' | head -1)
    if [ "$doc" != "$2" ]; then
      echo "docs/API.md says $1 = ${doc:-<missing>}, measured $2" >&2
      fail=1
    fi
  }
  expect "rust tests"     "$(echo "$out" | grep -E '^test result' | awk '{s+=$4} END {print s}')" '\*\*[0-9]+ tests\*\* across the crates'
  expect "corpus records" "$(wc -l < corpus/ctest.jsonl)" '\*\*[0-9]+ corpus records\*\*'
  expect "C oracle checks" "$(just ctest 2>&1 | grep -oE 'Checks: [0-9]+' | grep -oE '[0-9]+')" '\*\*[0-9]+ checks\*\*'
  expect "golden vector lines" "$(cat vectors/v1.tsv vectors/v2.tsv | grep -vcE '^#|^$')" '\*\*[0-9]+ golden vector lines\*\*'
  expect "difftest tests" "$(grep -hcE '^[[:space:]]*#\[test\]' difftest/tests/*.rs | paste -sd+ - | python3 -c 'import sys; print(eval(sys.stdin.read()))')" '\*\*[0-9]+ differential tests\*\*'
  [ "$fail" -eq 0 ] && echo "docs/API.md matches the measurement"
  exit "$fail"
fi
python3 - <<'PY'
import json, collections
c = collections.Counter()
for line in open('corpus/ctest.jsonl'):
    c[json.loads(line)['suite']] += 1
print('  per suite          ' + ', '.join(f'{k} {v}' for k, v in sorted(c.items())))
PY
