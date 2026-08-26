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
python3 - <<'PY'
import json, collections
c = collections.Counter()
for line in open('corpus/ctest.jsonl'):
    c[json.loads(line)['suite']] += 1
print('  per suite          ' + ', '.join(f'{k} {v}' for k, v in sorted(c.items())))
PY
