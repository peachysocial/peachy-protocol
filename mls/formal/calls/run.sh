#!/bin/sh
# SPDX-License-Identifier: MIT
# Run every call model through ProVerif and compare each verdict with
# expected.txt. It exits non-zero when a verdict moves, when a model fails to
# parse, or when a model prints no verdicts. See README.md.
#
#   mls/formal/calls/run.sh            # check against expected.txt
#   mls/formal/calls/run.sh --update   # rewrite expected.txt (review the diff!)
#
# PROVERIF names the binary; the default is `proverif` on PATH.

set -eu
here=$(cd "$(dirname "$0")" && pwd)
logs="$here/../../../build/formal/calls"   # build output lives under the repository's build/
mkdir -p "$logs"
pv=${PROVERIF:-proverif}
command -v "$pv" >/dev/null 2>&1 || { echo "run.sh: no ProVerif binary ('$pv'); see README.md" >&2; exit 2; }

models="server_sfu post_removal forward_secrecy forward_secrecy_control pcs_update_by_compromised pcs_update_by_other non_participant"
out=$(mktemp)
trap 'rm -f "$out"' EXIT

for m in $models; do
  log="$logs/$m.log"
  "$pv" -lib "$here/calls" "$here/$m.pv" >"$log" 2>&1 || { echo "run.sh: $m: ProVerif failed:" >&2; tail -5 "$log" >&2; exit 1; }
  n=$(grep -c '^RESULT' "$log" || true)
  [ "$n" -gt 0 ] || { echo "run.sh: $m: no verdicts" >&2; exit 1; }
  # Normalize ProVerif's generated variable suffixes (es_6 -> es) so a
  # ProVerif release that renumbers them does not read as a moved verdict.
  grep '^RESULT' "$log" | sed -E 's/([A-Za-z])_[0-9]+/\1/g; s/^/'"$m"': /' >>"$out"
done

if [ "${1:-}" = "--update" ]; then
  cp "$out" "$here/expected.txt"
  echo "run.sh: wrote expected.txt"
  exit 0
fi

if diff -u "$here/expected.txt" "$out"; then
  echo "run.sh: $(wc -l <"$out" | tr -d ' ') verdicts, all as expected"
else
  echo "run.sh: a verdict moved (diff above: - expected, + actual)" >&2
  exit 1
fi
