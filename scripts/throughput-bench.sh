#!/usr/bin/env bash
# Apples-to-apples throughput benchmark: time every recovery tool on the SAME
# machine and the SAME ~100 MB database, so the competitive-landscape doc can
# report comparable wall-clock times instead of the survey's cross-machine ones.
#
# Usage:   scripts/throughput-bench.sh [database.db] [runs]
#   database.db  default: tests/data/paper_fp/large_messages.db (gitignored;
#                regenerate with `python3 tests/data/paper_fp/gen_large.py`)
#   runs         default: 5 (median reported)
#
# Methodology (recorded in docs/competitive-landscape.md "Throughput"):
#   - same machine, same db, warm cache (a discarded priming run precedes timing);
#   - wall-clock seconds via the shell's SECONDS / `date`, median of >=`runs`;
#   - each tool's emitted-record count is reported alongside the time, because a
#     raw time is meaningless without what was produced (undark flat-dumps the
#     whole b-tree; ours recovers deleted-only).
#
# Tools are located the same way the differential harness locates them:
#   sqlite4n6  target/release/sqlite4n6        (cargo build --release -p sqlite4n6)
#   undark     tools/undark                    (UNDARK_BIN override)
#   fqlite     tools/fqlite/run-tap.sh         (FQLITE_JAVA = a JDK w/ JavaFX)
#   bring2lite scripts/run-bring2lite.sh       (may crash on large DBs; see doc)
#
# A tool that errors or cannot complete is reported as "did not complete" with
# its reason; NO time is invented for it.
set -uo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/.." && pwd)"
DB="${1:-$root/tests/data/paper_fp/large_messages.db}"
RUNS="${2:-5}"

if [ ! -f "$DB" ]; then
  echo "throughput-bench: database not found: $DB" >&2
  echo "  regenerate with: python3 tests/data/paper_fp/gen_large.py" >&2
  exit 2
fi

# median of a whitespace-separated list of numbers (sorted, middle element)
median() {
  printf '%s\n' "$@" | sort -n | awk '{a[NR]=$1} END{print (NR%2)? a[(NR+1)/2] : (a[NR/2]+a[NR/2+1])/2}'
}

# Time one command `runs` times after a priming run; print "<median_s> <lines>".
# $1 = label, rest = command (its stdout is piped to wc -l for the record count).
bench() {
  local label="$1"; shift
  local lines times=() t0 t1 n out
  out="$(mktemp)"
  # priming run (warms cache, not timed); also captures the record count
  lines="$("$@" 2>/dev/null | wc -l | tr -d ' ')"
  for ((i=0; i<RUNS; i++)); do
    t0="$(python3 -c 'import time;print(time.monotonic())')"
    # Pipe stdout through `cat`, the same shape the differential harness uses.
    # undark SIGSEGVs at exit when its stdout is a regular file or /dev/null
    # (after emitting all rows) but exits cleanly to a pipe; the pipe also keeps
    # the cost of actually producing output in the measurement.
    { "$@" 2>/dev/null | cat >"$out"; } 2>/dev/null
    t1="$(python3 -c 'import time;print(time.monotonic())')"
    times+=("$(python3 -c "print(f'{$t1-$t0:.3f}')")")
  done
  rm -f "$out"
  n="$(median "${times[@]}")"
  printf '%-34s median=%ss  runs=[%s]  records=%s\n' \
    "$label" "$n" "$(IFS=,; echo "${times[*]}")" "$lines"
}

echo "machine: $(sysctl -n machdep.cpu.brand_string 2>/dev/null || uname -m), $(uname -sr)"
echo "db:      $DB ($(du -h "$DB" | cut -f1))"
echo "runs:    $RUNS (median reported), warm cache"
echo

SQLITE4N6="$root/target/release/sqlite4n6"
UNDARK="${UNDARK_BIN:-$root/tools/undark}"

[ -x "$SQLITE4N6" ] && bench "sqlite4n6 carve --format jsonl" "$SQLITE4N6" carve "$DB" --format jsonl \
  || echo "sqlite4n6: binary missing (cargo build --release -p sqlite4n6)"
[ -x "$UNDARK" ] && bench "undark -i" "$UNDARK" -i "$DB" \
  || echo "undark: binary missing (see docs/corpus-catalog.md F.1)"
if [ -n "${FQLITE_JAVA:-}" ] || command -v java >/dev/null 2>&1; then
  bench "fqlite (run-tap.sh)" bash "$root/tools/fqlite/run-tap.sh" "$DB"
else
  echo "fqlite: no java on PATH and FQLITE_JAVA unset"
fi
# bring2lite is timed too, but watch its record count: a 0 with a nonzero time
# means it ran-but-recovered-nothing (it crashes mid-freelist on large DBs).
bench "bring2lite (run-bring2lite.sh)" bash "$here/run-bring2lite.sh" "$DB"
