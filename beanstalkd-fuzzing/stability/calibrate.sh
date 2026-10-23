#!/bin/bash
# AFL's own stability of whole corpora, measured by its calibration (dry run): every queue entry is
# run 8 times (40 if it varies). The two queues are calibrated at the same time, as the
# comparison runs fuzz at the same time.
#
# usage: beanstalkd-fuzzing/stability/calibrate.sh <target binary> <work dir> [rounds=3]
#   RUNS="cmp-default-new cmp-custom-new": the two fuzzer output dirs (under out/) to calibrate
#   AFL_FUZZ: the afl-fuzz binary (default ./aflnet/afl-fuzz)
# prints one line per round: stability and variable paths of both corpora
set -eu
R=$(cd "$(dirname "$0")/../.." && pwd)
BIN=$(realpath "$1"); W=$2; ROUNDS=${3:-3}
read -r RUN1 RUN2 <<< "${RUNS:-cmp-default-new cmp-custom-new}"
mkdir -p "$W"
for run in "$RUN1" "$RUN2"; do       # queue entries, names shortened to id:N
  if [ ! -d "$W/in-$run" ]; then
    mkdir -p "$W/in-$run"
    for f in "$R"/out/$run/queue/id*; do b=$(basename "$f"); cp "$f" "$W/in-$run/${b%%,*}"; done
  fi
done

calib() {  # calib <input dir> <out dir> <port>
  rm -rf "$2"
  (cd "$R" && exec env AFLNET_MAX_LEN=4096 AFL_OLD_FORKSERVER=1 AFLNET_SKIP_EARLY_RECV=1 AFL_NO_UI=1 \
     AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 \
     "${AFL_FUZZ:-./aflnet/afl-fuzz}" -d -i "$1" -o "$2" -N tcp://127.0.0.1/$3 -P BEANSTALKD -D 0 -q 3 -s 3 -E -R -W 10 \
       -t 200 -m none "$BIN" -p $3 -l 127.0.0.1 -z 1024 > "$2.log" 2>&1) & local pid=$!
  for _ in $(seq 1200); do [ -f "$2/fuzzer_stats" ] && break; sleep 0.1; done   # dry run done
  kill -INT $pid 2>/dev/null; wait $pid 2>/dev/null || true
}
stat() { grep -E "^(stability|variable_paths)" "$1/fuzzer_stats" | tr -s ' ' | sed 's/ : /=/' | tr '\n' ' '; }

for r in $(seq "$ROUNDS"); do
  calib "$W/in-$RUN1" "$W/d$r" 13001 &
  calib "$W/in-$RUN2" "$W/c$r" 13002
  wait
  echo "round $r: $RUN1: $(stat "$W/d$r")| $RUN2: $(stat "$W/c$r")"
done
