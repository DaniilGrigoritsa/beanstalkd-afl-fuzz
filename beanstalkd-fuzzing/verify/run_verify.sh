#!/bin/bash
# Checks that the fuzzing setup (patched AFLNet + patched beanstalkd) does not cut sessions short.
# For every seed:
#   reference: the unpatched beanstalkd (commit 25085c5) + a plain client (ref_client.py);
#   fuzz:      the fuzzer with mutations replaced by a stub (identity_mutator.so) replays the seed
#              unchanged for SECS seconds against the patched fuzzing build.
# Both servers are built with coverage. Traffic is recorded with dumpcap (Wireshark).
# compare.py then checks every fuzzer session against the seed and the reference, and
# compares the coverage line by line.
#
# usage: beanstalkd-fuzzing/verify/run_verify.sh [SECS per seed, default 3] [seed...]
# output: beanstalkd-fuzzing/verify/results/: report.txt, <seed>.ref.pcap (reference session),
#         <seed>.fuzz-sample.pcap (first 200 packets of the fuzzer's traffic). Builds, the full
#         fuzzer pcaps and the gcov files go to out/verify/.
set -eu
R=$(cd "$(dirname "$0")/../.." && pwd)
V=$R/beanstalkd-fuzzing/verify
B=$R/out/verify/build
W=$R/out/verify/work
RES=$V/results
SECS=${1:-3}; shift || true
SEEDS=("$@"); [ ${#SEEDS[@]} -gt 0 ] || SEEDS=("$R"/beanstalkd-fuzzing/seeds/*.raw)
REF_PORT=11950; FUZZ_PORT=11951; export REF_PORT FUZZ_PORT

# ---- builds: both from git, both with clang coverage instrumentation
if [ ! -x "$B/ref/beanstalkd" ] || [ ! -x "$B/fuzz/beanstalkd" ]; then
  rm -rf "$B"; mkdir -p "$B/ref" "$B/fuzz"
  git -C "$R/beanstalkd-afl" archive 25085c5 | tar -x -C "$B/ref"                  # original
  (cd "$R/beanstalkd-afl" && git ls-files -z | xargs -0 tar -c) | tar -x -C "$B/fuzz"  # + patch
  make -C "$B/ref" CC=clang CFLAGS="-O0 --coverage" LDFLAGS="--coverage" USE_SYSTEMD=no -j4 >/dev/null
  make -C "$B/fuzz" CC="$R/AFLplusplus/afl-clang-fast" USE_SYSTEMD=no -j4 \
    CFLAGS="-DFUZZ_EXIT_ON_CLOSE -DFUZZ_DETERMINISTIC -O0 --coverage" LDFLAGS="--coverage" >/dev/null 2>&1
fi
cc -O2 -shared -fPIC -o "$V/identity_mutator.so" "$V/identity_mutator.c"
cc -O2 -shared -fPIC -o "$V/exit_on_sigterm.so" "$V/exit_on_sigterm.c"

capture() {  # capture <port> <file>: starts dumpcap in the background, sets CAP
  dumpcap -q -P -i lo -f "tcp port $1" -w "$2" >/dev/null 2>&1 & CAP=$!
  for _ in $(seq 100); do [ -s "$2" ] && break; sleep 0.05; done
  sleep 0.3
}
stop_capture() { sleep 0.3; kill -INT "$CAP"; wait "$CAP" 2>/dev/null || true; }
gcov_into() {  # gcov_into <build dir> <dest dir>
  mkdir -p "$2"; (cd "$1" && llvm-cov gcov ./*.c >/dev/null 2>&1; mv ./*.gcov "$2"/)
}
wait_listen() { until ss -ltn "sport = :$1" | grep -q LISTEN; do sleep 0.01; done; }

mkdir -p "$RES" "$W"
: > "$RES/report.txt"
{
  echo "Verification run $(date -u +%Y-%m-%dT%H:%MZ), $SECS s of fuzzing per seed"
  echo "reference: beanstalkd 25085c5 (unpatched) + ref_client.py"
  echo "fuzz:      aflnet (patched) + identity mutator + beanstalkd-afl fuzzing build"
  echo
} >> "$RES/report.txt"
status=0
for seed in "${SEEDS[@]}"; do
  name=$(basename "$seed" .raw); w=$W/$name; rm -rf "$w"; mkdir -p "$w/in"
  cp "$seed" "$w/in/"

  # reference
  rm -f "$B"/ref/*.gcda
  capture $REF_PORT "$RES/$name.ref.pcap"
  LD_PRELOAD="$V/exit_on_sigterm.so" "$B/ref/beanstalkd" -p $REF_PORT -l 127.0.0.1 -z 1024 & srv=$!
  wait_listen $REF_PORT
  python3 -I "$V/ref_client.py" "$seed" $REF_PORT
  kill -TERM $srv; wait $srv 2>/dev/null || true
  stop_capture
  gcov_into "$B/ref" "$w/gcov-ref"

  # fuzzer, mutations stubbed
  rm -f "$B"/fuzz/*.gcda
  capture $FUZZ_PORT "$w/fuzz.pcap"
  (cd "$R" && env AFLNET_MAX_LEN=4096 AFL_OLD_FORKSERVER=1 AFLNET_SKIP_EARLY_RECV=1 AFL_NO_UI=1 \
     AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 \
     AFL_CUSTOM_MUTATOR_LIBRARY="$V/identity_mutator.so" AFL_CUSTOM_MUTATOR_PROB=100 \
     timeout -s INT "$SECS" ./aflnet/afl-fuzz -d -i "$w/in" -o "$w/out" -N tcp://127.0.0.1/$FUZZ_PORT \
       -P BEANSTALKD -D 0 -q 3 -s 3 -E -R -W 10 -t 200 -m none \
       "$B/fuzz/beanstalkd" -p $FUZZ_PORT -l 127.0.0.1 -z 1024 > "$w/afl.log" 2>&1) || true
  stop_capture
  gcov_into "$B/fuzz" "$w/gcov-fuzz"

  python3 -I "$V/compare.py" "$seed" "$RES/$name.ref.pcap" "$w/fuzz.pcap" "$w/gcov-ref" "$w/gcov-fuzz" \
    "$w/out/fuzzer_stats" >> "$RES/report.txt" || status=1
  editcap -r "$w/fuzz.pcap" "$RES/$name.fuzz-sample.pcap" 1-200 >/dev/null  # first ~10 sessions
  echo >> "$RES/report.txt"
done
cat "$RES/report.txt"
exit $status
