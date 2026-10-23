#!/bin/bash
# Per-execution coverage of inputs that AFLNet marked as variable (unstable).
#
# The fuzzing build of beanstalkd is built a second time with LLVM source-based coverage. Every
# server process writes its own profile (LLVM_PROFILE_FILE=%p; %p is expanded in the fork server,
# so all executions of one afl-fuzz run go to one file, cut apart by analyze.py). Each input is
# replayed by the real afl-fuzz, with its own timing, for SECS seconds:
#   MODE=calib (default): AFL's calibration (dry run) of the input, repeated. Every repetition
#             is a new afl-fuzz (its own profile file) and runs the exact stored input at least
#             8 times before fuzzing starts; analyze.py --first 8 keeps only those.
#   MODE=stub: fuzzing with the mutation stub from ../verify (identity_mutator.so,
#             AFL_CUSTOM_MUTATOR_PROB=100). More executions, but AFLNet rebuilds the session from
#             the regions around the mutated one, and for some inputs that repeats parts of it:
#             the input is then not always the same.
#
# usage: beanstalkd-fuzzing/stability/measure.sh <out dir with the profiles> [SECS] [input...]
#   default inputs: every queue entry in out/cmp-*-new/queue/.state/variable_behavior
#   environment: FUZZ_BIN (default: the coverage build), PARALLEL=2 runs two inputs at once,
#                as in the comparison runs, MODE (see above)
set -eu
R=$(cd "$(dirname "$0")/../.." && pwd)
V=$R/beanstalkd-fuzzing/verify
B=$R/out/stability/build
OUT=${1:?out dir}; SECS=${2:-2}; shift 2 || shift $#
INPUTS=("$@")
if [ ${#INPUTS[@]} -eq 0 ]; then
  for run in cmp-default-new cmp-custom-new; do
    for f in "$R"/out/$run/queue/.state/variable_behavior/*; do
      INPUTS+=("$R/out/$run/queue/$(basename "$f")")
    done
  done
fi

# coverage build of the fuzzing target (same sources and flags as the fuzzing build)
if [ ! -x "$B/beanstalkd" ]; then
  rm -rf "$B"; mkdir -p "$B"
  (cd "$R/beanstalkd-afl" && git ls-files -z | xargs -0 tar -c) | tar -x -C "$B"
  make -C "$B" CC="$R/AFLplusplus/afl-clang-fast" USE_SYSTEMD=no -j4 \
    CFLAGS="-DFUZZ_EXIT_ON_CLOSE -DFUZZ_DETERMINISTIC -fprofile-instr-generate -fcoverage-mapping" \
    LDFLAGS="-fprofile-instr-generate" >/dev/null 2>&1
fi
FUZZ_BIN=${FUZZ_BIN:-$B/beanstalkd}
cc -O2 -shared -fPIC -o "$V/identity_mutator.so" "$V/identity_mutator.c"

aflrun() {  # aflrun <in dir> <out dir> <port> <profile dir> [VAR=value...]: afl-fuzz in the background
  local in=$1 o=$2 port=$3 prof=$4; shift 4
  (cd "$R" && exec env "$@" AFLNET_MAX_LEN=4096 AFL_OLD_FORKSERVER=1 AFLNET_SKIP_EARLY_RECV=1 \
     AFL_NO_UI=1 AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1 \
     LLVM_PROFILE_FILE="$prof/%p.profraw" \
     ./aflnet/afl-fuzz -d -i "$in" -o "$o" -N tcp://127.0.0.1/$port -P BEANSTALKD -D 0 -q 3 -s 3 \
       -E -R -W 10 -t 200 -m none "$FUZZ_BIN" -p $port -l 127.0.0.1 -z 1024 > "$o.log" 2>&1) &
  AFLPID=$!
}

one() {  # one <input> <port>
  local in=$1 port=$2 name w end k=0
  name=$(basename "$(dirname "$(dirname "$in")")")_$(basename "$in" | cut -d, -f1)
  w=$OUT/$name; rm -rf "$w"; mkdir -p "$w/in" "$w/prof"
  cp "$in" "$w/in/"
  if [ "${MODE:-calib}" = calib ]; then
    end=$((SECONDS + SECS))
    while [ $SECONDS -lt $end ]; do
      k=$((k + 1)); rm -rf "$w/out"
      aflrun "$w/in" "$w/out" "$port" "$w/prof"
      for _ in $(seq 500); do [ -f "$w/out/fuzzer_stats" ] && break; sleep 0.02; done
      kill -INT $AFLPID 2>/dev/null; wait $AFLPID 2>/dev/null || true
    done
    echo "$name: $k calibrations"
  else
    aflrun "$w/in" "$w/out" "$port" "$w/prof" \
      AFL_CUSTOM_MUTATOR_LIBRARY="$V/identity_mutator.so" AFL_CUSTOM_MUTATOR_PROB=100
    sleep "$SECS"; kill -INT $AFLPID 2>/dev/null; wait $AFLPID 2>/dev/null || true
    echo "$name: fuzzed with the stub for $SECS s"
  fi
}

mkdir -p "$OUT"
i=0
for in in "${INPUTS[@]}"; do
  one "$in" $((12900 + i % 2)) &
  i=$((i + 1))
  if [ "${PARALLEL:-1}" -lt 2 ] || [ $((i % 2)) -eq 0 ]; then wait; fi
done
wait
