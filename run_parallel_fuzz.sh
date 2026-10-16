#!/bin/bash
# Runs multiple instances in parallel. All write to the same -o directory but use different ports and instance names:
# usage: ./run_parallel_fuzz.sh [instances=2] [out-dir=out-par] [default|custom]
N=${1:-2}; OUT=${2:-out-par}; MODE=${3:-default}

export AFLNET_MAX_LEN=4096 AFL_OLD_FORKSERVER=1 AFLNET_SKIP_EARLY_RECV=1 \
  AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1
[ "$MODE" = custom ] && export AFL_CUSTOM_MUTATOR_LIBRARY=$PWD/beanstalkd-fuzzing/mutator/beanstalkd_mutator.so

for i in $(seq 1 "$N"); do
  name=$(printf 'fuzzer%02d' "$i"); port=$((11300 + i))
  ./aflnet/afl-fuzz -S "$name" -i beanstalkd-fuzzing/seeds -o "out/$OUT" -N tcp://127.0.0.1/$port -P BEANSTALKD \
    -D 0 -q 3 -s 3 -E -R -W 10 -t 200 -m none \
    ./beanstalkd-afl/beanstalkd -p $port -l 127.0.0.1 -z 1024 > "$OUT-$name.log" 2>&1 &
  sleep 1   # let each instance pick its own free CPU core
done

echo "started $N instances in $OUT (logs: $OUT-fuzzer*.log), Ctrl-C stops all"
trap 'kill -INT $(jobs -p) 2>/dev/null' INT TERM
wait
