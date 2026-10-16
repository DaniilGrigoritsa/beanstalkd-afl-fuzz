#!/bin/bash
# Runs one AFLNet instance against beanstalkd.
# usage: ./run_fuzz.sh [default|custom] [out-dir]
MODE=${1:-default}

export AFLNET_MAX_LEN=4096 AFL_OLD_FORKSERVER=1 AFLNET_SKIP_EARLY_RECV=1 \
  AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1

if [ "$MODE" = custom ]; then
  # In each havoc iteration there's a 50% chance the custom structure-aware mutation is used
  # instead of AFLNet's stacked byte-level changes. Change that share with AFL_CUSTOM_MUTATOR_PROB=<0..100>.
  export AFL_CUSTOM_MUTATOR_LIBRARY=$PWD/beanstalkd-fuzzing/mutator/beanstalkd_mutator.so
  OUT=${2:-out/out-custom}
elif [ "$MODE" = default ]; then
  unset AFL_CUSTOM_MUTATOR_LIBRARY
  OUT=${2:-out/out-single}
else
  echo "usage: $0 [default|custom] [out-dir]" >&2
  exit 1
fi

./aflnet/afl-fuzz -d -i beanstalkd-fuzzing/seeds -o "$OUT" -N tcp://127.0.0.1/11300 -P BEANSTALKD \
  -D 0 -q 3 -s 3 -E -R -W 10 -t 200 -m none \
  ./beanstalkd-afl/beanstalkd -p 11300 -l 127.0.0.1
