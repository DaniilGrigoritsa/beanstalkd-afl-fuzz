#!/bin/bash
# usage: ./run_coverage.sh <afl-out-dir> <report-dir>
#   e.g. ./run_coverage.sh out/out-single cov/cov-single
#        ./run_coverage.sh out/out-par    cov/cov-par
set -eu
OUT=$1; REPORT=$2; PORT=11400
srv=
trap 'kill $srv 2>/dev/null; echo "interrupted"; exit 130' INT TERM
LCOV=tools/lcov-1.16/bin/lcov; GENHTML=tools/lcov-1.16/bin/genhtml

# 1. gcov build of the same (patched) sources the fuzzer used
if [ ! -x beanstalkd-gcov/beanstalkd ] || [ beanstalkd-afl/prot.c -nt beanstalkd-gcov/beanstalkd ]; then
  rm -rf beanstalkd-gcov && cp -r beanstalkd-afl beanstalkd-gcov
  make -C beanstalkd-gcov clean >/dev/null
  make -C beanstalkd-gcov CC=gcc CFLAGS="-DFUZZ_EXIT_ON_CLOSE -DFUZZ_DETERMINISTIC -O0 --coverage" LDFLAGS="--coverage" USE_SYSTEMD=no -j4 >/dev/null
fi

# 2. reset counters, then replay every test case the fuzzer kept
$LCOV --zerocounters --directory beanstalkd-gcov -q
mapfile -t CASES < <(find "$OUT" -path '*replayable-queue/*' -type f | sort)
echo "replaying ${#CASES[@]} test cases from $OUT"
for f in "${CASES[@]}"; do
  ./beanstalkd-gcov/beanstalkd -p $PORT -l 127.0.0.1 -z 1024 >/dev/null 2>&1 & srv=$!
  until ss -ltn "sport = :$PORT" | grep -q LISTEN; do sleep 0.01; done
  timeout 10 ./aflnet/aflnet-replay "$f" BEANSTALKD $PORT 1 >/dev/null 2>&1 || true
  # the server exits by itself when the client disconnects (that writes the .gcda files)
  for _ in $(seq 200); do kill -0 $srv 2>/dev/null || break; sleep 0.01; done
  kill $srv 2>/dev/null || true; wait $srv 2>/dev/null || true
done

# 3. LCOV tracefile + HTML report: line, function and branch coverage
mkdir -p "$REPORT"
$LCOV --capture --directory beanstalkd-gcov --rc lcov_branch_coverage=1 -o "$REPORT/coverage.info" -q
$LCOV --remove "$REPORT/coverage.info" '*/test*.c' '/usr/*' --rc lcov_branch_coverage=1 -o "$REPORT/coverage.info" -q
$GENHTML "$REPORT/coverage.info" --branch-coverage --title "beanstalkd: $OUT" -o "$REPORT/html" -q
$LCOV --summary "$REPORT/coverage.info" --rc lcov_branch_coverage=1 2>&1 | tee "$REPORT/summary.txt"
echo "report: $REPORT/html/index.html"
