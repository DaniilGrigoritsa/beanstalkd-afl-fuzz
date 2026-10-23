export AFLNET_MAX_LEN=4096 AFL_OLD_FORKSERVER=1 AFLNET_SKIP_EARLY_RECV=1 \
  AFL_I_DONT_CARE_ABOUT_MISSING_CRASHES=1 AFL_SKIP_CPUFREQ=1

# default mutations, port 11301
setsid nohup timeout -s INT 1800 ./aflnet/afl-fuzz -d -i beanstalkd-fuzzing/seeds -o out/cmp-default-new-1 \
  -N tcp://127.0.0.1/11301 -P BEANSTALKD -D 0 -q 3 -s 3 -E -R -W 10 -t 200 -m none \
  ./beanstalkd-afl/beanstalkd -p 11301 -l 127.0.0.1 -z 1024 > out/cmp-default.log 2>&1 < /dev/null &

sleep 2   # so the two instances pick different CPU cores

# custom mutator, port 11302
AFL_CUSTOM_MUTATOR_LIBRARY=$PWD/beanstalkd-fuzzing/mutator/beanstalkd_mutator.so \
setsid nohup timeout -s INT 1800 ./aflnet/afl-fuzz -d -i beanstalkd-fuzzing/seeds -o out/cmp-custom-new-1 \
  -N tcp://127.0.0.1/11302 -P BEANSTALKD -D 0 -q 3 -s 3 -E -R -W 10 -t 200 -m none \
  ./beanstalkd-afl/beanstalkd -p 11302 -l 127.0.0.1 -z 1024 > out/cmp-custom.log 2>&1 < /dev/null &
