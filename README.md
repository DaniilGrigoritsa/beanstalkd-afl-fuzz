# Fuzzing beanstalkd with AFLNet

- **Target:** [beanstalkd](https://github.com/beanstalkd/beanstalkd), a work-queue server with a
  stateful text protocol over TCP. Protocol: `beanstalkd-afl/doc/protocol.txt`.

Tested on Ubuntu 22.04 (aarch64, UTM VM on macOS, 4 vCPUs).
Base commits: AFLNet `96032f8`, AFL++ `dbaf1191`, beanstalkd `25085c5`.

## Layout

beanstalkd-fuzzing/
  patches/aflnet-beanstalkd.patch   AFLNet patch
  patches/beanstalkd-fuzz.patch     beanstalkd protocol patch
  mutator/beanstalkd_mutator.c      structure-aware custom mutator
  gen_seeds.py                      generates the testing scenarios
  seeds/                            9 scenarios = initial client sessions
run_fuzz.sh                         run fuzzing with one instance, default or custom mutations
run_parallel_fuzz.sh                run fuzzing in N instances in parallel
run_mutation_comparison.sh          run fuzzing for 30 min default vs custom mutations in parallel
run_coverage.sh                     replays a corpus on the gcov build, generates LCOV HTML report
out/                                fuzzer output directories
cov/                                LCOV reports

## 1. Build

```bash
sudo apt update
sudo apt install -y build-essential clang llvm libgraphviz-dev libcap-dev graphviz

# AFL++
git clone https://github.com/AFLplusplus/AFLplusplus.git
make -C AFLplusplus source-only
export AFLPP=$PWD/AFLplusplus

# AFLNet + the patch
git clone https://github.com/aflnet/aflnet.git
git -C aflnet apply ../beanstalkd-fuzzing/patches/aflnet-beanstalkd.patch
AFL_NO_X86=1 make -C aflnet clean all

# beanstalkd, fuzzing build
git clone https://github.com/beanstalkd/beanstalkd.git
cp -r beanstalkd beanstalkd-afl
git -C beanstalkd-afl apply ../beanstalkd-fuzzing/patches/beanstalkd-fuzz.patch
make -C beanstalkd-afl clean
CC=$AFLPP/afl-clang-fast CFLAGS="-DFUZZ_EXIT_ON_CLOSE -DFUZZ_DETERMINISTIC" USE_SYSTEMD=no make -C beanstalkd-afl

# custom mutator (loaded into afl-fuzz)
cc -O2 -shared -fPIC -o beanstalkd-fuzzing/mutator/beanstalkd_mutator.so beanstalkd-fuzzing/mutator/beanstalkd_mutator.c

# lcov for the coverage report
git clone --depth 1 -b v1.16 https://github.com/linux-test-project/lcov.git tools/lcov-1.16
```

The gcov build of beanstalkd (`beanstalkd-gcov/`) is created by `run_coverage.sh`.

### The patches

**beanstalkd** (`beanstalkd-fuzz.patch`, only active in the fuzzing/coverage builds):
- `main.c`: deferred fork server (`__AFL_INIT()`) after the listening socket is created, so every
  forked server is ready at once and start-up code is not re-run.
- `prot.c`, `FUZZ_EXIT_ON_CLOSE`: the server exits when the client disconnects. One test case = one
  session; no SIGTERM from the fuzzer at a random moment (main cause of the original low stability).
- `prot.c`, `FUZZ_DETERMINISTIC`: `pause-tube <tube> 0` pauses for 1 ns, below the 1 µs clock
  resolution, so the outcome depended on the clock ticking. The fuzzing build always takes the
  "already expired" outcome.
- `prot.c`, `FUZZ_DETERMINISTIC`: when a waiting `reserve-with-timeout` ends with `DEADLINE_SOON`,
  its timeout is dropped (as the `TIMED_OUT` branch already does). Left at 0, it armed an empty
  timer for "now" that fired or not depending on the clock, so `conn_timeout()`/`prottick()`
  coverage changed between runs. With it, calibration stability is 100% on both 30-minute
  corpora (was ~98.3–98.7%). Server replies are unchanged. Details: `beanstalkd-fuzzing/stability/`.

**AFLNet** (`aflnet-beanstalkd.patch`):
- `-P BEANSTALKD`: request splitter (a `put` keeps its job body) and reply-code parser (states).
- Reply model: counts the replies the server owes for the session (emulating beanstalkd's
  224-byte line buffer), so AFLNet returns as soon as they arrived and does not wait for messages
  that get no reply.
- Late replies: when an expected reply has not come within `-W` msec, AFLNet reads the server's
  process state (`/proc/<pid>/stat`) instead of guessing. It keeps waiting while the server is
  running (only slow, e.g. on a loaded machine) and stops once it is asleep (blocked, e.g. in
  `reserve`). Before, a slow reply cut the session short in single runs only; one such run in
  calibration marked hundreds of bitmap bytes as variable (stability 98% → 50–80%).
  `fuzzer_stats`: `late_replies` (came after `-W`), `stalled_sessions` (server blocked),
  `cut_sessions` (stopped waiting while the server was not asleep: should stay 0).
  `AFLNET_NO_PROC_STATE=1` restores the old behaviour (the counters still work).
- `TCP_NODELAY` on the client socket (Nagle held back messages for ~40 ms).
- Removed per-message `usleep()`s and the busy wait after each execution; `AFLNET_SKIP_EARLY_RECV`
  (no greeting to wait for); `AFLNET_MAX_LEN` (skip test cases larger than N bytes).
- Custom mutator support: `AFL_CUSTOM_MUTATOR_LIBRARY` (AFL++ API: `afl_custom_init/fuzz/deinit`),
  used in `AFL_CUSTOM_MUTATOR_PROB`% (default 50) of havoc iterations; `custom_execs` and
  `custom_finds` in `fuzzer_stats`.
- `aflnet-replay`: beanstalkd support, crash fix. `AFLNET_DEBUG_DIR`: debug dump of stalled sessions.

Result for a single instance (original setup → now): ~24 → ~1 200–2 700 execs/s, stability 56% → ~98–100%.

## 2. Scenarios (seeds)

```bash
python3 beanstalkd-fuzzing/gen_seeds.py beanstalkd-fuzzing/seeds
```

Each seed is one client session; together they use every command except the blocking `reserve`:

|                   Seed |                                                             Scenario |
|------------------------|----------------------------------------------------------------------|
| `01_lifecycle`         | put → reserve → delete                                               |
| `02_release_bury_kick` | priorities, touch, release, bury, kick, reserve-job                  |
| `03_tubes`             | use / watch / ignore, pause-tube, list-tubes*                        |
| `04_peek_stats`        | peek-*, bury, kick-job, stats-job / stats-tube / stats               |
| `05_errors`            | unknown command, bad formats, missing CRLF, too long tube name, quit |
| `06_delayed_kick`      | delayed jobs, kick of delayed jobs                                   |
| `07_multi_tube`        | several tubes, pause, NOT_IGNORED, bury + kick in another tube       |
| `08_bodies`            | empty / binary bodies, `\r\n` inside a body, JOB_TOO_BIG             |
| `09_deadline`          | TTR 0 → 1 s, DEADLINE_SOON                                           |

## 3. Custom mutator

`beanstalkd_mutator.c` splits the input into commands (a `put` together with its body) and
stacks 1–4 grammar-aware mutations: insert / replace a generated well-formed command, delete /
duplicate / swap commands, take a command from another seed, change an argument to an interesting
value (numbers, existing job ids, 200/201-char or invalid tube names), change the verb, change a job
body and keep or break the `<bytes>` field, insert a job-state scenario
(`put` → `reserve` → `bury`/`release`/`touch`/`delete`/`kick-job`).

## 4. Run fuzzing

```bash
./run_fuzz.sh                         # single instance, default mutations -> out/out-single
./run_fuzz.sh custom                  # single instance + custom mutator  -> out/out-custom
./run_parallel_fuzz.sh 2 out-par      # 2 instances (-S fuzzer01, fuzzer02; ports 11301, 11302) -> out/out-par
./run_parallel_fuzz.sh 2 out-par-custom custom
```

All scripts start beanstalkd with `-z 1024` (max job size 1024 bytes instead of 65535), so a
too-big job and its body fit into `AFLNET_MAX_LEN=4096` and the `JOB_TOO_BIG` path is reachable.
The AFLNet reply model (`BSD_MAX_JOB_SIZE` in `aflnet.c`) and the custom mutator (`MAX_JOB_SIZE`)
assume the same limit: change all three together.

## Run fuzzing with custom mutations and without for 30 minutes. Compare the outputs

Both runs at the same time (one CPU core each, ports 11301/11302), single instance, same seeds
(`beanstalkd-fuzzing/seeds`, 9 scenarios) and options, 30 minutes:

```bash
./run_mutation_comparison.sh
./run_coverage.sh out/cmp-default-new-1 cov/cmp-default
./run_coverage.sh out/cmp-custom-new-1  cov/cmp-custom
```

Results (one 30-minute run per mode; runs `out/cmp-*-new-1`, made with the stability fix in
`beanstalkd-fuzz.patch`, see `beanstalkd-fuzzing/stability/`):

| Metric                                 | Seeds only (no fuzzing) |     Default mutations | Default + custom mutator |
|----------------------------------------|------------------------:|----------------------:|-------------------------:|
| Executions                             |                       — |             2 259 469 |                1 729 535 |
| Average speed, execs/s                 |                       — |                 1 255 |                      961 |
| Paths in queue (`paths_total`)         |                       9 |                 1 020 |           1 174 (+15.1%) |
| Paths found by custom mutations        |                       — |                     — |       453 (of 1 165 new) |
| Executions with custom mutations       |                       — |                     — |        1 137 840 (65.8%) |
| Map coverage after 1 / 10 / 30 min     |                       — | 0.95% / 0.96% / 0.97% |    0.96% / 0.97% / 0.97% |
| Paths after 1 / 10 / 30 min            |                       — |     745 / 937 / 1 020 |      894 / 1 113 / 1 174 |
| Stability                              |                       — |                97.78% |                   98.90% |
| Sessions cut short (`cut_sessions`)    |                       — |                     0 |                        0 |
| Crashes / hangs                        |                       — |                 0 / 0 |                    0 / 0 |
| Lines (all files)                      |    54.3% (1342 of 2471) |  61.9% (1529 of 2471) |     61.9% (1529 of 2471) |
| Functions (all files)                  |      72.9% (132 of 181) |    75.7% (137 of 181) |       75.7% (137 of 181) |
| Branches (all files)                   |     46.0% (589 of 1281) |   57.5% (736 of 1281) |      57.5% (736 of 1281) |
| Lines / branches without binlog code\* |           68.0% / 57.1% |         77.6% / 71.4% |            77.6% / 71.4% |
| `prot.c` lines / branches              |           70.5% / 61.6% |         84.9% / 80.7% |            84.9% / 80.7% |

## 5. Coverage (LCOV HTML)

```bash
./run_coverage.sh out/out-single cov/cov-single
```

The script builds `beanstalkd-gcov/` once (copy of the patched `beanstalkd-afl`), for every test case in
`replayable-queue/` starts a fresh server, replays the session with `aflnet-replay` and lets the
server exit (that writes the `.gcda` counters). At the end `lcov` + `genhtml` create
`cov/<name>/html/index.html` and `summary.txt`.

\* `file.c` and `walg.c` (binlog, `-b <dir>`) are not used while fuzzing; most of the rest of the
uncovered code is start-up / command-line handling (`main.c`, `net.c`, `util.c`). The protocol
code `prot.c` is covered to ~85% lines / ~81% branches.

## 6. Sanitizer builds and replay of the 30-minute sessions

```bash
./build_targets.sh
```

The whole corpus of both 30-minute runs (`out/cmp-*-new-1`) was replayed against both builds
(made with the current `beanstalkd-fuzz.patch`, including the stability fix), each session on a
fresh server. The loops print every abnormal exit and, at the end, the number of sanitizer
reports in the servers' stderr (both 0):

```bash
# ASan + UBSan
( for f in out/cmp-*-new-1/replayable-queue/*; do targets/asan-ubsan/beanstalkd -p 11500 -l 127.0.0.1 -z 1024 2>> out/asan-ubsan.log & sleep 0.05; ./aflnet/aflnet-replay "$f" BEANSTALKD 11500 1 > /dev/null 2>&1; wait $! || echo "abnormal exit: $f"; done; grep -cE 'ERROR: AddressSanitizer|runtime error' out/asan-ubsan.log )

# MSan
( for f in out/cmp-*-new-1/replayable-queue/*; do targets/msan/beanstalkd -p 11500 -l 127.0.0.1 -z 1024 2>> out/msan.log & sleep 0.05; ./aflnet/aflnet-replay "$f" BEANSTALKD 11500 1 > /dev/null 2>&1; wait $! || echo "abnormal exit: $f"; done; grep -cE 'MemorySanitizer' out/msan.log )
```

|        Build | Sessions replayed | Sanitizer reports / abnormal exits |
|--------------|-------------------|------------------------------------|
| ASan + UBSan |             2 194 |                                  0 |
| MSan         |             2 194 |                                  0 |
