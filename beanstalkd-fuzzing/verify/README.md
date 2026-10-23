# Verification: the patches do not cut sessions short

Check: the fuzzer replays each seed **unchanged** (mutations replaced by a stub). Its traffic and
the server's coverage are compared with a **reference**: the unpatched server and a plain client.

```bash
beanstalkd-fuzzing/verify/run_verify.sh        # all 9 seeds, 3 s of fuzzing each, ~1 min
```

## Setup

| | Reference | Checked setup |
|---|---|---|
| Server | beanstalkd `25085c5`, **no patches** (`git archive`), `clang --coverage` | `beanstalkd-afl` (+ `beanstalkd-fuzz.patch`), `afl-clang-fast`, `-DFUZZ_EXIT_ON_CLOSE -DFUZZ_DETERMINISTIC`, `--coverage` |
| Client | `ref_client.py`: splits the seed by the protocol's framing, sends one message at a time, after each waits until the server is silent for 20 ms, closes at the end | patched `aflnet/afl-fuzz` with the run scripts' options; `identity_mutator.so` with `AFL_CUSTOM_MUTATOR_PROB=100` returns every input unchanged |
| Runs | 1 session per seed | 3 s per seed: 7 000–11 500 sessions |

- Traffic: `dumpcap` (Wireshark) on `lo`, one capture per run.
- Coverage: `llvm-cov gcov`; lines are matched by their text, since the patch shifts line
  numbers in `prot.c`. The fuzz build's counts are compared with N × the reference counts, N being
  the number of server processes (one per session).
- The original server saves coverage only on a normal exit, but dies on SIGTERM; the preloaded
  `exit_on_sigterm.so` turns SIGTERM into `exit(0)`. The server code is not changed.

## Checks per seed (`compare.py`)

Every fuzzer session in the capture must:
1. send exactly the seed bytes (also proves the mutation stub works);
2. receive the same reply stream as the reference session (only `stats` fields that depend on
   time or the process are masked: pid, uptime, rusage, id, version, host, age, time-left);
3. be closed by the client only after the server's last reply.

The coverage of the request-handling code must equal N × the reference.

## Result (`results/report.txt`, 2026-10-22)

Fuzz build: `beanstalkd-afl` with the current `beanstalkd-fuzz.patch`, including the stability
fix in `conn_timeout()` (see `../stability/README.md`). The builds in `out/verify/build/` are made
only when missing: delete that directory after changing `beanstalkd-afl`.

| Seed | Sessions | Seed sent unchanged | Replies = reference | Closed after the last reply | `cut_sessions` |
|---|---:|---:|---:|---:|---:|
| 01_lifecycle | 11 595 | all | all | all | 0 |
| 02_release_bury_kick | 9 594 | all | all | all | 0 |
| 03_tubes | 9 484 | all | all | all | 0 |
| 04_peek_stats | 8 855 | all | all | all | 0 |
| 05_errors | 9 392 | all | all | all | 0 |
| 06_delayed_kick | 8 892 | all | all | all | 0 |
| 07_multi_tube | 7 757 | all | all | all | 0 |
| 08_bodies | 9 106 | all | all | all | 0 |
| 09_deadline | 8 857 | all | all | all | 0 |

## Differences that remain, and why

All of them come from the end of a session, none from request handling:

- **The patch's own code** runs only in the fuzz build: `count_cur_conns()` and `exit(0)` in
  `h_conn()` (`FUZZ_EXIT_ON_CLOSE`), `__AFL_INIT()` in `main()`.
- **Only in the reference**: the `}` of `h_conn()` after the connection is closed. The fuzz build
  exits before it.
- **Event loop** (`prottick`, `epollq_apply`, `soonest_delayed_job`, `nanoseconds`, the tail of
  `h_conn`): the reference keeps looping after the client disconnects, until it is stopped; the
  fuzz build exits at once. So these run less often per session in the fuzz build.
- **05_errors only**: the half-close path (`socknext` returns `'h'`, `c->halfclosed = 1`). After
  `quit` AFLNet closes its socket right away, the reference client waits for the server to close.
  The replies are the same.
- **The last session of a run** is often cut: `timeout -s INT` stops the fuzzer in the middle of
  it. The fuzzer does not count it (`execs_done` is one less), and the report lists it separately.
  For the same reason the last server process is sometimes killed while saving its coverage, so
  some functions show N − 1 runs; the report lists them as such.
- **Refused connection attempts** at the very end of a run (seen once, 1001 of them in
  06_delayed_kick): the run was stopped while the fork server was shutting down, and AFLNet retries
  `connect()` up to 1000 times. The server never accepted them (no SYN-ACK); the report counts them
  separately and checks that they all come after the last session.
- **`main()` and `srvserve()`** are left out: they are still running when the process exits, and
  clang's gcov reports wrong line counts for such functions (for example 0 for executed lines).

## Files

- `run_verify.sh`: builds both servers, runs everything, writes `results/`.
- `ref_client.py`, `compare.py`, `identity_mutator.c`, `exit_on_sigterm.c`: see above.
- `results/report.txt`: the full report, including every coverage difference.
- `results/<seed>.ref.pcap`: the reference session; `results/<seed>.fuzz-sample.pcap`: the first
  200 packets of the fuzzer's traffic (about 10 sessions), to look at in Wireshark. The full
  captures and gcov files stay in `out/verify/work/`.
