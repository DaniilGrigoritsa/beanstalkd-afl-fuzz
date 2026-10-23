# Instability: cause and fix

After the AFLNet late-reply fix (`cut_sessions` = 0), the 30-minute runs still had stability
97–98%, with 10 (default) and 13 (custom) inputs marked as variable. This is where it came from.

## 1. Localization: which code runs differently between runs of the same input

```bash
PARALLEL=2 beanstalkd-fuzzing/stability/measure.sh out/stability/before 3   # all 23 variable inputs
python3 beanstalkd-fuzzing/stability/analyze.py out/stability/before
```

- `measure.sh` builds the fuzzing target a second time with LLVM source-based coverage
  (`-fprofile-instr-generate`) and lets the real `afl-fuzz` replay each variable input unchanged
  (mutation stub `../verify/identity_mutator.so`) for 3 s, two inputs at a time as in the
  comparison runs. Every server process saves its own coverage.
- `analyze.py` cuts the profiles into single executions (all processes append to one file, since
  `%p` is expanded in the fork server) and, for 60 executions per input, finds lines whose count is
  not the same every time, and among them those whose count changes the AFL hit-count bucket.

Result, before the fix: in 21 of 23 inputs the same 35 lines vary, all in the connection timer
code; in 4 inputs the change crosses an AFL bucket.

| File | Function | What it does |
|---|---|---|
| prot.c | `conn_timeout()` | handles an expired connection timer (TTR, reserve timeout) |
| prot.c | `prottick()` (connection-timer loop) | calls `conn_timeout()` for connections whose `tickat` has passed |
| conn.c | `connsched()`, `connsoonestjob()` | reschedules the connection timer |
| time.c | `nanoseconds()` | reads the clock |

E.g. input `cmp-default-new id:001115`: `conn_timeout()` runs 3 times in 53 of 60 executions and
2 times in 7; 2 and 3 are different AFL buckets.

## 2. Cause

A debug copy of the server that logs every timer decision (`out/stability/debug/`) showed calls
of `conn_timeout()` with nothing to do (`waiting=0 pending_timeout=0`): the client is not waiting,
yet its timer fires.

In beanstalkd, `c->pending_timeout` (the timeout of a waiting `reserve-with-timeout`) is reset to
-1 when a job is reserved, when the wait ends with `TIMED_OUT`, and on a half-closed connection,
but **not** when `conn_timeout()` ends the wait with `DEADLINE_SOON`. Left at 0, it makes
`conntickat()` return "now" (`min(t, 0 s)`) on every reschedule. That empty timer fires at the next
pass of the event loop only if the clock (µs resolution) has moved on by then, so the number of
`conn_timeout()` calls depends on timing and load.

It has no effect on replies: the call finds nothing to do. Only coverage is affected.

## 3. Fix and check

`beanstalkd-afl/prot.c`, `conn_timeout()`, in the fuzzing build (`FUZZ_DETERMINISTIC`, part of
`../patches/beanstalkd-fuzz.patch`): `c->pending_timeout = -1;` in the `DEADLINE_SOON` branch,
as the `TIMED_OUT` branch does.

| Check | Before | After |
|---|---|---|
| `analyze.py`, 23 variable inputs × 60 executions: lines that vary | 35 (4 inputs cross an AFL bucket) | **0** |
| `calibrate.sh`: AFL calibration of both whole corpora at once, 4 rounds, default | 98.26–98.73%, 6–8 variable | **100.00%, 0 variable** |
| same, custom | 98.43–98.58%, 13–14 variable | **100.00%, 0 variable** |
| replies to all 2307 corpus sessions (`../statemodel/replay.py`) | — | identical (only `pid`/`rusage`/`id` in `stats` differ) |

```bash
beanstalkd-fuzzing/stability/calibrate.sh <beanstalkd binary> out/stability/calib 4
```

## 4. What remains: rare TCP-timing events (localized, not fixed)

New 30-minute runs with the fix (`out/cmp-*-new-1`): variable paths 10 → 3 (default) and
13 → 1 (custom); stability 97.16% → 97.78% and 98.28% → 98.90%. The percentage moves less than the
path count because AFL counts the bitmap bytes ever seen varying during the whole run.

Calibrating these corpora (`RUNS="cmp-default-new-1 cmp-custom-new-1" calibrate.sh`) gives 100% in
most rounds, but once in a while (about 1-2 inputs per round, a different input each time) one run
differs. Such events are too rare to show up in sampled replays (0 varying lines in 400 exact
replays of each of these inputs), so they were caught in the act:

- `out/stability/aflnet-dbg`: a copy of AFLNet with `aflnet-calib-debug.patch` (applied on top of
  the main AFLNet patch; how to build it is at the top of the patch). When a calibration run's trace
  differs from the first run, it dumps the input, both runs' replies, the fork server pid and both
  runs' global execution numbers (`CALIB_DEBUG_DIR`);
- calibration on the coverage build (`LLVM_PROFILE_FILE=.../%p.profraw`), so each execution's
  coverage is in the fork server's profile file, in order;
- `rare_events.py <dumps> <profiles>`: takes both executions out of the profile and diffs them.

10 rounds, 3 events, all with identical replies:

| Input | Difference between the two runs |
|---|---|
| `001060` | hangup event (`socknext` returns `'h'`, `h_conn` sets `halfclosed`) seen 2 times instead of 1 |
| `000323` | 227 event-loop iterations instead of 212: 15 more `read()`s that end with an incomplete line (`scan_line_end` → 0) |
| `000226` | 69 iterations instead of 55, and the hangup seen 2 times instead of 1 |

Cause: how the client's bytes arrive. AFLNet sends messages that expect no reply without waiting,
so whether they reach the server together or in pieces depends on scheduling; more pieces mean
more `read()` calls and loop iterations (`srvserve`, `socknext`, `conn_process_io`, `h_conn`,
`scan_line_end`, `prottick`). Likewise, how often the server sees the client's close
(`EPOLLRDHUP`) depends on how much input it still has to process then. Server behaviour is the
same; only hit counts in the I/O and event-loop code change, sometimes across an AFL bucket.

Possible fixes, not done: in AFLNet, after a message that expects no reply, wait until the server
has read it (its process is asleep again), so the server always sees one message per read; or
leave the event-loop code out of AFL instrumentation (but `conn_process_io`, `h_conn` and
`scan_line_end` hold the input parsing, which is worth keeping).

## Notes

- The problem is in beanstalkd itself (also in the original 25085c5), not added by the fuzzer.
  It is harmless for clients, which is why it is fixed only in the fuzzing build; it is a
  candidate for an upstream fix.
- The 30-minute comparison runs were made before this fix; a new pair of runs would show the
  stability of a whole fuzzing session with it.
