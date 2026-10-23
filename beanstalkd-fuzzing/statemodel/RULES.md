# Reference model of the beanstalk protocol: rules

Every rule below comes from `beanstalkd-afl/doc/protocol.txt` (commit `43a834a`, unmodified);
`[L123]` is the line in that file. The server code (`prot.c` etc.) was **not** used, so the model
is independent of the implementation. Where the spec is silent or contradicts itself, the model
allows every reading (marked **AMBIGUOUS**) or makes an explicit assumption (marked
**ASSUMPTION**). These marks are findings in themselves.

`spec_model.py` implements exactly these rules.

## 1. Setting (assumptions about the fuzzing setup, not from the spec)

- **ASSUMPTION A1 — fresh server, one client.** Every fuzzing session runs on a freshly started
  server (`FUZZ_EXIT_ON_CLOSE`) with a single connection. So the model starts empty, and
  "reserved by the client" means "reserved by this connection".
- **ASSUMPTION A2 — a session lasts less than 1 second** (the exec timeout is 200 ms). No timer
  of 1 s or more fires within a session: delayed jobs stay delayed, TTRs do not expire, paused
  tubes stay paused, `reserve-with-timeout <n>` with n ≥ 1 does not time out.
- **ASSUMPTION A3 — no memory pressure, no drain mode.** `OUT_OF_MEMORY`, `INTERNAL_ERROR`,
  `DRAINING` and `BURIED` caused by out-of-memory [L37–42, L161–176, L305] are not part of
  normal behaviour; the checker reports them separately as "exceptional".
- `max-job-size` is a parameter (the run scripts use `-z 1024`).

## 2. Framing: how the byte stream becomes commands

- Commands are text lines ending in `\r\n` [L20–21, L127].
- A line longer than 224 bytes including `\r\n` → `BAD_FORMAT` [L44–46].
  **ASSUMPTION F1:** the whole line up to its `\r\n` is discarded.
- `put` is followed by a chunk of `<bytes>` bytes and `\r\n` [L127–128, L148–152].
  If the two bytes after the body are not `\r\n` → `EXPECTED_CRLF` [L166–168], no job.
- Body larger than max-job-size → `JOB_TOO_BIG` [L170–171].
  **AMBIGUOUS:** L149 says bytes "must be less than max-job-size", L170 says "larger than" is an
  error, so `<bytes>` == max-job-size may give either reply.
  **ASSUMPTION F2:** after `JOB_TOO_BIG` the body still follows and is skipped (the spec does
  not say what happens to it).
- **ASSUMPTION F3:** if the `put` line itself is `BAD_FORMAT`, no body is expected; the
  following bytes are read as new commands (the length is unknown).
- Data at the end of the stream without `\r\n` (or a body that is not complete): no reply.

## 3. Syntax: `BAD_FORMAT` and `UNKNOWN_COMMAND`

- Unknown command name → `UNKNOWN_COMMAND` [L51–52].
- Known command with the wrong number of arguments, non-numeric integer, tube name over
  200 bytes, or "mal-formed in any other way" → `BAD_FORMAT` [L44–49].
  So `watch` with no argument must be `BAD_FORMAT`, not `UNKNOWN_COMMAND`.
- Names: 1+ chars from `A-Z a-z 0-9 - + / ; . $ _ ( )`, not starting with `-` [L13–18];
  max 200 bytes for tubes [L184, L354, L502]. Anything else → `BAD_FORMAT`.
- Integers: decimal, non-negative [L9–11]. Limits given by the spec: pri < 2^32 [L133],
  delay ≤ 2^32−1 [L139], ttr ≤ 2^32−1 [L146], pause delay < 2^32 [L738]; over the limit →
  `BAD_FORMAT`. **AMBIGUOUS:** ids, kick bound, reserve timeout and `<bytes>` have no stated
  limit; values ≥ 2^31 may be `BAD_FORMAT` or be accepted (the server rejects a reserve timeout
  of 2^31).
- **AMBIGUOUS:** the spec does not define separators. Doubled, leading or trailing spaces may be
  accepted or give `BAD_FORMAT`. An empty line, or one of only spaces, may give
  `UNKNOWN_COMMAND` or `BAD_FORMAT`.
- **AMBIGUOUS:** a line with a NUL byte is not an ASCII text line [L6, L20–21]; it may give
  `BAD_FORMAT` (malformed) as well as its normal reply.
- A `put` whose body has not fully arrived gets no reply yet: the server waits for the rest.
- Any command may get `BAD_FORMAT` / `UNKNOWN_COMMAND` only for the reasons above
  [L54–57]; a well-formed known command never gets them.

## 4. State

- **Jobs**: id, tube, state ∈ {ready, delayed, reserved, buried}, priority, TTR, body [L66–68].
  Job lifecycle (the diagram) [L86–103]:
  - put → ready, or delayed if delay > 0 [L137–138]
  - delayed → ready: time passes (never within a session, A2), `kick`, `kick-job`
  - ready → reserved: `reserve*`; reserved → ready/delayed: `release`; reserved → buried: `bury`
  - buried → ready: `kick`, `kick-job`; reserved/buried → gone: `delete`
- **Connection**: used tube (initially `default`) [L113–115, L178–180]; watch list (initially
  `default`) [L113, L349–350]; blocked in `reserve`; closed by `quit`.
- **Tubes**: each job lives in one tube for life [L106–107]. Tubes are created on demand when
  referenced [L117]. A tube with no ready, delayed or buried jobs and no client referring to it
  "will be deleted" [L117–119]. **AMBIGUOUS:** when it is deleted is not said, so such a tube
  may or may not still exist. (Note: by the spec even `default` may disappear.)
- Paused tube: no job is reserved from it for `<delay>` seconds [L732–739]. A delay of 0
  pauses for 0 seconds, so it has no effect.

## 5. Commands and allowed replies

| Command | Allowed replies (state condition) | Spec |
|---|---|---|
| `put` | `INSERTED <new unique id>`; `EXPECTED_CRLF`; `JOB_TOO_BIG` (see §2) | L124–176 |
| `use <tube>` | `USING <tube>` (tube created) | L178–191 |
| `reserve` | `RESERVED` job; no job → **blocks** (no reply, later commands unanswered); `DEADLINE_SOON` (see below) | L196–252 |
| `reserve-with-timeout <s>` | as `reserve`; no job and s = 0 → `TIMED_OUT`; s ≥ 1 → blocks (A2) | L201–236 |
| `reserve-job <id>` | `RESERVED` if the job is ready, buried or delayed; else `NOT_FOUND` | L254–269 |
| `delete <id>` | reserved by client or buried → `DELETED`; ready or delayed → **AMBIGUOUS** `DELETED`/`NOT_FOUND` (L272–274 vs L284–285); no job → `NOT_FOUND` | L271–286 |
| `release <id> <pri> <delay>` | reserved by client → `RELEASED`, new pri, ready (delay 0) or delayed; else `NOT_FOUND` | L288–308 |
| `bury <id> <pri>` | reserved by client → `BURIED`, new pri; else `NOT_FOUND` | L310–326 |
| `touch <id>` | reserved by client → `TOUCHED`; else `NOT_FOUND` | L328–345 |
| `watch <tube>` | `WATCHING <n>`, n = size of the watch list (a set); tube created | L347–361 |
| `ignore <tube>` | in list, list has 1 tube → `NOT_IGNORED`; in list → `WATCHING <n−1>`; not in list → `WATCHING <n>` (**AMBIGUOUS** if n = 1: also `NOT_IGNORED`) | L363–375 |
| `peek <id>` | job exists (any tube, any state) → `FOUND <id>`; else `NOT_FOUND` | L380–407 |
| `peek-ready` / `peek-delayed` / `peek-buried` | used tube only: next ready / shortest delay / first buried → `FOUND`; none → `NOT_FOUND` | L380–407 |
| `kick <bound>` | used tube only; buried jobs if any, else delayed; `KICKED <k>`, k = min(bound, count) | L409–422 |
| `kick-job <id>` | buried or delayed → `KICKED`, job ready; else `NOT_FOUND` | L424–438 |
| `stats-job <id>` | exists → `OK`; else `NOT_FOUND` | L440–449 |
| `stats-tube <tube>` | tube exists → `OK`; else `NOT_FOUND` | L497–508 |
| `stats`, `list-tubes`, `list-tubes-watched` | `OK` | L553–726 |
| `list-tube-used` | `USING <used tube>` | L702–711 |
| `pause-tube <tube> <delay>` | tube exists → `PAUSED`; else `NOT_FOUND` | L732–745 |
| `quit` | no reply; the connection closes, nothing after it is processed | L728–730 |

Job choice:
- `reserve*` takes the ready job with the smallest priority from the watched, non-paused tubes;
  within a priority, the one "received first" [L212–214]. **AMBIGUOUS:** for a job that was put
  back (release, kick) "received first" is unclear, so then any job of that priority is allowed.
- `peek-ready` uses the same order in the used tube. `peek-delayed`: shortest delay left
  [L387]; ties are AMBIGUOUS. `peek-buried`: "next job in the list of buried jobs", a FIFO
  [L310–312, L389].
- `kick`: which jobs move when bound < count is not said — **AMBIGUOUS** for delayed jobs;
  buried jobs are taken in FIFO order.

Deadline [L221–230]: the last second of a reserved job's TTR is a safety margin. With A2, a job
is in the margin only if its TTR is 1 (TTR 0 is raised to 1 [L145–146]). `reserve*` while
this client holds such a job → `DEADLINE_SOON`. **AMBIGUOUS:** if a ready job is also available,
the spec does not say which wins, so `RESERVED` is allowed too.

The data part of `OK`, `FOUND` and `RESERVED` replies (YAML, bodies) is not checked by the model
yet, except the job id and body of `FOUND`/`RESERVED`.

## 6. Differences of the real server from these rules

Found by checking the fuzzing corpus against the model (`check_corpus.py`) and confirmed by
black-box probes (`probe_server.py`, output in `results/probes.txt`); the server code was not
used. `spec_model.py` can emulate them (`SERVER_DEVIATIONS`, off by default) so that the corpus
check can look past them. All five concern how the server reads the input, none the job or tube
logic.

| Name | Server behaviour | Spec | Sessions that need it* |
|---|---|---|---:|
| `prefix` | A command without arguments is recognized by the start of the line: `statsX`, `peek-readyX`, `reserveX` → `BAD_FORMAT`; `pause-tubeX a 0` likewise. A line starting with `quit` (`quitX`, `quit 1`) closes the connection | unknown name → `UNKNOWN_COMMAND` [L51]; `quit 1` → `BAD_FORMAT` [L47] | 1052 |
| `framing` | Only the first `\r` of the 224-byte command buffer can end a line. A lone `\r` hides the `\r\n` after it: `foo\rbar\r\nstats\r\n` gets **no reply at all**, and once 224 bytes pile up, the whole stretch, valid commands included, is thrown away with one `BAD_FORMAT` | a line ends with `\r\n` [L20–21, L127] | 671 |
| `trailing-junk` | `kick` and `reserve-with-timeout` read the number at the start of their argument and ignore the rest of the line (`kick 1X`, `kick 1 0`, `reserve-with-timeout 0 0` are accepted); all other commands reject this | non-numeric character or extra argument → `BAD_FORMAT` [L44–49] | 112 |
| `no-space` | A command with arguments sent without them and without a space (`watch`, `use`) → `UNKNOWN_COMMAND` | wrong number of arguments → `BAD_FORMAT` [L47] | 38 |
| `too-big-first` | A malformed `put` line whose `<bytes>` exceeds max-job-size (`put 0 0 60 2000 7`) is not rejected: the server skips `<bytes>`+2 bytes of the following input as a body, then answers `JOB_TOO_BIG` | malformed line → `BAD_FORMAT` [L44–49] | 5 |

\* of the 2307 corpus sessions: how many stop matching the model when only this difference is
left out.

`framing` is the most serious one: a single stray `\r` makes the server silently drop the
client's following, valid commands, without crashing. The others only change which error code
is returned.
