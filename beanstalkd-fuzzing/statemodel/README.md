# Reference state machine and comparison with AFLNet's ipsm.dot

Task: find a reference state machine of the protocol independently, compare it with the one AFLNet
builds (`ipsm.dot`), and look for logic errors that do not crash the server.

Independent source: the protocol specification `beanstalkd-afl/doc/protocol.txt`. The server code
was not used for the model; the server was only run as a black box.

## Steps

```bash
cd beanstalkd-fuzzing/statemodel
python3 spec_model.py ../seeds/*.raw                     # 2. the model on the seeds
python3 ref_graph.py                                     # 3. reference graph
python3 replay.py ../../out/cmp-{default,custom}-new/replayable-{queue,new-ipsm-paths}
python3 ipsm_compare.py ../../out/cmp-default-new ../../out/cmp-custom-new   # 4.
python3 check_corpus.py ../../out/cmp-default-new ../../out/cmp-custom-new   # 5.
python3 probe_server.py                                  # evidence for the differences
```

1. **Rules** (`RULES.md`): states of jobs, connection and tubes, and the replies allowed for each
   of the 25 commands, each with the spec line it comes from. Where the spec contradicts itself
   or is silent, every reading is allowed (marked AMBIGUOUS), e.g. `delete` of a ready job
   (L272–274 vs L284–285), `<bytes>` equal to max-job-size (L149 vs L170).
2. **Model** (`spec_model.py`): reads the client's byte stream, splits it into commands and gives
   the replies the spec allows. Where several are allowed it keeps several possible states.
3. **Reference graph** (`ref_graph.py`, `results/ref_graph.{json,dot}`): the same kind of graph
   as `ipsm.dot` (a node per reply code, A → B if reply B can follow reply A), built by applying
   a 40-command alphabet to every state the model reaches from a fresh server. The number of
   edges stops growing at session length 6 (checked up to 8, and with 3 jobs instead of 2).
   Result: 21 nodes, 411 edges. The spec forbids only 7 replies as the first one of a session
   (`BURIED`, `RESERVED`, `DEADLINE_SOON`, `DELETED`, `RELEASED`, `TOUCHED`, `FOUND`) and
   2 transitions (`DEADLINE_SOON → TIMED_OUT`, `TIMED_OUT → DEADLINE_SOON`).
4. **Comparison with ipsm.dot** (`ipsm_compare.py`, `results/ipsm_compare.txt`). AFLNet numbers
   the nodes in the order reply codes first appear in a run and does not save the mapping; it is
   recovered by replaying the 1054 sessions AFLNet saved for new graph paths (each file name holds
   the session's node sequence). Every node got one code, with no conflicts, and the same mapping
   in both runs.
   - edges in ipsm.dot: 306 (default) / 335 (custom); **not allowed by the reference: 0**;
   - reference edges never seen in either run: 56 of 411 (mostly around `JOB_TOO_BIG`,
     `NOT_IGNORED`, `TOUCHED`).
5. **Every corpus session against the model** (`check_corpus.py`, `results/check_corpus.txt`):
   the server's replies to all 2307 sessions of both 30-minute runs, reply by reply.
   - strictly by the spec: 919 sessions match; 1388 differ;
   - with the 5 server differences below accepted: **all 2307 match**. So the job lifecycle,
     ids, priority order, tubes, pause and deadline logic behave as the spec says on everything
     the fuzzer produced; the differences are all in how the server reads its input.

## Findings

Server differences from the spec (details and probes: `RULES.md` §6, `results/probes.txt`):

| Difference | Example | Server | Spec |
|---|---|---|---|
| `framing` | `foo\rbar\r\nstats\r\n` | no reply at all; valid commands after a stray `\r` are dropped | `UNKNOWN_COMMAND`, `OK` |
| `prefix` | `statsX`, `quit 1` | `BAD_FORMAT`; connection closed | `UNKNOWN_COMMAND`; `BAD_FORMAT` |
| `trailing-junk` | `kick 1X`, `reserve-with-timeout 0 0` | accepted | `BAD_FORMAT` |
| `no-space` | `watch` | `UNKNOWN_COMMAND` | `BAD_FORMAT` |
| `too-big-first` | `put 0 0 60 2000 7` | following input skipped as a body | `BAD_FORMAT` |

The `framing` one is a real logic error of the kind the task asks about: without any crash, one
stray `\r` makes the server silently ignore the client's next, valid commands. AFLNet could not
show it: its graph only records which reply follows which, and a missing reply leaves no edge.

Spec problems found on the way (AMBIGUOUS in `RULES.md`): contradictory rules for `delete`, for
the max-job-size boundary, unspecified tube deletion time (by the spec even `default` may be
deleted), unspecified separators, no limits for ids and timeouts, no rule for NUL bytes.

## Limits

- Graph comparison is weak by nature for this protocol: AFLNet's "states" are reply codes, and
  almost any reply can follow almost any other, so the reference forbids very little. The corpus
  check (step 5) is the strong one.
- Timing: the model assumes a session shorter than 1 s (no delay, TTR or pause expires); the
  replay sends each session at once, so this holds.
- `OK` bodies (stats YAML, tube lists) are not checked, only reply codes, ids, job bodies and
  the counts in `WATCHING` / `KICKED`.
