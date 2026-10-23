#!/usr/bin/env python3
"""Step 5: checks every session of the fuzzing corpus against the spec model.

For each session in <out dir>/replayable-queue, the server's replies (replay.py) are walked
together with spec_model.py: every reply must be one the spec allows for that command in the
states the model can be in. The first reply that is not allowed ends the check of that session and
is recorded. At the end, if the server sent nothing more, the model must allow silence too (a
blocked reserve, quit, or no complete command left).

Differences are grouped by (command, reply the server sent, replies the spec allows), with an
example session each.

usage: check_corpus.py <fuzzer out dir>...   -> results/check_corpus.txt
"""
import collections
import os
import sys

import replay
import spec_model as m

HERE = os.path.dirname(os.path.abspath(__file__))
MAX_JOB_SIZE = 1024
EXCEPTIONAL = {"OUT_OF_MEMORY", "INTERNAL_ERROR", "DRAINING"}


def parse_replies(buf):
    """The server's reply stream as reply tuples, in the form spec_model.apply returns them."""
    out, pos = [], 0
    while True:
        eol = buf.find(b"\r\n", pos)
        if eol < 0:
            return out
        parts = buf[pos:eol].split(b" ")
        word = parts[0].decode("latin1")
        nxt = eol + 2
        args = parts[1:]
        if word in ("RESERVED", "FOUND") and len(args) == 2 and args[1].isdigit():
            n = int(args[1])
            out.append((word, int(args[0]), buf[nxt:nxt + n]))
            nxt += n + 2
        elif word == "OK" and len(args) == 1 and args[0].isdigit():
            out.append(("OK",))
            nxt += int(args[0]) + 2
        elif word in ("INSERTED", "WATCHING") and len(args) == 1:
            out.append((word, int(args[0])))
        elif word in ("KICKED", "BURIED") and len(args) == 1:
            out.append((word, int(args[0])) if word == "KICKED" else ("BURIED", int(args[0])))
        elif word == "USING" and len(args) == 1:
            out.append(("USING", args[0]))
        else:
            out.append((word,) + tuple(a.decode("latin1") for a in args))
        pos = nxt


def fmt(r):
    return m.fmt_reply(r) if r != m.NONE else "(no reply)"


def check(session, replies):
    """None if the session conforms, else (reply index, command, server reply, allowed replies)."""
    branches = [(0, m.State())]
    for k, obs in enumerate(replies):
        res = m.step(session, branches, MAX_JOB_SIZE, observed=obs)
        keep = list(dict.fromkeys(nb for _, r, nb in res if r == obs))
        if not keep:
            cmds = list(dict.fromkeys(m.fmt_cmd(c) for c, _, _ in res)) or ["(end of input)"]
            allowed = sorted({fmt(r) for _, r, _ in res}) or ["(nothing)"]
            return k, cmds, obs, allowed
        branches = keep
    # the server stopped answering: the spec must allow that for at least one branch
    for b in branches:
        res = m.step(session, [b], MAX_JOB_SIZE)
        if not res or any(r == m.NONE for _, r, _ in res):
            return None
    res = m.step(session, branches, MAX_JOB_SIZE)
    cmds = list(dict.fromkeys(m.fmt_cmd(c) for c, _, _ in res))
    return len(replies), cmds, m.NONE, sorted({fmt(r) for _, r, _ in res})


def run(run_dirs):
    groups = collections.defaultdict(list)
    total = ok = 0
    exceptional = 0
    for run_dir in run_dirs:
        run = os.path.basename(os.path.normpath(run_dir))
        qdir = os.path.join(run_dir, "replayable-queue")
        for f in sorted(os.listdir(qdir)):
            path = os.path.join(qdir, f)
            session = b"".join(replay.read_session(path))
            replies = parse_replies(replay.replies(path))
            total += 1
            if any(r[0] in EXCEPTIONAL for r in replies):
                exceptional += 1
            res = check(session, replies)
            if res is None:
                ok += 1
                continue
            k, cmds, obs, allowed = res
            cmd_name = cmds[0].split(" ")[0] if len(cmds) == 1 else " | ".join(c.split(" ")[0] for c in cmds)
            key = (cmd_name, obs[0] if obs != m.NONE else "(no reply)", tuple(sorted({a.split(" ")[0] for a in allowed})))
            groups[key].append((run, f, k, cmds, fmt(obs), allowed))
    return groups, total, ok, exceptional


def section(title, groups, total, ok, exceptional):
    lines = [f"===== {title}",
             f"Sessions checked: {total}; conform: {ok}; first difference found in: {total - ok}; "
             f"with OUT_OF_MEMORY/INTERNAL_ERROR/DRAINING: {exceptional}", ""]
    for key, items in sorted(groups.items(), key=lambda kv: -len(kv[1])):
        cmd, got, allowed = key
        run, f, k, cmds, obs, allowed_full = items[0]
        lines.append(f"[{len(items):4} sessions] command: {cmd}   server: {got}   spec allows: {', '.join(allowed)}")
        lines.append(f"    e.g. {run}/{f}, reply #{k + 1}")
        lines.append(f"         command(s) {' | '.join(c[:70] for c in cmds[:3])}")
        lines.append(f"         server: {obs[:70]}   spec: {' | '.join(a[:40] for a in allowed_full[:4])}")
    return lines


def main():
    text = []
    m.SERVER_DEVIATIONS.clear()
    text += section("1. Strict: the spec model", *run(sys.argv[1:])) + [""]
    m.SERVER_DEVIATIONS.update({"prefix", "no-space", "trailing-junk", "framing", "too-big-first"})
    text += section("2. The spec model + the server differences already found "
                    f"({', '.join(sorted(m.SERVER_DEVIATIONS))})", *run(sys.argv[1:]))
    text = "\n".join(text)
    print(text)
    with open(os.path.join(HERE, "results", "check_corpus.txt"), "w") as fh:
        fh.write(text + "\n")


if __name__ == "__main__":
    main()
