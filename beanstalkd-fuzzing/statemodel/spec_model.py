#!/usr/bin/env python3
"""Reference model of the beanstalk protocol, built only from doc/protocol.txt.

The rules, with the spec lines they come from, are in RULES.md; the server code is not used.

The model is nondeterministic: where the spec allows more than one reply, every reply is kept,
each with its own resulting state. A branch is (position in the client byte stream, state).

usage: spec_model.py [--max-job-size N] <session file>...
  prints, for every step of each session, the commands the model reads and the replies the spec
  allows for them.
"""
import argparse
import itertools
import re
import sys
from dataclasses import dataclass, replace

U32 = 2 ** 32
LINE_MAX = 224                     # max line length including "\r\n" [L45]
NAME_MAX = 200                     # max tube name length [L184]
NAME_CHARS = frozenset(b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-+/;.$_()")
MAX_BRANCHES = 256                 # cap on states kept at once
MAX_KICK_CHOICES = 16              # cap on "which delayed jobs does kick move" alternatives

NONE = ("NONE",)                   # no reply: blocked in reserve, or quit

# Differences of the real server from the spec, found by black-box probing (check_corpus.py,
# RULES.md section 6). Off by default: the model is the spec. Turning them on lets the corpus
# check look past these known differences for further ones.
#   prefix:   a zero-argument command name followed by junk ("statsX"), or "pause-tube" followed
#             by anything but a space, is taken as that command: BAD_FORMAT; a line starting with
#             "quit" (even "quit 1") closes the connection, "reserve..." may act as reserve
#   no-space: a known command that takes arguments, sent without them ("watch"): UNKNOWN_COMMAND
#   trailing-junk: kick and reserve-with-timeout read the number at the start of their argument
#             and ignore the rest of the line ("kick 1X", "kick 5out 0")
#   framing:  a lone '\r' in a line hides the line end that follows; see server_line_end()
#   too-big-first: a put line with junk after a <bytes> larger than max-job-size is not rejected:
#             the server skips <bytes>+2 bytes as the body and then answers JOB_TOO_BIG
SERVER_DEVIATIONS = set()

# Argument kinds: integers with a limit from the spec, integers without one, tube names.
LIMITS = {"pri": U32 - 1, "delay": U32 - 1, "ttr": U32 - 1, "pause": U32 - 1}
COMMANDS = {
    b"put": ("pri", "delay", "ttr", "int"),
    b"use": ("tube",), b"watch": ("tube",), b"ignore": ("tube",), b"stats-tube": ("tube",),
    b"reserve": (), b"reserve-with-timeout": ("int",), b"reserve-job": ("int",),
    b"delete": ("int",), b"touch": ("int",), b"peek": ("int",), b"kick-job": ("int",),
    b"stats-job": ("int",), b"release": ("int", "pri", "delay"), b"bury": ("int", "pri"),
    b"peek-ready": (), b"peek-delayed": (), b"peek-buried": (), b"kick": ("int",),
    b"stats": (), b"list-tubes": (), b"list-tube-used": (), b"list-tubes-watched": (),
    b"pause-tube": ("tube", "pause"), b"quit": (),
}


@dataclass(frozen=True)
class Job:
    id: int
    tube: bytes
    state: str          # ready | delayed | reserved | buried
    pri: int
    ttr: int
    delay: int          # seconds, meaningful while delayed
    body: bytes
    seq: int            # creation order ("received first" [L213])
    requeued: bool      # put back by release/kick: its place in the order is unclear
    bury_seq: int       # order in the buried FIFO [L311]


@dataclass(frozen=True)
class State:
    jobs: tuple = ()                       # Job, sorted by id
    used: bytes = b"default"
    watch: tuple = (b"default",)
    created: frozenset = frozenset([b"default"])   # tubes created and maybe not deleted yet
    paused: frozenset = frozenset()
    ids: frozenset = frozenset()           # every id handed out so far (ids are unique [L244])
    next_id: int = 1
    seq: int = 0
    bury_seq: int = 0
    blocked: bool = False
    closed: bool = False

    def job(self, jid):
        for j in self.jobs:
            if j.id == jid:
                return j
        return None

    def put_job(self, job):
        return replace(self, jobs=tuple(sorted([j for j in self.jobs if j.id != job.id] + [job],
                                               key=lambda j: j.id)))

    def drop_job(self, jid):
        return replace(self, jobs=tuple(j for j in self.jobs if j.id != jid))

    def tube_status(self, name):
        """'yes', 'maybe' (unreferenced and empty: may have been deleted [L117-119]) or 'no'."""
        if name == self.used or name in self.watch:
            return "yes"
        if any(j.tube == name and j.state != "reserved" for j in self.jobs):
            return "yes"
        return "maybe" if name in self.created else "no"


# ---------------------------------------------------------------- framing and syntax (RULES §2-3)

def parse_int(tok, kind):
    """List of alternatives: an int value, or 'BAD' for BAD_FORMAT."""
    if not tok or not tok.isdigit():
        return ["BAD"]
    v = int(tok)
    if kind in LIMITS:
        return ["BAD"] if v > LIMITS[kind] else [v]
    return [v] if v < 2 ** 31 else ["BAD", v]      # no limit in the spec: AMBIGUOUS


def parse_name(tok):
    ok = 0 < len(tok) <= NAME_MAX and tok[0:1] != b"-" and all(c in NAME_CHARS for c in tok)
    return [tok] if ok else ["BAD"]


def parse_line(line):
    """Alternatives for one command line: ('ERR', code) or ('CMD', name, args)."""
    toks = line.split(b" ")
    if line == b"":
        return [("ERR", "UNKNOWN_COMMAND"), ("ERR", "BAD_FORMAT")]           # AMBIGUOUS
    alts = []
    if b"\x00" in line:                             # not a text line: may be BAD_FORMAT (AMBIGUOUS)
        alts.append(("ERR", "BAD_FORMAT"))
    if any(t == b"" for t in toks):                 # doubled/leading/trailing space: AMBIGUOUS
        alts.append(("ERR", "BAD_FORMAT"))
        toks = [t for t in toks if t != b""]
        if not toks:                                # only spaces: like an empty line
            return list(dict.fromkeys(alts + [("ERR", "UNKNOWN_COMMAND")]))
    name, args = toks[0], toks[1:]
    if "trailing-junk" in SERVER_DEVIATIONS:
        for c in (b"kick", b"reserve-with-timeout"):
            if line.startswith(c + b" "):
                rest = line[len(c) + 1:].lstrip(b" ")
                lead = len(rest) - len(rest.lstrip(b"0123456789"))
                if lead and lead < len(rest):       # a number followed by anything
                    for v in parse_int(rest[:lead], "int"):
                        alts.append(("ERR", "BAD_FORMAT") if v == "BAD" else ("CMD", c.decode(), (v,)))
    kinds = COMMANDS.get(name)
    if kinds is None:
        if "prefix" in SERVER_DEVIATIONS:
            pre = [c for c, k in COMMANDS.items() if (not k or c == b"pause-tube") and name.startswith(c)]
            if pre:
                alts.append(("ERR", "BAD_FORMAT"))
                base = max(pre, key=len).decode()
                if base in ("quit", "reserve"):
                    alts.append(("CMD", base, ()))
        return list(dict.fromkeys(alts + [("ERR", "UNKNOWN_COMMAND")]))
    if "prefix" in SERVER_DEVIATIONS and name == b"quit" and args:
        alts.append(("CMD", "quit", ()))
    if len(args) != len(kinds):
        if "no-space" in SERVER_DEVIATIONS and not args:
            alts.append(("ERR", "UNKNOWN_COMMAND"))
        return list(dict.fromkeys(alts + [("ERR", "BAD_FORMAT")]))
    per_arg = [parse_name(a) if k == "tube" else parse_int(a, k) for a, k in zip(args, kinds)]
    for combo in itertools.product(*per_arg):
        alts.append(("ERR", "BAD_FORMAT") if "BAD" in combo else ("CMD", name.decode(), combo))
    return list(dict.fromkeys(alts))


def server_line_end(buf, pos):
    """Line end as the real server finds it (deviation "framing", from black-box probes): only the
    first '\\r' in the 224-byte command buffer counts, and only if '\\n' follows it. A full buffer
    without a line end is thrown away in 224-byte steps until a step holds a line end; that whole
    stretch gets one BAD_FORMAT. Returns (end of the "\\r\\n" or None, bad_format?)."""
    def scan(p):
        w = buf[p:p + LINE_MAX]
        cr = w.find(b"\r", 0, max(len(w) - 1, 0))
        return (p + cr + 2 if cr >= 0 and w[cr + 1:cr + 2] == b"\n" else None), len(w)
    end, size = scan(pos)
    if end is not None:
        return end, False
    if size < LINE_MAX:
        return None, False                                     # waits for more data
    p = pos + LINE_MAX
    while True:
        end, size = scan(p)
        if end is not None:
            return end, True
        if size < LINE_MAX:
            return None, False                                 # still throwing away
        p += LINE_MAX


# a put line whose <bytes> is followed by junk (spaces between the numbers may be repeated)
PUT_TOO_BIG = re.compile(rb"^put +\d+ +\d+ +\d+ +(\d+)(.+)$", re.S)


def parse_at(buf, pos, max_job_size):
    """Commands the server may read at buf[pos:]: list of (command, new position).
    An empty list means there is no complete command left (no reply)."""
    if "framing" in SERVER_DEVIATIONS:
        end, bad = server_line_end(buf, pos)
        if end is None:
            return []
        if bad:
            return [(("ERR", "BAD_FORMAT"), end)]
        eol = end - 2
    else:
        eol = buf.find(b"\r\n", pos)
        if eol < 0:
            return []
    line, after = buf[pos:eol], eol + 2
    if len(line) + 2 > LINE_MAX:
        return [(("ERR", "BAD_FORMAT"), after)]                # whole line discarded (F1)
    out = []
    cmds = parse_line(line)
    if "too-big-first" in SERVER_DEVIATIONS:
        mt = PUT_TOO_BIG.match(line)
        if mt and int(mt.group(1)) > max_job_size:
            cmds.append(("TOOBIG", int(mt.group(1))))
    for cmd in cmds:
        if cmd[0] == "TOOBIG":
            end = after + cmd[1] + 2
            out.append((("WAIT",), len(buf)) if len(buf) < end else (("PUTERR", "JOB_TOO_BIG"), end))
            continue
        if cmd[0] == "CMD" and cmd[1] == "put":
            n = cmd[2][3]
            end = after + n + 2
            if len(buf) < end:                                 # body not complete: the server
                out.append((("WAIT",), len(buf)))              # waits, no reply
                continue
            body, trailer = buf[after:after + n], buf[after + n:end]
            replies = []
            if n >= max_job_size:                              # == is AMBIGUOUS (L149 vs L170)
                replies.append(("PUTERR", "JOB_TOO_BIG"))      # body skipped (F2)
            if n <= max_job_size:
                replies.append(("PUTERR", "EXPECTED_CRLF") if trailer != b"\r\n"
                               else ("CMD", "put", cmd[2], body))
            out += [(r, end) for r in replies]
        else:
            out.append((cmd, after))                           # bad put line: no body (F3)
    return out


# ---------------------------------------------------------------- semantics (RULES §4-5)

def first_choices(jobs):
    """Jobs that may come first: smallest priority; within it the one received first, unless
    one of them was put back (then the order is AMBIGUOUS) [L212-214]."""
    if not jobs:
        return []
    best = min(j.pri for j in jobs)
    tied = [j for j in jobs if j.pri == best]
    if any(j.requeued for j in tied):
        return tied
    return [min(tied, key=lambda j: j.seq)]


def in_safety_margin(st):
    """With A2 only a reserved job with TTR 1 is in its last second [L221-230]."""
    return any(j.state == "reserved" and j.ttr <= 1 for j in st.jobs)


def make_ready(st, j):
    return st.put_job(replace(j, state="ready", requeued=True))


def reserve(st, timeout):
    cands = first_choices([j for j in st.jobs if j.state == "ready" and j.tube in st.watch
                           and j.tube not in st.paused])
    out = []
    if in_safety_margin(st):
        out.append((("DEADLINE_SOON",), st))
    for j in cands:                                     # with a margin too: AMBIGUOUS
        out.append((("RESERVED", j.id, j.body), st.put_job(replace(j, state="reserved"))))
    if not out:
        if timeout == 0:
            out.append((("TIMED_OUT",), st))
        else:                                           # waits longer than the session (A2)
            out.append((NONE, replace(st, blocked=True)))
    return out


def reference(st, name):
    """use/watch create the tube [L117]. A tube that may have been deleted loses its pause."""
    alts = [replace(st, created=st.created | {name})]
    if st.tube_status(name) == "maybe" and name in st.paused:
        alts.append(replace(alts[0], paused=st.paused - {name}))
    return alts


def apply(st, cmd, observed=None):
    """Replies the spec allows for cmd in state st: list of (reply, new state).
    observed: the server's actual reply, used to bind the id of a new job."""
    if st.blocked:
        return [(NONE, st)]
    kind = cmd[0]
    if kind == "WAIT":
        return [(NONE, replace(st, blocked=True))]
    if kind in ("ERR", "PUTERR"):
        return [((cmd[1],), st)]
    name, args = cmd[1], cmd[2]
    out = []

    if name == "put":
        pri, delay, ttr, _ = args
        if observed and observed[0] == "INSERTED" and len(observed) > 1:
            jid = observed[1]
            if jid in st.ids:
                return []                               # ids must be unique [L244]
        else:
            jid = st.next_id
        job = Job(jid, st.used, "delayed" if delay > 0 else "ready", pri, max(ttr, 1), delay,
                  cmd[3], st.seq + 1, False, 0)
        nst = replace(st, seq=st.seq + 1, ids=st.ids | {jid}, next_id=max(st.next_id, jid + 1))
        return [(("INSERTED", jid), nst.put_job(job))]

    if name == "use":
        return [(("USING", args[0]), replace(s, used=args[0])) for s in reference(st, args[0])]
    if name == "watch":
        watch = st.watch if args[0] in st.watch else st.watch + (args[0],)
        return [(("WATCHING", len(watch)), replace(s, watch=watch)) for s in reference(st, args[0])]
    if name == "ignore":
        t, n = args[0], len(st.watch)
        if t in st.watch:
            if n == 1:
                return [(("NOT_IGNORED",), st)]
            return [(("WATCHING", n - 1), replace(st, watch=tuple(w for w in st.watch if w != t)))]
        out = [(("WATCHING", n), st)]
        if n == 1:
            out.append((("NOT_IGNORED",), st))          # AMBIGUOUS [L374]
        return out
    if name == "list-tube-used":
        return [(("USING", st.used), st)]
    if name in ("stats", "list-tubes", "list-tubes-watched"):
        return [(("OK",), st)]
    if name == "quit":
        return [(NONE, replace(st, closed=True))]

    if name == "reserve":
        return reserve(st, None)
    if name == "reserve-with-timeout":
        return reserve(st, args[0])

    if name in ("stats-tube", "pause-tube"):
        t, status = args[0], st.tube_status(args[0])
        ok = ("OK",) if name == "stats-tube" else ("PAUSED",)
        if status in ("yes", "maybe"):
            nst = st
            if name == "pause-tube":                    # delay 0 pauses for 0 s
                nst = replace(st, paused=(st.paused | {t}) if args[1] > 0 else (st.paused - {t}))
            out.append((ok, nst))
        if status in ("no", "maybe"):                   # maybe: it was deleted
            out.append((("NOT_FOUND",), replace(st, created=st.created - {t},
                                               paused=st.paused - {t})))
        return out

    if name in ("peek-ready", "peek-delayed", "peek-buried"):
        mine = [j for j in st.jobs if j.tube == st.used]
        if name == "peek-ready":
            choices = first_choices([j for j in mine if j.state == "ready"])
        elif name == "peek-delayed":
            delayed = [j for j in mine if j.state == "delayed"]
            choices = [j for j in delayed if j.delay == min(d.delay for d in delayed)] if delayed else []
        else:
            buried = [j for j in mine if j.state == "buried"]
            choices = [min(buried, key=lambda j: j.bury_seq)] if buried else []
        return [(("FOUND", j.id, j.body), st) for j in choices] or [(("NOT_FOUND",), st)]

    if name == "kick":
        mine = [j for j in st.jobs if j.tube == st.used]
        buried = sorted([j for j in mine if j.state == "buried"], key=lambda j: j.bury_seq)
        if buried:                                      # buried first, in FIFO order
            k = min(args[0], len(buried))
            nst = st
            for j in buried[:k]:
                nst = make_ready(nst, j)
            return [(("KICKED", k), nst)]
        delayed = [j for j in mine if j.state == "delayed"]
        k = min(args[0], len(delayed))
        for combo in itertools.islice(itertools.combinations(delayed, k), MAX_KICK_CHOICES):
            nst = st                                    # which ones: AMBIGUOUS
            for j in combo:
                nst = make_ready(nst, j)
            out.append((("KICKED", k), nst))
        return out

    # the rest take a job id
    jid = args[0]
    j = st.job(jid)
    if j is None:
        return [(("NOT_FOUND",), st)]
    if name == "peek":
        return [(("FOUND", j.id, j.body), st)]
    if name == "stats-job":
        return [(("OK",), st)]
    if name == "reserve-job":
        if j.state in ("ready", "buried", "delayed"):
            return [(("RESERVED", j.id, j.body), st.put_job(replace(j, state="reserved")))]
        return [(("NOT_FOUND",), st)]
    if name == "kick-job":
        if j.state in ("buried", "delayed"):
            return [(("KICKED",), make_ready(st, j))]
        return [(("NOT_FOUND",), st)]
    if name == "delete":
        if j.state in ("reserved", "buried"):
            return [(("DELETED",), st.drop_job(jid))]
        return [(("DELETED",), st.drop_job(jid)), (("NOT_FOUND",), st)]   # AMBIGUOUS
    if j.state != "reserved":                           # release, bury, touch
        return [(("NOT_FOUND",), st)]
    if name == "touch":
        return [(("TOUCHED",), st)]
    if name == "bury":
        return [(("BURIED",), replace(st, bury_seq=st.bury_seq + 1).put_job(
            replace(j, state="buried", pri=args[1], bury_seq=st.bury_seq + 1)))]
    if name == "release":
        delay = args[2]
        nj = replace(j, state="delayed" if delay > 0 else "ready", pri=args[1], delay=delay,
                     requeued=True)
        return [(("RELEASED",), st.put_job(nj))]
    raise AssertionError(name)


def step(buf, branches, max_job_size, observed=None):
    """Advance every branch by one command: list of (command, reply, new branch)."""
    out, seen = [], set()
    for pos, st in branches:
        if st.closed:
            continue
        for cmd, npos in parse_at(buf, pos, max_job_size):
            for reply, nst in apply(st, cmd, observed):
                key = (reply, npos, nst)
                if key not in seen:
                    seen.add(key)
                    out.append((cmd, reply, (npos, nst)))
    return out[:MAX_BRANCHES]


def fmt_cmd(cmd):
    if cmd[0] == "WAIT":
        return "<incomplete: waits for more data>"
    if cmd[0] != "CMD":
        return "<" + cmd[1] + ">"
    args = [a.decode() if isinstance(a, bytes) else str(a) for a in cmd[2]]
    return " ".join([cmd[1]] + args)


def fmt_reply(r):
    parts = []
    for x in r:
        if isinstance(x, bytes):
            parts.append(f"<{len(x)} bytes>" if len(x) > 12 else
                         repr(x)[2:-1] if x else "''")
        else:
            parts.append(str(x))
    return " ".join(parts)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--max-job-size", type=int, default=1024)
    ap.add_argument("files", nargs="+")
    a = ap.parse_args()
    for f in a.files:
        buf = open(f, "rb").read()
        print(f"== {f}")
        branches, n = [(0, State())], 0
        while True:
            res = step(buf, branches, a.max_job_size)
            if not res:
                break
            n += 1
            by_cmd = {}
            for cmd, reply, _ in res:
                by_cmd.setdefault(fmt_cmd(cmd), []).append(fmt_reply(reply))
            for c, rs in by_cmd.items():
                rs = list(dict.fromkeys(rs))
                print(f"  {n:3} {c[:40]:40} -> {' | '.join(rs)}")
            branches = [b for _, _, b in res]
        print(f"  ({len(branches)} possible end states)")


if __name__ == "__main__":
    main()
