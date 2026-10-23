#!/usr/bin/env python3
"""Step 3: the reference "reply code -> reply code" graph, built from the spec model only.

AFLNet's ipsm.dot has a node per reply code (plus 0, the start of a session) and an edge A -> B
when reply B followed reply A in a session. This script builds the same kind of graph from
spec_model.py: starting from a fresh server it applies every command of a fixed alphabet to every
reachable state, and records A -> B whenever the spec allows reply B right after reply A.

The alphabet covers all 25 commands with job ids 1-2 and tubes "default" and "a", plus a TTR-1 job
(DEADLINE_SOON), a delayed job, a body without its CRLF, a too-big job, an unknown command and a
command with a missing argument. At most --max-puts jobs are created per session. The search goes
level by level (session length) up to --max-depth and prints how many edges each level adds: when
the count stays the same for many levels, longer sessions do not add edges.

usage: ref_graph.py [--max-puts 2] [--max-depth 10] [--max-job-size N]
  -> results/ref_graph.json, results/ref_graph.dot
"""
import argparse
import json
import os
from dataclasses import replace

import spec_model as m

HERE = os.path.dirname(os.path.abspath(__file__))

# AFLNet's numbering of reply words (aflnet.c, bsd_reply_words): code = index + 1, 0 = start
REPLY_WORDS = ["INSERTED", "BURIED", "EXPECTED_CRLF", "JOB_TOO_BIG", "DRAINING", "USING",
               "RESERVED", "DEADLINE_SOON", "TIMED_OUT", "DELETED", "NOT_FOUND", "RELEASED",
               "TOUCHED", "WATCHING", "NOT_IGNORED", "KICKED", "FOUND", "OK", "PAUSED",
               "BAD_FORMAT", "UNKNOWN_COMMAND", "OUT_OF_MEMORY", "INTERNAL_ERROR"]
START = "START"


def alphabet(max_job_size):
    big = max_job_size + 1
    return [
        b"put 0 0 60 1\r\nx\r\n", b"put 0 0 1 1\r\nt\r\n",
        b"put 0 5 60 1\r\nd\r\n", b"put 0 0 60 1\r\nxyz",                 # body without CRLF
        b"put 0 0 60 %d\r\n" % big + b"z" * big + b"\r\n",              # too big
        b"use a\r\n", b"use default\r\n", b"watch a\r\n", b"ignore default\r\n", b"ignore a\r\n",
        b"reserve\r\n", b"reserve-with-timeout 0\r\n",
        b"reserve-job 1\r\n", b"delete 1\r\n", b"delete 2\r\n",
        b"release 1 0 0\r\n", b"release 1 0 5\r\n", b"bury 1 0\r\n", b"touch 1\r\n",
        b"release 2 0 0\r\n", b"bury 2 0\r\n", b"touch 2\r\n",
        b"peek 1\r\n", b"peek-ready\r\n", b"peek-delayed\r\n", b"peek-buried\r\n",
        b"kick 1\r\n", b"kick-job 1\r\n", b"stats-job 1\r\n", b"stats-tube default\r\n",
        b"stats-tube a\r\n", b"stats\r\n", b"list-tubes\r\n", b"list-tube-used\r\n",
        b"list-tubes-watched\r\n", b"pause-tube default 1\r\n", b"pause-tube a 0\r\n",
        b"quit\r\n", b"foo\r\n", b"watch\r\n",
    ]


def canonical(st):
    """The bury order matters only relatively: renumber it so the state space stays finite."""
    buried = sorted((j for j in st.jobs if j.state == "buried"), key=lambda j: j.bury_seq)
    rank = {j.id: i + 1 for i, j in enumerate(buried)}
    jobs = tuple(replace(j, bury_seq=rank.get(j.id, 0)) for j in st.jobs)
    return replace(st, jobs=jobs, bury_seq=len(buried))


def build(max_job_size, max_puts, max_depth):
    cmds = []
    for raw in alphabet(max_job_size):
        alts = m.parse_at(raw, 0, max_job_size)
        assert alts, raw
        cmds.append((raw, [c for c, _ in alts]))
    start = (m.State(), START)
    seen, frontier = {start}, [start]
    edges, example = set(), {}
    depth = 0
    while frontier and depth < max_depth:
        depth += 1
        nxt = []
        for st, last in frontier:
            for raw, alts in cmds:
                if raw.startswith(b"put ") and st.next_id > max_puts:
                    continue
                for cmd in alts:
                    for reply, nst in m.apply(st, cmd):
                        if reply == m.NONE:          # blocked or closed: no reply, no edge
                            continue
                        edge = (last, reply[0])
                        if edge not in edges:
                            edges.add(edge)
                            example[edge] = raw.split(b"\r\n")[0].decode("latin1")
                        key = (canonical(nst), reply[0])
                        if key not in seen:
                            seen.add(key)
                            nxt.append(key)
        frontier = nxt
        print(f"  session length {depth:2}: {len(edges):3} edges, {len(seen):7} states, "
              f"{len(frontier):6} new", flush=True)
    return edges, example, len(seen), depth, bool(frontier)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--max-job-size", type=int, default=1024)
    ap.add_argument("--max-puts", type=int, default=2)
    ap.add_argument("--max-depth", type=int, default=10)
    a = ap.parse_args()
    edges, example, states, depth, more = build(a.max_job_size, a.max_puts, a.max_depth)
    nodes = sorted({x for e in edges for x in e}, key=lambda n: -1 if n == START else REPLY_WORDS.index(n))
    out = os.path.join(HERE, "results")
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, "ref_graph.json"), "w") as f:
        json.dump({"states_explored": states, "max_puts": a.max_puts, "session_length": depth,
                   "complete": not more, "nodes": nodes,
                   "edges": sorted([a_, b_, example[(a_, b_)]] for a_, b_ in edges)}, f, indent=1)
    with open(os.path.join(out, "ref_graph.dot"), "w") as f:
        f.write("digraph reference {\n")
        for a_, b_ in sorted(edges):
            f.write(f'  "{a_}" -> "{b_}";\n')
        f.write("}\n")
    print(f"{states} (state, last reply) pairs explored; {len(nodes)} nodes, {len(edges)} edges")
    never_first = [n for n in nodes if n != START and (START, n) not in edges]
    print("replies that can never come first in a session:", ", ".join(never_first))
    missing = sorted((a_, b_) for a_ in nodes for b_ in nodes
                     if b_ != START and (a_, b_) not in edges and a_ != START)
    print(f"impossible A -> B pairs (A not START): {len(missing)}")
    for a_, b_ in missing:
        print(f"  {a_} -> {b_}")


if __name__ == "__main__":
    main()
