#!/usr/bin/env python3
"""Step 4: compares AFLNet's state machine (ipsm.dot) with the reference graph (ref_graph.py).

ipsm.dot numbers its nodes in the order the reply codes first appeared in that run, and the
mapping is not saved. It is recovered here: AFLNet saves every session that produced a new path
through the graph in replayable-new-ipsm-paths/, with the session's node sequence in the file
name. The session is replayed against the server (replay.py), its replies are turned into reply
codes the way AFLNet does it (extract_response_codes_beanstalkd), and the two sequences are lined
up. Each node gets the code most sessions agree on.

usage: ipsm_compare.py <fuzzer out dir>...   (replay.py must have replayed the sessions first)
"""
import collections
import json
import os
import re
import sys

import replay

HERE = os.path.dirname(os.path.abspath(__file__))
START = "START"


def reply_codes(buf):
    """Reply codes in a server reply stream, as AFLNet extracts them (unknown words -> '?')."""
    from ref_graph import REPLY_WORDS
    out, pos = [], 0
    while True:
        eol = buf.find(b"\r\n", pos)
        if eol < 0:
            break
        line = buf[pos:eol]
        parts = line.split()
        word = parts[0].decode("latin1") if parts else ""
        out.append(word if word in REPLY_WORDS else "?")
        pos = eol + 2
        size = None
        if word in ("RESERVED", "FOUND") and len(parts) >= 3 and parts[2].isdigit():
            size = int(parts[2])
        elif word == "OK" and len(parts) >= 2 and parts[1].isdigit():
            size = int(parts[1])
        if size is not None:
            pos += size + 2
    return out


def squeeze(seq):
    """AFLNet's file names leave out the 3rd and later repeats of a node (state_sequence_to_string)."""
    return [x for i, x in enumerate(seq) if not (i >= 2 and x == seq[i - 1] == seq[i - 2])]


def name_sequence(fname):
    """Node ids in a replayable-new-ipsm-paths file name: (ids, truncated?)."""
    body = fname[len("id:"):].split(":", 1)[0]
    truncated = "end-at-" in body
    if truncated:
        body = body.split("end-at-")[0].rstrip("-")
    return [int(x) for x in body.split("-") if x], truncated


def recover_mapping(run_dir):
    votes = collections.defaultdict(collections.Counter)
    files = sorted(os.listdir(os.path.join(run_dir, "replayable-new-ipsm-paths")))
    length_mismatch = 0
    for f in files:
        ids, truncated = name_sequence(f)
        resp = replay.replies(os.path.join(run_dir, "replayable-new-ipsm-paths", f))
        codes = squeeze([START] + reply_codes(resp))
        if len(codes) != len(ids) and not (truncated and len(codes) > len(ids)):
            length_mismatch += 1
        for node, code in zip(ids, codes):
            votes[node][code] += 1
    mapping = {node: c.most_common(1)[0][0] for node, c in votes.items()}
    conflicts = {node: dict(c) for node, c in votes.items() if len(c) > 1}
    return mapping, conflicts, len(files), length_mismatch


def ipsm_edges(run_dir):
    edges = set()
    for line in open(os.path.join(run_dir, "ipsm.dot")):
        m = re.match(r"\s*(\d+)\s*->\s*(\d+)", line)
        if m:
            edges.add((int(m.group(1)), int(m.group(2))))
    return edges


def find_example(run_dir, a, b):
    """A session in the run's queue where reply b directly follows reply a."""
    qdir = os.path.join(run_dir, "replayable-queue")
    for f in sorted(os.listdir(qdir)):
        codes = [START] + reply_codes(replay.replies(os.path.join(qdir, f)))
        for i in range(1, len(codes)):
            if codes[i - 1] == a and codes[i] == b:
                return f, i
    return None, None


def main():
    ref = json.load(open(os.path.join(HERE, "results", "ref_graph.json")))
    ref_edges = {(a, b) for a, b, _ in ref["edges"]}
    report = []
    all_seen = set()
    for run_dir in sys.argv[1:]:
        run = os.path.basename(os.path.normpath(run_dir))
        mapping, conflicts, nfiles, mism = recover_mapping(run_dir)
        edges = ipsm_edges(run_dir)
        named = {(mapping.get(a, f"#{a}"), mapping.get(b, f"#{b}")) for a, b in edges}
        all_seen |= named
        report.append(f"== {run}: ipsm.dot has {len(edges)} edges, "
                      f"{len({x for e in edges for x in e})} nodes")
        report.append(f"  node -> reply code, from {nfiles} saved sessions "
                      f"({mism} with a different length on replay):")
        for node in sorted(mapping):
            c = f"  CONFLICT {conflicts[node]}" if node in conflicts else ""
            report.append(f"    {node:3} = {mapping[node]}{c}")
        unmapped = sorted({x for e in edges for x in e} - set(mapping))
        if unmapped:
            report.append(f"  nodes without a mapping: {unmapped}")
        extra = sorted(named - ref_edges)
        report.append(f"  edges in ipsm.dot: {len(named)}; also in the reference: {len(named & ref_edges)}; "
                      f"NOT allowed by the reference: {len(extra)}")
        for a, b in extra:
            f, i = find_example(run_dir, a, b)
            where = f"e.g. {f}, reply #{i}" if f else "no example in the queue"
            report.append(f"    {a} -> {b}   ({where})")
    missing = sorted(ref_edges - all_seen)
    report.append("")
    report.append(f"== reference edges never seen by AFLNet (both runs together): {len(missing)} "
                  f"of {len(ref_edges)}")
    by_src = collections.defaultdict(list)
    for a, b in missing:
        by_src[a].append(b)
    for a in sorted(by_src):
        report.append(f"    {a} -> {', '.join(by_src[a])}")
    text = "\n".join(report)
    print(text)
    with open(os.path.join(HERE, "results", "ipsm_compare.txt"), "w") as f:
        f.write(text + "\n")


if __name__ == "__main__":
    main()
