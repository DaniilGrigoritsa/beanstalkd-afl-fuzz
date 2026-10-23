#!/usr/bin/env python3
"""Finds the source lines whose execution counts change between runs of the same input.

Input: the directories written by measure.sh. All server processes of one input append their raw
LLVM profiles to one file (LLVM_PROFILE_FILE's %p is expanded once, in the fork server, before it
forks); the file is cut back into executions at each raw-profile header.

For a sample of executions per input, line counts come from llvm-cov. A line is "unstable" when
its count is not the same in all executions; it matters for AFL when the count falls into
different AFL hit-count buckets (1, 2, 3, 4-7, 8-15, 16-31, 32-127, 128+), because then the
trace differs and AFL lowers its stability.

usage: analyze.py <measure.sh out dir> [--sample N] [--binary BIN] [--json FILE]
"""
import argparse
import collections
import concurrent.futures
import glob
import json
import os
import subprocess
import tempfile

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MAGIC = b"\x81rforpl\xff"           # raw profile header (0xff6c70726f667281, little endian)


def bucket(c):
    for b, lim in ((0, 0), (1, 1), (2, 2), (3, 3), (4, 7), (5, 15), (6, 31), (7, 127)):
        if c <= lim:
            return b
    return 8


def executions_of_file(path):
    """Raw profiles in one file, in the order the executions ended."""
    data = open(path, "rb").read()
    starts = []
    i = data.find(MAGIC)
    while i >= 0:
        starts.append(i)
        i = data.find(MAGIC, i + 1)
    return [data[a:b] for a, b in zip(starts, starts[1:] + [len(data)])]


def executions(prof_dir, first=0):
    """Raw profiles of the executions, in the order they ended; with first > 0 only the first
    executions of each profile file (each file is one afl-fuzz run)."""
    out = []
    for f in sorted(glob.glob(os.path.join(prof_dir, "*.profraw"))):
        data = open(f, "rb").read()
        starts = []
        i = data.find(MAGIC)
        while i >= 0:
            starts.append(i)
            i = data.find(MAGIC, i + 1)
        runs = [data[a:b] for a, b in zip(starts, starts[1:] + [len(data)])]
        out += runs[:first] if first else runs
    return out


def line_counts(raw, binary):
    """{(file, line): count} and {(file, line): function} for one execution."""
    with tempfile.TemporaryDirectory() as d:
        p, pd = os.path.join(d, "x.profraw"), os.path.join(d, "x.profdata")
        open(p, "wb").write(raw)
        subprocess.run(["llvm-profdata", "merge", "-o", pd, p], check=True, capture_output=True)
        lcov = subprocess.run(["llvm-cov", "export", "-format=lcov", "-instr-profile", pd, binary],
                              check=True, capture_output=True, text=True).stdout
    counts, funcs, src, fn_starts = {}, {}, None, []
    for line in lcov.splitlines():
        if line.startswith("SF:"):
            src, fn_starts = os.path.basename(line[3:]), []
        elif line.startswith("FN:"):
            num, name = line[3:].split(",", 1)
            fn_starts.append((int(num), name))
        elif line.startswith("DA:"):
            num, cnt = line[3:].split(",")[:2]
            counts[(src, int(num))] = int(cnt)
            name = None
            for start, fname in sorted(fn_starts):
                if start <= int(num):
                    name = fname
            funcs[(src, int(num))] = name
    return counts, funcs


def analyze_input(d, sample, binary, first=0):
    runs = executions(os.path.join(d, "prof"), first)
    if len(runs) > sample:                         # evenly spread over the whole replay
        step = len(runs) / sample
        runs = [runs[int(i * step)] for i in range(sample)]
    per_line, funcs = collections.defaultdict(list), {}
    for raw in runs:
        c, f = line_counts(raw, binary)
        funcs.update(f)
        for k, v in c.items():
            per_line[k].append(v)
    unstable = {}
    for k, vals in per_line.items():
        if len(set(vals)) > 1:
            unstable[k] = {"min": min(vals), "max": max(vals),
                           "afl": len({bucket(v) for v in vals}) > 1,
                           "values": collections.Counter(vals).most_common(4)}
    return os.path.basename(d), len(runs), unstable, funcs


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--sample", type=int, default=60)
    ap.add_argument("--binary", default=os.path.join(ROOT, "out", "stability", "build", "beanstalkd"))
    ap.add_argument("--json")
    ap.add_argument("--first", type=int, default=0,
                    help="use only the first N executions of each profile file (MODE=calib: 8)")
    a = ap.parse_args()
    dirs = sorted(d for d in glob.glob(os.path.join(a.dir, "*")) if os.path.isdir(os.path.join(d, "prof")))
    with concurrent.futures.ProcessPoolExecutor(4) as ex:
        results = list(ex.map(analyze_input, dirs, [a.sample] * len(dirs), [a.binary] * len(dirs),
                              [a.first] * len(dirs)))

    by_line = collections.defaultdict(lambda: {"inputs": 0, "afl_inputs": 0, "example": None})
    funcs = {}
    print(f"{'input':34} runs  unstable lines (changing the AFL trace)")
    for name, n, unstable, f in results:
        funcs.update(f)
        afl = sum(1 for u in unstable.values() if u["afl"])
        print(f"{name:34} {n:4}  {len(unstable):4} ({afl})")
        for k, u in unstable.items():
            e = by_line[k]
            e["inputs"] += 1
            e["afl_inputs"] += u["afl"]
            if e["example"] is None or u["afl"]:
                e["example"] = (name, u["values"])
    print()
    by_func = collections.defaultdict(lambda: [0, 0, set()])
    for (src, line), e in by_line.items():
        g = by_func[(src, funcs.get((src, line)))]
        g[0] += 1
        g[1] = max(g[1], e["afl_inputs"])
        g[2].add(line)
    print(f"{'file':8} {'function':28} lines  inputs where the AFL trace changes")
    for (src, fn), (k, afl_inputs, lines) in sorted(by_func.items(), key=lambda kv: (-kv[1][1], -kv[1][0])):
        print(f"{src:8} {str(fn):28} {k:5}  {afl_inputs:3}   lines {min(lines)}-{max(lines)}")
    if a.json:
        json.dump({"inputs": [(n, runs, len(u)) for n, runs, u, _ in results],
                   "lines": [{"file": s, "line": l, "function": funcs.get((s, l)), **e}
                             for (s, l), e in sorted(by_line.items())]},
                  open(a.json, "w"), indent=1, default=str)


if __name__ == "__main__":
    main()
