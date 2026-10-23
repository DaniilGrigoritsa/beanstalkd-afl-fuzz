#!/usr/bin/env python3
"""Source-level view of rare instability events caught during calibration.

The debug afl-fuzz (out/stability/aflnet-dbg, CALIB_DEBUG_DIR) writes a dump when a calibration
run's trace differs from the input's first run: the input, the fork server pid and the global
execution numbers of both runs. Calibration runs on the coverage build, so every execution's
profile is appended, in order, to <profile dir>/<fork server pid>.profraw. This script takes the
two executions out of that file and lists the source lines whose counts differ.

usage: rare_events.py <dump dir> <profile dir> [--binary BIN]
"""
import argparse
import glob
import os
import re

import analyze


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dumps")
    ap.add_argument("profiles")
    ap.add_argument("--binary", default=os.path.join(analyze.ROOT, "out", "stability", "build", "beanstalkd"))
    a = ap.parse_args()
    for d in sorted(f for f in glob.glob(os.path.join(a.dumps, "var-*")) if not f.endswith(".resp")):
        text = open(d).read()
        pid = int(re.search(r"forkserver (\d+)", text).group(1))
        first, this = map(int, re.search(r"execution: first (\d+), this (\d+)", text).groups())
        data_file = os.path.join(a.profiles, f"{pid}.profraw")
        runs = analyze.executions_of_file(data_file)
        print(f"== {os.path.basename(d)}: {text.splitlines()[0].split('/')[-1]}, "
              f"{text.splitlines()[1]}; {re.search(r'replies: .*', text).group(0)}")
        print(f"   profile has {len(runs)} executions; comparing execution {first} with {this}")
        if this > len(runs):
            print("   (not in the profile)")
            continue
        c1, funcs = analyze.line_counts(runs[first - 1], a.binary)
        c2, _ = analyze.line_counts(runs[this - 1], a.binary)
        diff = sorted(k for k in set(c1) | set(c2) if c1.get(k, 0) != c2.get(k, 0))
        by_func = {}
        for k in diff:
            by_func.setdefault((k[0], funcs.get(k)), []).append((k[1], c1.get(k, 0), c2.get(k, 0)))
        for (src, fn), lines in sorted(by_func.items(), key=lambda kv: (kv[0][0], str(kv[0][1]))):
            shown = ", ".join(f"{l}: {x}->{y}" for l, x, y in lines[:6])
            print(f"   {src}:{fn}  {len(lines)} lines  ({shown}{' ...' if len(lines) > 6 else ''})")


if __name__ == "__main__":
    main()
