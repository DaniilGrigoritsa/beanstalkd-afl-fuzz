#!/usr/bin/env python3
"""Compares one seed's verification run with its reference run.

Traffic: every TCP session in fuzz.pcap (the fuzzer replaying the seed unchanged) is checked
against the seed and against the single session in ref.pcap (the unpatched server, a plain
client):
  - the client sent exactly the seed bytes;
  - the server's reply stream equals the reference one (fields that depend on time or on the
    process, such as pid and uptime, are masked);
  - the client closed the connection only after the server's last reply.
Coverage: per source line, the fuzz build's execution counts against N x the reference counts,
where N is the number of sessions (each session is one server process that saves its counters).
Lines are matched by their text, since the patch shifts line numbers in prot.c.

usage: compare.py <seed> <ref.pcap> <fuzz.pcap> <ref gcov dir> <fuzz gcov dir> <fuzzer_stats>
prints the report; exit code 1 if a traffic check fails.
"""
import difflib
import glob
import os
import re
import struct
import sys

# ------------------------------------------------------------------------------ pcap -> sessions


def read_pcap(path):
    data = open(path, "rb").read()
    magic = struct.unpack("<I", data[:4])[0]
    if magic not in (0xA1B2C3D4, 0xA1B23C4D):
        raise SystemExit(f"{path}: not a classic little-endian pcap (use dumpcap -P)")
    linktype = struct.unpack("<I", data[20:24])[0]
    pos, n = 24, 0
    while pos + 16 <= len(data):
        _, _, incl, _ = struct.unpack("<IIII", data[pos:pos + 16])
        pkt = data[pos + 16:pos + 16 + incl]
        pos += 16 + incl
        n += 1
        if linktype == 1:            # Ethernet (Linux loopback)
            if pkt[12:14] != b"\x08\x00":
                continue
            ip = pkt[14:]
        elif linktype == 113:        # Linux cooked capture
            ip = pkt[16:]
        else:
            raise SystemExit(f"{path}: unsupported link type {linktype}")
        if ip[0] >> 4 != 4 or ip[9] != 6:
            continue
        ihl = (ip[0] & 15) * 4
        tcp = ip[ihl:struct.unpack(">H", ip[2:4])[0]]
        sport, dport, seq = struct.unpack(">HHI", tcp[:8])
        off = (tcp[12] >> 4) * 4
        yield n, sport, dport, seq, tcp[13], tcp[off:]


class Session:
    def __init__(self):
        self.isn = {}                # direction -> initial sequence number
        self.data = {"c": {}, "s": {}}
        self.last_server_data = 0    # packet number
        self.client_close = None     # packet number of the client's first FIN/RST
        self.client_close_kind = None
        self.accepted = False        # the server answered the SYN (SYN-ACK)


def sessions(path, port):
    conns, order = {}, []
    for n, sport, dport, seq, flags, payload in read_pcap(path):
        if dport == port:
            key, d = sport, "c"
        elif sport == port:
            key, d = dport, "s"
        else:
            continue
        if flags & 0x02:             # SYN: a new session on this client port
            if d == "c":
                conns[key] = Session()
                conns[key].first_packet = n
                order.append(conns[key])
            if key in conns:
                conns[key].isn[d] = seq + 1
                if d == "s":
                    conns[key].accepted = True
            continue
        s = conns.get(key)
        if s is None or d not in s.isn:
            continue
        if payload:
            s.data[d].setdefault((seq - s.isn[d]) & 0xFFFFFFFF, payload)
            if d == "s":
                s.last_server_data = n
        if d == "c" and flags & 0x05 and s.client_close is None:   # FIN or RST
            s.client_close = n
            s.client_close_kind = "RST" if flags & 0x04 else "FIN"
    for s in order:
        for d in ("c", "s"):
            buf = b""
            for off in sorted(s.data[d]):
                chunk = s.data[d][off]
                if off <= len(buf):
                    buf += chunk[len(buf) - off:]
            s.data[d] = buf
    return order


VOLATILE = rb"pid|uptime|rusage-utime|rusage-stime|id|version|hostname|os|platform|age|time-left|pause-time-left"


def normalize(stream):
    stream = re.sub(rb"(?m)^(" + VOLATILE + rb"): .*$", rb"\1: *", stream)
    return re.sub(rb"(?m)^OK \d+\r$", b"OK *\r", stream)


# ------------------------------------------------------------------------------ gcov


FUNC_START = re.compile(r"^([A-Za-z_]\w*)\(")    # beanstalkd style: the name starts the line

# Functions still running when the process exits (main and the server loop never return). Clang's
# gcov derives line counts from branch counters, and for a function that has not returned they
# come out wrong (e.g. 0 for executed lines), differently in the two builds since they exit from
# different places. Their lines are left out of the comparison.
STILL_RUNNING_AT_EXIT = {"main", "srvserve"}


def read_gcov(path):
    """[(count or None, source text, function)] by line number; None = not executable."""
    lines, func = [], None
    for raw in open(path, errors="replace"):
        parts = raw.rstrip("\n").split(":", 2)
        if len(parts) < 3:
            continue
        cnt, num = parts[0].strip(), parts[1].strip()
        if not num.isdigit() or int(num) == 0:
            continue
        m = FUNC_START.match(parts[2])
        if m:
            func = m.group(1)
        if cnt == "-":
            c = None
        elif cnt.startswith("#") or cnt.startswith("="):
            c = 0
        else:
            c = int(cnt.rstrip("*"))
        lines.append((c, parts[2], func))
    return lines


def compare_coverage(ref_dir, fuzz_dir):
    """Returns (totals, N used for the counts, notes)."""
    pairs, patch_lines = [], []    # (file, ref line no., ref count, fuzz count, text, function)
    for rpath in sorted(glob.glob(os.path.join(ref_dir, "*.c.gcov"))):
        name = os.path.basename(rpath)[:-len(".gcov")]
        fpath = os.path.join(fuzz_dir, os.path.basename(rpath))
        if not os.path.exists(fpath):
            continue
        r, f = read_gcov(rpath), read_gcov(fpath)
        sm = difflib.SequenceMatcher(None, [t for _, t, _ in r], [t for _, t, _ in f], autojunk=False)
        matched_f = set()
        for a, b, size in sm.get_matching_blocks():
            for k in range(size):
                (rc, text, func), (fc, _, _) = r[a + k], f[b + k]
                matched_f.add(b + k)
                if rc is not None and fc is not None:
                    pairs.append((name, a + k + 1, rc, fc, text.strip(), func))
        for j, (fc, text, _) in enumerate(f):          # lines that only the patched source has
            if j not in matched_f and fc:
                patch_lines.append(f"    patch     {name}:{j + 1}  fuzz={fc}  |{text.strip()[:70]}")

    reliable = [p for p in pairs if p[5] not in STILL_RUNNING_AT_EXIT]
    # N = server processes that saved their counters: the usual fuzz/ref ratio, per source file.
    # (Each file has its own .gcda, written one after another at exit; when the fuzzer stops, the
    # last server process may be killed after writing only some of them.)
    ratios = {}
    for name, _, rc, fc, _, _ in reliable:
        if rc > 0 and fc > 0 and fc % rc == 0:
            r = ratios.setdefault(name, {})
            r[fc // rc] = r.get(fc // rc, 0) + 1
    n_file = {name: max(r, key=r.get) for name, r in ratios.items()}
    n = max(n_file.values(), default=0)

    totals = {"ref": 0, "fuzz": 0, "only_ref": 0, "only_fuzz": 0, "count_diff": 0,
              "skipped": len(pairs) - len(reliable)}
    notes, by_func, partial = [], {}, set()
    for name, line, rc, fc, text, func in reliable:
        nf = n_file.get(name, n)
        totals["ref"] += rc > 0
        totals["fuzz"] += fc > 0
        where = f"{name}:{line} {func}()"
        if rc > 0 and fc == 0:
            totals["only_ref"] += 1
            notes.append(f"    ONLY REF  {where}  ref={rc}  |{text[:60]}")
        elif fc > 0 and rc == 0:
            totals["only_fuzz"] += 1
            notes.append(f"    only fuzz {where}  fuzz={fc}  |{text[:60]}")
        elif rc > 0 and fc == (n - 1) * rc:
            partial.add(f"{name}:{func or '<file scope>'}()")          # saved by all processes but the last one
        elif rc > 0 and fc != nf * rc:
            totals["count_diff"] += 1
            g = by_func.setdefault((name, func), [0, set()])
            g[0] += 1
            g[1].add(round(fc / rc))
    for (name, func), (k, per) in sorted(by_func.items()):
        notes.append(f"    count     {name} {func}(): {k} lines run {', '.join(map(str, sorted(per)))} "
                     f"times per reference run instead of {n_file.get(name, n)}")
    if partial:
        notes.insert(0, f"    note      {len(partial)} functions saved by {n - 1} processes instead of {n}: "
                        f"the last server process was stopped while writing its counters "
                        f"({', '.join(sorted(partial)[:6])}{', ...' if len(partial) > 6 else ''})")
    return totals, n, notes + patch_lines


# ------------------------------------------------------------------------------ main


def cut_sessions(stats_path):
    for line in open(stats_path):
        if line.startswith("cut_sessions"):
            return int(line.split(":")[1])
    return None


def execs_done(stats_path):
    for line in open(stats_path):
        if line.startswith("execs_done"):
            return int(line.split(":")[1])
    return None


def main():
    seed_path, ref_pcap, fuzz_pcap, ref_gcov, fuzz_gcov, stats = sys.argv[1:7]
    port_ref, port_fuzz = int(os.environ.get("REF_PORT", 11950)), int(os.environ.get("FUZZ_PORT", 11951))
    seed = open(seed_path, "rb").read()
    ref = sessions(ref_pcap, port_ref)
    fuzz = sessions(fuzz_pcap, port_fuzz)
    name = os.path.basename(seed_path)
    print(f"== {name}")
    if len(ref) != 1 or ref[0].data["c"] != seed:
        print(f"  REFERENCE RUN BROKEN: {len(ref)} sessions")
        return 1
    want = normalize(ref[0].data["s"])

    def complete(s):
        return (s.data["c"] == seed and normalize(s.data["s"]) == want
                and s.client_close is not None and s.client_close > s.last_server_data)

    # The run ends with timeout -s INT: the session in flight at that moment is cut by stopping the
    # fuzzer, not by its logic. It is the last one, the fuzzer does not count it (execs_done is one
    # less), and what it sent is a prefix of the seed.
    # Connection attempts the server did not accept (no SYN-ACK: nothing listening). AFLNet retries
    # up to 1000 times when it cannot connect; this happens when the run is stopped while the
    # fork server is shutting down. They must all come after the last real session.
    refused = [s for s in fuzz if not s.accepted]
    fuzz = [s for s in fuzz if s.accepted]
    refused_at_end = all(r.first_packet > fuzz[-1].first_packet for r in refused) if refused and fuzz else True
    execs, stopped = execs_done(stats), None
    if fuzz and not complete(fuzz[-1]) and execs == len(fuzz) - 1 and seed.startswith(fuzz[-1].data["c"]):
        stopped = fuzz.pop()
    n = len(fuzz)
    sent_ok = sum(1 for s in fuzz if s.data["c"] == seed)
    reply_ok = sum(1 for s in fuzz if normalize(s.data["s"]) == want)
    close_ok = sum(1 for s in fuzz if s.client_close and s.client_close > s.last_server_data)
    kinds = {}
    for s in fuzz:
        kinds[s.client_close_kind] = kinds.get(s.client_close_kind, 0) + 1
    print(f"  sessions run by the fuzzer:            {n}  (execs_done {execs})")
    if refused:
        print(f"  + {len(refused)} connection attempts refused (no server listening), "
              f"{'all after the last session: the run was being stopped' if refused_at_end else 'DURING THE RUN'}")
    print(f"  fuzzer verdict: cut_sessions = {cut_sessions(stats)}")
    if stopped:
        print(f"  + 1 last session cut by stopping the fuzzer at the end of the run "
              f"(sent {len(stopped.data['c'])} of {len(seed)} B, not counted by the fuzzer)")
    print(f"  client sent the seed unchanged:        {sent_ok}/{n}")
    print(f"  server replies equal the reference:    {reply_ok}/{n}  ({len(ref[0].data['s'])} bytes)")
    print(f"  client closed after the last reply:    {close_ok}/{n}  (close: {kinds})")
    # execs_done may miss the last session if the fuzzer was stopped right after it
    ok = n > 0 and sent_ok == reply_ok == close_ok == n and execs in (n, n - 1) and refused_at_end
    if not ok:
        for i, s in enumerate(fuzz):
            if not complete(s):
                print(f"  FAIL first incomplete session #{i + 1}: sent {len(s.data['c'])} B, "
                      f"got {len(s.data['s'])} B")
                break
    totals, n_cov, notes = compare_coverage(ref_gcov, fuzz_gcov)
    print(f"  coverage: server processes that saved counters N = {n_cov} "
          f"(lines in {sorted(STILL_RUNNING_AT_EXIT)} skipped: {totals['skipped']})")
    print(f"  lines executed: reference {totals['ref']}, fuzz {totals['fuzz']}; "
          f"only in reference {totals['only_ref']}, only in fuzz {totals['only_fuzz']}, "
          f"count != N x reference: {totals['count_diff']}")
    for line in notes:
        print(line)
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
