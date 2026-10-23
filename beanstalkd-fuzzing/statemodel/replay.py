#!/usr/bin/env python3
"""Replays AFLNet sessions (replayable-* files) against the server and caches its replies.

Every session runs on a fresh server process, as in fuzzing: the fuzzing build of beanstalkd
(beanstalkd-afl/beanstalkd, exits when the client disconnects) with -z 1024. The client sends the
whole session, reads until the server has been silent for QUIET seconds (or closes), and closes.
A server blocked in reserve simply sends nothing more.

usage: replay.py <replayable file or dir>...   (replies go to out/statemodel/replies/)
"""
import concurrent.futures
import os
import queue
import socket
import struct
import subprocess
import sys
import threading
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SERVER = os.path.join(ROOT, "beanstalkd-afl", "beanstalkd")
CACHE = os.path.join(ROOT, "out", "statemodel", "replies")
QUIET = 0.05
BASE_PORT = 12100
WORKERS = 4


def read_session(path):
    """Messages of a replayable file: (u32 length, data)*."""
    d, pos, msgs = open(path, "rb").read(), 0, []
    while pos + 4 <= len(d):
        n = struct.unpack("<I", d[pos:pos + 4])[0]
        msgs.append(d[pos + 4:pos + 4 + n])
        pos += 4 + n
    return msgs


def run_session(data, port):
    srv = subprocess.Popen([SERVER, "-p", str(port), "-l", "127.0.0.1", "-z", "1024"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(500):
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=1)
                break
            except OSError:
                time.sleep(0.005)
        else:
            raise RuntimeError("server did not start")
        s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        try:
            s.sendall(data)
        except OSError:
            pass                                    # server closed early (quit)
        got, start = b"", time.monotonic()
        while time.monotonic() - start < 3:
            s.settimeout(QUIET)
            try:
                chunk = s.recv(65536)
            except socket.timeout:
                break
            except OSError:
                break
            if not chunk:
                break
            got += chunk
        s.close()
        return got
    finally:
        try:
            srv.wait(timeout=2)
        except subprocess.TimeoutExpired:
            srv.kill()
            srv.wait()


def cache_path(path):
    run = os.path.basename(os.path.dirname(os.path.dirname(os.path.abspath(path))))
    kind = os.path.basename(os.path.dirname(os.path.abspath(path)))
    return os.path.join(CACHE, run, kind, os.path.basename(path) + ".resp")


def replies(path, port=BASE_PORT):
    """Server reply bytes for a replayable file (cached)."""
    out = cache_path(path)
    if os.path.exists(out):
        return open(out, "rb").read()
    got = run_session(b"".join(read_session(path)), port)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "wb") as f:
        f.write(got)
    return got


def replay_all(paths):
    todo = [p for p in paths if not os.path.exists(cache_path(p))]
    ports = queue.Queue()
    for i in range(WORKERS):
        ports.put(BASE_PORT + i)
    local = threading.local()

    def work(path):                     # each worker thread keeps its own port
        if not hasattr(local, "port"):
            local.port = ports.get()
        return replies(path, local.port)

    with concurrent.futures.ThreadPoolExecutor(WORKERS) as ex:
        list(ex.map(work, todo))
    return len(todo)


def main():
    paths = []
    for a in sys.argv[1:]:
        paths += sorted(os.path.join(a, f) for f in os.listdir(a)) if os.path.isdir(a) else [a]
    t = time.monotonic()
    n = replay_all(paths)
    print(f"replayed {n} sessions ({len(paths) - n} cached) in {time.monotonic() - t:.0f} s")


if __name__ == "__main__":
    main()
