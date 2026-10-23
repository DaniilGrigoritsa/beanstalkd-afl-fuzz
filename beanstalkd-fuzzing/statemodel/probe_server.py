#!/usr/bin/env python3
"""Black-box probes behind the server differences in RULES.md section 6.

Each probe goes to a fresh server (the fuzzing build, -z 1024, as in fuzzing); the reply codes
are printed next to what the spec (protocol.txt) requires. The server code is not used.

usage: probe_server.py   -> results/probes.txt
"""
import os
import socket
import subprocess
import time

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
SERVER = os.path.join(ROOT, "beanstalkd-afl", "beanstalkd")
HERE = os.path.dirname(os.path.abspath(__file__))

# (difference, bytes sent, what the spec requires)
PROBES = [
    ("ambiguous: NUL", b"foo\x00bar\r\n", "UNKNOWN_COMMAND or BAD_FORMAT (not a text line)"),
    ("ambiguous: NUL", b"fo\x80o\r\n", "UNKNOWN_COMMAND"),
    ("prefix", b"stats\r\n", "OK"),
    ("prefix", b"statsX\r\n", "UNKNOWN_COMMAND (unknown name 'statsX')"),
    ("prefix", b"peek-readyX\r\n", "UNKNOWN_COMMAND"),
    ("prefix", b"list-tubesX\r\n", "UNKNOWN_COMMAND"),
    ("prefix", b"reserveX\r\n", "UNKNOWN_COMMAND"),
    ("prefix", b"pause-tubeX a 0\r\n", "UNKNOWN_COMMAND"),
    ("prefix", b"quitX\r\nstats\r\n", "UNKNOWN_COMMAND, OK"),
    ("prefix", b"quit 1\r\nstats\r\n", "BAD_FORMAT, OK (quit takes no arguments)"),
    ("no-space", b"watch\r\n", "BAD_FORMAT (known command, missing argument)"),
    ("no-space", b"use\r\n", "BAD_FORMAT"),
    ("no-space", b"watch \r\n", "BAD_FORMAT"),
    ("no-space", b"watchX a\r\n", "UNKNOWN_COMMAND"),
    ("trailing-junk", b"kick 1X\r\n", "BAD_FORMAT (non-numeric character in an integer)"),
    ("trailing-junk", b"kick 1 0\r\n", "BAD_FORMAT (wrong number of arguments)"),
    ("trailing-junk", b"reserve-with-timeout 0X\r\n", "BAD_FORMAT"),
    ("trailing-junk", b"reserve-with-timeout 0 0\r\n", "BAD_FORMAT"),
    ("trailing-junk", b"delete 1X\r\n", "BAD_FORMAT"),
    ("trailing-junk", b"touch 1 0\r\n", "BAD_FORMAT"),
    ("framing", b"stats\r\n", "OK"),
    ("framing", b"foo\rbar\r\nstats\r\n", "UNKNOWN_COMMAND, OK"),
    ("framing", b"stats\r\nfoo\rbar\r\nstats\r\n", "OK, UNKNOWN_COMMAND, OK"),
    ("framing", b"a\rb\r\n" + b"x" * 300 + b"\r\nstats\r\n", "UNKNOWN_COMMAND, BAD_FORMAT, OK"),
    ("too-big-first", b"put 0 0 60 5 7\r\nhello\r\nstats\r\n", "BAD_FORMAT, UNKNOWN_COMMAND, OK"),
    ("too-big-first", b"put 0 0 60 2000 7\r\nhello\r\nstats\r\n", "BAD_FORMAT, UNKNOWN_COMMAND, OK"),
    ("too-big-first", b"put 0 0 60 2000X\r\nhello\r\nstats\r\n", "BAD_FORMAT, UNKNOWN_COMMAND, OK"),
    ("ambiguous: limit", b"reserve-with-timeout 2147483648\r\n", "no limit given: TIMED_OUT, or BAD_FORMAT if the server has one"),
]


def probe(data, port):
    srv = subprocess.Popen([SERVER, "-p", str(port), "-l", "127.0.0.1", "-z", "1024"],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(400):
            try:
                s = socket.create_connection(("127.0.0.1", port))
                break
            except OSError:
                time.sleep(0.005)
        s.settimeout(0.3)
        s.sendall(data)
        got, end = b"", "silent"
        try:
            while True:
                chunk = s.recv(65536)
                if not chunk:
                    end = "closed"
                    break
                got += chunk
        except socket.timeout:
            pass
        s.close()
    finally:
        srv.wait(timeout=2)
    codes, pos = [], 0
    while True:
        eol = got.find(b"\r\n", pos)
        if eol < 0:
            break
        parts = got[pos:eol].split(b" ")
        codes.append(parts[0].decode("latin1"))
        pos = eol + 2
        if parts[0] in (b"OK", b"FOUND", b"RESERVED") and parts[-1].isdigit():
            pos += int(parts[-1]) + 2
    return ", ".join(codes) or "-", end


def main():
    lines = [f"{'difference':17} {'sent':44} {'server':38} spec requires"]
    for i, (kind, data, spec) in enumerate(PROBES):
        codes, end = probe(data, 12700 + i)
        shown = repr(data if len(data) < 44 else data[:20] + b"..." + data[-15:])[2:-1]
        lines.append(f"{kind:17} {shown:44} {codes + ' (' + end + ')':38} {spec}")
    text = "\n".join(lines)
    print(text)
    with open(os.path.join(HERE, "results", "probes.txt"), "w") as f:
        f.write(text + "\n")


if __name__ == "__main__":
    main()
