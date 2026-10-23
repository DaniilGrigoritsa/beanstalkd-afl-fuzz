#!/usr/bin/env python3
"""Reference client: plays a seed against a server the way an ordinary client would.

It does not use AFLNet or its reply model. The seed is cut into messages by the protocol's own
framing (a command line ends with "\\r\\n"; a put line with a valid <bytes> takes the body and its
"\\r\\n" with it). After each message the client reads until the server has been silent for
--quiet ms; after the last one it waits --final ms (or until the server closes), then closes.

usage: ref_client.py <seed file> <port> [--quiet MS] [--final MS]
"""
import argparse
import re
import socket
import time

PUT = re.compile(rb"^put \d+ \d+ \d+ (\d+)$")


def messages(data):
    out, pos = [], 0
    while pos < len(data):
        eol = data.find(b"\r\n", pos)
        if eol < 0:
            out.append(data[pos:])
            break
        end = eol + 2
        m = PUT.match(data[pos:eol])
        if m:
            end = min(len(data), end + int(m.group(1)) + 2)
        out.append(data[pos:end])
        pos = end
    return out


def drain(sock, quiet_s, total_s):
    """Read until the server is silent for quiet_s, closes, or total_s passes."""
    got, start = b"", time.monotonic()
    while time.monotonic() - start < total_s:
        sock.settimeout(quiet_s)
        try:
            chunk = sock.recv(65536)
        except socket.timeout:
            break
        if not chunk:
            return got, True
        got += chunk
    return got, False


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("seed")
    ap.add_argument("port", type=int)
    ap.add_argument("--quiet", type=int, default=20)
    ap.add_argument("--final", type=int, default=200)
    a = ap.parse_args()
    data = open(a.seed, "rb").read()
    s = socket.create_connection(("127.0.0.1", a.port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    closed = False
    for msg in messages(data):
        s.sendall(msg)
        _, closed = drain(s, a.quiet / 1000, 2.0)
        if closed:
            break
    if not closed:
        drain(s, a.final / 1000, 5.0)
    s.close()


if __name__ == "__main__":
    main()
