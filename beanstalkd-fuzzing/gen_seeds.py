#!/usr/bin/env python3
# Generate AFLNet seed files for beanstalkd: one file = one client->server TCP stream.

import os, sys

def put(body, pri=0, delay=0, ttr=60, size=None):
    b = body if isinstance(body, bytes) else body.encode()
    n = len(b) if size is None else size
    return b"put %d %d %d %d\r\n" % (pri, delay, ttr, n) + b + b"\r\n"

def cmd(s):
    return s.encode() + b"\r\n"

SEEDS = {
    # basic job lifecycle: put -> reserve -> delete
    "01_lifecycle": [put("hello"), cmd("reserve-with-timeout 0"), cmd("delete 1")],
    # release / bury / kick / touch
    "02_release_bury_kick": [
        put("job-a", pri=5), put("job-b", pri=1),
        cmd("reserve-with-timeout 0"), cmd("touch 2"), cmd("release 2 10 0"),
        cmd("reserve-with-timeout 0"), cmd("bury 1 3"), cmd("kick 5"),
        cmd("reserve-job 1"), cmd("delete 1")],
    # tubes: use / watch / ignore / pause (0 s = the 1 ns pause, see FUZZ_DETERMINISTIC)
    "03_tubes": [
        cmd("use emails"), put("mail-1"), cmd("watch emails"), cmd("ignore default"),
        cmd("reserve-with-timeout 0"), cmd("pause-tube emails 0"),
        cmd("list-tubes"), cmd("list-tube-used"), cmd("list-tubes-watched"),
        cmd("delete 1")],
    # peek family and statistics
    "04_peek_stats": [
        put("x"), put("y", delay=100), put("z"),
        cmd("peek 1"), cmd("peek-ready"), cmd("peek-delayed"), cmd("peek-buried"),
        cmd("reserve-with-timeout 0"), cmd("bury 1 0"), cmd("peek-buried"),
        cmd("kick-job 1"), cmd("stats-job 1"), cmd("stats-tube default"), cmd("stats")],
    # error handling: bad formats, unknown commands, no CRLF after the body
    # ("abcde" for 3 bytes: "de" is where the CRLF should be -> EXPECTED_CRLF)
    "05_errors": [
        cmd("foo"), cmd("put a b c d"), b"put 0 0 1 3\r\nabcde", cmd("delete 999"),
        cmd("use " + "x" * 201), cmd("release 1"), cmd("watch "), cmd("reserve-with-timeout x"),
        put("ok-after-errors"), cmd("quit")],
    # delayed jobs: kick moves delayed jobs to ready when nothing is buried
    "06_delayed_kick": [
        put("d1", delay=50), put("d2", delay=60), cmd("stats-job 1"), cmd("peek-delayed"),
        cmd("kick-job 2"), cmd("kick 10"), cmd("reserve-with-timeout 0"),
        cmd("release 1 0 30"), cmd("stats-tube default"), cmd("peek-delayed"),
        cmd("delete 1"), cmd("delete 2")],
    # several tubes; paused tube "a" is skipped by reserve, ignoring the last watched tube
    # (NOT_IGNORED); kick only looks in the used tube
    "07_multi_tube": [
        cmd("use a"), put("in-a"), cmd("use b"), put("in-b", pri=1), cmd("watch a"),
        cmd("watch b"), cmd("pause-tube a 1"), cmd("reserve-with-timeout 0"),
        cmd("ignore default"), cmd("ignore a"), cmd("ignore b"), cmd("stats-tube a"),
        cmd("stats-tube b"), cmd("list-tubes"), cmd("use a"), cmd("bury 2 0"), cmd("kick 1"),
        cmd("use b"), cmd("kick 1"), cmd("stats-job 2")],
    # job bodies: empty, with CRLF inside, binary, too big
    "08_bodies": [
        put(""), put(b"a\r\nb\r\n"), put(b"\x00\xff" * 8, pri=4294967295),
        cmd("peek 1"), cmd("peek 2"), cmd("reserve-job 3"), cmd("stats-job 3"),
        cmd("delete 3"), cmd("peek-ready"),
        # > max job size (the run scripts start beanstalkd with -z 1024): the server reads and
        # discards the body, answers JOB_TOO_BIG and goes on with the next command
        put("A" * 1025), cmd("peek-ready")],
    # ttr of 0 becomes 1 s: with no ready job, the next reserve answers DEADLINE_SOON
    "09_deadline": [
        put("t1", ttr=0), cmd("reserve-with-timeout 0"), cmd("reserve-with-timeout 0"),
        cmd("touch 1"), cmd("stats-job 1"), cmd("release 1 0 0"), put("t2", ttr=0),
        cmd("reserve-job 2"), cmd("bury 2 1"), cmd("stats")],
}

out = sys.argv[1] if len(sys.argv) > 1 else "seeds"
os.makedirs(out, exist_ok=True)
for name, msgs in SEEDS.items():
    with open(os.path.join(out, name + ".raw"), "wb") as f:
        f.write(b"".join(msgs))
print("wrote", len(SEEDS), "seeds to", out)
