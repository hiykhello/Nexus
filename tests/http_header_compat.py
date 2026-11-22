#!/usr/bin/env python3
"""Compare two builds of http-header-compat-fixture on a deterministic corpus."""
import argparse
import random
import subprocess


def corpus():
    rng = random.Random(0x48545450)
    common = [b"Host: example.test", b"X-Test: value", b"x-X:  \tval\t ", b"Connection: X-Remove",
              b"X-Remove: secret", b"Connection: ,", b"Connection: Host", b"Connection: a,,b",
              b"Content-Length: 1", b"Content-Length: 0", b"Transfer-Encoding: chunked",
              b"Expect: 100-continue", b"Expect: other", b"Upgrade: websocket", b"Proxy-Authorization: x",
              b"X@Bad: x", b"X : x", b" : x", b"missing colon", b"X: v\x00x", b"X: v\x7fx",
              b"X: v\xffx", b"X:\t ", b"X: bad\rvalue", b"X: bad\nvalue", b"\tcontinued"]
    starts = {
        "C": [b"CONNECT example.test:443 HTTP/1.1", b"GET http://example.test/ HTTP/1.1",
              b"CONNECT [::1]:443 HTTP/1.1", b"CONNECT bad HTTP/1.1", b"CONNECT example.test:0 HTTP/1.1",
              b"CONNECT example.test:443 HTTP/1.0", b"CONNECT example.test:443 HTTP/1.1 extra"],
        "F": [b"GET http://example.test/path HTTP/1.1", b"POST http://example.test/?q=1 HTTP/1.1",
              b"HEAD http://example.test/ HTTP/1.1", b"CONNECT example.test:443 HTTP/1.1",
              b"GET http://127.1/ HTTP/1.1", b"GET http://example.test/%xx HTTP/1.1", b"bad start"],
        "R": [b"HTTP/1.1 200 OK", b"HTTP/1.0 200 OK", b"HTTP/1.1 204 No Content", b"HTTP/1.1 304 Not Modified",
              b"HTTP/1.1 100 Continue", b"HTTP/1.1 101 Upgrade", b"HTTP/1.1 205 Reset Content", b"HTTP/1.1 999 X"],
    }
    rows = []
    def add(kind, data, mode="2"):
        rows.append((kind, mode, data))
    def header(first, fields, tail=b"\r\n\r\nTAIL"):
        return first + (b"\r\n" + b"\r\n".join(fields) if fields else b"") + tail
    for kind, lines in starts.items():
        for first in lines:
            add(kind, header(first, []), "1")
            for field in common:
                add(kind, header(first, [b"Host: example.test", field]), "1")
        for n in [0, 1, 99, 100, 101, 102]:
            add(kind, header(lines[0], [b"Host: example.test"] + [b"X: a"] * n), "3")
        for n in [8191, 8192, 8193]:
            add(kind, header(lines[0], [b"Host: example.test", b"X:" + b"a" * (n-2)]), "3")
            add(kind, header(b"X" * n, [b"Host: example.test"]), "3")
        for n in [16383, 16384, 16385]:
            add(kind, b"x" * n, "3")
            add(kind, header(lines[0], [b"Host: example.test", b"X:" + b"a" * (n-len(lines[0])-len(b"\r\nHost: example.test\r\nX:")-4)], b"\r\n\r\n"), "3")
        for byte in range(256):
            add(kind, header(lines[0], [b"Host: example.test", b"X-" + bytes([byte]) + b": v"]))
            add(kind, header(lines[0], [b"Host: example.test", b"X: \t" + bytes([byte]) + b" \t"]))
        for _ in range(2200):
            first = rng.choice(lines)
            fields = [rng.choice(common) for _ in range(rng.randrange(0, 7))]
            if rng.randrange(5) != 0:
                fields.insert(rng.randrange(len(fields) + 1), b"Host: example.test")
            data = header(first, fields, rng.choice([b"\r\n\r\nTAIL", b"\r\n\r\n", b"\r\n", b"", b"\n\n"]))
            if data and rng.randrange(3) == 0:
                index = rng.randrange(len(data))
                data = data[:index] + rng.choice([b"", bytes([rng.randrange(256)]), b"\r\n"]) + data[index+1:]
            add(kind, data, rng.choice("123"))
    # HEAD and regular responses differ in body framing.
    for kind, mode, data in list(rows):
        if kind == "R" and (len(data) < 2048 or mode == "3"):
            add("H", data, mode)
    trailer_names = [b"X-Ok", b"Content-Length", b"transfer-encoding", b"Host", b"Connection", b"Keep-Alive",
                     b"Proxy-Authenticate", b"Proxy-Authorization", b"Trailer", b"Upgrade", b"bad name", b""]
    for name in trailer_names:
        for value in [b"ok", b" \t", b"v\x00x", b"v\x7fx", b"v\xffx"]:
            add("T", b"1\r\na\r\n0\r\n" + name + b": " + value + b"\r\n\r\nTAIL", "1")
    for n in [0, 1, 99, 100, 101]:
        add("T", b"0\r\n" + b"X: a\r\n" * n + b"\r\nTAIL", "3")
    for n in [8191, 8192, 8193]:
        add("T", b"0\r\nX:" + b"a" * (n-2) + b"\r\n\r\nTAIL", "3")
    for byte in range(256):
        add("T", b"0\r\nX: \t" + bytes([byte]) + b" \t\r\n\r\nTAIL")
    for _ in range(1600):
        fields = [rng.choice(common) for _ in range(rng.randrange(0, 8))]
        data = b"0\r\n" + b"\r\n".join(fields) + rng.choice([b"\r\n\r\nTAIL", b"\r\n", b"", b"\n\n"])
        add("T", data, rng.choice("123"))
    return rows


def run(path, payload):
    result = subprocess.run([path], input=payload, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
    return result.stdout.splitlines()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("baseline")
    parser.add_argument("candidate")
    args = parser.parse_args()
    rows = corpus()
    payload = b"".join(kind.encode() + mode.encode() + data.hex().encode() + b"\n" for kind, mode, data in rows)
    baseline = run(args.baseline, payload)
    candidate = run(args.candidate, payload)
    if len(baseline) != len(rows) or len(candidate) != len(rows):
        raise RuntimeError(f"fixture output count: corpus={len(rows)}, baseline={len(baseline)}, candidate={len(candidate)}")
    for i, (old, new) in enumerate(zip(baseline, candidate)):
        if old != new:
            kind, mode, data = rows[i]
            raise AssertionError(f"case {i}, {kind}{mode}, input={data!r}\nbaseline={old!r}\ncandidate={new!r}")
    print(f"HTTP header compatibility: {len(rows)} cases matched, including parser allocations and fragmented decoders")


if __name__ == "__main__":
    main()
