"""Different question routes and bootstrap steps share one TCP budget."""
import argparse
import pathlib
import struct
import tempfile
import time
from dns_rule_support import DnsPeer, Echo, connect, exact, free_port, nexus_process, stream_request

parser = argparse.ArgumentParser()
parser.add_argument("binary", type=pathlib.Path)
parser.add_argument("--cache-options", action="store_true")
args = parser.parse_args()
with tempfile.TemporaryDirectory(prefix="nexus-question-deadline-") as directory, \
     DnsPeer() as first, DnsPeer() as second, DnsPeer() as bootstrap, Echo() as origin:
    root = pathlib.Path(directory)
    for named in (False, True):
        name = f"deadline-{int(named)}.rules.test"
        delay = .105 if named else .21
        first.delays[(name, 1)] = delay
        second.delays[(name, 28)] = delay
        bootstrap.delays = {("upstream.test", 1): delay, ("upstream.test", 28): delay}
        front = free_port()
        config = root / "server.kdl"
        options = 'rule domain-suffix="rules.test" action="route-options" disable-cache=#true;' if args.cache_options else ""
        config.write_text(f'''schema-version 1
role "server"
inbound "in" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct" {{ connect-timeout-ms 350; }}
routing {{ default-outbound "direct"; }}
dns {{
 server "first" type="udp" host="127.0.0.1" port={first.port};
 server "second" type="udp" host="{'upstream.test' if named else '127.0.0.1'}" port={second.port} {'domain-resolver="bootstrap"' if named else ''};
 server "bootstrap" type="udp" host="127.0.0.1" port={bootstrap.port};
 {options}
 rule query-type=1 server="first";
 rule query-type=28 server="second";
}}
''')
        with nexus_process(args.binary.resolve(), config):
            before = len(origin.accepted)
            with connect(front) as client:
                started = time.monotonic()
                client.sendall(b"\x05\x01\x00")
                if exact(client, 2) != b"\x05\x00":
                    raise RuntimeError("SOCKS greeting failed")
                raw = name.encode()
                client.sendall(b"\x05\x01\x00\x03" + bytes([len(raw)]) + raw + struct.pack("!H", origin.port))
                reply = exact(client, 10)
                elapsed = time.monotonic() - started
                if reply[1] != 6 or not .25 <= elapsed <= .8 or len(origin.accepted) != before:
                    raise RuntimeError(f"question deadline reset: named={named}, reply={reply!r}, elapsed={elapsed:.3f}")
            stream_request(front, origin.port, f"healthy-{int(named)}.rules.test")
        if not first.count(name, 1) or not second.count(name, 28):
            raise RuntimeError("deadline did not reach both question routes")
        if named and not all(bootstrap.count("upstream.test", kind) for kind in (1, 28)):
            raise RuntimeError("hostname bootstrap was not included in the deadline")
print("A/AAAA routes and DNS hostname bootstrap share one TCP deadline; later sessions recover")
