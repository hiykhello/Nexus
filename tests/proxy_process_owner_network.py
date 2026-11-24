"""Exercise Linux executable predicates with real TCP endpoint ownership."""

import argparse
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
from pathlib import Path

from detour_network import exact, reserve, running


CLIENT = r"""
import ctypes, socket, struct, sys
from detour_network import exact

mode, host, listen, origin, inherited = sys.argv[1:]
if mode == "hidden":
    assert ctypes.CDLL(None).prctl(4, 0, 0, 0, 0) == 0  # PR_SET_DUMPABLE
if mode.startswith("redirect"):
    try:
        with socket.create_connection((host, int(listen)), timeout=4) as client:
            client.sendall(b"redirect")
            if mode == "redirect":
                assert exact(client, 5) == b"reply"
            else:
                assert client.recv(1) == b""
    except ConnectionResetError:
        assert mode == "redirect-deny"
    print("0")
    raise SystemExit(0)
family = socket.AF_INET6 if ":" in host else socket.AF_INET
fd = int(inherited)
if mode == "received":
    with socket.socket(fileno=fd) as channel:
        message, (fd,), _, _ = socket.recv_fds(channel, 1, 1)
        assert message == b"F" and channel.recv(2) == b"go"
with (socket.socket(family) if fd < 0 else socket.socket(fileno=fd)) as client:
    client.settimeout(4)
    client.connect((host, int(listen)))
    client.sendall(b"\x05\x01\x00")
    assert exact(client, 2) == b"\x05\x00"
    client.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01" + struct.pack("!H", int(origin)))
    reply = exact(client, 4)
    exact(client, 6 if reply[3] == 1 else 18)
    if reply[1] == 0:
        client.sendall(b"owned")
        assert exact(client, 5) == b"reply"
    else:
        assert reply[1] == 2, reply
    print(reply[1], flush=True)
"""


def complete(client, expected):
    output, errors = client.communicate(timeout=5)
    assert client.returncode == 0 and output.strip() == expected, (output, errors)


def check_route(binary, root, first, second, ordered, regex=False, srs_compiler=None):
    frontend = reserve()
    with socket.socket(socket.AF_INET6) as reservation:
        reservation.bind(("::1", 0))
        frontend6 = reservation.getsockname()[1]
    control = root / "control.sock"
    config = root / "proxy.kdl"
    path_type = "process-path-regex" if regex else "process-path"
    path_value = "^" + "".join("\\" + b if b in r"\.^$|?*+()[]{}" else b for b in str(first)) + "$" if regex else str(first)
    (root / "process.kdl").write_text(
        f'schema-version 2\nkind "predicate"\nrule type="and" {{\n'
        f'  rule type="{path_type}" value={json.dumps(path_value)}\n'
        f'  rule type="process-name" value={json.dumps(first.name)}\n'
        '}\n'
    )
    file, format_name = "process.kdl", "kdl"
    if srs_compiler:
        file, format_name = "process.srs", "srs"
        source = root / "process.json"
        source.write_text(json.dumps({"version": 5, "rules": [{
            "process_name": [first.name, second.name],
            "process_path": [str(first), str(second)],
            "process_path_regex": [path_value[:-1] + "{1}$", r"^/never/matches$"],
        }]}))
        subprocess.run([srs_compiler, "rule-set", "compile", source, "-o", root / file], check=True)
        for fmt in ("kdl", "beve"):
            subprocess.run([binary, "rule", "convert", "srs", fmt, root / file, root / f"converted-{int(ordered)}.{fmt}"],
                           check=True, timeout=4)
        if not ordered:
            source.write_text(json.dumps({"version": 5, "rules": [{"process_path_regex": r"^/tmp/.{2}$"}]}))
            rejected = root / "rune.srs"
            subprocess.run([srs_compiler, "rule-set", "compile", source, "-o", rejected], check=True)
            invalid = subprocess.run([binary, "rule", "convert", "srs", "kdl", rejected, root / "rune.kdl"],
                                     capture_output=True, timeout=4)
            if not invalid.returncode or b"must consume only ASCII" not in invalid.stderr:
                raise RuntimeError(f"SRS rune-counting regex accepted: {invalid.stderr!r}")
    (root / "other.kdl").write_text(
        f'schema-version 2\nkind "predicate"\n'
        f'rule type="not" {{ rule type="process-name" value={json.dumps(first.name)}; }}\n'
    )
    other_set = '' if ordered else 'rule-set "other" path="other.kdl" format="kdl"'
    if ordered:
        route = '''tcp-program sniff-timeout-ms=50 unknown="skip" {
            rule action="route" rule-set="first" outbound="direct"
            rule action="reject"
        }'''
    else:
        route = '''rules {
            - kind="rule-set" value="first" outbound="direct"
            - kind="rule-set" value="other" outbound="deny"
        }'''
    config.write_text(f'''schema-version 1
role "client"
workers 2
control socket="{control}"
inbounds {{
    mixed "four" {{ listen host="127.0.0.1" port={frontend}; authentication "none"; }}
    socks5 "six" {{ listen host="::1" port={frontend6}; authentication "none"; }}
}}
outbounds {{ direct "direct"; block "deny"; }}
routing {{
    rule-set "first" path="{file}" format="{format_name}"
    {other_set}
    {route}
    default-outbound "direct"
}}
''')
    with socket.socket() as origin:
        origin.bind(("127.0.0.1", 0))
        origin.listen()
        origin.settimeout(5)
        target = origin.getsockname()[1]
        with running([binary, "run", "--config", str(config)], frontend, root / "proxy.log"):
            def start(image, mode="normal", host="127.0.0.1", port=frontend, inherited=-1, other_mount=False):
                command = ["unshare", "-m", "--"] if other_mount else []
                return subprocess.Popen(
                    [*command, str(image), "-c", CLIENT, mode, host, str(port), str(target), str(inherited)],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                    pass_fds=(inherited,) if inherited >= 0 else (),
                )

            def allowed(client, listener, observed):
                with origin.accept()[0] as peer:
                    peer.settimeout(5)
                    assert exact(peer, 5) == b"owned"
                    rows = subprocess.check_output(
                        [binary, "control", str(control), "connections", str(listener)], timeout=4, text=True
                    )
                    row = [line for line in rows.splitlines() if line.startswith("id=")][-1]
                    assert ("process-path=" in row) == observed, rows
                    if observed:
                        assert 'process-path=' + json.dumps(str(first)) in row, rows
                    peer.sendall(b"reply")
                complete(client, "0")

            for host, port, index in (("127.0.0.1", frontend, 0), ("::ffff:127.0.0.1", frontend, 0), ("::1", frontend6, 1)):
                with start(first, host=host, port=port) as client:
                    allowed(client, index, True)
            with start(second) as client:
                complete(client, "2")
            with start(second, "hidden") as client:
                if ordered:
                    complete(client, "2")
                else:
                    allowed(client, 0, False)
            with start(second, other_mount=True) as client:
                if ordered:
                    complete(client, "2")
                else:
                    allowed(client, 0, False)
            with socket.socket() as shared, start(second, inherited=shared.fileno()) as client:
                if ordered:
                    complete(client, "2")
                else:
                    allowed(client, 0, False)
            sender, receiver = socket.socketpair(type=socket.SOCK_SEQPACKET)
            with sender, receiver, start(first, "received", inherited=receiver.fileno()) as client:
                with socket.socket() as transferred:
                    socket.send_fds(sender, [b"F"], [transferred.fileno()])
                sender.sendall(b"go")
                allowed(client, 0, True)
            # A closed or ambiguous previous peer must not contaminate new attribution.
            with start(first) as client:
                allowed(client, 0, True)
            explanation = subprocess.check_output(
                [binary, "rule", "explain", str(config), "four", "tcp", f"127.0.0.1:{target}", f"process-path={first}"],
                timeout=4, text=True,
            )
            assert "rule=1" in explanation, explanation


def check_redirect(binary, root, first, second):
    for family, host, table in ((socket.AF_INET, "127.0.0.1", "iptables"), (socket.AF_INET6, "::1", "ip6tables")):
        with socket.socket(family) as origin, socket.socket(family) as reservation:
            reservation.bind((host, 0))
            frontend = reservation.getsockname()[1]
            reservation.close()
            origin.bind((host, 0))
            origin.listen()
            origin.settimeout(5)
            target = origin.getsockname()[1]
            ready = reserve()
            mark = 20852
            config = root / "redirect.kdl"
            config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{
    mixed "probe" {{ listen host="127.0.0.1" port={ready}; authentication "none"; }}
    redirect "local" {{ listen host="{host}" port={frontend}; }}
}}
outbounds {{ direct "direct" {{ routing-mark {mark}; }}; block "deny"; }}
routing {{
    rule-set "other" path="other.kdl" format="kdl"
    rules {{ - kind="rule-set" value="other" outbound="deny"; }}
    default-outbound "direct"
}}
''')
            rule = ["OUTPUT", "-p", "tcp", "-d", host, "--dport", str(target), "-m", "mark", "!", "--mark",
                    str(mark), "-j", "REDIRECT", "--to-ports", str(frontend)]
            subprocess.run([table, "-t", "nat", "-A", *rule], check=True)
            try:
                with running([binary, "run", "--config", str(config)], ready, root / "redirect.log"):
                    for image, mode in ((first, "redirect"), (second, "redirect-deny")):
                        with subprocess.Popen([str(image), "-c", CLIENT, mode, host, str(target), str(target), "-1"],
                                              stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True) as client:
                            if mode == "redirect":
                                with origin.accept()[0] as peer:
                                    peer.settimeout(5)
                                    assert exact(peer, 8) == b"redirect"
                                    peer.sendall(b"reply")
                            complete(client, "0")
                print(f"Linux REDIRECT {host}: executable predicate followed the original TCP destination")
            finally:
                subprocess.run([table, "-t", "nat", "-D", *rule], check=True)


def main():
    tests = str(Path(__file__).resolve().parent)
    parent = os.environ.get("PYTHONPATH")
    os.environ["PYTHONPATH"] = os.pathsep.join((tests, parent)) if parent else tests
    parser = argparse.ArgumentParser()
    parser.add_argument("binary", type=Path)
    parser.add_argument("--redirect", action="store_true")
    parser.add_argument("--regex", action="store_true")
    parser.add_argument("--srs-compiler", type=Path)
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    compiler = args.srs_compiler.resolve(strict=True) if args.srs_compiler else None
    if args.redirect:
        subprocess.run(["ip", "link", "set", "lo", "up"], check=True)
    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)
        first, second = root / "allowed client", root / "other client"
        for image in (first, second):
            shutil.copy2(Path(sys.executable).resolve(), image)
        for ordered in (False, True):
            check_route(binary, root, first, second, ordered, args.regex or bool(compiler), compiler)
            print(f"ordered={ordered}: executable and name, dual stack, unknown shared/hidden/cross-mount peers, recovery and explain")
        if args.redirect:
            check_redirect(binary, root, first, second)


if __name__ == "__main__":
    main()
