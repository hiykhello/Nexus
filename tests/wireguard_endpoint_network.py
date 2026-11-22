#!/usr/bin/env python3
"""Drive the single-peer Endpoint through three real wireguard-go generations."""
import argparse
import json
import os
import pathlib
import select
import socket
import subprocess
import tempfile
import threading
import time

import wireguard_network as common


def reference_source():
    # Retain the independent packet/checksum generator and pinned peer setup.
    # The only changes are three distinguishable rounds and a bounded barrier
    # between them; the real wireguard-go device handles every handshake.
    source = common.SOURCE.replace("sizes[index]", "sizes[index%10]")
    for port in (10000, 20000):
        source = source.replace(f",{port})", f",uint16({port}+index/10))")
    before = "for index:=0;index<10;index++ {"
    after = '''scanner:=bufio.NewScanner(os.Stdin)
 for index:=0;index<30;index++ {
  if index>0 && index%10==0 {
   if !scanner.Scan() || scanner.Text()!=fmt.Sprintf("epoch-%d",index/10) { panic("round barrier failed") }
  }'''
    if source.count(before) != 1 or source.count("bufio.NewScanner(os.Stdin).Scan()") != 1:
        raise RuntimeError("independent reference structure changed")
    return source.replace(before, after).replace("bufio.NewScanner(os.Stdin).Scan()", "scanner.Scan()")


def build_reference(root):
    (root / "go.mod").write_text(f"module nexus-wireguard-endpoint-network\n\ngo 1.23.1\n\nrequire golang.zx2c4.com/wireguard {common.REVISION}\n")
    (root / "main.go").write_text(reference_source())
    executable = root / "wireguard-endpoint-reference"
    result = subprocess.run(["go", "build", "-mod=mod", "-o", executable, "."], cwd=root,
                            capture_output=True, text=True, timeout=120,
                            env=dict(os.environ, GOPROXY="off", GOTOOLCHAIN="local"))
    if result.returncode:
        raise RuntimeError(f"pinned wireguard-go endpoint reference build failed: {result.stderr}")
    return executable


def run(fixture, reference, role, ipv6, corrupt, shared=False):
    family, host = (socket.AF_INET6, "::1") if ipv6 else (socket.AF_INET, "127.0.0.1")
    with socket.socket(family, socket.SOCK_DGRAM) as relay:
        relay.bind((host, 0))
        relay.settimeout(.05)
        go = subprocess.Popen([reference, role, "6" if ipv6 else "4", str(relay.getsockname()[1])],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        core, stopped, errors = None, threading.Event(), []
        counters = {"wire": 0, "initiation": 0, "response": 0, "transport": 0, "corrupt": 0, "replay": 0, "epochs": 0, "paced": 0}
        try:
            if not select.select([go.stdout], [], [], 10)[0]:
                raise RuntimeError("reference did not announce its port")
            line = go.stdout.readline()
            try:
                setup = json.loads(line)
            except Exception:
                raise RuntimeError(f"reference setup failed: {line!r}, {go.stderr.read() if go.poll() is not None else ''}")
            go_peer = (host, setup["port"])

            def forward():
                peer, pending = None, []
                last_initiation = 0.0

                def deliver(data, destination):
                    nonlocal last_initiation
                    counters["wire"] += 1
                    kind = data[0] if len(data) >= 4 and data[1:4] == b"\0\0\0" else 0
                    if kind in (1, 2, 4):
                        counters[{1: "initiation", 2: "response", 4: "transport"}[kind]] += 1
                    if kind == 1 and destination == go_peer:
                        # Endpoint uses injected logical time; wireguard-go
                        # independently enforces a real 20ms per-peer floor.
                        delay = last_initiation + .025 - time.monotonic()
                        if delay > 0:
                            time.sleep(delay)
                            counters["paced"] += 1
                        last_initiation = time.monotonic()
                    if corrupt and kind == 4:
                        altered = bytearray(data)
                        altered[8:16] = (int.from_bytes(data[8:16], "little") + 1000000).to_bytes(8, "little")
                        altered[-1] ^= 1
                        relay.sendto(altered, destination)
                        counters["corrupt"] += 1
                    relay.sendto(data, destination)
                    if corrupt and kind == 4:
                        relay.sendto(data, destination)
                        counters["replay"] += 1

                try:
                    while not stopped.is_set():
                        try:
                            data, source = relay.recvfrom(65535)
                        except TimeoutError:
                            continue
                        normalized = source[:2]
                        if data == b"NEXUS-WG-READY":
                            peer = normalized
                            for payload in pending:
                                deliver(payload, peer)
                            pending.clear()
                            continue
                        if data.startswith(b"NEXUS-WG-EPOCH-"):
                            expected = counters["epochs"] + 1
                            if normalized != peer or data != f"NEXUS-WG-EPOCH-{expected}".encode() or expected > 2:
                                raise RuntimeError(f"invalid round marker: {data!r}")
                            go.stdin.write(f"epoch-{expected}\n")
                            go.stdin.flush()
                            counters["epochs"] = expected
                            continue
                        destination = peer if normalized == go_peer else go_peer
                        if destination is None:
                            if len(pending) >= 16:
                                raise RuntimeError("unbounded pre-ready datagrams")
                            pending.append(data)
                            continue
                        deliver(data, destination)
                except Exception as error:
                    errors.append(error)

            thread = threading.Thread(target=forward)
            thread.start()
            try:
                command = [fixture, role, "6" if ipv6 else "4", str(relay.getsockname()[1])]
                if shared:
                    command += ["plain", "shared"]
                core = subprocess.Popen(command,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = core.communicate(f"{setup['core-private']} {setup['peer-public']} {setup['psk']}\n", timeout=30)
                if core.returncode:
                    raise RuntimeError(f"endpoint fixture failed {core.returncode}: {stdout} {stderr}; relay={counters}; errors={errors}")
                if not select.select([go.stdout], [], [], 5)[0] or go.stdout.readline() != "done\n":
                    raise RuntimeError("wireguard-go did not validate all 30 inner packets")
                go.stdin.write("stop\n")
                go.stdin.flush()
                _, go_stderr = go.communicate(timeout=5)
                if go.returncode or errors or counters["epochs"] != 2 or counters["initiation"] != 3 or \
                        counters["response"] != 3 or counters["transport"] < 60 or \
                        (corrupt and (counters["corrupt"] != counters["transport"] or counters["replay"] != counters["transport"])):
                    raise RuntimeError(f"reference/relay failed {go.returncode}: {go_stderr}, {errors}, {counters}")
                print(stdout.strip(), flush=True)
                print(f"wireguard-go {common.REVISION}: role={role}, outer={'IPv6' if ipv6 else 'IPv4'}, fault={corrupt}, {counters}", flush=True)
            finally:
                stopped.set()
                thread.join(2)
        finally:
            for process in (core, go):
                if process and process.poll() is None:
                    process.kill()
                    process.communicate(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=pathlib.Path)
    parser.add_argument("--build-reference", type=pathlib.Path)
    parser.add_argument("--reference", type=pathlib.Path)
    parser.add_argument("--role", choices=("initiate", "respond"))
    parser.add_argument("--family", choices=("4", "6"))
    parser.add_argument("--fault", choices=("yes", "no"))
    parser.add_argument("--shared", action="store_true", help="exercise one identity gate and global registry/source routing")
    args = parser.parse_args()
    if args.build_reference:
        args.build_reference.mkdir(parents=True, exist_ok=True)
        print(build_reference(args.build_reference.resolve()))
        return
    if not args.fixture:
        parser.error("supply the endpoint fixture or --build-reference")
    with tempfile.TemporaryDirectory(prefix="nexus-wireguard-endpoint-network-") as directory:
        reference = args.reference.resolve() if args.reference else build_reference(pathlib.Path(directory))
        for role in (args.role,) if args.role else ("initiate", "respond"):
            for ipv6 in (args.family == "6",) if args.family else (False, True):
                for corrupt in (args.fault == "yes",) if args.fault else (False, True):
                    run(args.fixture.resolve(), reference, role, ipv6, corrupt, args.shared)


if __name__ == "__main__":
    main()
