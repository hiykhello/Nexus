#!/usr/bin/env python3
"""Actual UDP cookie-required handshakes against pinned official cookie code."""
import argparse
import json
import os
import pathlib
import select
import socket
import subprocess
import tempfile
import threading

import wireguard_network as common


GATE = r'''
type cookieBind struct {
 conn.Bind
 checker device.CookieChecker
 issued atomic.Uint64
 accepted atomic.Uint64
}
func (bind *cookieBind) Open(port uint16) ([]conn.ReceiveFunc,uint16,error) {
 functions,actual,err:=bind.Bind.Open(port); if err!=nil { return nil,0,err }
 for i,original:=range functions {
  receive:=original
  functions[i]=func(packets [][]byte,sizes []int,endpoints []conn.Endpoint)(int,error) {
   n,err:=receive(packets,sizes,endpoints); if err!=nil { return n,err }
   for index:=0;index<n;index++ {
    if sizes[index]<4 { continue }; packet:=packets[index][:sizes[index]]
    kind:=binary.LittleEndian.Uint32(packet[:4]); if (kind!=1 || len(packet)!=148) && (kind!=2 || len(packet)!=92) { continue }
    if !bind.checker.CheckMAC1(packet) { sizes[index]=0; continue }
    if bind.checker.CheckMAC2(packet,endpoints[index].DstToBytes()) { bind.accepted.Add(1); continue }
    reply,err:=bind.checker.CreateReply(packet,binary.LittleEndian.Uint32(packet[4:8]),endpoints[index].DstToBytes())
    if err!=nil { panic(err) }; var output bytes.Buffer
    if err=binary.Write(&output,binary.LittleEndian,reply); err!=nil { panic(err) }
    if err=bind.Bind.Send([][]byte{output.Bytes()},endpoints[index]); err!=nil { panic(err) }
    bind.issued.Add(1); sizes[index]=0
   }
   return n,nil
  }
 }
 return functions,actual,nil
}
'''


def reference_source():
    source = common.SOURCE.replace(' "time"', ' "time"\n "sync/atomic"')
    source = source.replace("func main() {", GATE + "\nfunc main() {")
    source = source.replace('if len(os.Args)!=4 { panic("usage: reference ROLE FAMILY RELAY_PORT") }',
                            'if len(os.Args)!=5 { panic("usage: reference ROLE FAMILY RELAY_PORT MODE") }')
    before = 'tun:=tuntest.NewChannelTUN(); dev:=device.NewDevice(tun.TUN(),conn.NewDefaultBind(),'
    after = '''var binding conn.Bind=conn.NewDefaultBind(); var gate *cookieBind
 if os.Args[4]=="receive" || os.Args[4]=="both" {
  gate=&cookieBind{Bind:binding}; var public device.NoisePublicKey
  copy(public[:],localKey.PublicKey().Bytes()); gate.checker.Init(public); binding=gate
 }
 tun:=tuntest.NewChannelTUN(); dev:=device.NewDevice(tun.TUN(),binding,'''
    if source.count(before) != 1 or source.count('fmt.Println("done")') != 1:
        raise RuntimeError("independent reference structure changed")
    source = source.replace(before, after).replace("time.After(10*time.Second)", "time.After(30*time.Second)")
    return source.replace('fmt.Println("done")',
                          'issued,accepted:=uint64(0),uint64(0); if gate!=nil { issued=gate.issued.Load(); accepted=gate.accepted.Load() }; fmt.Printf("done %d %d\\n",issued,accepted)')


def build_reference(root):
    (root / "go.mod").write_text(f"module nexus-wireguard-endpoint-cookie-network\n\ngo 1.23.1\n\nrequire golang.zx2c4.com/wireguard {common.REVISION}\n")
    (root / "main.go").write_text(reference_source())
    executable = root / "wireguard-endpoint-cookie-reference"
    result = subprocess.run(["go", "build", "-mod=mod", "-o", executable, "."], cwd=root,
                            capture_output=True, text=True, timeout=120,
                            env=dict(os.environ, GOPROXY="off", GOTOOLCHAIN="local"))
    if result.returncode:
        raise RuntimeError(f"pinned wireguard-go cookie reference build failed: {result.stderr}")
    return executable


def run(fixture, reference, role, ipv6, mode, shared=False):
    family, host = (socket.AF_INET6, "::1") if ipv6 else (socket.AF_INET, "127.0.0.1")
    with socket.socket(family, socket.SOCK_DGRAM) as relay:
        relay.bind((host, 0))
        relay.settimeout(.05)
        go = subprocess.Popen([reference, role, "6" if ipv6 else "4", str(relay.getsockname()[1]), mode],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        core, stopped, errors = None, threading.Event(), []
        counters = {"initiation": 0, "response": 0, "cookie-core": 0, "cookie-go": 0, "transport": 0}
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

                def deliver(data, destination):
                    kind = data[0] if len(data) >= 4 and data[1:4] == b"\0\0\0" else 0
                    if kind in (1, 2, 4):
                        counters[{1: "initiation", 2: "response", 4: "transport"}[kind]] += 1
                    elif kind == 3:
                        counters["cookie-core" if destination == go_peer else "cookie-go"] += 1
                    relay.sendto(data, destination)

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
                command = [fixture, role, "6" if ipv6 else "4", str(relay.getsockname()[1]), mode]
                if shared:
                    command += ["shared"]
                core = subprocess.Popen(command,
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = core.communicate(f"{setup['core-private']} {setup['peer-public']} {setup['psk']}\n", timeout=35)
                if core.returncode:
                    raise RuntimeError(f"endpoint cookie fixture failed {core.returncode}: {stdout} {stderr}; relay={counters}; errors={errors}")
                if not select.select([go.stdout], [], [], 5)[0]:
                    raise RuntimeError("wireguard-go did not validate all 10 inner packets")
                done = go.stdout.readline().split()
                expected_gate = mode in ("receive", "both")
                if len(done) != 3 or done[0] != "done" or int(done[1]) != int(expected_gate) or (expected_gate and int(done[2]) < 1):
                    raise RuntimeError(f"wireguard-go cookie gate did not validate the real retry: {done}")
                go.stdin.write("stop\n")
                go.stdin.flush()
                _, go_stderr = go.communicate(timeout=5)
                expected_core, expected_go = int(mode in ("require", "both")), int(expected_gate)
                if go.returncode or errors or counters["cookie-core"] != expected_core or counters["cookie-go"] != expected_go or counters["transport"] < 20:
                    raise RuntimeError(f"reference/relay failed {go.returncode}: {go_stderr}, {errors}, {counters}")
                print(stdout.strip(), flush=True)
                print(f"wireguard-go {common.REVISION}: role={role}, outer={'IPv6' if ipv6 else 'IPv4'}, mode={mode}, gate-issued={done[1]}, gate-accepted={done[2]}, {counters}", flush=True)
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
    parser.add_argument("--mode", choices=("require", "receive", "both"))
    parser.add_argument("--shared", action="store_true", help="exercise one identity gate and global registry/source routing")
    args = parser.parse_args()
    if args.build_reference:
        args.build_reference.mkdir(parents=True, exist_ok=True)
        print(build_reference(args.build_reference.resolve()))
        return
    if not args.fixture:
        parser.error("supply the endpoint fixture or --build-reference")
    with tempfile.TemporaryDirectory(prefix="nexus-wireguard-endpoint-cookie-network-") as directory:
        reference = args.reference.resolve() if args.reference else build_reference(pathlib.Path(directory))
        for role in (args.role,) if args.role else ("initiate", "respond"):
            for ipv6 in (args.family == "6",) if args.family else (False, True):
                for mode in (args.mode,) if args.mode else ("require", "receive", "both"):
                    run(args.fixture.resolve(), reference, role, ipv6, mode, args.shared)


if __name__ == "__main__":
    main()
