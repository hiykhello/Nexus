#!/usr/bin/env python3
"""Two real wireguard-go peers share one Nexus UDP socket and identity."""
import argparse
import json
import os
import pathlib
import select
import socket
import subprocess
import tempfile

import wireguard_network as common


def peer_source():
    source = common.SOURCE
    source = source.replace('if len(os.Args)!=4 { panic("usage: reference ROLE FAMILY RELAY_PORT") }',
                            'if len(os.Args)!=6 { panic("usage: reference ROLE FAMILY CORE_PORT NODE MODE") }; node,_:=strconv.Atoi(os.Args[4]); if node!=2 && node!=3 { panic("bad node") }')
    source = source.replace('coreKey,err:=ecdh.X25519().GenerateKey(rand.Reader); if err!=nil { panic(err) }',
                            'input:=bufio.NewScanner(os.Stdin); if !input.Scan() { panic("missing core public") }; corePublic,err:=hex.DecodeString(input.Text()); if err!=nil || len(corePublic)!=32 { panic("bad core public") }')
    source = source.replace('coreKey.PublicKey().Bytes()', 'corePublic').replace('"core-private":hex.EncodeToString(coreKey.Bytes()),', '')
    source = source.replace('allowed_ip=10.42.0.2/32\\nallowed_ip=fd42::2/128', 'allowed_ip=10.42.0.1/32\\nallowed_ip=fd42::1/128')
    source = source.replace('packet(index int, coreToGo, reply bool)', 'packet(index int, coreToGo, reply bool, node, source int)')
    source = source.replace('if coreToGo { out[23]=2; out[39]=1 } else { out[23]=1; out[39]=2 }',
                            'if coreToGo { out[23]=1; out[39]=byte(node) } else { out[23]=byte(node); out[39]=1 }; if source!=0 { out[23]=byte(source) }')
    source = source.replace('if coreToGo { out[15]=2; out[19]=1 } else { out[15]=1; out[19]=2 }',
                            'if coreToGo { out[15]=1; out[19]=byte(node) } else { out[15]=byte(node); out[19]=1 }; if source!=0 { out[15]=byte(source) }')
    for port in (10000, 20000):
        source = source.replace(f',{port})', f',uint16({port}+node))')
    source = source.replace('out[header+8+i]=byte(index+i)', 'out[header+8+i]=byte(index+i+node)')
    source = source.replace('fmt.Println(string(encoded))', '''fmt.Println(string(encoded))
 if !input.Scan() || !strings.HasPrefix(input.Text(),"endpoint-") { panic("endpoint barrier") }
 selected:=strings.TrimPrefix(input.Text(),"endpoint-")
 if err=dev.IpcSet(fmt.Sprintf("public_key=%x\\nendpoint=%s\\n",corePublic,net.JoinHostPort(host,selected))); err!=nil { panic(err) }
 if !input.Scan() || input.Text()!="start" { panic("start barrier") }''')
    before = '''for index:=0;index<10;index++ {
  if !coreInitiates { select { case tun.Outbound<-packet(index,false,false): case <-time.After(10*time.Second): panic("outbound TUN blocked") } }'''
    after = '''if os.Args[5]=="backpressure" && !coreInitiates {
  select { case tun.Outbound<-packet(0,false,false,node,5-node): case <-time.After(10*time.Second): panic("spoofed TUN blocked") }
  select { case tun.Outbound<-packet(1,false,false,node,5-node): case <-time.After(10*time.Second): panic("spoofed TUN blocked") }
  for index:=0;index<10;index++ { select { case tun.Outbound<-packet(index,false,false,node,0): case <-time.After(10*time.Second): panic("pressure TUN blocked") } }
 }
 for index:=0;index<10;index++ {
  if !coreInitiates && (index==0 || index==1) { select { case tun.Outbound<-packet(index,false,false,node,5-node): case <-time.After(10*time.Second): panic("spoofed TUN blocked") } }
  if !coreInitiates && os.Args[5]!="backpressure" { select { case tun.Outbound<-packet(index,false,false,node,0): case <-time.After(10*time.Second): panic("outbound TUN blocked") } }'''
    if source.count(before) != 1:
        raise RuntimeError("pinned peer source changed")
    source = source.replace(before, after)
    source = source.replace('packet(index,true,!coreInitiates)', 'packet(index,true,!coreInitiates,node,0)')
    source = source.replace('for index:=0;index<10;index++ {\n  if !coreInitiates', 'seen:=make([]bool,10); for index:=0;index<10;index++ {\n  if !coreInitiates')
    expected = 'if !bytes.Equal(incoming,packet(index,true,!coreInitiates,node,0)) { panic(fmt.Sprintf("inner packet %d mismatch",index)) }'
    replacement = '''if os.Args[5]=="backpressure" {
  matched:=-1; for candidate:=0;candidate<10;candidate++ { if !seen[candidate] && bytes.Equal(incoming,packet(candidate,true,!coreInitiates,node,0)) { matched=candidate; break } }
  if matched<0 { panic(fmt.Sprintf("unknown/duplicate pressure inner packet %d",index)) }; seen[matched]=true
 } else if !bytes.Equal(incoming,packet(index,true,!coreInitiates,node,0)) { panic(fmt.Sprintf("inner packet %d mismatch",index)) }'''
    if source.count(expected) != 1:
        raise RuntimeError("pinned packet verification changed")
    source = source.replace(expected, replacement)
    source = source.replace('packet(index,false,true)', 'packet(index,false,true,node,0)')
    source = source.replace('if coreInitiates { select { case tun.Outbound<-packet(index,false,true,node,0)',
                            'if coreInitiates && (index==0 || index==1) { select { case tun.Outbound<-packet(index,false,false,node,5-node): case <-time.After(10*time.Second): panic("spoofed reply TUN blocked") } }; if coreInitiates { select { case tun.Outbound<-packet(index,false,true,node,0)')
    source = source.replace(' }\n fmt.Println("done")', '  if os.Args[5]=="cookie-active" && index==0 { time.Sleep(time.Second) }\n }\n fmt.Println("done")')
    source = source.replace('time.After(10*time.Second)', 'time.After(30*time.Second)')
    return source.replace('bufio.NewScanner(os.Stdin).Scan()', 'input.Scan()')


def build_peer(root):
    (root / "go.mod").write_text(f"module nexus-wireguard-port-network\n\ngo 1.23.1\n\nrequire golang.zx2c4.com/wireguard {common.REVISION}\n")
    (root / "main.go").write_text(peer_source())
    executable = root / "wireguard-port-peer"
    result = subprocess.run(["go", "build", "-mod=mod", "-o", executable, "."], cwd=root,
                            capture_output=True, text=True, timeout=120,
                            env=dict(os.environ, GOPROXY="off", GOTOOLCHAIN="local"))
    if result.returncode:
        raise RuntimeError(f"wireguard-go shared-port peer build failed: {result.stderr}")
    return executable


def prepare(root):
    # Independent standard Go X25519 creates a private credential for Nexus;
    # peer credentials and PSKs are independently generated in each Go device.
    source = '''package main
import ("crypto/ecdh";"crypto/rand";"encoding/json";"encoding/hex";"fmt")
func main(){ key,err:=ecdh.X25519().GenerateKey(rand.Reader);if err!=nil{panic(err)}; psk:=make([]byte,64);if _,err=rand.Read(psk);err!=nil{panic(err)};out,_:=json.Marshal(map[string]string{"private":hex.EncodeToString(key.Bytes()),"public":hex.EncodeToString(key.PublicKey().Bytes()),"psk1":hex.EncodeToString(psk[:32]),"psk2":hex.EncodeToString(psk[32:])});fmt.Println(string(out))}
'''
    (root / "keys.go").write_text(source)
    result = subprocess.run(["go", "run", root / "keys.go"], capture_output=True, text=True, timeout=60,
                            env=dict(os.environ, GOTOOLCHAIN="local"))
    if result.returncode:
        raise RuntimeError(f"independent key setup failed: {result.stderr}")
    return json.loads(result.stdout)


def run(fixture, peer, role, ipv6, mode, root):
    family, host = (socket.AF_INET6, "::1") if ipv6 else (socket.AF_INET, "127.0.0.1")
    core = None
    peers = []
    keys = prepare(root)
    try:
        # Peer source takes its own PSK from random and announces it; core
        # first needs the peer static identities, so start Go before binding
        # the actual core endpoint and update the peer endpoint afterwards.
        with socket.socket(family, socket.SOCK_DGRAM) as reservation:
            reservation.bind((host, 0))
            port = reservation.getsockname()[1]
        setup = []
        for node in (2, 3):
            peer_mode = "cookie" if mode == "auto-cookie" else mode
            process = subprocess.Popen([peer, role, "6" if ipv6 else "4", str(port), str(node), peer_mode],
                                       stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            peers.append(process)
            process.stdin.write(keys["public"] + "\n")
            process.stdin.flush()
            if not select.select([process.stdout], [], [], 10)[0]:
                raise RuntimeError("peer setup timeout")
            line = process.stdout.readline()
            setup.append(json.loads(line))
        core = subprocess.Popen([fixture, role, "6" if ipv6 else "4", mode],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        core.stdin.write(f"{keys['private']} {setup[0]['peer-public']} {setup[1]['peer-public']} {setup[0]['psk']} {setup[1]['psk']}\n")
        core.stdin.flush()
        if not select.select([core.stdout], [], [], 10)[0]:
            raise RuntimeError("core port bind timeout")
        actual = json.loads(core.stdout.readline())["port"]
        # Reconfigure the Go peers to the actual bound source port with a
        # control line; no extra relay socket or source-address substitution.
        for process in peers:
            process.stdin.write(f"endpoint-{actual}\n")
            process.stdin.flush()
        core.stdin.write(f"{setup[0]['port']} {setup[1]['port']}\n")
        core.stdin.flush()
        if mode == "auto-cookie":
            if not select.select([core.stdout], [], [], 10)[0] or core.stdout.readline() != "auto-cookie-ready\n":
                raise RuntimeError("automatic protection was not activated")
        for process in peers:
            process.stdin.write("start\n")
            process.stdin.flush()
        stdout, stderr = core.communicate(timeout=40)
        if core.returncode:
            diagnostics = []
            for process in peers:
                diagnostics.append(f"peer-exit={process.poll()}")
                if process.poll() is not None:
                    diagnostics.append(process.stderr.read())
            raise RuntimeError(f"core shared-port failed {core.returncode}: {stdout} {stderr}; {'; '.join(diagnostics)}")
        if mode in ("deadline", "stop-pending"):
            marker = "deadline stopped and drained both peer queues" if mode == "deadline" else "stop drained two confirmed peers with two EAGAIN business packets and 56 charged bytes"
            if marker not in stdout:
                raise RuntimeError("shared port did not drain on deadline")
            print(stdout.strip(), flush=True)
            print(f"wireguard-go {common.REVISION}: two real peers active at {mode}, outer={'IPv6' if ipv6 else 'IPv4'}", flush=True)
            return
        for process in peers:
            if not select.select([process.stdout], [], [], 5)[0] or process.stdout.readline() != "done\n":
                raise RuntimeError(f"wireguard-go peer failed to validate all packets: {process.poll()}")
            process.stdin.write("stop\n")
            process.stdin.flush()
            _, error = process.communicate(timeout=5)
            if process.returncode:
                raise RuntimeError(f"wireguard-go peer failed {process.returncode}: {error}")
        print(stdout.strip(), flush=True)
        print(f"wireguard-go {common.REVISION}: same socket, two distinct static peers, role={role}, outer={'IPv6' if ipv6 else 'IPv4'}, mode={mode}", flush=True)
    finally:
        for process in (core, *peers):
            if process and process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=pathlib.Path)
    parser.add_argument("--build-peer", type=pathlib.Path)
    parser.add_argument("--peer", type=pathlib.Path)
    parser.add_argument("--role", choices=("initiate", "respond"))
    parser.add_argument("--family", choices=("4", "6"))
    parser.add_argument("--mode", choices=("plain", "cookie", "auto-cookie", "backpressure", "deadline", "stop-pending", "cookie-active"))
    args = parser.parse_args()
    if args.build_peer:
        args.build_peer.mkdir(parents=True, exist_ok=True)
        print(build_peer(args.build_peer.resolve()))
        return
    if not args.fixture:
        parser.error("supply the shared-port fixture or --build-peer")
    with tempfile.TemporaryDirectory(prefix="nexus-wireguard-port-network-") as directory:
        root = pathlib.Path(directory)
        peer = args.peer.resolve() if args.peer else build_peer(root)
        for role in (args.role,) if args.role else ("initiate", "respond"):
            for ipv6 in (args.family == "6",) if args.family else (False, True):
                for mode in (args.mode,) if args.mode else ("plain", "cookie"):
                    run(args.fixture.resolve(), peer, role, ipv6, mode, root)
        if not args.role and not args.mode:
            for ipv6 in (args.family == "6",) if args.family else (False, True):
                run(args.fixture.resolve(), peer, "respond", ipv6, "backpressure", root)
                run(args.fixture.resolve(), peer, "respond", ipv6, "deadline", root)
                run(args.fixture.resolve(), peer, "respond", ipv6, "stop-pending", root)


if __name__ == "__main__":
    main()
