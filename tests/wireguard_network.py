#!/usr/bin/env python3
"""Actual UDP interop with pinned wireguard-go and memory TUN; no host routes."""
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


REVISION = "v0.0.0-20250521234502-f333402bd9cb"
SOURCE = r'''package main
import (
 "bufio"
 "bytes"
 "crypto/ecdh"
 "crypto/rand"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "net"
 "os"
 "strconv"
 "strings"
 "time"
 "golang.zx2c4.com/wireguard/conn"
 "golang.zx2c4.com/wireguard/device"
 "golang.zx2c4.com/wireguard/tun/tuntest"
)
func checksum(data []byte) uint16 {
 var sum uint32
 for len(data)>1 { sum+=uint32(binary.BigEndian.Uint16(data)); data=data[2:] }; if len(data)>0 { sum+=uint32(data[0])<<8 }
 for sum>>16!=0 { sum=(sum&65535)+(sum>>16) }; return ^uint16(sum)
}
func packet(index int, coreToGo, reply bool) []byte {
 sizes:=[]int{0,1,15,16,17,63,64,65,512,1024}; ipv6:=index%2!=0; header:=20; if ipv6 { header=40 }
 udpSize:=8+sizes[index]; out:=make([]byte,header+udpSize)
 if ipv6 {
  out[0]=0x60; binary.BigEndian.PutUint16(out[4:],uint16(udpSize)); out[6]=17; out[7]=64
  out[8]=0xfd; out[9]=0x42; out[24]=0xfd; out[25]=0x42
  if coreToGo { out[23]=2; out[39]=1 } else { out[23]=1; out[39]=2 }
 } else {
  out[0]=0x45; binary.BigEndian.PutUint16(out[2:],uint16(len(out))); out[8]=64; out[9]=17
  out[12]=10; out[13]=42; out[16]=10; out[17]=42
  if coreToGo { out[15]=2; out[19]=1 } else { out[15]=1; out[19]=2 }
  binary.BigEndian.PutUint16(out[10:],checksum(out[:20]))
 }
 if reply { binary.BigEndian.PutUint16(out[header:],20000); binary.BigEndian.PutUint16(out[header+2:],10000)
 } else { binary.BigEndian.PutUint16(out[header:],10000); binary.BigEndian.PutUint16(out[header+2:],20000) }
 binary.BigEndian.PutUint16(out[header+4:],uint16(udpSize)); for i:=0;i<sizes[index];i++ { out[header+8+i]=byte(index+i) }
 var pseudo []byte
 if ipv6 { pseudo=append(pseudo,out[8:40]...); pseudo=append(pseudo,0,0,byte(udpSize>>8),byte(udpSize),0,0,0,17)
 } else { pseudo=append(pseudo,out[12:20]...); pseudo=append(pseudo,0,17,byte(udpSize>>8),byte(udpSize)) }
 pseudo=append(pseudo,out[header:]...); check:=checksum(pseudo); if check==0 { check=65535 }; binary.BigEndian.PutUint16(out[header+6:],check)
 return out
}
func main() {
 if len(os.Args)!=4 { panic("usage: reference ROLE FAMILY RELAY_PORT") }
 coreInitiates:=os.Args[1]=="initiate"; host:="127.0.0.1"; if os.Args[2]=="6" { host="::1" }
 coreKey,err:=ecdh.X25519().GenerateKey(rand.Reader); if err!=nil { panic(err) }
 localKey,err:=ecdh.X25519().GenerateKey(rand.Reader); if err!=nil { panic(err) }
 psk:=make([]byte,32); if _,err=rand.Read(psk); err!=nil { panic(err) }
 tun:=tuntest.NewChannelTUN(); dev:=device.NewDevice(tun.TUN(),conn.NewDefaultBind(),&device.Logger{Verbosef:device.DiscardLogf,Errorf:device.DiscardLogf}); defer dev.Close()
 config:=fmt.Sprintf("private_key=%x\nlisten_port=0\nreplace_peers=true\npublic_key=%x\npreshared_key=%x\nprotocol_version=1\nreplace_allowed_ips=true\nallowed_ip=10.42.0.2/32\nallowed_ip=fd42::2/128\nendpoint=%s\n",localKey.Bytes(),coreKey.PublicKey().Bytes(),psk,net.JoinHostPort(host,os.Args[3]))
 if err=dev.IpcSet(config); err!=nil { panic(err) }; if err=dev.Up(); err!=nil { panic(err) }
 current,err:=dev.IpcGet(); if err!=nil { panic(err) }; port:=0
 for _,line:=range strings.Split(current,"\n") { if strings.HasPrefix(line,"listen_port=") { port,_=strconv.Atoi(strings.TrimPrefix(line,"listen_port=")) } }
 if port==0 { panic("missing UDP port") }
 setup:=map[string]interface{}{"port":port,"core-private":hex.EncodeToString(coreKey.Bytes()),"peer-public":hex.EncodeToString(localKey.PublicKey().Bytes()),"psk":hex.EncodeToString(psk)}
 encoded,_:=json.Marshal(setup); fmt.Println(string(encoded))
 for index:=0;index<10;index++ {
  if !coreInitiates { select { case tun.Outbound<-packet(index,false,false): case <-time.After(10*time.Second): panic("outbound TUN blocked") } }
  var incoming []byte
  select { case incoming=<-tun.Inbound: case <-time.After(10*time.Second): panic(fmt.Sprintf("inner packet %d timed out",index)) }
  if !bytes.Equal(incoming,packet(index,true,!coreInitiates)) { panic(fmt.Sprintf("inner packet %d mismatch",index)) }
  if coreInitiates { select { case tun.Outbound<-packet(index,false,true): case <-time.After(10*time.Second): panic("reply TUN blocked") } }
 }
 fmt.Println("done")
 bufio.NewScanner(os.Stdin).Scan()
}
'''


def build_reference(root):
    (root / "go.mod").write_text(f"module nexus-wireguard-network\n\ngo 1.23.1\n\nrequire golang.zx2c4.com/wireguard {REVISION}\n")
    (root / "main.go").write_text(SOURCE)
    executable = root / "wireguard-reference"
    result = subprocess.run(["go", "build", "-mod=mod", "-o", executable, "."], cwd=root, capture_output=True, text=True,
                            env=dict(os.environ, GOPROXY="off", GOTOOLCHAIN="local"), timeout=120)
    if result.returncode:
        raise RuntimeError(f"pinned wireguard-go reference build failed: {result.stderr}")
    return executable


def run(fixture, reference, role, ipv6, corrupt):
    family, host = (socket.AF_INET6, "::1") if ipv6 else (socket.AF_INET, "127.0.0.1")
    with socket.socket(family, socket.SOCK_DGRAM) as relay:
        relay.bind((host, 0))
        relay.settimeout(.05)
        go = subprocess.Popen([reference, role, "6" if ipv6 else "4", str(relay.getsockname()[1])],
                              stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        core, stopped, errors = None, threading.Event(), []
        counters = {"wire": 0, "transport": 0, "corrupt": 0, "replay": 0}
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
                    counters["wire"] += 1
                    transport = len(data) >= 32 and data[:4] == b"\x04\0\0\0"
                    if transport:
                        counters["transport"] += 1
                    if corrupt and transport:
                        altered = bytearray(data)
                        # A valid-looking high counter with a bad tag must
                        # leave both peers' real replay windows unchanged.
                        altered[8:16] = (int.from_bytes(data[8:16], "little") + 1000000).to_bytes(8, "little")
                        altered[-1] ^= 1
                        relay.sendto(altered, destination)
                        counters["corrupt"] += 1
                    relay.sendto(data, destination)
                    if corrupt and transport:
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
                core = subprocess.Popen([fixture, role, "6" if ipv6 else "4", str(relay.getsockname()[1])],
                                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
                stdout, stderr = core.communicate(f"{setup['core-private']} {setup['peer-public']} {setup['psk']}\n", timeout=20)
                if core.returncode:
                    raise RuntimeError(f"core fixture failed {core.returncode}: {stdout} {stderr}")
                if not select.select([go.stdout], [], [], 5)[0] or go.stdout.readline() != "done\n":
                    raise RuntimeError("wireguard-go did not validate all inner packets")
                go.stdin.write("stop\n")
                go.stdin.flush()
                _, go_stderr = go.communicate(timeout=5)
                expected_transport = 21 if role == "initiate" else 20
                if go.returncode or errors or counters["wire"] < expected_transport + 2 or counters["transport"] < expected_transport or \
                        (corrupt and (counters["corrupt"] != counters["transport"] or counters["replay"] != counters["transport"])):
                    raise RuntimeError(f"reference/relay failed {go.returncode}: {go_stderr}, {errors}, {counters}")
                print(stdout.strip(), flush=True)
                print(f"wireguard-go {REVISION}: role={role}, outer={'IPv6' if ipv6 else 'IPv4'}, fault={corrupt}, {counters}", flush=True)
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
    parser.add_argument("--build-reference", type=pathlib.Path, help="build the pinned independent reference only")
    args = parser.parse_args()
    if args.build_reference:
        args.build_reference.mkdir(parents=True, exist_ok=True)
        print(build_reference(args.build_reference.resolve()))
        return
    if not args.fixture:
        parser.error("supply the core fixture or --build-reference")
    with tempfile.TemporaryDirectory(prefix="nexus-wireguard-network-") as directory:
        reference = build_reference(pathlib.Path(directory))
        for role in ("initiate", "respond"):
            for ipv6 in (False, True):
                for corrupt in (False, True):
                    run(args.fixture.resolve(), reference, role, ipv6, corrupt)


if __name__ == "__main__":
    main()
