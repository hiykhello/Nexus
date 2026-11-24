#!/usr/bin/env python3
"""Compare Nexus DERP/STUN wire output with pinned official Tailscale v1.104.1."""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess

VERSION = "v1.104.1"
COMMIT = "9a522a9786c97eb7910c01ccb7bd66557b04c910"
SOURCE = r'''package main

import (
 "bufio"
 "bytes"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "net"
 "net/netip"
 "os"
 "strconv"
 "tailscale.com/derp"
 "tailscale.com/net/stun"
)

func seq(start, size int) []byte {
 result:=make([]byte,size)
 for i:=range result { result[i]=byte(start+i) }
 return result
}
func frame(kind derp.FrameType, body ...[]byte) string {
 var result bytes.Buffer
 var payload []byte
 for _,part:=range body { payload=append(payload,part...) }
 writer:=bufio.NewWriter(&result)
 if err:=derp.WriteFrame(writer,kind,payload);err!=nil { panic(err) }
 reader:=bufio.NewReader(bytes.NewReader(result.Bytes()))
 parsed,size,err:=derp.ReadFrameHeader(reader)
 if err!=nil || parsed!=kind || int(size)!=len(payload) { panic("upstream header mismatch") }
 return hex.EncodeToString(result.Bytes())
}
func vectors() {
 key,other,nonce,sealed:=seq(0,32),seq(32,32),seq(64,24),seq(88,32)
 result:=map[string]string{}
 result["server-key"]=frame(derp.FrameServerKey,[]byte(derp.Magic),key,[]byte{0xfe,0xff})
 result["client-info"]=frame(derp.FrameClientInfo,other,nonce,sealed)
 result["server-info"]=frame(derp.FrameServerInfo,nonce,sealed)
 result["send-empty"]=frame(derp.FrameSendPacket,key)
 result["recv-empty"]=frame(derp.FrameRecvPacket,other)
 result["send-packet"]=frame(derp.FrameSendPacket,key,seq(100,17))
 result["recv-packet"]=frame(derp.FrameRecvPacket,other,seq(101,19))
 result["forward-packet"]=frame(derp.FrameForwardPacket,key,other,seq(102,23))
 result["keep-alive"]=frame(derp.FrameKeepAlive)
 result["preferred"]=frame(derp.FrameNotePreferred,[]byte{1})
 result["not-preferred"]=frame(derp.FrameNotePreferred,[]byte{0})
 result["peer-gone"]=frame(derp.FramePeerGone,key,[]byte{1})
 result["ping"]=frame(derp.FramePing,seq(1,8))
 result["pong"]=frame(derp.FramePong,seq(2,8))
 result["health"]=frame(derp.FrameHealth,[]byte("duplicate"))
 result["restarting"]=frame(derp.FrameRestarting,[]byte{0,0,0,25,0xff,0xff,0xff,0xff})
 result["watch-connections"]=frame(derp.FrameWatchConns)
 result["close-peer"]=frame(derp.FrameClosePeer,other)
 result["unknown"]=frame(derp.FrameType(0xfe),[]byte{1,2,3})
 var tx stun.TxID
 copy(tx[:],seq(0,12))
 request:=stun.Request(tx)
 actual,err:=stun.ParseBindingRequest(request)
 if err!=nil || actual!=tx { panic("upstream request mismatch") }
 result["stun-request"]=hex.EncodeToString(request)
 for _,name:=range []string{"192.0.2.1:3478","[2001:db8::1234]:9999"} {
  endpoint:=netip.MustParseAddrPort(name)
  response:=stun.Response(tx,endpoint)
  parsed,address,err:=stun.ParseResponse(response)
  if err!=nil || parsed!=tx || address!=endpoint { panic("upstream response mismatch") }
  result["stun-"+name]=hex.EncodeToString(response)
 }
 value,err:=json.Marshal(result);if err!=nil {panic(err)}
 fmt.Println(string(value))
}
func server(family string) {
 host:="127.0.0.1"
 if family=="6" {host="::1"}
 connection,err:=net.ListenUDP("udp"+family,net.UDPAddrFromAddrPort(netip.MustParseAddrPort(net.JoinHostPort(host,"0"))))
 if err!=nil {panic(err)}
 defer connection.Close()
 fmt.Println(connection.LocalAddr().(*net.UDPAddr).Port)
 buffer:=make([]byte,65536)
 accepted:=0
 for accepted<4 {
  n,peer,err:=connection.ReadFromUDPAddrPort(buffer)
  if err!=nil {panic(err)}
  tx,err:=stun.ParseBindingRequest(buffer[:n])
  if err!=nil {panic(err)}
  reply:=stun.Response(tx,peer)
  if _,err:=connection.WriteToUDPAddrPort(reply,peer);err!=nil {panic(err)}
  accepted++
 }
 fmt.Println("stun-complete:"+strconv.Itoa(accepted))
}
func main() {
 if len(os.Args)==3 && os.Args[1]=="server" {server(os.Args[2]);return}
 if len(os.Args)!=1 {panic("unknown mode")}
 vectors()
}
'''


def reference_binary():
    root = pathlib.Path("/tmp/nexus-tailscale-reference-v1.104.1")
    root.mkdir(exist_ok=True)
    source = root / "main.go"
    module = root / "go.mod"
    binary = root / "tailscale-reference"
    digest = hashlib.sha256((SOURCE + VERSION + COMMIT).encode()).hexdigest()
    stamp = root / "build-id"
    if binary.exists() and stamp.exists() and stamp.read_text().strip() == digest:
        return binary
    source.write_text(SOURCE)
    module.write_text(f"module nexus-tailscale-reference\n\ngo 1.26.0\n\nrequire tailscale.com {VERSION}\n")
    env = dict(os.environ, GOTOOLCHAIN="local", GOMODCACHE=str(root / "modules"), GOCACHE=str(root / "cache"),
               GOPROXY=os.environ.get("GOPROXY", f"file://{pathlib.Path.home() / 'go/pkg/mod/cache/download'},https://proxy.golang.org"))
    built = subprocess.run(["go", "build", "-p", "1", "-mod=mod", "-o", binary, "."], cwd=root, env=env,
                           capture_output=True, text=True, timeout=240)
    if built.returncode:
        raise RuntimeError(f"Tailscale reference build failed: {built.stderr}")
    stamp.write_text(digest + "\n")
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=pathlib.Path)
    args = parser.parse_args()
    reference = reference_binary()
    expected = json.loads(subprocess.run([reference], check=True, capture_output=True, text=True, timeout=10).stdout)
    if args.fixture:
        actual = json.loads(subprocess.run([args.fixture.resolve(), "--vectors"], check=True, capture_output=True, text=True, timeout=10).stdout)
        if actual != expected:
            raise RuntimeError(f"DERP/STUN differential mismatch: missing={set(expected)-set(actual)}, extra={set(actual)-set(expected)}, "
                               f"different={[key for key in expected if actual.get(key) != expected[key]]}")
        print(f"DERP/STUN official Tailscale {VERSION} ({COMMIT}) differential passed: {len(expected)} vectors")
    else:
        print(json.dumps(expected, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

