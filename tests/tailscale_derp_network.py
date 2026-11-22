#!/usr/bin/env python3
"""Pinned DERP client auth/packets against the real official server and a Go client."""
import argparse
import hashlib
import os
import pathlib
import select
import subprocess

VERSION = "v1.104.1"
SOURCE = r'''package main
import (
 "bufio"
 "context"
 "encoding/hex"
 "fmt"
 "io"
 "net"
 "os"
 "sync"
 "time"
 "go4.org/mem"
 "tailscale.com/derp"
 "tailscale.com/derp/derpserver"
 "tailscale.com/types/key"
 "tailscale.com/types/logger"
)
func raw(public key.NodePublic) string {bytes:=public.Raw32();return hex.EncodeToString(bytes[:])}
func selfcheck(address string) error {
 rawKey:=make([]byte,32);for i:=range rawKey {rawKey[i]=byte(i)}
 private:=key.NodePrivateFromRaw32(mem.B(rawKey))
 connection,err:=net.Dial("tcp",address);if err!=nil {return err};defer connection.Close()
 client,err:=derp.NewClient(private,connection,bufio.NewReadWriter(bufio.NewReader(connection),bufio.NewWriter(connection)),logger.Discard)
 if err!=nil {return err}
 var peer key.NodePublic
 // The helper receives its buddy public key over the local test pipe below.
 select {case peer=<-selfPeer:case <-time.After(5*time.Second):return fmt.Errorf("missing self peer")}
 for _,size:=range []int{0,17,65536} {
  data:=make([]byte,size);for i:=range data {data[i]=byte(i+size)}
  if err:=client.Send(peer,data);err!=nil {return err}
  for {
   message,err:=client.Recv();if err!=nil {return err}
   packet,ok:=message.(derp.ReceivedPacket);if !ok {continue}
   if packet.Source!=peer || len(packet.Data)!=size {return fmt.Errorf("self peer or size")}
   for i,x:=range packet.Data {if x!=data[i]^0x5a {return fmt.Errorf("self payload")}}
   break
  }
 }
 if err:=derp.WriteFrame(bufio.NewWriter(connection),derp.FrameType(0xfe),[]byte{1,2,3});err!=nil {return err}
 token:=[8]byte{1,2,3,4,5,6,7,8};if err:=client.SendPing(token);err!=nil {return err}
 for {
  message,err:=client.Recv();if err!=nil {return err}
  if pong,ok:=message.(derp.PongMessage);ok {if [8]byte(pong)!=token {return fmt.Errorf("self pong")};return nil}
 }
}
var selfPeer=make(chan key.NodePublic,1)
func main() {
 listener,err:=net.Listen("tcp","127.0.0.1:0");if err!=nil {panic(err)}
 server:=derpserver.New(key.NewNode(),logger.Discard)
 ctx,cancel:=context.WithCancel(context.Background())
 var sessions sync.WaitGroup
 accepted:=make(chan struct{})
 go func() {
  defer close(accepted)
  for {
   connection,err:=listener.Accept();if err!=nil {return}
   sessions.Add(1)
   go func() {defer sessions.Done();defer connection.Close();server.Accept(ctx,connection,bufio.NewReadWriter(bufio.NewReader(connection),bufio.NewWriter(connection)),connection.RemoteAddr().String())}()
  }
 }()
 defer func() {cancel();listener.Close();<-accepted;server.Close();sessions.Wait()}()
 connection,err:=net.Dial("tcp",listener.Addr().String());if err!=nil {panic(err)}
 private:=key.NewNode()
 client,err:=derp.NewClient(private,connection,bufio.NewReadWriter(bufio.NewReader(connection),bufio.NewWriter(connection)),logger.Discard,derp.CanAckPings(true))
 if err!=nil {panic(err)}
 for {
  message,err:=client.Recv();if err!=nil {panic(err)}
  if _,ok:=message.(derp.ServerInfoMessage);ok {break}
 }
 done:=make(chan error,1)
 go func() {
  defer connection.Close()
  sizes:=[]int{0,17,65536};count:=0
  for count<len(sizes) {
   message,err:=client.Recv();if err!=nil {done<-err;return}
   switch value:=message.(type) {
   case derp.ReceivedPacket:
    if raw(value.Source)!="8f40c5adb68f25624ae5b214ea767a6ec94d829d3d7b5e1ad1ba6f3e2138285f" || len(value.Data)!=sizes[count] {done<-fmt.Errorf("incorrect peer or size");return}
    data:=make([]byte,len(value.Data))
    for i,x:=range value.Data {if x!=byte(i+sizes[count]) {done<-fmt.Errorf("incorrect data");return};data[i]=x^0x5a}
    if err:=client.Send(value.Source,data);err!=nil {done<-err;return}
    count++
   case derp.PingMessage:
    if err:=client.SendPong([8]byte(value));err!=nil {done<-err;return}
   }
  }
  done<-nil
 }()
 selfDone:=make(chan error,1)
 if len(os.Args)==2 && os.Args[1]=="selftest" {selfPeer<-private.Public();go func() {selfDone<-selfcheck(listener.Addr().String())}()}
 fmt.Printf("%d %s %s\n",listener.Addr().(*net.TCPAddr).Port,raw(server.PublicKey()),raw(private.Public()))
 select {case err:=<-done:if err!=nil {panic(err)};case <-time.After(12*time.Second):panic("packets timed out")}
 fmt.Println("derp-peer-complete:3")
 if len(os.Args)==2 && os.Args[1]=="selftest" {select {case err:=<-selfDone:if err!=nil {panic(err)};case <-time.After(5*time.Second):panic("self timed out")};fmt.Println("derp-selftest-passed")}
 var stop [1]byte
 if _,err:=io.ReadFull(os.Stdin,stop[:]);err!=nil {panic(err)}
}
'''


def reference_binary():
    root = pathlib.Path("/tmp/nexus-tailscale-derp-peer-v1.104.1")
    root.mkdir(exist_ok=True)
    binary = root / "derp-peer"
    stamp = root / "build-id"
    digest = hashlib.sha256(SOURCE.encode()).hexdigest()
    if not binary.exists() or not stamp.exists() or stamp.read_text().strip() != digest:
        (root / "go.mod").write_text(f"module nexus-tailscale-derp-peer\n\ngo 1.26.0\n\nrequire tailscale.com {VERSION}\n")
        (root / "main.go").write_text(SOURCE)
        env = dict(os.environ, GOTOOLCHAIN="local", GOMODCACHE=str(root / "modules"), GOCACHE=str(root / "cache"),
                   GOPROXY="file:///home/yk/go/pkg/mod/cache/download,https://proxy.golang.org")
        checked = subprocess.run(["go", "build", "-p", "1", "-mod=mod", "-o", binary, "."], cwd=root, env=env,
                                 capture_output=True, text=True, timeout=240)
        if checked.returncode:
            raise RuntimeError(checked.stderr)
        stamp.write_text(digest + "\n")
    return binary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", type=pathlib.Path)
    args = parser.parse_args()
    reference = reference_binary()
    for backend in (0, 1):
        env = dict(os.environ, TS_DERP_DISABLE_RTT_STATS="true")
        peer = subprocess.Popen([reference], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env)
        try:
            if not select.select([peer.stdout], [], [], 8)[0]:
                raise RuntimeError("official DERP peer did not start")
            fields = peer.stdout.readline().decode().strip().split()
            if len(fields) != 3 or not fields[0].isdigit() or any(len(value) != 64 for value in fields[1:]):
                raise RuntimeError(f"invalid DERP peer readiness: {fields!r}")
            checked = subprocess.run([args.fixture.resolve(), *fields, str(backend)], capture_output=True, timeout=12)
            if checked.returncode or checked.stdout.strip() != b"derp-network-passed":
                raise RuntimeError(f"DERP backend={backend}: {checked.returncode}, {checked.stdout!r}, {checked.stderr!r}")
            stdout, stderr = peer.communicate(b"x", timeout=5)
            if peer.returncode or stdout.strip() != b"derp-peer-complete:3":
                raise RuntimeError(f"official DERP peer: {peer.returncode}, {stdout!r}, {stderr!r}")
            print(f"DERP real {VERSION} server+Go client, pinned NaCl login, empty/17/65536 packet and ping: backend={backend} passed", flush=True)
        finally:
            if peer.poll() is None:
                peer.kill()
                peer.communicate(timeout=3)


if __name__ == "__main__":
    main()

