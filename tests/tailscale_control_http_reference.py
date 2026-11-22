#!/usr/bin/env python3
"""TS2021 HTTP syntax and early/Map framing checked by pinned official Go."""
import argparse
import hashlib
import os
import pathlib
import subprocess

SOURCE = r'''package main
import (
 "bufio"
 "bytes"
 "context"
 "encoding/base64"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/http/httptest"
 "os"
 "strings"
 "time"
 "tailscale.com/control/controlbase"
 "tailscale.com/control/controlhttp/controlhttpcommon"
 "tailscale.com/control/controlhttp/controlhttpserver"
 "tailscale.com/control/ts2021"
 "tailscale.com/tailcfg"
 "tailscale.com/types/key"
)
const earlyJSON=`{"nodeKeyChallenge":"chalpub:0000000000000000000000000000000000000000000000000000000000000000","future":{"value":1}}`
var h2Header=[]byte{0,0,0,4,0,0,0,0,0}
type bufferedConn struct {net.Conn;reader *bufio.Reader}
func (c *bufferedConn) Read(data []byte) (int,error) {return c.reader.Read(data)}
func selfcheck(early bool) error {
 control,machine:=key.NewMachine(),key.NewMachine();done:=make(chan error,1)
 server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
  ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel()
  if r.Method!="POST" || r.URL.Path!="/ts2021" {done<-fmt.Errorf("upgrade request method/path");return}
  writeEarly:=func(version int,w io.Writer) error {
   if version!=148 {return fmt.Errorf("upgrade version")};if !early {return nil}
   header:=make([]byte,9);copy(header,ts2021.EarlyPayloadMagic);binary.BigEndian.PutUint32(header[5:],uint32(len(earlyJSON)))
   if _,err:=w.Write(header);err!=nil {return err};_,err:=io.WriteString(w,earlyJSON);return err
  }
  connection,err:=controlhttpserver.AcceptHTTP(ctx,w,r,control,writeEarly);if err!=nil {done<-err;return};defer connection.Close()
  if connection.Peer()!=machine.Public() {done<-fmt.Errorf("upgrade machine identity");return}
  if _,err=connection.Write(h2Header);err!=nil {done<-err;return}
  var reply [9]byte;if _,err=io.ReadFull(connection,reply[:]);err!=nil {done<-err;return}
  if !bytes.Equal(reply[:],h2Header) {done<-fmt.Errorf("upgrade application reply");return};done<-nil
 }));defer server.Close()
 raw,err:=net.Dial("tcp",strings.TrimPrefix(server.URL,"http://"));if err!=nil {return err};defer raw.Close()
 raw.SetDeadline(time.Now().Add(3*time.Second))
 initial,continuation,err:=controlbase.ClientDeferred(machine,control.Public(),148);if err!=nil {return err}
 request,err:=http.NewRequest("POST",server.URL+"/ts2021",nil);if err!=nil {return err}
 request.Header.Set("Connection","upgrade");request.Header.Set("Upgrade",controlhttpcommon.UpgradeHeaderValue)
 request.Header.Set(controlhttpcommon.HandshakeHeaderName,base64.StdEncoding.EncodeToString(initial))
 if err=request.Write(raw);err!=nil {return err};reader:=bufio.NewReader(raw)
 response,err:=http.ReadResponse(reader,request);if err!=nil {return err}
 if response.StatusCode!=101 || response.Header.Get("Upgrade")!=controlhttpcommon.UpgradeHeaderValue {return fmt.Errorf("upgrade 101")}
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second);defer cancel()
 connection,err:=continuation(ctx,&bufferedConn{Conn:raw,reader:reader});if err!=nil {return err}
 wrapped:=ts2021.NewConn(connection,func() {});defer wrapped.Close()
 var header [9]byte;if _,err=io.ReadFull(wrapped,header[:]);err!=nil {return err}
 if !bytes.Equal(header[:],h2Header) {return fmt.Errorf("lost first H2 header")}
 payload,err:=wrapped.GetEarlyPayload(ctx);if err!=nil {return err}
 if (payload!=nil)!=early {return fmt.Errorf("early payload presence")}
 if _,err=wrapped.Write(h2Header);err!=nil {return err}
 select {case err:=<-done:return err;case <-ctx.Done():return ctx.Err()}
}
func initial() []byte {data:=make([]byte,101);for i:=range data {data[i]=byte(i)};data[2]=1;data[3]=0;data[4]=96;return data}
func checkRequest(wire []byte,authority string) error {
 reader:=bufio.NewReader(bytes.NewReader(wire));request,err:=http.ReadRequest(reader);if err!=nil {return err};defer request.Body.Close()
 if request.Method!="POST" || request.RequestURI!="/ts2021" || request.Host!=authority || request.Proto!="HTTP/1.1" || request.ContentLength!=0 {return fmt.Errorf("POST metadata")}
 if request.Header.Get("Connection")!="upgrade" || request.Header.Get("Upgrade")!=controlhttpcommon.UpgradeHeaderValue {return fmt.Errorf("upgrade headers")}
 encoded:=request.Header.Get(controlhttpcommon.HandshakeHeaderName)
 decoded,err:=base64.StdEncoding.Strict().DecodeString(encoded);if err!=nil {return err}
 if !bytes.Equal(decoded,initial()) || len(encoded)!=136 || !strings.HasSuffix(encoded,"=") {return fmt.Errorf("init header bytes/padding")}
 body,err:=io.ReadAll(request.Body);if err!=nil {return err}
 if len(body)!=0 || reader.Buffered()!=0 {return fmt.Errorf("init copied outside header")};return nil
}
func frame(data []byte,early bool) []byte {
 header:=make([]byte,4);if early {header=make([]byte,9);copy(header,ts2021.EarlyPayloadMagic);binary.BigEndian.PutUint32(header[5:],uint32(len(data)))} else {binary.LittleEndian.PutUint32(header,uint32(len(data)))}
 return append(header,data...)
}
func checkVectors() error {
 values:=map[string][]byte{};scanner:=bufio.NewScanner(os.Stdin)
 for scanner.Scan() {label,raw,ok:=strings.Cut(scanner.Text(),"=");if !ok {return fmt.Errorf("vector separator")};if _,exists:=values[label];exists {return fmt.Errorf("duplicate vector")};data,err:=hex.DecodeString(raw);if err!=nil {return err};values[label]=data}
 if err:=scanner.Err();err!=nil {return err};if len(values)!=9 {return fmt.Errorf("vector count %d",len(values))}
 for _,authority:=range []string{"control.example","control.example:8443","[::1]:8080"} {if err:=checkRequest(values["request-"+authority],authority);err!=nil {return err}}
 var info tailcfg.EarlyNoise;if err:=json.Unmarshal([]byte(earlyJSON),&info);err!=nil {return err};if !info.NodeKeyChallenge.IsZero() {return fmt.Errorf("challenge parsing")}
 expected:=map[string][]byte{"early-wire":frame([]byte(earlyJSON),true),"early-payload":[]byte(earlyJSON),"h2-prefix":h2Header}
 for _,size:=range []int{1,17,256} {data:=make([]byte,size);for i:=range data {data[i]=byte(i*17+size)};expected[fmt.Sprintf("map-%d",size)]=frame(data,false)}
 for label,data:=range expected {if !bytes.Equal(values[label],data) {return fmt.Errorf("frame vector %s",label)}}
 return nil
}
func main() {
 if len(os.Args)==2 && os.Args[1]=="--check" {if err:=checkVectors();err!=nil {panic(err)};fmt.Println("TS2021 official Go HTTP/base64 and early/Map frame differential passed: 9 vectors");return}
 for _,early:=range []bool{false,true} {if err:=selfcheck(early);err!=nil {panic(err)};fmt.Printf("official-upgrade-early:%v\n",early)}
}
'''


def reference_binary():
    root = pathlib.Path("/tmp/nexus-tailscale-control-http-reference-v1.104.1")
    root.mkdir(exist_ok=True)
    binary, stamp = root / "control-http-reference", root / "build-id"
    digest = hashlib.sha256(SOURCE.encode()).hexdigest()
    if not binary.exists() or not stamp.exists() or stamp.read_text().strip() != digest:
        (root / "go.mod").write_text("module nexus-tailscale-control-http-reference\n\ngo 1.27.1\n\nrequire tailscale.com v1.104.1\n")
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
    parser.add_argument("fixture", nargs="?", type=pathlib.Path)
    args = parser.parse_args()
    reference = reference_binary()
    checked = subprocess.check_output([reference], text=True, timeout=10)
    if checked.splitlines() != ["official-upgrade-early:false", "official-upgrade-early:true"]:
        raise RuntimeError(f"official Upgrade/early selftest failed: {checked!r}")
    print("Official v1.104.1 AcceptHTTP + Noise continuation + ts2021.Conn early/no-early TCP selftest passed", flush=True)
    if args.fixture:
        vectors = subprocess.check_output([args.fixture.resolve(), "--vectors"], timeout=10)
        checked = subprocess.run([reference, "--check"], input=vectors, capture_output=True, text=False, timeout=8)
        if checked.returncode:
            raise RuntimeError(f"wire differential failed: {checked.stdout!r}, {checked.stderr!r}")
        print(checked.stdout.decode().strip())


if __name__ == "__main__":
    main()
