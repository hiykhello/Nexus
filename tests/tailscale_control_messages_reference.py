#!/usr/bin/env python3
"""Fixed v148 tailcfg JSON serialization against the narrow typed codec."""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess

SOURCE = r'''package main
import (
 "bytes"
 "encoding/json"
 "fmt"
 "io"
 "net/netip"
 "os"
 "go4.org/mem"
 "tailscale.com/tailcfg"
 "tailscale.com/types/key"
)
type vector struct {Name string `json:"name"`;Kind string `json:"kind"`;Status int `json:"status"`;Body json.RawMessage `json:"body"`;Expected string `json:"expected"`}
func public(first int) key.NodePublic {data:=make([]byte,32);for i:=range data {data[i]=byte(first+i)};return key.NodePublicFromRaw32(mem.B(data))}
func peer(id int64,first int) *tailcfg.Node {
 return &tailcfg.Node{ID:tailcfg.NodeID(id),Key:public(first),Name:"alpha",Addresses:[]netip.Prefix{netip.MustParsePrefix("100.64.0.1/32"),netip.MustParsePrefix("fd7a:115c:a1e0::1/128")}}
}
func must(value any) json.RawMessage {data,err:=json.Marshal(value);if err!=nil {panic(err)};return data}
func presence(object map[string]json.RawMessage,name string) int {raw,ok:=object[name];if !ok {return 0};if bytes.Equal(raw,[]byte("null")) {return 1};return 2}
func mapExpected(data json.RawMessage) string {
 var wire tailcfg.MapResponse;if err:=json.Unmarshal(data,&wire);err!=nil {panic(err)}
 var fields map[string]json.RawMessage;if err:=json.Unmarshal(data,&fields);err!=nil {panic(err)}
 p,c,r:=len(wire.Peers),len(wire.PeersChanged),len(wire.PeersRemoved);mode:=0;if p!=0 {mode=1} else if c!=0 || r!=0 {mode=2}
 hasSelf:=wire.Node!=nil;peerPresence:=presence(fields,"Peers")
 if wire.KeepAlive {mode=0;p=0;c=0;r=0;hasSelf=false;peerPresence=0}
 return fmt.Sprintf("map:%d:%t:%t:%d:%d:%d:%d:%d:%d",mode,wire.KeepAlive,hasSelf,p,c,r,peerPresence,presence(fields,"Seq"),presence(fields,"MapSessionHandle"))
}
func vectors() []vector {
 var output []vector
 addRegister:=func(name string,response tailcfg.RegisterResponse) {
  expected:="state:pending"
  switch {case response.Error!="":expected="state:denied";case len(response.NodeKeySignature)>0:expected="failure:unsupported_security:0";case response.NodeKeyExpired:expected="state:expired";case response.AuthURL!="":expected="state:pending";case response.MachineAuthorized:expected="state:authorized"}
  data:=must(response);var roundtrip tailcfg.RegisterResponse;if err:=json.Unmarshal(data,&roundtrip);err!=nil {panic(err)}
  output=append(output,vector{name,"register",200,data,expected})
 }
 addRegister("authorized",tailcfg.RegisterResponse{MachineAuthorized:true})
 addRegister("pending",tailcfg.RegisterResponse{})
 addRegister("auth-url-over-authorized",tailcfg.RegisterResponse{MachineAuthorized:true,AuthURL:"https://login.example/authorize"})
 addRegister("expiry-over-auth-url",tailcfg.RegisterResponse{MachineAuthorized:true,NodeKeyExpired:true,AuthURL:"https://login.example/authorize"})
 addRegister("signature-before-expiry",tailcfg.RegisterResponse{NodeKeyExpired:true,NodeKeySignature:[]byte{1}})
 addRegister("error-over-all",tailcfg.RegisterResponse{Error:"denied",NodeKeyExpired:true,MachineAuthorized:true,AuthURL:"https://login.example",NodeKeySignature:[]byte{1}})
 output=append(output,vector{"http-status","register",429,json.RawMessage(`{"MachineAuthorized":true}`),"failure:http_status:429"})
 addMap:=func(name string,value any) {data:=must(value);output=append(output,vector{name,"map",200,data,mapExpected(data)})}
 addMap("empty",tailcfg.MapResponse{})
 addMap("full",tailcfg.MapResponse{Node:peer(1,1),Peers:[]*tailcfg.Node{peer(2,41)},MapSessionHandle:"session-1",Seq:1})
 addMap("delta",tailcfg.MapResponse{PeersChanged:[]*tailcfg.Node{peer(2,41)},PeersRemoved:[]tailcfg.NodeID{3},Seq:2})
 addMap("full-has-priority",tailcfg.MapResponse{Peers:[]*tailcfg.Node{peer(2,41)},PeersChanged:[]*tailcfg.Node{peer(3,73)},PeersRemoved:[]tailcfg.NodeID{4}})
 addMap("keepalive",tailcfg.MapResponse{KeepAlive:true,Peers:[]*tailcfg.Node{peer(2,41)}})
 addMap("null-fields",map[string]any{"Peers":nil,"Seq":nil,"MapSessionHandle":nil})
 addMap("empty-fields",map[string]any{"Peers":[]*tailcfg.Node{},"Seq":0,"MapSessionHandle":""})
 p:=peer(2,41);p.AllowedIPs=[]netip.Prefix{};addMap("explicit-empty-allowedips",tailcfg.MapResponse{Peers:[]*tailcfg.Node{p}})
 p=peer(2,41);p.Endpoints=[]netip.AddrPort{netip.MustParseAddrPort("192.0.2.3:443"),netip.MustParseAddrPort("[2001:db8::3]:443")};p.HomeDERP=1;addMap("udp-path-candidates",tailcfg.MapResponse{Peers:[]*tailcfg.Node{p}})
 for _,entry:=range []struct{name string;value any}{
  {"empty-packet-filter",map[string]any{"PacketFilter":[]tailcfg.FilterRule{}}},
  {"named-packet-filter",tailcfg.MapResponse{PacketFilters:map[string][]tailcfg.FilterRule{"base":{}}}},
  {"tailnet-lock-disable-unverified",tailcfg.MapResponse{TKAInfo:&tailcfg.TKAInfo{Disabled:true}}},
  {"peer-patch",tailcfg.MapResponse{PeersChangedPatch:[]*tailcfg.PeerChange{{NodeID:2,Key:&p.Key}}}},
 } {output=append(output,vector{entry.name,"map",200,must(entry.value),"failure:unsupported_security:0"})}
 p=peer(2,41);p.CapMap=tailcfg.NodeCapMap{"future-security":nil};output=append(output,vector{"unknown-node-capability","map",200,must(tailcfg.MapResponse{Peers:[]*tailcfg.Node{p}}),"failure:unsupported_security:0"})
 return output
}
func verifyRequest() error {
 data,err:=io.ReadAll(io.LimitReader(os.Stdin,16385));if err!=nil {return err};if len(data)>16384 {return fmt.Errorf("request cap")}
 decoder:=json.NewDecoder(bytes.NewReader(data));decoder.DisallowUnknownFields();var request tailcfg.RegisterRequest
 if err:=decoder.Decode(&request);err!=nil {return err};var extra any;if decoder.Decode(&extra)!=io.EOF {return fmt.Errorf("request trailing JSON")}
 if request.Version!=148 || request.NodeKey!=public(1) || request.Auth==nil || request.Auth.AuthKey!=`test-auth-key-\"example` || !request.Ephemeral {return fmt.Errorf("request version/key/auth/ephemeral")}
 if request.Hostinfo==nil || request.Hostinfo.Hostname!="nexus-test" || request.Hostinfo.OS!="linux" || request.Hostinfo.IPNVersion!="Nexus-test" {return fmt.Errorf("request hostinfo")}
 return nil
}
func main() {
 if len(os.Args)==2 && os.Args[1]=="--request" {if err:=verifyRequest();err!=nil {panic(err)};fmt.Println("official-v148-register-request-passed");return}
 data:=must(vectors());os.Stdout.Write(data)
}
'''


def reference_binary():
    root = pathlib.Path("/tmp/nexus-tailscale-control-messages-reference-v1.104.1")
    root.mkdir(exist_ok=True)
    binary, stamp = root / "control-messages-reference", root / "build-id"
    digest = hashlib.sha256(SOURCE.encode()).hexdigest()
    if not binary.exists() or not stamp.exists() or stamp.read_text().strip() != digest:
        (root / "go.mod").write_text("module nexus-tailscale-control-messages-reference\n\ngo 1.27.1\n\nrequire tailscale.com v1.104.1\n")
        (root / "main.go").write_text(SOURCE)
        env = dict(os.environ, GOTOOLCHAIN="local", GOMODCACHE=str(root / "modules"), GOCACHE=str(root / "cache"),
                   GOPROXY=os.environ.get("GOPROXY", f"file://{pathlib.Path.home() / 'go/pkg/mod/cache/download'},https://proxy.golang.org"))
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
    cases = json.loads(subprocess.check_output([reference], timeout=8))
    if len(cases) != 21 or len({case["name"] for case in cases}) != len(cases):
        raise RuntimeError(f"invalid official JSON cases: {len(cases)}")
    if not args.fixture:
        print(f"Official v148 tailcfg register/Map JSON oracle self-check passed: {len(cases)} cases")
        return
    request = subprocess.check_output([args.fixture.resolve(), "--request"], timeout=8)
    checked = subprocess.run([reference, "--request"], input=request, capture_output=True, timeout=8)
    if checked.returncode or checked.stdout.strip() != b"official-v148-register-request-passed":
        raise RuntimeError(f"register request differs: {checked.stdout!r}, {checked.stderr!r}")
    for case in cases:
        command = [args.fixture.resolve(), "--register", str(case["status"])] if case["kind"] == "register" else [args.fixture.resolve(), "--map"]
        checked = subprocess.run(command, input=json.dumps(case["body"], separators=(",", ":")).encode(), capture_output=True, timeout=8)
        if checked.returncode or checked.stdout.decode().strip() != case["expected"]:
            raise RuntimeError(f"{case['name']}: expected {case['expected']!r}, got {checked.returncode}, {checked.stdout!r}, {checked.stderr!r}")
    print(f"Official v148 tailcfg register request and {len(cases)} response/Map JSON differential cases passed; unsupported policies rejected locally")


if __name__ == "__main__":
    main()
