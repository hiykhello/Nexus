#!/usr/bin/env python3
"""Independent fixed Noise IK/record vectors using Go x/crypto primitives."""
import argparse
import hashlib
import os
import pathlib
import subprocess

SOURCE = r'''package main
import (
 "bytes"
 "crypto/sha256"
 "encoding/binary"
 "encoding/hex"
 "fmt"
 "hash"
 "io"
 "strconv"
 "golang.org/x/crypto/blake2s"
 "golang.org/x/crypto/chacha20poly1305"
 "golang.org/x/crypto/curve25519"
 "golang.org/x/crypto/hkdf"
)
type state struct { h,ck [32]byte }
func hasher() hash.Hash {h,err:=blake2s.New256(nil);if err!=nil {panic(err)};return h}
func (s *state) mix(data []byte) {h:=hasher();h.Write(s.h[:]);h.Write(data);copy(s.h[:],h.Sum(nil))}
func initialize(version uint16,control []byte) state {
 h:=blake2s.Sum256([]byte("Noise_IK_25519_ChaChaPoly_BLAKE2s"));s:=state{h:h,ck:h}
 s.mix([]byte("Tailscale Control Protocol v"+strconv.Itoa(int(version))));s.mix(control);return s
}
func (s *state) derive(input []byte) (one,two [32]byte) {
 h:=hkdf.New(hasher,input,s.ck[:],nil)
 if _,err:=io.ReadFull(h,one[:]);err!=nil {panic(err)}
 if _,err:=io.ReadFull(h,two[:]);err!=nil {panic(err)};return
}
func (s *state) dh(private,public []byte) [32]byte {
 shared,err:=curve25519.X25519(private,public);if err!=nil {panic(err)}
 chain,key:=s.derive(shared);s.ck=chain;return key
}
func (s *state) encrypt(key [32]byte,plain []byte) []byte {
 cipher,err:=chacha20poly1305.New(key[:]);if err!=nil {panic(err)}
 sealed:=cipher.Seal(nil,make([]byte,12),plain,s.h[:]);s.mix(sealed);return sealed
}
func (s *state) decrypt(key [32]byte,sealed []byte) []byte {
 cipher,err:=chacha20poly1305.New(key[:]);if err!=nil {panic(err)}
 plain,err:=cipher.Open(nil,make([]byte,12),sealed,s.h[:]);if err!=nil {panic(err)};s.mix(sealed);return plain
}
func private(seed int) []byte {b:=make([]byte,32);for i:=range b {b[i]=byte(i+seed)};return b}
func public(private []byte) []byte {b,err:=curve25519.X25519(private,curve25519.Basepoint);if err!=nil {panic(err)};return b}
func emit(label string,data []byte) {
 if len(data)>256 {sum:=sha256.Sum256(data);fmt.Printf("%s=sha256:%x\n",label,sum)} else {fmt.Printf("%s=%s\n",label,hex.EncodeToString(data))}
}
func record(key [32]byte,count uint64,plain []byte) []byte {
 cipher,err:=chacha20poly1305.New(key[:]);if err!=nil {panic(err)}
 nonce:=make([]byte,12);binary.BigEndian.PutUint64(nonce[4:],count)
 wire:=make([]byte,3);wire[0]=4;binary.BigEndian.PutUint16(wire[1:],uint16(len(plain)+16))
 return cipher.Seal(wire,nonce,plain,nil)
}
func openRecord(key [32]byte,count uint64,wire []byte) []byte {
 cipher,err:=chacha20poly1305.New(key[:]);if err!=nil {panic(err)}
 nonce:=make([]byte,12);binary.BigEndian.PutUint64(nonce[4:],count)
 plain,err:=cipher.Open(nil,nonce,wire[3:],nil);if err!=nil {panic(err)};return plain
}
func vectors(version uint16) {
 machine,control,ce,se:=private(3),private(71),private(141),private(211)
 mp,cp,cep,sep:=public(machine),public(control),public(ce),public(se)
 c,s:=initialize(version,cp),initialize(version,cp)
 initial:=make([]byte,101);binary.BigEndian.PutUint16(initial,version);initial[2]=1;binary.BigEndian.PutUint16(initial[3:],96);copy(initial[5:],cep)
 c.mix(cep);copy(initial[37:],c.encrypt(c.dh(ce,cp),mp));copy(initial[85:],c.encrypt(c.dh(machine,cp),nil))
 s.mix(initial[5:37]);authenticated:=s.decrypt(s.dh(control,initial[5:37]),initial[37:85]);if !bytes.Equal(authenticated,mp) {panic("machine identity")}
 if len(s.decrypt(s.dh(control,authenticated),initial[85:]))!=0 {panic("init payload")}
 response:=make([]byte,51);response[0]=2;binary.BigEndian.PutUint16(response[1:],48);copy(response[3:],sep)
 s.mix(sep);s.dh(se,cep);copy(response[35:],s.encrypt(s.dh(se,mp),nil))
 c.mix(response[3:35]);c.dh(ce,response[3:35]);if len(c.decrypt(c.dh(machine,response[3:35]),response[35:]))!=0 {panic("response payload")}
 if c.h!=s.h || c.ck!=s.ck {panic("handshake binding")}
 c1,c2:=c.derive(nil);s1,s2:=s.derive(nil);if c1!=s1 || c2!=s2 {panic("split")}
 suffix:=strconv.Itoa(int(version));emit("init-"+suffix,initial);emit("response-"+suffix,response);emit("hash-"+suffix,c.h[:])
 for count,size:=range []int{0,1,17,33,4077} {
  plain:=make([]byte,size);for i:=range plain {plain[i]=byte(i*17+size)}
  a,b:=record(c1,uint64(count),plain),record(s2,uint64(count),plain)
  if !bytes.Equal(openRecord(s1,uint64(count),a),plain) || !bytes.Equal(openRecord(c2,uint64(count),b),plain) {panic("record directions")}
  emit("c2s-"+suffix+"-"+strconv.Itoa(size),a);emit("s2c-"+suffix+"-"+strconv.Itoa(size),b)
 }
}
func main() {for _,version:=range []uint16{1,148,65535} {vectors(version)}}
'''


def reference_binary():
    root = pathlib.Path("/tmp/nexus-tailscale-control-reference-v0.57.0")
    root.mkdir(exist_ok=True)
    binary, stamp = root / "control-reference", root / "build-id"
    digest = hashlib.sha256(SOURCE.encode()).hexdigest()
    if not binary.exists() or not stamp.exists() or stamp.read_text().strip() != digest:
        (root / "go.mod").write_text("module nexus-tailscale-control-reference\n\ngo 1.27.1\n\nrequire golang.org/x/crypto v0.57.0\n")
        (root / "main.go").write_text(SOURCE)
        env = dict(os.environ, GOTOOLCHAIN="local", GOMODCACHE=str(root / "modules"), GOCACHE=str(root / "cache"),
                   GOPROXY="file:///home/yk/go/pkg/mod/cache/download,https://proxy.golang.org")
        checked = subprocess.run(["go", "build", "-p", "1", "-mod=mod", "-o", binary, "."], cwd=root, env=env,
                                 capture_output=True, text=True, timeout=240)
        if checked.returncode:
            raise RuntimeError(checked.stderr)
        stamp.write_text(digest + "\n")
    return binary


def parsed(text):
    result = {}
    for line in text.splitlines():
        label, value = line.split("=", 1)
        if label in result:
            raise RuntimeError(f"duplicate vector {label}")
        if value.startswith("sha256:"):
            if len(value) != 71:
                raise RuntimeError(f"invalid vector digest {label}")
            bytes.fromhex(value[7:])
        else:
            bytes.fromhex(value)
        result[label] = value
    if len(result) != 39:
        raise RuntimeError(f"expected 39 vectors, got {len(result)}")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=pathlib.Path)
    args = parser.parse_args()
    expected = parsed(subprocess.check_output([reference_binary()], text=True, timeout=8))
    if args.fixture:
        actual = parsed(subprocess.check_output([args.fixture.resolve(), "--vectors"], text=True, timeout=12))
        if actual != expected:
            failed = sorted(label for label in expected.keys() | actual.keys() if expected.get(label) != actual.get(label))
            raise RuntimeError(f"control vectors differ: {failed}")
        print("Control Noise IK/BE64 record differential passed: 39 independent Go x/crypto vectors")
    else:
        print("Independent Go x/crypto control Noise IK/record oracle self-check passed: 39 vectors")


if __name__ == "__main__":
    main()
