#!/usr/bin/env python3
"""Independent NaCl box/secretbox oracle using Go x/crypto v0.57.0."""
import argparse
import hashlib
import json
import os
import pathlib
import subprocess

SOURCE = r'''package main
import (
 "crypto/ecdh"
 "crypto/sha256"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "golang.org/x/crypto/nacl/box"
 "golang.org/x/crypto/nacl/secretbox"
)
func sequence(start, size int) []byte { value:=make([]byte,size);for i:=range value {value[i]=byte(start+i)};return value }
func array32(start int) *[32]byte {return (*[32]byte)(sequence(start,32))}
func main() {
 result:=map[string]string{}
 key,nonce:=array32(0),(*[24]byte)(sequence(32,24))
 for _,size:=range []int{0,1,15,16,17,31,32,33,63,64,65,127,128,129,1024,1048576} {
  plain:=sequence(64,size)
  sealed:=secretbox.Seal(nil,plain,nonce,key)
  reopened,ok:=secretbox.Open(nil,sealed,nonce,key)
  if !ok || string(reopened)!=string(plain) {panic("secretbox self-check")}
  if size<=129 {result[fmt.Sprint("secretbox-",size)]=hex.EncodeToString(sealed)} else {digest:=sha256.Sum256(sealed);result[fmt.Sprint("secretbox-sha256-",size)]=hex.EncodeToString(digest[:])}
 }
 local,remote:=array32(0),array32(32)
 one,_:=ecdh.X25519().NewPrivateKey(local[:]);two,_:=ecdh.X25519().NewPrivateKey(remote[:])
 ap,bp:=(*[32]byte)(one.PublicKey().Bytes()),(*[32]byte)(two.PublicKey().Bytes())
 result["local-public"]=hex.EncodeToString(ap[:]);result["remote-public"]=hex.EncodeToString(bp[:])
 nonce=(*[24]byte)(sequence(64,24))
 for _,size:=range []int{0,1,31,32,33,64,65,1024,1048576} {
  plain:=sequence(128,size)
  sealed:=box.Seal(nil,plain,nonce,bp,local)
  reopened,ok:=box.Open(nil,sealed,nonce,ap,remote)
  if !ok || string(reopened)!=string(plain) {panic("box self-check")}
  if size<=65 {result[fmt.Sprint("box-",size)]=hex.EncodeToString(sealed)} else {digest:=sha256.Sum256(sealed);result[fmt.Sprint("box-sha256-",size)]=hex.EncodeToString(digest[:])}
 }
 encoded,err:=json.Marshal(result);if err!=nil {panic(err)};fmt.Println(string(encoded))
}
'''


def reference():
    root = pathlib.Path("/tmp/nexus-tailscale-box-reference-v0.57.0")
    root.mkdir(exist_ok=True)
    binary = root / "box-reference"
    stamp = root / "build-id"
    digest = hashlib.sha256(SOURCE.encode()).hexdigest()
    if not binary.exists() or not stamp.exists() or stamp.read_text().strip() != digest:
        (root / "go.mod").write_text("module nexus-tailscale-box-reference\n\ngo 1.26.0\n\nrequire golang.org/x/crypto v0.57.0\n")
        (root / "main.go").write_text(SOURCE)
        env = dict(os.environ, GOTOOLCHAIN="local", GOMODCACHE=str(root / "modules"), GOCACHE=str(root / "cache"),
                   GOPROXY="file:///home/yk/go/pkg/mod/cache/download,https://proxy.golang.org")
        result = subprocess.run(["go", "build", "-p", "1", "-mod=mod", "-o", binary, "."], cwd=root, env=env,
                                capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise RuntimeError(result.stderr)
        stamp.write_text(digest + "\n")
    return json.loads(subprocess.run([binary], check=True, capture_output=True, text=True, timeout=15).stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=pathlib.Path)
    args = parser.parse_args()
    expected = reference()
    if args.fixture:
        actual = json.loads(subprocess.run([args.fixture.resolve(), "--vectors"], check=True, capture_output=True, text=True, timeout=20).stdout)
        if actual != expected:
            raise RuntimeError(f"NaCl differential mismatch: missing={set(expected)-set(actual)}, extra={set(actual)-set(expected)}, "
                               f"different={[name for name in expected if actual.get(name) != expected[name]]}")
        print(f"NaCl XSalsa20/Poly1305 secretbox and X25519 box differential passed: {len(expected)} official Go vectors")
    else:
        print(json.dumps(expected, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

