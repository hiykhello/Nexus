#!/usr/bin/env python3
"""Compare deterministic WireGuard core output with independent Go primitives."""
import argparse
import json
import os
import pathlib
import subprocess
import tempfile


# Go's X25519 and x/crypto BLAKE2s/AEAD are independent of Nexus/libcrypto.
# No fixed values below are used by a Nexus production entropy source.
SOURCE = r'''package main
import (
 "crypto/ecdh"
 "crypto/hmac"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "fmt"
 stdhash "hash"
 "os"
 "golang.org/x/crypto/blake2s"
 "golang.org/x/crypto/chacha20poly1305"
)
func seq(start, count int) []byte { out:=make([]byte,count); for i:=range out { out[i]=byte(start+i) }; return out }
func hash(parts ...[]byte) []byte { h,_:=blake2s.New256(nil); for _,p:=range parts { h.Write(p) }; return h.Sum(nil) }
func hmacSum(key []byte, parts ...[]byte) []byte {
 h:=hmac.New(func() stdhash.Hash { result,_:=blake2s.New256(nil); return result },key)
 for _,p:=range parts { h.Write(p) }; return h.Sum(nil)
}
func kdf(key, data []byte, n int) [][]byte {
 extract:=hmacSum(key,data); out:=make([][]byte,n); var previous []byte
 for i:=range out { out[i]=hmacSum(extract,previous,[]byte{byte(i+1)}); previous=out[i] }; return out
}
func dh(private, public []byte) []byte {
 sk,err:=ecdh.X25519().NewPrivateKey(private); if err!=nil { panic(err) }
 pk,err:=ecdh.X25519().NewPublicKey(public); if err!=nil { panic(err) }
 shared,err:=sk.ECDH(pk); if err!=nil { panic(err) }; return shared
}
func public(private []byte) []byte { key,err:=ecdh.X25519().NewPrivateKey(private); if err!=nil { panic(err) }; return key.PublicKey().Bytes() }
func seal(key []byte, count uint64, plain, aad []byte) []byte {
 aead,err:=chacha20poly1305.New(key); if err!=nil { panic(err) }; nonce:=make([]byte,12); binary.LittleEndian.PutUint64(nonce[4:],count)
 return aead.Seal(nil,nonce,plain,aad)
}
func mac(key, input []byte) []byte { h,err:=blake2s.New128(key); if err!=nil { panic(err) }; h.Write(input); return h.Sum(nil) }
func addMac(wire, receiver []byte) { offset:=len(wire)-32; copy(wire[offset:],mac(hash([]byte("mac1----"),receiver),wire[:offset])) }
func data(key []byte, receiver uint32, count uint64, plain []byte) []byte {
 padded:=make([]byte,(len(plain)+15)&^15); copy(padded,plain); wire:=make([]byte,16); wire[0]=4
 binary.LittleEndian.PutUint32(wire[4:],receiver); binary.LittleEndian.PutUint64(wire[8:],count)
 return append(wire,seal(key,count,padded,nil)...)
}
func main() {
 a,b,x,y:=seq(0,32),seq(32,32),seq(64,32),seq(96,32)
 ap,bp,xp,yp:=public(a),public(b),public(x),public(y)
 psk:=seq(128,32)
 ck:=hash([]byte("Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s")); transcript:=hash(ck,[]byte("WireGuard v1 zx2c4 Jason@zx2c4.com")); transcript=hash(transcript,bp)
 initiation:=make([]byte,148); initiation[0]=1; binary.LittleEndian.PutUint32(initiation[4:],0x12345678); copy(initiation[8:],xp)
 transcript=hash(transcript,xp); ck=kdf(ck,xp,1)[0]; derived:=kdf(ck,dh(x,bp),2); ck=derived[0]
 encrypted:=seal(derived[1],0,ap,transcript); copy(initiation[40:],encrypted); transcript=hash(transcript,encrypted)
 derived=kdf(ck,dh(a,bp),2); ck=derived[0]
 timestamp:=make([]byte,12); binary.BigEndian.PutUint64(timestamp,0x400000000000000a+1793494318); binary.BigEndian.PutUint32(timestamp[8:],0x12000000)
 encrypted=seal(derived[1],0,timestamp,transcript); copy(initiation[88:],encrypted); transcript=hash(transcript,encrypted); addMac(initiation,bp)
 response:=make([]byte,92); response[0]=2; binary.LittleEndian.PutUint32(response[4:],0x9abcdef0); binary.LittleEndian.PutUint32(response[8:],0x12345678); copy(response[12:],yp)
 transcript=hash(transcript,yp); ck=kdf(ck,yp,1)[0]; ck=kdf(ck,dh(y,xp),1)[0]; ck=kdf(ck,dh(y,ap),1)[0]
 derived=kdf(ck,psk,3); ck=derived[0]; transcript=hash(transcript,derived[1]); encrypted=seal(derived[2],0,nil,transcript); copy(response[44:],encrypted); transcript=hash(transcript,encrypted); addMac(response,ap)
 keys:=kdf(ck,nil,2)
 source:=[]byte{192,0,2,10,0x30,0x39}; cookie:=mac(seq(160,32),source); nonce:=seq(192,24)
 xaead,err:=chacha20poly1305.NewX(hash([]byte("cookie--"),bp)); if err!=nil { panic(err) }
 cookieReply:=make([]byte,32); cookieReply[0]=3; binary.LittleEndian.PutUint32(cookieReply[4:],0x12345678); copy(cookieReply[8:],nonce)
 cookieReply=append(cookieReply,xaead.Seal(nil,nonce,cookie,initiation[116:132])...)
 withCookie:=append([]byte(nil),initiation...); copy(withCookie[132:],mac(cookie,withCookie[:132]))
 result:=map[string]string{}
 for name,value:=range map[string][]byte{"initiation":initiation,"response":response,"cookie":cookieReply,"with-cookie":withCookie,
  "keepalive":data(keys[0],0x9abcdef0,0,nil),"initiator-data":data(keys[0],0x9abcdef0,1,seq(0,33)),"responder-data":data(keys[1],0x12345678,0,seq(1,17))} { result[name]=hex.EncodeToString(value) }
 encoded,_:=json.Marshal(result); fmt.Fprintln(os.Stdout,string(encoded))
}
'''


def reference():
    with tempfile.TemporaryDirectory(prefix="nexus-wireguard-reference-") as directory:
        root = pathlib.Path(directory)
        (root / "go.mod").write_text("module nexus-wireguard-reference\n\ngo 1.26.0\n\nrequire golang.org/x/crypto v0.57.0\n")
        (root / "main.go").write_text(SOURCE)
        output = subprocess.run(["go", "run", "-mod=mod", "."], cwd=root, capture_output=True, text=True,
                                env=dict(os.environ, GOPROXY="off", GOTOOLCHAIN="local"), timeout=60)
        if output.returncode:
            raise RuntimeError(f"Go reference failed: {output.stderr}")
        return json.loads(output.stdout)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("fixture", nargs="?", type=pathlib.Path)
    args = parser.parse_args()
    expected = reference()
    if args.fixture:
        actual = json.loads(subprocess.run([args.fixture.resolve(), "--vectors"], check=True, capture_output=True, text=True, timeout=15).stdout)
        if actual != expected:
            raise RuntimeError(f"independent WireGuard transcript mismatch: {set(actual) ^ set(expected)}; differing: {[key for key in expected if actual.get(key) != expected[key]]}")
        print("WireGuard independent Go X25519/BLAKE2s/ChaChaPoly/XChaCha handshake, MAC/cookie and transport vectors passed")
    else:
        print(json.dumps(expected, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()
