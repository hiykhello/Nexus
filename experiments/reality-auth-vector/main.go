package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"fmt"
	"math/big"
	"time"
)

func unhex(s string) []byte {
	b, e := hex.DecodeString(s)
	if e != nil {
		panic(e)
	}
	return b
}
func main() {
	x := ecdh.X25519()
	c, _ := x.NewPrivateKey(unhex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"))
	s, _ := x.NewPrivateKey(unhex("5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"))
	secret, _ := c.ECDH(s.PublicKey())
	random := make([]byte, 32)
	for i := range random {
		random[i] = byte(i)
	}
	ext := append(unhex("003300260024001d0020"), c.PublicKey().Bytes()...)
	body := append([]byte{3, 3}, random...)
	body = append(body, 32)
	body = append(body, make([]byte, 32)...)
	body = append(body, unhex("000213010100")...)
	body = append(body, byte(len(ext)>>8), byte(len(ext)))
	body = append(body, ext...)
	hello := append([]byte{1, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	extract := hmac.New(sha256.New, random[:20])
	extract.Write(secret)
	expand := hmac.New(sha256.New, extract.Sum(nil))
	expand.Write(append([]byte("REALITY"), 1))
	block, _ := aes.NewCipher(expand.Sum(nil))
	aead, _ := cipher.NewGCM(block)
	sealed := aead.Seal(nil, random[20:], unhex("010203006553f1000102030405060708"), hello)
	private := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{7}, 32))
	template := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test.invalid"}, NotBefore: time.Unix(0, 0), NotAfter: time.Unix(86400, 0), KeyUsage: x509.KeyUsageDigitalSignature}
	cert, err := x509.CreateCertificate(bytes.NewReader(make([]byte, 1024)), template, template, private.Public(), private)
	if err != nil {
		panic(err)
	}
	mac := hmac.New(sha512.New, expand.Sum(nil))
	mac.Write(private.Public().(ed25519.PublicKey))
	copy(cert[len(cert)-64:], mac.Sum(nil))
	fmt.Printf("certificate %x\n", cert)
	fmt.Printf("hello %x\nsealed %x\nserver %x\nclient %x\n", hello, sealed, s.PublicKey().Bytes(), c.PublicKey().Bytes())
}
