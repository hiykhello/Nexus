// Package echfixture lets the independent loopback peers require ECH.
package echfixture

import (
	"crypto/tls"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"os"
)

func Configure(config *tls.Config) (bool, error) {
	path := os.Getenv("NEXUS_TEST_ECH_KEYS")
	if path == "" {
		return false, nil
	}
	wire, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	block, rest := pem.Decode(wire)
	if block == nil || block.Type != "ECH KEYS" || len(rest) != 0 || len(block.Bytes) < 36 {
		return false, fmt.Errorf("invalid ECH fixture keys")
	}
	keyLen := int(binary.BigEndian.Uint16(block.Bytes))
	if keyLen != 32 || len(block.Bytes) < 2+keyLen+2 {
		return false, fmt.Errorf("invalid ECH fixture private key length")
	}
	key, list := block.Bytes[2:2+keyLen], block.Bytes[2+keyLen:]
	if int(binary.BigEndian.Uint16(list)) != len(list)-2 {
		return false, fmt.Errorf("invalid ECH fixture configuration length")
	}
	config.EncryptedClientHelloKeys = []tls.EncryptedClientHelloKey{{Config: list[2:], PrivateKey: key}}
	if os.Getenv("NEXUS_TEST_ECH_RETRY") == "1" {
		config.CurvePreferences = []tls.CurveID{tls.CurveP256}
	}
	return true, nil
}
