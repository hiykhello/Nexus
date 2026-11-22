// Command batch94a_tls_cover runs a controlled TLS endpoint for interop tests.
package main

import (
	"crypto/tls"
	"io"
	"log"
	"net"
	"os"
	"time"
)

func main() {
	if len(os.Args) != 5 {
		log.Fatal("usage: cover address certificate key hybrid|classical")
	}
	certificate, err := tls.LoadX509KeyPair(os.Args[2], os.Args[3])
	if err != nil {
		log.Fatal(err)
	}
	groups := []tls.CurveID{tls.X25519}
	switch os.Args[4] {
	case "hybrid":
		groups = append([]tls.CurveID{tls.X25519MLKEM768}, groups...)
	case "classical":
	default:
		log.Fatal("invalid curve selection")
	}
	config := &tls.Config{
		Certificates:     []tls.Certificate{certificate},
		CurvePreferences: groups,
		MinVersion:       tls.VersionTLS13,
		NextProtos:       []string{"h2", "http/1.1"},
	}
	listener, err := net.Listen("tcp", os.Args[1])
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	for {
		connection, err := listener.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			defer connection.Close()
			_ = connection.SetDeadline(time.Now().Add(10 * time.Second))
			stream := tls.Server(connection, config)
			if stream.Handshake() == nil {
				_, _ = io.Copy(stream, stream)
			}
		}()
	}
}
