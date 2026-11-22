// Controlled HTTP/3 peer advertises a numeric receive rate and checks that
// the Nexus client proceeds to a real Hysteria TCP exchange.
package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
)

func checkRate(err error) {
	if err != nil {
		panic(err)
	}
}

func main() {
	if len(os.Args) != 5 {
		panic("usage: rate-server 4|6 PORT CERT.pem KEY.pem")
	}
	host := "127.0.0.1"
	if os.Args[1] == "6" {
		host = "::1"
	}
	cert, err := tls.LoadX509KeyPair(os.Args[3], os.Args[4])
	checkRate(err)
	listener, err := quic.ListenAddr(net.JoinHostPort(host, os.Args[2]),
		&tls.Config{Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13},
		&quic.Config{EnableDatagrams: true})
	checkRate(err)
	defer listener.Close()
	fmt.Println("READY")
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := listener.Accept(ctx)
	checkRate(err)
	defer conn.CloseWithError(0, "")
	var authenticated atomic.Bool
	done := make(chan error, 1)
	server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "POST" || r.Host != "hysteria" || r.URL.Path != "/auth" || r.Header.Get("Hysteria-Auth") != "test-password" || r.Header.Get("Hysteria-CC-RX") != "0" {
				http.Error(w, "invalid authentication", http.StatusForbidden)
				return
			}
			authenticated.Store(true)
			w.Header().Set("Hysteria-UDP", "true")
			w.Header().Set("Hysteria-CC-RX", "1250000")
			w.WriteHeader(233)
		}),
		StreamDispatcher: func(frame http3.FrameType, stream *quic.Stream, err error) (bool, error) {
			if err != nil || frame != 0x401 {
				return false, err
			}
			if !authenticated.Load() {
				return true, fmt.Errorf("stream before authentication")
			}
			go func() {
				reader := quicvarint.NewReader(stream)
				typ, err := quicvarint.Read(reader)
				if err != nil || typ != 0x401 {
					done <- fmt.Errorf("invalid frame: %d %v", typ, err)
					return
				}
				size, err := quicvarint.Read(reader)
				if err != nil || size > 256 {
					done <- fmt.Errorf("invalid address length: %d %v", size, err)
					return
				}
				address := make([]byte, size)
				if _, err = io.ReadFull(reader, address); err != nil {
					done <- err
					return
				}
				padding, err := quicvarint.Read(reader)
				if err != nil || padding > 4096 {
					done <- fmt.Errorf("invalid padding: %d %v", padding, err)
					return
				}
				if _, err = io.CopyN(io.Discard, reader, int64(padding)); err != nil {
					done <- err
					return
				}
				if string(address) != "127.0.0.1:12345" {
					done <- fmt.Errorf("unexpected target %q", address)
					return
				}
				if _, err = stream.Write([]byte{0, 0, 0}); err == nil {
					_, err = io.Copy(stream, reader)
				}
				if err == nil {
					err = stream.Close()
				}
				done <- err
			}()
			return true, nil
		},
	}
	go func() { _ = server.ServeQUICConn(conn) }()
	select {
	case err = <-done:
		checkRate(err)
		fmt.Println("numeric receive rate and TCP echo verified")
		select {
		case <-conn.Context().Done():
		case <-time.After(3 * time.Second):
		}
	case <-ctx.Done():
		panic("TCP exchange timed out")
	}
}
