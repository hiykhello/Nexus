package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"sync/atomic"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
)

func reply(stream *quic.Stream) error {
	if err := stream.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		return err
	}
	reader := bufio.NewReader(stream)
	if frame, err := quicvarint.Read(reader); err != nil || frame != 0x401 {
		return fmt.Errorf("invalid Hy2 TCPRequest frame: %d, %v", frame, err)
	}
	for _, limit := range []uint64{2048, 4096} {
		length, err := quicvarint.Read(reader)
		if err != nil || length > limit {
			return fmt.Errorf("invalid Hy2 TCPRequest field: length=%d error=%v", length, err)
		}
		if _, err = io.CopyN(io.Discard, reader, int64(length)); err != nil {
			return err
		}
	}
	if _, err := stream.Write([]byte{0, 0, 0}); err != nil {
		return err
	}
	if _, err := io.Copy(stream, reader); err != nil {
		return err
	}
	return stream.Close()
}

func listener(ctx context.Context, address string, cert tls.Certificate, group string, ticketKey [32]byte, expected int, ready chan<- struct{}) error {
	packet, err := net.ListenPacket("udp", address)
	if err != nil {
		return err
	}
	defer packet.Close()
	cfg := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	cfg.SetSessionTicketKeys([][32]byte{ticketKey})
	server, err := quic.Listen(packet, http3.ConfigureTLSConfig(cfg), &quic.Config{Allow0RTT: true})
	if err != nil {
		return err
	}
	defer server.Close()
	fmt.Printf("%s %d\n", group, packet.LocalAddr().(*net.UDPAddr).Port)
	ready <- struct{}{}
	for range expected {
		conn, err := server.Accept(ctx)
		if err != nil {
			return err
		}
		go serve(conn, group)
	}
	<-ctx.Done()
	return ctx.Err()
}

func serve(conn *quic.Conn, group string) {
	var authenticated atomic.Bool
	defer conn.CloseWithError(0, "")
	server := http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
			if request.Method != http.MethodPost || request.URL.Path != "/auth" ||
				request.Header.Get("Hysteria-Auth") != "test-password" {
				http.Error(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			authenticated.Store(true)
			state := conn.ConnectionState()
			fmt.Printf("auth group=%s resumed=%v early=%v\n", group, state.TLS.DidResume, state.Used0RTT)
			w.Header().Set("Hysteria-UDP", "false")
			w.Header().Set("Hysteria-CC-RX", "auto")
			w.WriteHeader(233)
		}),
		StreamDispatcher: func(frame http3.FrameType, stream *quic.Stream, err error) (bool, error) {
			if err != nil || frame != 0x401 {
				return false, err
			}
			if !authenticated.Load() {
				return true, fmt.Errorf("TCP request before Hy2 authentication")
			}
			if err := reply(stream); err != nil {
				log.Printf("TCP request: %v", err)
				return true, err
			}
			return true, nil
		},
	}
	_ = server.ServeQUICConn(conn)
}

func main() {
	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	ctx, stop := context.WithTimeout(context.Background(), 25*time.Second)
	defer stop()
	var key [32]byte
	key[0] = 91 // Shared between these loopback servers to verify endpoint isolation.
	ready := make(chan struct{}, 3)
	for index, address := range []string{"127.0.0.1:0", "[::1]:0", "127.0.0.1:0"} {
		group := []string{"ipv4", "ipv6", "other-port"}[index]
		expected := []int{3, 2, 1}[index]
		go func() {
			if err := listener(ctx, address, cert, group, key, expected, ready); err != nil {
				log.Fatal(err)
			}
		}()
	}
	for range 3 {
		<-ready
	}
	<-ctx.Done()
}
