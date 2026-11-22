// Loopback Hysteria 2 peer that waits for one byte before replying to TCPRequest.
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
	"nexus-hy2-peer/echfixture"
	"os"
	"sync/atomic"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
)

func dispatch(stream *quic.Stream) error {
	if err := stream.SetDeadline(time.Now().Add(8 * time.Second)); err != nil {
		return err
	}
	reader := bufio.NewReader(stream)
	if frame, err := quicvarint.Read(reader); err != nil || frame != 0x401 {
		return fmt.Errorf("invalid TCPRequest frame: %d, %v", frame, err)
	}
	for _, limit := range []uint64{2048, 4096} {
		length, err := quicvarint.Read(reader)
		if err != nil || length > limit {
			return fmt.Errorf("invalid TCPRequest field length: %d, %v", length, err)
		}
		if _, err := io.CopyN(io.Discard, reader, int64(length)); err != nil {
			return err
		}
	}
	fmt.Println("waiting for TCP payload")
	first, err := reader.ReadByte()
	if err != nil {
		return err
	}
	if first == '!' {
		_, err := stream.Write([]byte{1, 0, 0})
		return err
	}
	if _, err := stream.Write([]byte{0, 0, 0, first}); err != nil {
		return err
	}
	_, err = io.Copy(stream, reader)
	return err
}

func main() {
	if len(os.Args) != 3 {
		log.Fatal("usage: lazy-peer CERT.pem KEY.pem")
	}
	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	socket, err := net.ListenPacket("udp4", "127.0.0.1:0")
	if err != nil {
		log.Fatal(err)
	}
	defer socket.Close()
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	requireECH, err := echfixture.Configure(tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	listener, err := quic.Listen(socket, http3.ConfigureTLSConfig(tlsConfig), &quic.Config{})
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()
	fmt.Println(socket.LocalAddr())
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	conn, err := listener.Accept(ctx)
	if err != nil {
		log.Fatal(err)
	}
	defer conn.CloseWithError(0, "")
	if requireECH && !conn.ConnectionState().TLS.ECHAccepted {
		log.Fatal("Hysteria 2 fixture requires accepted ECH")
	}

	var authenticated atomic.Bool
	server := &http3.Server{
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost || r.URL.Path != "/auth" || r.Header.Get("Hysteria-Auth") != "test-password" {
				http.NotFound(w, r)
				return
			}
			authenticated.Store(true)
			w.Header().Set("Hysteria-UDP", "false")
			w.Header().Set("Hysteria-CC-RX", "auto")
			w.WriteHeader(233)
		}),
		StreamDispatcher: func(frame http3.FrameType, stream *quic.Stream, err error) (bool, error) {
			if err != nil || frame != 0x401 {
				return false, err
			}
			if !authenticated.Load() {
				return true, fmt.Errorf("TCPRequest before authentication")
			}
			if err := dispatch(stream); err != nil {
				return true, err
			}
			return true, stream.Close()
		},
	}
	_ = server.ServeQUICConn(conn)
}
