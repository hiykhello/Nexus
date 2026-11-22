// Independent TUIC authentication and CONNECT peer for TLS resumption tests.
package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"time"

	quic "github.com/sagernet/quic-go"
)

func authenticate(conn *quic.Conn, uuid []byte) error {
	ctx, cancel := context.WithTimeout(context.Background(), 4*time.Second)
	defer cancel()
	authenticate, err := conn.AcceptUniStream(ctx)
	if err != nil {
		return err
	}
	var wire [50]byte
	if _, err := io.ReadFull(authenticate, wire[:]); err != nil {
		return err
	}
	state := conn.ConnectionState()
	token, err := state.TLS.ExportKeyingMaterial(string(uuid), []byte("tuic-test"), 32)
	if err != nil {
		return err
	}
	if wire[0] != 5 || wire[1] != 0 || !bytes.Equal(wire[2:18], uuid) || !bytes.Equal(wire[18:], token) {
		return fmt.Errorf("invalid TUIC authentication")
	}
	fmt.Printf("auth resumed=%t early=%t\n", state.TLS.DidResume, state.Used0RTT)
	for {
		stream, err := conn.AcceptStream(conn.Context())
		if err != nil {
			return nil
		}
		go echo(stream)
	}
}

func echo(stream *quic.Stream) {
	defer stream.Close()
	var header [9]byte
	if _, err := io.ReadFull(stream, header[:]); err != nil {
		return
	}
	if header != [9]byte{5, 1, 1, 127, 0, 0, 1, 0, 53} {
		stream.CancelRead(1)
		return
	}
	if _, err := io.Copy(stream, stream); err != nil {
		stream.CancelRead(1)
	}
}

func main() {
	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	socket, err := net.ListenPacket("udp", os.Args[3])
	if err != nil {
		log.Fatal(err)
	}
	defer socket.Close()
	server, err := quic.ListenEarly(socket, &tls.Config{
		Certificates: []tls.Certificate{cert}, NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13,
	}, &quic.Config{Allow0RTT: true, EnableDatagrams: true})
	if err != nil {
		log.Fatal(err)
	}
	defer server.Close()
	fmt.Println(socket.LocalAddr())
	uuid, err := hex.DecodeString("00112233445566778899aabbccddeeff")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := server.Accept(context.Background())
		if err != nil {
			log.Fatal(err)
		}
		go func() {
			if err := authenticate(conn, uuid); err != nil {
				log.Print(err)
				conn.CloseWithError(1, "authentication failed")
			}
		}()
	}
}
