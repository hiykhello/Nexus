package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"

	quic "github.com/sagernet/quic-go"
	"time"

	"github.com/sagernet/quic-go/http3"
)

type observedConnection struct{}

func serveDetour(certPath, keyPath string, multipleTargets bool) {
	serveDetourAt(certPath, keyPath, "127.0.0.1:0", multipleTargets)
}

func serveDetourAt(certPath, keyPath, address string, multipleTargets bool) {
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	must(err)
	socket, err := net.ListenPacket("udp", address)
	must(err)
	defer socket.Close()
	fmt.Println(socket.LocalAddr())
	server := http3.Server{
		TLSConfig:       &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13},
		EnableDatagrams: true,
		QUICConfig:      &quic.Config{EnableDatagrams: true, Allow0RTT: true},
		ConnContext: func(ctx context.Context, conn *quic.Conn) context.Context {
			return context.WithValue(ctx, observedConnection{}, conn)
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			targetOK := r.URL.Path == "/.well-known/masque/udp/127.0.0.1/53/"
			if multipleTargets {
				switch r.URL.Path {
				case "/.well-known/masque/udp/127.0.0.1/53/", "/.well-known/masque/udp/127.0.0.1/54/", "/.well-known/masque/udp/::1/53/":
					targetOK = true
				default:
					targetOK = false
				}
			}
			if r.Method != http.MethodConnect || r.Proto != "connect-udp" || r.Host != "localhost" || !targetOK ||
				r.Header.Get("Proxy-Authorization") != "Bearer approved" {
				http.Error(w, "unexpected CONNECT-UDP request", http.StatusForbidden)
				return
			}
			if os.Getenv("NEXUS_TEST_MASQUE_RESUMPTION") != "" {
				conn := r.Context().Value(observedConnection{}).(*quic.Conn)
				fmt.Printf("resumed=%t early=%t\n", r.TLS.DidResume, conn.ConnectionState().Used0RTT)
			} else if multipleTargets {
				fmt.Println(r.URL.Path)
			} else {
				fmt.Println(r.RemoteAddr)
			}
			w.Header().Set("Capsule-Protocol", "?1")
			w.WriteHeader(http.StatusOK)
			stream := w.(http3.HTTPStreamer).HTTPStream()
			ctx, cancel := context.WithTimeout(r.Context(), 7*time.Second)
			defer cancel()
			for {
				datagram, err := stream.ReceiveDatagram(ctx)
				if err != nil {
					return
				}
				// The first byte is the CONNECT-UDP Context ID.
				if len(datagram) == 0 || datagram[0] != 0 {
					return
				}
				if err := stream.SendDatagram(datagram); err != nil {
					return
				}
			}
		}),
	}
	log.Fatal(server.Serve(socket))
}
