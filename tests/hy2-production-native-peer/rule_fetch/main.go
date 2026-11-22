package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"

	"github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"nexus-hy2-peer/echfixture"
)

type connectionID struct{}

type limitedIngress struct {
	net.PacketConn
	expectedHost string
	maxPacket    int
	invalid      atomic.Bool
}

func (s *limitedIngress) ReadFrom(buffer []byte) (int, net.Addr, error) {
	n, address, err := s.PacketConn.ReadFrom(buffer)
	if n > s.maxPacket {
		s.invalid.Store(true)
		log.Printf("received UDP payload of %d bytes", n)
	}
	if err == nil {
		host, _, splitErr := net.SplitHostPort(address.String())
		if splitErr != nil || host != s.expectedHost {
			s.invalid.Store(true)
			log.Printf("unexpected UDP source %v", address)
		}
	}
	return n, address, err
}

func main() {
	if len(os.Args) != 4 {
		log.Fatal("usage: rule-fetch-peer CERT KEY RULES")
	}
	rules, err := os.ReadFile(os.Args[3])
	if err != nil {
		log.Fatal(err)
	}
	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	config := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	expectedHost := os.Getenv("NEXUS_TEST_SOURCE_HOST")
	if expectedHost == "" {
		expectedHost = "127.0.0.2"
	}
	expectedPort := os.Getenv("NEXUS_TEST_SOURCE_PORT")
	expectedName, present := os.LookupEnv("NEXUS_TEST_SERVER_NAME")
	if !present {
		expectedName = "localhost"
	}
	maxPacket := 1200
	if value := os.Getenv("NEXUS_TEST_MAX_PACKET"); value == "1500" {
		maxPacket = 1500
	}
	requireECH, err := echfixture.Configure(config)
	if err != nil {
		log.Fatal(err)
	}
	bind := os.Getenv("NEXUS_TEST_BIND_UDP_ADDRESS")
	if bind == "" {
		bind = "127.0.0.1:0"
	}
	socket, err := net.ListenPacket("udp", bind)
	if err != nil {
		log.Fatal(err)
	}
	defer socket.Close()
	ingress := &limitedIngress{PacketConn: socket, expectedHost: expectedHost, maxPacket: maxPacket}
	fmt.Println(socket.LocalAddr())
	started := make(chan struct{}, 1)
	canceled := make(chan struct{}, 1)
	var connections atomic.Uint64
	server := http3.Server{
		TLSConfig: config,
		ConnContext: func(ctx context.Context, _ *quic.Conn) context.Context {
			return context.WithValue(ctx, connectionID{}, connections.Add(1))
		},
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			host, port, _ := net.SplitHostPort(r.RemoteAddr)
			if ingress.invalid.Load() || host != expectedHost || (expectedPort != "" && port != expectedPort) || r.TLS == nil || r.TLS.ServerName != expectedName ||
				r.TLS.NegotiatedProtocol != "h3" || (requireECH && !r.TLS.ECHAccepted) ||
				r.Method != "GET" || r.Header.Get("Accept-Encoding") != "identity" {
				http.Error(w, "unexpected HTTP/3 request", http.StatusBadRequest)
				return
			}
			switch r.URL.Path {
			case "/resume":
				fmt.Println("resume", r.Context().Value(connectionID{}), strconv.FormatBool(r.TLS.DidResume))
				_, _ = w.Write([]byte("ok"))
			case "/consumer-warm":
				fmt.Println(r.URL.Path, r.Context().Value(connectionID{}))
				_, _ = w.Write([]byte("ok"))
			case "/consumer-after":
				select {
				case <-canceled:
					fmt.Println(r.URL.Path, r.Context().Value(connectionID{}))
					_, _ = w.Write([]byte("ok"))
				case <-r.Context().Done():
				}
			case "/consumer-slow":
				fmt.Println(r.URL.Path, r.Context().Value(connectionID{}))
				select {
				case <-started:
					w.Header().Set("Content-Length", strconv.Itoa(len(rules)))
					_, _ = w.Write(rules)
				case <-r.Context().Done():
				}
			case "/consumer-reject":
				fmt.Println(r.URL.Path, r.Context().Value(connectionID{}))
				select {
				case started <- struct{}{}:
				default:
				}
				_, _ = w.Write([]byte("discard this chunk"))
				w.(http.Flusher).Flush()
				<-r.Context().Done()
				fmt.Println("stream-canceled", r.Context().Value(connectionID{}))
				select {
				case canceled <- struct{}{}:
				default:
				}
			case "/conditional":
				if r.Header.Get("If-None-Match") == `W/"rules-1"` {
					fmt.Println("conditional 304")
					w.Header().Set("ETag", `"rules-1"`)
					w.WriteHeader(http.StatusNotModified)
				} else {
					fmt.Println("conditional 200")
					w.Header().Set("ETag", `W/"rules-1"`)
					_, _ = w.Write(rules)
				}
			case "/redirect":
				fmt.Println("redirect", r.Context().Value(connectionID{}))
				w.Header().Set("Location", "/with-header")
				w.WriteHeader(http.StatusTemporaryRedirect)
			case "/with-header":
				fmt.Println("final", r.Context().Value(connectionID{}))
				if r.Header.Get("X-Nexus-Test") != "custom value" {
					http.Error(w, "missing configured header", http.StatusBadRequest)
					return
				}
				w.Header().Set("Content-Length", strconv.Itoa(len(rules)))
				_, _ = w.Write(rules)
			case "/rules":
				fmt.Println("rules request")
				w.Header().Set("Content-Length", strconv.Itoa(len(rules)))
				_, _ = w.Write(rules)
			case "/stream-limit":
				w.(http.Flusher).Flush()
				_, _ = w.Write(rules)
				_, _ = w.Write(rules)
			case "/short":
				w.Header().Set("Content-Length", strconv.Itoa(len(rules)+7))
				_, _ = w.Write(rules)
			case "/encoded":
				w.Header().Set("Content-Encoding", "gzip")
				_, _ = w.Write(rules)
			case "/watch":
				fmt.Println("watch request")
				fallthrough
			case "/timeout":
				<-r.Context().Done()
			default:
				http.NotFound(w, r)
			}
		}),
	}
	log.Fatal(server.Serve(ingress))
}
