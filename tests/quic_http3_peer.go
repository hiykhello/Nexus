package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"sync/atomic"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}
func payload() []byte {
	out := make([]byte, 12000)
	for i := range out {
		out[i] = byte(i * 73)
	}
	return out
}

func main() {
	if len(os.Args) != 6 {
		panic("usage: http3-peer client|server 4|6 PORT CERT.der KEY.der")
	}
	server := os.Args[1] == "server"
	port, err := strconv.Atoi(os.Args[3])
	check(err)
	network, host := "udp4", "127.0.0.1"
	if os.Args[2] == "6" {
		network, host = "udp6", "::1"
	}
	socket, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(host)})
	check(err)
	defer socket.Close()
	transport := &quic.Transport{Conn: socket, ConnectionIDLength: 8}
	defer transport.Close()
	certDER, err := os.ReadFile(os.Args[4])
	check(err)
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		NextProtos: []string{"h3"}, ServerName: "localhost", CurvePreferences: []tls.CurveID{tls.X25519}}
	config := &quic.Config{Versions: []quic.Version{quic.Version1}, HandshakeIdleTimeout: 5 * time.Second,
		MaxIdleTimeout: 10 * time.Second, InitialStreamReceiveWindow: 4096, MaxStreamReceiveWindow: 65536,
		InitialConnectionReceiveWindow: 65536, MaxConnectionReceiveWindow: 65536, InitialPacketSize: 1200}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if server {
		key, err := os.ReadFile(os.Args[5])
		check(err)
		cert, err := tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}), pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: key}))
		check(err)
		tlsConfig.Certificates = []tls.Certificate{cert}
		closed := make(chan error, 1)
		var auth, business atomic.Int32
		srv := &http3.Server{TLSConfig: tlsConfig, QUICConfig: config}
		srv.ConnContext = func(ctx context.Context, conn *quic.Conn) context.Context {
			go func() { <-conn.Context().Done(); closed <- context.Cause(conn.Context()) }()
			return ctx
		}
		srv.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.TLS == nil || !r.TLS.HandshakeComplete || r.TLS.NegotiatedProtocol != "h3" {
				panic("HTTP3 before authenticated TLS")
			}
			if r.Method == "POST" && r.Host == "hysteria" && r.URL.Path == "/auth" && r.Header.Get("Hysteria-Auth") == "test-password" && r.Header.Get("Hysteria-CC-RX") == "125000" {
				auth.Add(1)
				w.Header().Set("Hysteria-UDP", "true")
				w.Header().Set("Hysteria-CC-RX", "0")
				w.WriteHeader(233)
				return
			}
			if auth.Load() != 1 || r.Method != "GET" || r.Host != "cover.example" {
				panic("unexpected HTTP3 request")
			}
			business.Add(1)
			w.Header().Set("Content-Length", "12000")
			_, err := w.Write(payload())
			check(err)
		})
		serving := make(chan error, 1)
		go func() { serving <- srv.Serve(socket) }()
		fmt.Printf("READY %d\n", socket.LocalAddr().(*net.UDPAddr).Port)
		select {
		case err = <-closed:
			var application *quic.ApplicationError
			if !errors.As(err, &application) || application.ErrorCode != 0x100 {
				panic(fmt.Sprintf("expected H3_NO_ERROR close: %v", err))
			}
		case err = <-serving:
			check(err)
		case <-ctx.Done():
			panic(ctx.Err())
		}
		check(srv.Close())
		if auth.Load() != 1 || business.Load() != 1 {
			panic("missing authenticated HTTP3 exchange")
		}
	} else {
		roots := x509.NewCertPool()
		cert, err := x509.ParseCertificate(certDER)
		check(err)
		roots.AddCert(cert)
		tlsConfig.RootCAs = roots
		httpTransport := &http3.Transport{TLSClientConfig: tlsConfig, QUICConfig: config,
			Dial: func(ctx context.Context, _ string, tls *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
				return transport.Dial(ctx, &net.UDPAddr{IP: net.ParseIP(host), Port: port}, tls, cfg)
			}}
		defer httpTransport.Close()
		fmt.Printf("READY %d\n", socket.LocalAddr().(*net.UDPAddr).Port)
		url := "https://" + net.JoinHostPort(host, strconv.Itoa(port))
		auth, err := http.NewRequestWithContext(ctx, "POST", url+"/auth", nil)
		check(err)
		auth.Host = "hysteria"
		auth.Header.Set("Hysteria-Auth", "test-password")
		auth.Header.Set("Hysteria-CC-RX", "125000")
		auth.Header.Set("Hysteria-Padding", "padding")
		response, err := httpTransport.RoundTrip(auth)
		check(err)
		if response.StatusCode != 233 || response.Header.Get("Hysteria-UDP") != "true" {
			panic("HTTP3 auth233 response differs")
		}
		_, err = io.ReadAll(response.Body)
		check(err)
		check(response.Body.Close())
		request, err := http.NewRequestWithContext(ctx, "GET", url+"/", nil)
		check(err)
		request.Host = "cover.example"
		response, err = httpTransport.RoundTrip(request)
		check(err)
		data, err := io.ReadAll(response.Body)
		check(err)
		check(response.Body.Close())
		if response.StatusCode != 200 || !bytes.Equal(data, payload()) {
			panic("HTTP3 response DATA/FIN differs")
		}
		// Keep processing native ACKs before closing the client transport.
		time.Sleep(150 * time.Millisecond)
	}
	fmt.Printf("HTTP3 UDP Go %s authenticated auth233 and 12000B DATA/FIN passed\n", os.Args[1])
}
