package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"reflect"
	"strconv"
	"time"

	quic "github.com/sagernet/quic-go"
	hy "github.com/sagernet/sing-quic/hysteria2"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	stls "github.com/sagernet/sing/common/tls"
)

type config struct {
	value   *tls.Config
	timeout time.Duration
}

func (c *config) ServerName() string                      { return c.value.ServerName }
func (c *config) SetServerName(v string)                  { c.value.ServerName = v }
func (c *config) NextProtos() []string                    { return c.value.NextProtos }
func (c *config) SetNextProtos(v []string)                { c.value.NextProtos = v }
func (c *config) HandshakeTimeout() time.Duration         { return c.timeout }
func (c *config) SetHandshakeTimeout(v time.Duration)     { c.timeout = v }
func (c *config) STDConfig() (*tls.Config, error)         { return c.value, nil }
func (c *config) Client(conn net.Conn) (stls.Conn, error) { return tls.Client(conn, c.value), nil }
func (c *config) Clone() stls.Config                      { return &config{c.value.Clone(), c.timeout} }

type dialer struct{ network string }

func (d dialer) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, destination.String())
}
func (d dialer) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	return (&net.ListenConfig{}).ListenPacket(ctx, d.network, ":0")
}
func check(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	if len(os.Args) != 5 {
		panic("usage: hy2-salamander-peer 4|6 PORT CERT.der TARGET")
	}
	port, err := strconv.Atoi(os.Args[2])
	check(err)
	host, network := "127.0.0.1", "udp4"
	if os.Args[1] == "6" {
		host, network = "::1", "udp6"
	}
	cert, err := os.ReadFile(os.Args[3])
	check(err)
	anchor, err := x509.ParseCertificate(cert)
	check(err)
	roots := x509.NewCertPool()
	roots.AddCert(anchor)
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	client, err := hy.NewClient(hy.ClientOptions{Context: ctx, Dialer: dialer{network}, Logger: logger.NOP(), ServerAddress: M.ParseSocksaddr(net.JoinHostPort(host, strconv.Itoa(port))), Password: "test-password", SalamanderPassword: "salamander-secret", TLSConfig: &config{value: &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}, timeout: 5 * time.Second}})
	check(err)
	defer client.CloseWithError(nil)
	conn, err := client.DialConn(ctx, M.ParseSocksaddr(os.Args[4]))
	check(err)
	defer conn.Close()
	payload := make([]byte, 131072)
	for i := range payload {
		payload[i] = byte(i)
	}
	n, err := conn.Write(payload)
	check(err)
	if n != len(payload) {
		panic("short write")
	}
	// The pinned client wrapper closes its read side in Close. Access its
	// exported embedded QUIC stream to send FIN while retaining the read side.
	stream, ok := reflect.ValueOf(conn).Elem().FieldByName("Stream").Interface().(*quic.Stream)
	if !ok {
		panic("underlying QUIC stream unavailable")
	}
	check(stream.Close())
	received, err := io.ReadAll(conn)
	if err != nil && !errors.Is(err, io.EOF) {
		check(err)
	}
	if !bytes.Equal(received, payload) {
		panic(fmt.Sprintf("response mismatch %d", len(received)))
	}
	fmt.Println("Salamander TCP half-close response verified")
}
