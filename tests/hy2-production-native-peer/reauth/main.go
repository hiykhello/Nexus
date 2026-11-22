// Exercise repeated Hysteria 2 HTTP/3 authentication on one real QUIC connection.
package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	family := flag.String("family", "4", "outer UDP family: 4 or 6")
	port := flag.Int("port", 0, "Hysteria listener UDP port")
	certPath := flag.String("cert", "", "PEM trust certificate")
	target := flag.String("target", "", "actual TCP echo target")
	firstRate := flag.Uint64("first-rate", 600000, "first request receive rate in bytes/sec")
	secondRate := flag.Uint64("second-rate", 0, "second request receive rate in bytes/sec")
	firstPassword := flag.String("first-password", "test-password", "first request credential")
	secondPassword := flag.String("second-password", "test-password", "second request credential")
	firstStatus := flag.Int("first-status", 233, "expected first HTTP status")
	secondStatus := flag.Int("second-status", 233, "expected second HTTP status")
	size := flag.Int("size", 524288, "data length in each direction")
	assertPacing := flag.Bool("assert-pacing", false, "require server download pacing")
	maxDownload := flag.Int("max-download-ms", 0, "optional maximum download time for retained-rate comparison")
	flag.Parse()
	if (*family != "4" && *family != "6") || *port < 1 || *port > 65535 || *target == "" || *size < 0 || *size > 1048576 {
		panic("invalid arguments")
	}
	pem, err := os.ReadFile(*certPath)
	check(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("invalid PEM certificate")
	}
	host, network := "127.0.0.1", "udp4"
	if *family == "6" {
		host, network = "::1", "udp6"
	}
	socket, err := net.ListenPacket(network, net.JoinHostPort(host, "0"))
	check(err)
	defer socket.Close()
	remote, err := net.ResolveUDPAddr(network, net.JoinHostPort(host, strconv.Itoa(*port)))
	check(err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, socket, remote, &tls.Config{RootCAs: roots, ServerName: "localhost", MinVersion: tls.VersionTLS13, NextProtos: []string{"h3"}}, &quic.Config{EnableDatagrams: true})
	check(err)
	defer conn.CloseWithError(0, "")
	transport := &http3.Transport{}
	h3 := transport.NewClientConn(conn)
	authenticate := func(rate uint64, password string, expected int) (string, string) {
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, "https://hysteria/auth", nil)
		check(err)
		req.Header.Set("Hysteria-Auth", password)
		req.Header.Set("Hysteria-CC-RX", strconv.FormatUint(rate, 10))
		response, err := h3.RoundTrip(req)
		check(err)
		_, err = io.Copy(io.Discard, response.Body)
		check(err)
		check(response.Body.Close())
		if response.StatusCode != expected {
			panic(fmt.Sprintf("auth rx=%d: got status %d, expected %d", rate, response.StatusCode, expected))
		}
		return response.Header.Get("Hysteria-CC-Rx"), response.Header.Get("Hysteria-UDP")
	}
	firstHeader, firstUDP := authenticate(*firstRate, *firstPassword, *firstStatus)
	secondHeader, secondUDP := authenticate(*secondRate, *secondPassword, *secondStatus)
	if *firstStatus == 233 && *secondStatus == 233 && (firstHeader != secondHeader || firstUDP != secondUDP) {
		panic("repeat response changed negotiated headers")
	}
	stream, err := conn.OpenStreamSync(ctx)
	check(err)
	deadline, _ := ctx.Deadline()
	check(stream.SetDeadline(deadline))
	wire := quicvarint.Append(nil, 0x401)
	wire = quicvarint.Append(wire, uint64(len(*target)))
	wire = append(wire, []byte(*target)...)
	wire = quicvarint.Append(wire, 0)
	_, err = stream.Write(wire)
	check(err)
	reader := bufio.NewReader(stream)
	status, err := reader.ReadByte()
	check(err)
	msgLen, err := quicvarint.Read(reader)
	check(err)
	if msgLen > 4096 {
		panic("response message too large")
	}
	msg := make([]byte, msgLen)
	_, err = io.ReadFull(reader, msg)
	check(err)
	padding, err := quicvarint.Read(reader)
	check(err)
	if padding > 4096 {
		panic("response padding too large")
	}
	_, err = io.CopyN(io.Discard, reader, int64(padding))
	check(err)
	if status != 0 {
		panic(fmt.Sprintf("TCP refused: %s", msg))
	}
	payload := make([]byte, *size)
	for i := range payload {
		payload[i] = byte(i*71 + 37)
	}
	_, err = stream.Write(payload)
	check(err)
	check(stream.Close())
	started := time.Now()
	reply, err := io.ReadAll(reader)
	check(err)
	if !bytes.Equal(reply, payload) {
		panic(fmt.Sprintf("TCP echo mismatch length=%d", len(reply)))
	}
	duration := time.Since(started)
	if *assertPacing && duration < 700*time.Millisecond {
		panic(fmt.Sprintf("server download was not paced: %s", duration))
	}
	if *maxDownload > 0 && duration > time.Duration(*maxDownload)*time.Millisecond {
		panic(fmt.Sprintf("server download exceeded retained-rate deadline: %s", duration))
	}
	fmt.Printf("first=%d rx=%s udp=%s second=%d rx=%s udp=%s target=%s bytes=%d FIN=true download=%s\n", *firstStatus, firstHeader, firstUDP, *secondStatus, secondHeader, secondUDP, *target, *size, duration)
}
