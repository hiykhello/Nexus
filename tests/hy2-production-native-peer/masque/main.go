// Independent quic-go HTTP/3 CONNECT-UDP client for the Nexus integration test.
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
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
)

func must(err error) {
	if err != nil {
		panic(err)
	}
}
func main() {
	if len(os.Args) == 5 && os.Args[1] == "serve-network" {
		serveDetourAt(os.Args[2], os.Args[3], os.Args[4], true)
		return
	}
	if len(os.Args) == 4 && (os.Args[1] == "serve-detour" || os.Args[1] == "serve-targets") {
		serveDetour(os.Args[2], os.Args[3], os.Args[1] == "serve-targets")
		return
	}
	family := flag.String("family", "4", "address family")
	port := flag.Int("port", 0, "proxy port")
	target := flag.Int("target", 0, "UDP echo port")
	deniedTarget := flag.Int("denied-target", 0, "UDP port outside allowed range")
	cert := flag.String("cert", "", "root certificate")
	mode := flag.String("mode", "datagram", "datagram or capsule")
	rebind := flag.Bool("rebind", false, "wait for relay source-port change after first reply")
	flag.Parse()
	pem, err := os.ReadFile(*cert)
	must(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		panic("invalid certificate")
	}
	host, network := "127.0.0.1", "udp4"
	if *family == "6" {
		host, network = "::1", "udp6"
	}
	socket, err := net.ListenPacket(network, net.JoinHostPort(host, "0"))
	must(err)
	defer socket.Close()
	addr, err := net.ResolveUDPAddr(network, net.JoinHostPort(host, strconv.Itoa(*port)))
	must(err)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	conn, err := quic.Dial(ctx, socket, addr, &tls.Config{RootCAs: roots, ServerName: "localhost", NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13}, &quic.Config{EnableDatagrams: true})
	must(err)
	defer conn.CloseWithError(0, "")
	transport := &http3.Transport{EnableDatagrams: true}
	h3 := transport.NewClientConn(conn)
	select {
	case <-h3.ReceivedSettings():
	case <-ctx.Done():
		panic(ctx.Err())
	}
	settings := h3.Settings()
	if !settings.EnableExtendedConnect || !settings.EnableDatagrams {
		panic("missing H3 CONNECT or datagram settings")
	}
	open := func(password string, destination int, early bool) (*http3.RequestStream, *http.Response) {
		stream, err := h3.OpenRequestStream(ctx)
		must(err)
		req, err := http.NewRequestWithContext(ctx, http.MethodConnect, fmt.Sprintf("https://localhost/.well-known/masque/udp/%s/%d/", strings.ReplaceAll(url.PathEscape(host), ":", "%3A"), destination), nil)
		must(err)
		req.Proto = "connect-udp"
		req.Header.Set("Proxy-Authorization", "Bearer "+password)
		req.Header.Set("Capsule-Protocol", "?1")
		must(stream.SendRequestHeader(req))
		if early {
			must(stream.SendDatagram([]byte{0, 0x42, 0x4c, 0x4f, 0x43, 0x4b}))
		}
		response, err := stream.ReadResponse()
		must(err)
		return stream, response
	}
	denied, bad := open("wrong", *target, false)
	if bad.StatusCode == 200 {
		panic("incorrect credential accepted")
	}
	denied.CancelRead(0)
	denied.CancelWrite(0)
	if *deniedTarget != 0 {
		blocked, response := open("approved", *deniedTarget, true)
		if response.StatusCode != 403 {
			panic(fmt.Sprintf("forbidden target returned %d", response.StatusCode))
		}
		blocked.CancelRead(0)
		blocked.CancelWrite(0)
	}
	stream, response := open("approved", *target, false)
	if response.StatusCode != 200 {
		panic(fmt.Sprintf("CONNECT returned %d", response.StatusCode))
	}
	payloads := [][]byte{[]byte(fmt.Sprintf("reference-%s-0", *mode)), []byte(fmt.Sprintf("reference-%s-1", *mode)), {}, bytes.Repeat([]byte{0xa5}, 1024)}
	for i, payload := range payloads {
		if *mode == "datagram" {
			must(stream.SendDatagram(append([]byte{0}, payload...)))
		} else if *mode == "capsule" {
			wire := quicvarint.Append(nil, 0)
			wire = quicvarint.Append(wire, uint64(len(payload)+1))
			wire = append(wire, 0)
			wire = append(wire, payload...)
			_, err = stream.Write(wire)
			must(err)
		} else {
			panic("invalid mode")
		}
		typ, err := quicvarint.Read(quicvarint.NewReader(stream))
		must(err)
		length, err := quicvarint.Read(quicvarint.NewReader(stream))
		must(err)
		if typ != 0 || length != uint64(len(payload)+1) {
			panic(fmt.Sprintf("bad capsule type=%d length=%d", typ, length))
		}
		buf := make([]byte, length)
		_, err = io.ReadFull(stream, buf)
		must(err)
		if buf[0] != 0 || !bytes.Equal(buf[1:], payload) {
			panic("echo mismatch")
		}
		if i == 0 && *rebind {
			fmt.Println("READY_REBIND")
			if _, err = bufio.NewReader(os.Stdin).ReadString('\n'); err != nil {
				panic(err)
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	stream.CancelRead(0)
	stream.CancelWrite(0)
	policy := "bad credential rejected"
	if *deniedTarget != 0 {
		policy += ", forbidden target returned 403"
	}
	fmt.Printf("quic-go IPv%s %s: %s, four UDP echoes including empty and 1024 bytes received as capsules\n", *family, *mode, policy)
}
