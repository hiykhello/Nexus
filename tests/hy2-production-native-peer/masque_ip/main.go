// HTTP/3 loopback peer for the production CONNECT-IP outbound.
package main

import (
	"bufio"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"nexus-hy2-peer/echfixture"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
)

func capsule(w io.Writer, kind uint64, body []byte) error {
	wire := quicvarint.Append(nil, kind)
	wire = quicvarint.Append(wire, uint64(len(body)))
	_, err := w.Write(append(wire, body...))
	return err
}

func checksum6(packet []byte, protocol uint32) uint16 {
	body := packet[40:]
	sum := uint32(len(body)) + protocol
	for _, bytes := range [][]byte{packet[8:40], body} {
		for len(bytes) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(bytes))
			bytes = bytes[2:]
		}
		if len(bytes) == 1 {
			sum += uint32(bytes[0]) << 8
		}
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func checksum4(bytes []byte) uint16 {
	var sum uint32
	for len(bytes) >= 2 {
		sum += uint32(binary.BigEndian.Uint16(bytes))
		bytes = bytes[2:]
	}
	if len(bytes) != 0 {
		sum += uint32(bytes[0]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}

func servePackets(stream *http3.Stream, connection uint64, requireRequest bool, tun *os.File, static bool) error {
	defer stream.Close()
	defer stream.CancelRead(0)
	if err := stream.SetDeadline(time.Now().Add(12 * time.Second)); err != nil {
		return err
	}
	local6 := net.ParseIP("fd10::2").To16()
	reader := bufio.NewReader(stream)
	var v4ID, v6ID byte
	if requireRequest {
		kind, err := quicvarint.Read(reader)
		if err != nil || kind != 2 {
			return fmt.Errorf("expected ADDRESS_REQUEST: %d, %v", kind, err)
		}
		length, err := quicvarint.Read(reader)
		if err != nil || length != 26 {
			return fmt.Errorf("invalid ADDRESS_REQUEST length: %d, %v", length, err)
		}
		var request [26]byte
		if _, err := io.ReadFull(reader, request[:]); err != nil {
			return err
		}
		if request[0] != 4 || request[1] != 4 || request[7] != 6 || request[8] != 6 {
			return fmt.Errorf("unexpected ADDRESS_REQUEST: %x", request)
		}
		v4ID, v6ID = request[0], request[7]
	}
	v4Address := []byte{v4ID, 4, 10, 10, 0, 2, 32}
	addresses := make([]byte, 0, len(v4Address)+19)
	addresses = append(addresses, v4Address...)
	addresses = append(addresses, v6ID, 6)
	addresses = append(addresses, local6...)
	addresses = append(addresses, 128)
	if !static {
		if err := capsule(stream, 1, addresses); err != nil {
			return err
		}
		routes := []byte{4, 198, 51, 100, 0, 198, 51, 100, 255, 17, 6}
		routes = append(routes, net.ParseIP("2001:db8:42::").To16()...)
		routes = append(routes, net.ParseIP("2001:db8:42:0:ffff:ffff:ffff:ffff").To16()...)
		routes = append(routes, 17)
		if tun != nil {
			routes[9], routes[len(routes)-1] = 0, 0
		}
		if err := capsule(stream, 3, routes); err != nil {
			return err
		}
	}
	if tun != nil {
		return relayTun(stream, reader, tun)
	}
	for {
		kind, err := quicvarint.Read(reader)
		if err != nil {
			return err
		}
		length, err := quicvarint.Read(reader)
		if err != nil || kind != 0 || length < 29 || length > 1501 {
			return fmt.Errorf("unexpected capsule %d/%d: %v", kind, length, err)
		}
		body := make([]byte, length)
		if _, err := io.ReadFull(reader, body); err != nil {
			return err
		}
		packet := body[1:]
		if body[0] != 0 {
			return fmt.Errorf("unexpected datagram context")
		}
		if len(packet) >= 48 && packet[0]>>4 == 6 && packet[6] == 58 {
			if len(packet) != 1280 || packet[40] != 2 || packet[41] != 0 ||
				binary.BigEndian.Uint32(packet[44:48]) != 1280 || checksum6(packet, 58) != 0 {
				return fmt.Errorf("invalid ICMPv6 Packet Too Big")
			}
			fmt.Println("ptb 1280")
			continue
		}
		if len(packet) >= 28 && packet[0] == 0x45 && packet[9] == 1 {
			if len(packet) != 576 || packet[20] != 3 || packet[21] != 4 ||
				binary.BigEndian.Uint16(packet[26:28]) != 1280 || checksum4(packet[:20]) != 0 || checksum4(packet[20:]) != 0 {
				return fmt.Errorf("invalid ICMPv4 Fragmentation Needed")
			}
			fmt.Println("frag-needed 1280")
			continue
		}
		header := 20
		source, destination := packet[12:16], packet[16:20]
		valid := packet[0] == 0x45 && packet[9] == 17 &&
			net.IP(source).Equal(net.IPv4(10, 10, 0, 2)) &&
			string(destination[:3]) == string([]byte{198, 51, 100})
		if packet[0]>>4 == 6 && len(packet) >= 48 {
			header = 40
			source, destination = packet[8:24], packet[24:40]
			valid = packet[6] == 17 && net.IP(source).Equal(local6) &&
				string(destination[:8]) == string(net.ParseIP("2001:db8:42::").To16()[:8])
		}
		if !valid {
			return fmt.Errorf("packet did not match the assigned source and route")
		}
		var original [16]byte
		copy(original[:], source)
		copy(source, destination)
		copy(destination, original[:])
		packet[header], packet[header+2] = packet[header+2], packet[header]
		packet[header+1], packet[header+3] = packet[header+3], packet[header+1]
		payload := packet[header+8:]
		if string(payload) == "invalid-hop" {
			if header == 20 {
				packet[8], packet[10], packet[11] = 0, 0, 0
				binary.BigEndian.PutUint16(packet[10:], checksum4(packet[:20]))
			} else {
				packet[7] = 0
			}
		}
		// Swapping addresses and ports preserves both checksums.
		if err := capsule(stream, 0, body); err != nil {
			return err
		}
		fmt.Printf("echo %d %s\n", connection, payload)
		switch string(payload) {
		case "withdraw":
			if err := capsule(stream, 3, nil); err != nil {
				return err
			}
		case "withdraw-v6":
			if err := capsule(stream, 1, v4Address); err != nil {
				return err
			}
		case "clear-addresses":
			if err := capsule(stream, 1, nil); err != nil {
				return err
			}
			time.Sleep(500 * time.Millisecond)
			if err := capsule(stream, 1, addresses); err != nil {
				return err
			}
		case "mtu-report":
			oversized := make([]byte, 1320)
			copy(oversized, packet)
			binary.BigEndian.PutUint16(oversized[header+4:], uint16(len(oversized)-header))
			oversized[header+6], oversized[header+7] = 0, 0
			if header == 20 {
				binary.BigEndian.PutUint16(oversized[2:], uint16(len(oversized)))
				binary.BigEndian.PutUint16(oversized[6:], 0x4000)
				oversized[10], oversized[11] = 0, 0
				binary.BigEndian.PutUint16(oversized[10:], checksum4(oversized[:20]))
			} else {
				binary.BigEndian.PutUint16(oversized[4:], uint16(len(oversized)-40))
				sum := checksum6(oversized, 17)
				if sum == 0 {
					sum = 0xffff
				}
				binary.BigEndian.PutUint16(oversized[header+6:], sum)
			}
			if err := capsule(stream, 0, append([]byte{0}, oversized...)); err != nil {
				return err
			}
		case "disconnect":
			return nil
		}
	}
}

func main() {
	if len(os.Args) == 4 && os.Args[1] == "check-server" {
		if err := checkServer(os.Args[2], os.Args[3]); err != nil {
			log.Fatal(err)
		}
		return
	}
	tunMode := len(os.Args) == 5 && os.Args[3] == "tun"
	if len(os.Args) != 3 && (len(os.Args) != 4 || os.Args[3] != "request") && !tunMode {
		log.Fatal("usage: masque-ip-peer CERT.pem KEY.pem [request | tun LISTEN]")
	}
	cert, err := tls.LoadX509KeyPair(os.Args[1], os.Args[2])
	if err != nil {
		log.Fatal(err)
	}
	listen := "127.0.0.1:0"
	if configured := os.Getenv("NEXUS_TEST_CONNECT_IP_LISTEN"); configured != "" {
		listen = configured
	}
	if tunMode {
		listen = os.Args[4]
	}
	socket, err := net.ListenPacket("udp", listen)
	if err != nil {
		log.Fatal(err)
	}
	defer socket.Close()
	tlsConfig := &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS13}
	requireECH, err := echfixture.Configure(tlsConfig)
	if err != nil {
		log.Fatal(err)
	}
	var connections atomic.Uint64
	var active atomic.Bool
	expectedSource := os.Getenv("NEXUS_TEST_CONNECT_IP_SOURCE")
	protocol, path := "connect-ip", "/.well-known/masque/ip/*/*/"
	warp := os.Getenv("NEXUS_TEST_WARP") == "1"
	if warp {
		protocol, path = "cf-connect-ip", "/"
	}
	server := &http3.Server{
		TLSConfig: tlsConfig,
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if expectedSource != "" && r.RemoteAddr != expectedSource && !strings.HasPrefix(r.RemoteAddr, expectedSource+":") {
				http.Error(w, "unexpected CONNECT-IP source", http.StatusForbidden)
				return
			}
			if requireECH && (r.TLS == nil || !r.TLS.ECHAccepted) {
				http.Error(w, "ECH required", http.StatusForbidden)
				return
			}
			if r.Method != http.MethodConnect || r.Proto != protocol ||
				r.URL.Path != path || r.Header.Get("Proxy-Authorization") != "Bearer approved" {
				http.Error(w, "invalid CONNECT-IP request", http.StatusForbidden)
				return
			}
			if warp && (r.Header.Get("Cf-Connect-Proto") != "cf-connect-ip" || r.Header.Get("User-Agent") != "warp-fixture") {
				http.Error(w, "invalid WARP headers", http.StatusForbidden)
				return
			}
			var tun *os.File
			if tunMode {
				if !active.CompareAndSwap(false, true) {
					http.Error(w, "test TUN already in use", http.StatusServiceUnavailable)
					return
				}
				defer active.Store(false)
				var stop func()
				var err error
				tun, stop, err = openTun()
				if err != nil {
					log.Printf("initialize test TUN: %v", err)
					http.Error(w, "test TUN unavailable", http.StatusInternalServerError)
					return
				}
				defer stop()
			}
			w.Header().Set("Capsule-Protocol", "?1")
			w.WriteHeader(http.StatusAccepted)
			stream := w.(http3.HTTPStreamer).HTTPStream()
			if err := servePackets(stream, connections.Add(1), len(os.Args) >= 4, tun, warp); err != nil {
				log.Printf("CONNECT-IP stream: %v", err)
			}
		}),
	}
	fmt.Println(socket.LocalAddr())
	log.Fatal(server.Serve(socket))
}
