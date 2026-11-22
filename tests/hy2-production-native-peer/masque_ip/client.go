package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	quic "github.com/sagernet/quic-go"
	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
)

func udpPacket(source, destination string, port uint16, payload string) []byte {
	local := net.ParseIP(source)
	remote := net.ParseIP(destination)
	size := 40
	if local.To4() != nil {
		size = 20
	}
	packet := make([]byte, size+8+len(payload))
	udp := packet[size:]
	binary.BigEndian.PutUint16(udp, 23456)
	binary.BigEndian.PutUint16(udp[2:], port)
	binary.BigEndian.PutUint16(udp[4:], uint16(len(udp)))
	copy(udp[8:], payload)
	if size == 20 {
		packet[0], packet[8], packet[9] = 0x45, 64, 17
		binary.BigEndian.PutUint16(packet[2:], uint16(len(packet)))
		copy(packet[12:16], local.To4())
		copy(packet[16:20], remote.To4())
		binary.BigEndian.PutUint16(packet[10:], checksum4(packet[:20]))
	} else {
		packet[0], packet[6], packet[7] = 0x60, 17, 64
		binary.BigEndian.PutUint16(packet[4:], uint16(len(udp)))
		copy(packet[8:24], local.To16())
		copy(packet[24:40], remote.To16())
		check := checksum6(packet, 17)
		if check == 0 {
			check = 0xffff
		}
		binary.BigEndian.PutUint16(udp[6:], check)
	}
	return packet
}

func checkServerPackets(stream *http3.RequestStream) error {
	reader := bufio.NewReader(stream)
	read := func(expected uint64) ([]byte, error) {
		kind, err := quicvarint.Read(reader)
		if err != nil {
			return nil, err
		}
		size, err := quicvarint.Read(reader)
		if err != nil || kind != expected || size > 1300 {
			return nil, fmt.Errorf("unexpected capsule type %d, size %d: %v", kind, size, err)
		}
		body := make([]byte, size)
		_, err = io.ReadFull(reader, body)
		return body, err
	}
	for _, kind := range []uint64{1, 3} {
		if _, err := read(kind); err != nil {
			return err
		}
	}
	oversized := udpPacket("10.60.0.2", "198.51.100.42", 18082, strings.Repeat("x", 1253))
	if err := capsule(stream, 0, append([]byte{0}, oversized...)); err != nil {
		return err
	}
	// Only the following assigned IPv4 and IPv6 packets may reach the echo socket.
	for _, packet := range [][]byte{
		udpPacket("10.60.0.99", "198.51.100.42", 18082, "spoofed-source"),
		udpPacket("10.60.0.2", "198.51.100.99", 18082, "blocked-destination"),
		udpPacket("10.60.0.2", "198.51.100.42", 18080, "datagram-v4"),
	} {
		if err := stream.SendDatagram(append([]byte{0}, packet...)); err != nil {
			return err
		}
	}
	reply, err := read(0)
	if err != nil {
		return err
	}
	if len(reply) < 29 || string(reply[29:]) != "datagram-v4" {
		return fmt.Errorf("invalid IPv4 response")
	}
	payload := strings.Repeat("v6", 616)
	if err := capsule(stream, 0, append([]byte{0}, udpPacket("fd60::2", "2001:db8:60::42", 18080, payload)...)); err != nil {
		return err
	}
	reply, err = read(0)
	if err != nil {
		return err
	}
	if len(reply) != 1281 || string(reply[49:]) != payload {
		return fmt.Errorf("invalid IPv6 response")
	}
	return nil
}

func checkServer(certificate, address string) error {
	pem, err := os.ReadFile(certificate)
	if err != nil {
		return err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(pem) {
		return fmt.Errorf("invalid server certificate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	connection, err := quic.DialAddr(ctx, address, &tls.Config{
		RootCAs: roots, ServerName: "localhost", NextProtos: []string{"h3"}, MinVersion: tls.VersionTLS13,
	}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		return err
	}
	defer connection.CloseWithError(0, "")
	transport := &http3.Transport{EnableDatagrams: true}
	client := transport.NewClientConn(connection)
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-client.ReceivedSettings():
	}
	for _, request := range []struct {
		target, bearer string
		status         int
	}{
		{"*/*/", "wrong", 403},
		{"203.0.113.1%2F32/*/", "approved", 403},
		{"*/*/", "approved", 200},
	} {
		stream, err := client.OpenRequestStream(ctx)
		if err != nil {
			return err
		}
		if err := stream.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			return err
		}
		message, err := http.NewRequestWithContext(ctx, http.MethodConnect,
			"https://localhost/.well-known/masque/ip/"+request.target, nil)
		if err != nil {
			return err
		}
		message.Proto = "connect-ip"
		message.Header.Set("Proxy-Authorization", "Bearer "+request.bearer)
		message.Header.Set("Capsule-Protocol", "?1")
		if err := stream.SendRequestHeader(message); err != nil {
			return err
		}
		response, err := stream.ReadResponse()
		if err != nil {
			return err
		}
		if response.StatusCode != request.status {
			return fmt.Errorf("CONNECT-IP %s returned %d, expected %d", request.target, response.StatusCode, request.status)
		}
		if request.status == 200 {
			if err := checkServerPackets(stream); err != nil {
				return err
			}
		}
		stream.CancelRead(0)
		stream.CancelWrite(0)
	}
	return nil
}
