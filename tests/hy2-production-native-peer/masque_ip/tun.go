package main

import (
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"time"

	"github.com/sagernet/quic-go/http3"
	"github.com/sagernet/quic-go/quicvarint"
	"golang.org/x/sys/unix"
)

func openTun() (*os.File, func(), error) {
	const name = "nx-masque-peer"
	fd, err := unix.Open("/dev/net/tun", unix.O_RDWR|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	request, err := unix.NewIfreq(name)
	if err == nil {
		request.SetUint16(unix.IFF_TUN | unix.IFF_NO_PI)
		err = unix.IoctlIfreq(fd, unix.TUNSETIFF, request)
	}
	if err != nil {
		unix.Close(fd)
		return nil, nil, err
	}
	tun := os.NewFile(uintptr(fd), name)
	var listeners []net.Listener
	stop := func() {
		for _, listener := range listeners {
			listener.Close()
		}
		tun.Close()
	}
	for _, args := range [][]string{
		{"link", "set", name, "up", "mtu", "1280"},
		{"address", "add", "198.51.100.42/32", "dev", name},
		{"-6", "address", "add", "2001:db8:42::42/128", "dev", name, "nodad"},
		{"route", "add", "10.10.0.2/32", "dev", name},
		{"-6", "route", "add", "fd10::2/128", "dev", name},
	} {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			stop()
			return nil, nil, fmt.Errorf("ip %v: %v: %s", args, err, output)
		}
	}
	for _, address := range []string{"198.51.100.42:18080", "[2001:db8:42::42]:18080"} {
		listener, err := net.Listen("tcp", address)
		if err != nil {
			stop()
			return nil, nil, err
		}
		listeners = append(listeners, listener)
		go func() {
			for {
				client, err := listener.Accept()
				if err != nil {
					return
				}
				go func() {
					defer client.Close()
					_ = client.SetDeadline(time.Now().Add(12 * time.Second))
					_, _ = io.Copy(client, client)
				}()
			}
		}()
	}
	return tun, stop, nil
}

func relayTun(stream *http3.Stream, reader quicvarint.Reader, tun *os.File) error {
	done := make(chan struct{})
	go func() {
		defer close(done)
		defer stream.CancelRead(0)
		var body [1281]byte
		for {
			size, err := tun.Read(body[1:])
			if err != nil || capsule(stream, 0, body[:size+1]) != nil {
				return
			}
		}
	}()
	defer func() {
		tun.Close()
		stream.CancelWrite(0)
		<-done
	}()
	client6 := net.ParseIP("fd10::2").To16()
	server6 := net.ParseIP("2001:db8:42::42").To16()
	var body [1281]byte
	for {
		kind, err := quicvarint.Read(reader)
		if err != nil {
			return err
		}
		size, err := quicvarint.Read(reader)
		if err != nil || kind != 0 || size < 21 || size > uint64(len(body)) {
			return fmt.Errorf("invalid test TUN capsule: %d/%d", kind, size)
		}
		if _, err := io.ReadFull(reader, body[:size]); err != nil {
			return err
		}
		packet := body[1:size]
		allowed := packet[0]>>4 == 4 &&
			net.IP(packet[12:16]).Equal(net.IPv4(10, 10, 0, 2)) &&
			net.IP(packet[16:20]).Equal(net.IPv4(198, 51, 100, 42))
		if packet[0]>>4 == 6 && len(packet) >= 40 {
			allowed = net.IP(packet[8:24]).Equal(client6) && net.IP(packet[24:40]).Equal(server6)
		}
		if body[0] != 0 || !allowed {
			continue
		}
		if _, err := tun.Write(packet); err != nil {
			return err
		}
	}
}
