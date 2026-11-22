package main

import (
	"context"
	"fmt"
	v5 "github.com/sagernet/sing-snell/snellv5"
	"github.com/sagernet/sing/common/buf"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"
)

var served atomic.Int32

type handler struct{}

func (handler) NewConnectionEx(ctx context.Context, c net.Conn, source, dest M.Socksaddr, done N.CloseHandlerFunc) {
	served.Add(1)
	p := make([]byte, 10)
	_, e := io.ReadFull(c, p)
	if e == nil && dest.String() == "example.org:443" && string(p) == "early-data" {
		_, e = c.Write([]byte("server-response"))
		if e == nil {
			_, e = io.Copy(io.Discard, c)
		}
	}
	if done != nil {
		done(e)
	}
}
func (handler) NewPacketConnectionEx(ctx context.Context, c N.PacketConn, source, dest M.Socksaddr, done N.CloseHandlerFunc) {
	defer c.Close()
	b := buf.NewSize(1024)
	target, e := c.ReadPacket(b)
	if e == nil {
		var u *net.UDPConn
		u, e = net.DialUDP("udp", nil, net.UDPAddrFromAddrPort(target.AddrPort()))
		if e == nil {
			defer u.Close()
			u.SetDeadline(time.Now().Add(5 * time.Second))
			_, e = u.Write(b.Bytes())
			if e == nil {
				p := make([]byte, 1024)
				var n int
				n, e = u.Read(p)
				if e == nil {
					out := buf.NewSize(1024)
					out.Resize(512, 0)
					out.Write(p[:n])
					e = c.WritePacket(out, target)
				}
			}
		}
	}
	b.Release()
	if done != nil {
		done(e)
	}
}
func main() {
	l, e := net.Listen("tcp", "127.0.0.1:0")
	if e != nil {
		panic(e)
	}
	defer l.Close()
	fmt.Println(l.Addr().(*net.TCPAddr).Port)
	c, e := l.Accept()
	if e != nil {
		panic(e)
	}
	service, e := v5.NewService(v5.ServiceOptions{PSK: []byte("nexus-snell-test"), Handler: handler{}})
	if e != nil {
		panic(e)
	}
	e = service.NewConnection(context.Background(), c, M.ParseSocksaddr("127.0.0.1:1"), nil)
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	if served.Load() != 4 {
		fmt.Fprintln(os.Stderr, "served", served.Load())
		os.Exit(1)
	}
}
