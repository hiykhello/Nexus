// Generates reference bytes using the pinned SagerNet implementation.
package main

import (
    "bytes"
    "fmt"
    "net"
    "net/netip"
    "time"
    "github.com/sagernet/sing/common/buf"
    M "github.com/sagernet/sing/common/metadata"
    "github.com/sagernet/sing/common/uot"
)

type conn struct { bytes.Buffer }
func (*conn) Close() error { return nil }
func (*conn) LocalAddr() net.Addr { return nil }
func (*conn) RemoteAddr() net.Addr { return nil }
func (*conn) SetDeadline(time.Time) error { return nil }
func (*conn) SetReadDeadline(time.Time) error { return nil }
func (*conn) SetWriteDeadline(time.Time) error { return nil }
func main() {
    addresses := []M.Socksaddr{
        {Addr: netip.MustParseAddr("192.0.2.1"), Port: 53},
        {Addr: netip.MustParseAddr("2001:db8::1"), Port: 443},
        {Fqdn: "example.com", Port: 5353},
    }
    for _, address := range addresses {
        request := uot.Request{IsConnect:true, Destination:address}
        encoded, err := uot.EncodeRequest(request); if err != nil { panic(err) }
        fmt.Printf("request %x\n", encoded.Bytes()); encoded.Release()
        raw := &conn{}
        c := uot.NewConn(raw, uot.Request{})
        packet := buf.As([]byte{0xde,0xad,0xbe,0xef})
        if err := c.WritePacket(packet, address); err != nil { panic(err) }
        fmt.Printf("packet  %x\n", raw.Bytes())
    }
    raw := &conn{}
    c := uot.NewConn(raw, uot.Request{IsConnect:true, Destination:addresses[0]})
    if err := c.WritePacket(buf.As([]byte{0xde,0xad,0xbe,0xef}), addresses[0]); err != nil { panic(err) }
    fmt.Printf("connected %x\n", raw.Bytes())
}
