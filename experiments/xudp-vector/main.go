package main
import (
 "encoding/hex"
 "fmt"
 "github.com/xtls/xray-core/common/buf"
 "github.com/xtls/xray-core/common/net"
 "github.com/xtls/xray-core/common/xudp"
)
func main() {
 dest:=net.UDPDestination(net.ParseAddress("192.0.2.1"),443)
 var out buf.MultiBufferContainer
 writer:=xudp.NewPacketWriter(&out,dest,[8]byte{1,2,3,4,5,6,7,8})
 a:=buf.New(); a.Write([]byte("hello")); a.UDP=&dest
 b:=buf.New(); b.Write([]byte("world")); addr:=net.UDPDestination(net.ParseAddress("2001:db8::1"),5353); b.UDP=&addr
 c:=buf.New(); c.Write([]byte("end"))
 if err:=writer.WriteMultiBuffer(buf.MultiBuffer{a,b,c}); err!=nil { panic(err) }
 for _,p:=range out.MultiBuffer { fmt.Println(hex.EncodeToString(p.Bytes())); p.Release() }
}
