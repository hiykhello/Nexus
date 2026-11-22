package main

import (
 "context"
 "crypto/tls"
 "crypto/x509"
 "fmt"
 "net"
 "os"
 "strconv"
 "time"
 hy "github.com/sagernet/sing-quic/hysteria2"
 "github.com/sagernet/sing/common/logger"
 M "github.com/sagernet/sing/common/metadata"
 stls "github.com/sagernet/sing/common/tls"
)
type config struct { value *tls.Config; timeout time.Duration }
func(c *config)ServerName()string{return c.value.ServerName}
func(c *config)SetServerName(v string){c.value.ServerName=v}
func(c *config)NextProtos()[]string{return c.value.NextProtos}
func(c *config)SetNextProtos(v []string){c.value.NextProtos=v}
func(c *config)HandshakeTimeout()time.Duration{return c.timeout}
func(c *config)SetHandshakeTimeout(v time.Duration){c.timeout=v}
func(c *config)STDConfig()(*tls.Config,error){return c.value,nil}
func(c *config)Client(conn net.Conn)(stls.Conn,error){return tls.Client(conn,c.value),nil}
func(c *config)Clone()stls.Config{return &config{c.value.Clone(),c.timeout}}
type dialer struct { network string }
func(d dialer)DialContext(ctx context.Context,network string,destination M.Socksaddr)(net.Conn,error){return (&net.Dialer{}).DialContext(ctx,network,destination.String())}
func(d dialer)ListenPacket(ctx context.Context,destination M.Socksaddr)(net.PacketConn,error){return (&net.ListenConfig{}).ListenPacket(ctx,d.network,":0")}
func check(err error){if err!=nil{panic(err)}}
func main(){
 if len(os.Args)!=5{panic("usage: hy2-library-peer 4|6 PORT CERT.der SIZE")}
 port,err:=strconv.Atoi(os.Args[2]);check(err);size,err:=strconv.Atoi(os.Args[4]);check(err)
 host,network:="127.0.0.1","udp4";if os.Args[1]=="6"{host,network="::1","udp6"}
 cert,err:=os.ReadFile(os.Args[3]);check(err);anchor,err:=x509.ParseCertificate(cert);check(err);roots:=x509.NewCertPool();roots.AddCert(anchor)
 ctx,cancel:=context.WithTimeout(context.Background(),8*time.Second);defer cancel()
 client,err:=hy.NewClient(hy.ClientOptions{Context:ctx,Dialer:dialer{network},Logger:logger.NOP(),ServerAddress:M.ParseSocksaddr(net.JoinHostPort(host,strconv.Itoa(port))),Password:"test-password",TLSConfig:&config{value:&tls.Config{RootCAs:roots,ServerName:"localhost",MinVersion:tls.VersionTLS13,NextProtos:[]string{"h3"}},timeout:5*time.Second}});check(err);defer client.CloseWithError(nil)
 socket,err:=client.ListenPacket(ctx);check(err);defer socket.Close();check(socket.SetReadDeadline(time.Now().Add(6*time.Second)))
 destination:=M.ParseSocksaddr("target.example:443");data:=make([]byte,size);for i:=range data{data[i]=byte(i*71+37)}
 n,err:=socket.WriteTo(data,destination);check(err);if n!=size{panic("short datagram")}
 buffer:=make([]byte,65535);n,source,err:=socket.ReadFrom(buffer);check(err);if n!=size||source.String()!=destination.String(){panic(fmt.Sprintf("datagram mismatch size=%d target=%v",n,source))};for i:=range data{if data[i]!=buffer[i]{panic("corrupt data")}}
 _,err=socket.WriteTo([]byte{0xa5},destination);check(err)
 _,_,err=socket.ReadFrom(buffer);if err==nil{panic("unexpected data after confirmation")}
 fmt.Printf("fixed sing-quic native client payload=%d empty=%v address=%s accepted; peer closed after confirmation: %v\n",size,size==0,source,err)
}
