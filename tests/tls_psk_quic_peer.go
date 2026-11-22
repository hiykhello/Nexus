package main
import (
 "bytes"
 "context"
 "crypto/tls"
 "crypto/x509"
 "encoding/pem"
 "errors"
 "fmt"
 "io"
 "net"
 "os"
 "strconv"
 "strings"
 "sync"
 "sync/atomic"
 "time"
 quic "github.com/sagernet/quic-go"
)
func check(err error){if err!=nil{panic(err)}}
type Cache struct{sync.Mutex;inner tls.ClientSessionCache;puts int}
func(c *Cache)Get(key string)(*tls.ClientSessionState,bool){c.Lock();defer c.Unlock();return c.inner.Get(key)}
func(c *Cache)Put(key string,s *tls.ClientSessionState){c.Lock();defer c.Unlock();c.inner.Put(key,s);if s!=nil{c.puts++}}
func(c *Cache)Count()int{c.Lock();defer c.Unlock();return c.puts}
func payload()[]byte{b:=make([]byte,12000);for i:=range b{b[i]=byte(i*73)};return b}
func exchange(ctx context.Context,c *quic.Conn,server bool,cache *Cache,before int)error{
 state:=c.ConnectionState().TLS
 if !state.HandshakeComplete||state.NegotiatedProtocol!="h3"{return errors.New("missing authenticated TLS/ALPN")}
 if !server&&len(state.VerifiedChains)==0{return errors.New("empty verified PKI chains")}
 if !server {for cache.Count()<=before{select{case <-ctx.Done():return ctx.Err();case <-time.After(time.Millisecond):}}}
 datagrams:=make(chan error,1)
 go func(){
  var data []byte;var err error
  if !server{err=c.SendDatagram([]byte{0,1,255,127,0})}
  if err==nil{data,err=c.ReceiveDatagram(ctx)}
  if err==nil&&!bytes.Equal(data,[]byte{0,1,255,127,0}){err=errors.New("datagram differs")}
  if err==nil&&server{err=c.SendDatagram(data)}
  datagrams<-err
 }()
 var stream *quic.Stream;var err error
 if server{stream,err=c.AcceptStream(ctx)}else{stream,err=c.OpenStreamSync(ctx)}
 if err!=nil{return err};check(stream.SetDeadline(time.Now().Add(8*time.Second)))
 original:=payload()
 if !server{if _,err=stream.Write(original);err!=nil{return err};if err=stream.Close();err!=nil{return err}}
 data,err:=io.ReadAll(stream);if err!=nil{return err};if !bytes.Equal(data,original){return errors.New("stream differs")}
 if server{if _,err=stream.Write(data);err!=nil{return err};if err=stream.Close();err!=nil{return err}}
 if err=<-datagrams;err!=nil{return err}
 if server{select{case <-c.Context().Done():var closed *quic.ApplicationError;err=context.Cause(c.Context());if errors.As(err,&closed)&&closed.ErrorCode==0{return nil};return err;case <-ctx.Done():return ctx.Err()}}
 time.Sleep(150*time.Millisecond);return c.CloseWithError(0,"done")
}
func main(){
 if len(os.Args)!=8{panic("usage: quic-psk server|client 4|6 PORT CERT.der KEY.der GROUP MODE")}
 server:=os.Args[1]=="server";port,err:=strconv.Atoi(os.Args[3]);check(err);group,err:=strconv.ParseUint(os.Args[6],0,16);check(err);mode:=os.Args[7]
 network,host:="udp4","127.0.0.1";if os.Args[2]=="6"{network,host="udp6","::1"}
 certDER,err:=os.ReadFile(os.Args[4]);check(err);base:=&tls.Config{MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13,NextProtos:[]string{"h3"},ServerName:"localhost",CurvePreferences:[]tls.CurveID{tls.CurveID(group)}}
 if !server&&strings.HasPrefix(mode,"hrr"){
  unsupported:=tls.SecP256r1MLKEM768;if group==23{unsupported=tls.SecP384r1MLKEM1024};base.CurvePreferences=[]tls.CurveID{unsupported,tls.CurveID(group)}
 }
 cache:=&Cache{inner:tls.NewLRUClientSessionCache(8)}
 if server{keyDER,err:=os.ReadFile(os.Args[5]);check(err);cert,err:=tls.X509KeyPair(pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:certDER}),pem.EncodeToMemory(&pem.Block{Type:"PRIVATE KEY",Bytes:keyDER}));check(err);base.Certificates=[]tls.Certificate{cert};var ticket [32]byte;for i:=range ticket{ticket[i]=byte(i+1)};base.SetSessionTicketKeys([][32]byte{ticket})
 }else{roots:=x509.NewCertPool();cert,err:=x509.ParseCertificate(certDER);check(err);roots.AddCert(cert);base.RootCAs=roots;base.ClientSessionCache=cache}
 var transport *quic.Transport;var socket *net.UDPConn;var listener *quic.Listener
 if !server{socket,err=net.ListenUDP(network,&net.UDPAddr{IP:net.ParseIP(host)});check(err);defer socket.Close();transport=&quic.Transport{Conn:socket,ConnectionIDLength:8};defer transport.Close()}
 for round:=0;round<3;round++{
  config:=&quic.Config{Versions:[]quic.Version{quic.Version1},HandshakeIdleTimeout:5*time.Second,MaxIdleTimeout:10*time.Second,InitialStreamReceiveWindow:4096,MaxStreamReceiveWindow:65536,InitialConnectionReceiveWindow:uint64(65536-round*1024),MaxConnectionReceiveWindow:65536,EnableDatagrams:true,InitialPacketSize:1200,Allow0RTT:false}
  if server && round==0{
   socket,err=net.ListenUDP(network,&net.UDPAddr{IP:net.ParseIP(host),Port:port});check(err);transport=&quic.Transport{Conn:socket,ConnectionIDLength:8}
   var handshakes atomic.Uint32
   selector:=base.Clone()
   selector.GetConfigForClient=func(*tls.ClientHelloInfo)(*tls.Config,error){
    cfg:=base.Clone();var key [32]byte;index:=handshakes.Add(1)-1
    for i:=range key{if index>0&&strings.HasSuffix(mode,"fallback"){key[i]=byte(i+99)}else{key[i]=byte(i+1)}}
    cfg.SetSessionTicketKeys([][32]byte{key});return cfg,nil
   }
   listener,err=transport.Listen(selector,config);check(err);defer listener.Close();defer transport.Close();defer socket.Close()
  }
  fmt.Printf("READY %d\n",socket.LocalAddr().(*net.UDPAddr).Port)
  ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second);before:=cache.Count();var conn *quic.Conn
  if server{conn,err=listener.Accept(ctx)}else{conn,err=transport.Dial(ctx,&net.UDPAddr{IP:net.ParseIP(host),Port:port},base,config)};check(err)
  expected:=round!=0&&!(round==1&&strings.HasSuffix(mode,"fallback"));state:=conn.ConnectionState().TLS
  if state.DidResume!=expected{panic(fmt.Sprintf("round%d DidResume=%v expected=%v",round,state.DidResume,expected))}
  check(exchange(ctx,conn,server,cache,before));cancel()
  fmt.Printf("round=%d resumed=%v cipher=%#x verified=%d Go authenticated QUIC stream FIN/echo and DATAGRAM passed\n",round,state.DidResume,state.CipherSuite,len(state.VerifiedChains))

 }
}
