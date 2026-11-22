package main

import (
 "context"
 "crypto/tls"
 "crypto/x509"
 "errors"
 "fmt"
 "io"
 "net"
 "net/http"
 "os"
 "strconv"
 "sync"
 "time"
 quic "github.com/sagernet/quic-go"
 "github.com/sagernet/quic-go/http3"
 "github.com/sagernet/quic-go/qlog"
 "github.com/sagernet/quic-go/qlogwriter"
)

type observed struct {
 mu sync.Mutex
 packets map[qlog.PacketNumber]bool
 acked chan struct{}
 target qlog.StreamID
 once sync.Once
}
func(t *observed) arm(id quic.StreamID)<-chan struct{}{
 t.mu.Lock();defer t.mu.Unlock();t.target=qlog.StreamID(id);t.packets=make(map[qlog.PacketNumber]bool);t.acked=make(chan struct{});t.once=sync.Once{};return t.acked
}
func (t *observed) AddProducer() qlogwriter.Recorder {return t}
func (t *observed) SupportsSchemas(string) bool {return true}
func (t *observed) Close() error {return nil}
func (t *observed) RecordEvent(event qlogwriter.Event) {
 t.mu.Lock();defer t.mu.Unlock()
 switch e:=event.(type) {
 case qlog.PacketSent:
  if e.Header.PacketType!=qlog.PacketType1RTT{return}
  for _,frame:=range e.Frames {
   if s,ok:=frame.Frame.(*qlog.StreamFrame);ok&&s.StreamID==t.target&&s.Offset==0&&s.Length>0{t.packets[e.Header.PacketNumber]=true}
   if s,ok:=frame.Frame.(qlog.StreamFrame);ok&&s.StreamID==t.target&&s.Offset==0&&s.Length>0{t.packets[e.Header.PacketNumber]=true}
  }
 case qlog.PacketReceived:
  if e.Header.PacketType!=qlog.PacketType1RTT{return}
  for _,frame:=range e.Frames {if a,ok:=frame.Frame.(*qlog.AckFrame);ok{for p:=range t.packets{if a.AcksPacket(p){t.once.Do(func(){close(t.acked)})}}}}
 }
}
func check(err error){if err!=nil{panic(err)}}
func rejected(stream *quic.Stream){
 check(stream.SetReadDeadline(time.Now().Add(2*time.Second)))
 one:=make([]byte,1);_,err:=stream.Read(one);var reset *quic.StreamError
 if !errors.As(err,&reset)||!reset.Remote||reset.ErrorCode!=0x100{panic(fmt.Sprintf("premature stream did not get actual reset0x100: %v",err))}
}
func request(address string) []byte {
 if len(address)>=64{panic("fixture address exceeds single-byte QUIC varint")}
 return append(append([]byte{0x44,1,byte(len(address))},[]byte(address)...),0)
}
func main(){
 if len(os.Args)!=6{panic("usage: preauth-peer 4|6 PORT CERT.der split|full|full-flood|truncated-fin SIZE")}
 port,err:=strconv.Atoi(os.Args[2]);check(err);size,err:=strconv.Atoi(os.Args[5]);check(err)
 raw,err:=os.ReadFile(os.Args[3]);check(err);cert,err:=x509.ParseCertificate(raw);check(err);roots:=x509.NewCertPool();roots.AddCert(cert)
 host:="127.0.0.1";if os.Args[1]=="6"{host="::1"}
 ctx,cancel:=context.WithTimeout(context.Background(),8*time.Second);defer cancel()
 observer:=&observed{packets:make(map[qlog.PacketNumber]bool),acked:make(chan struct{})}
 conn,err:=quic.DialAddr(ctx,net.JoinHostPort(host,strconv.Itoa(port)),&tls.Config{RootCAs:roots,ServerName:"localhost",MinVersion:tls.VersionTLS13,NextProtos:[]string{"h3"}},&quic.Config{Tracer:func(context.Context,bool,quic.ConnectionID)qlogwriter.Trace{return observer}});check(err)
 defer conn.CloseWithError(0,"")
 wire:=request("premature.example:443");prefix:=len(wire);rounds:=1
 switch os.Args[4]{case "split","truncated-fin":prefix=1;case "full":case "full-flood":rounds=20;default:panic("invalid mode")}
 var early *quic.Stream
 for index:=0;index<rounds;index++{
  early,err=conn.OpenStreamSync(ctx);check(err);acked:=observer.arm(early.StreamID())
  _,err=early.Write(wire[:prefix]);check(err)
  if os.Args[4]=="truncated-fin"{check(early.Close())}
  // Authentication starts only after the actual 1-RTT packet containing the
  // premature prefix was independently acknowledged by the real server.
  select{case<-acked:case<-ctx.Done():panic("premature stream packet was never acknowledged")}
  if prefix==len(wire)||os.Args[4]=="truncated-fin"{rejected(early);early=nil}
 }
 transport:=&http3.Transport{};h3:=transport.NewClientConn(conn)
 req,err:=http.NewRequestWithContext(ctx,http.MethodPost,"https://hysteria/auth",nil);check(err)
 req.Header.Set("Hysteria-Auth","test-password");req.Header.Set("Hysteria-CC-RX","0")
 response,err:=h3.RoundTrip(req);check(err);if response.StatusCode!=233{panic(fmt.Sprintf("auth status%d",response.StatusCode))};check(response.Body.Close())
 if early!=nil{_,err=early.Write(wire[prefix:]);if err!=nil{var reset *quic.StreamError;if !errors.As(err,&reset)||!reset.Remote{panic(err)}};rejected(early)}
 fresh,err:=conn.OpenStreamSync(ctx);check(err);_,err=fresh.Write(request("target.example:443"));check(err)
 deadline,_:=ctx.Deadline();check(fresh.SetDeadline(deadline))
 header:=make([]byte,3);_,err=io.ReadFull(fresh,header);check(err);if string(header)!=string([]byte{0,0,0}){panic(fmt.Sprintf("invalid TCP response%v",header))}
 uploaded:=make([]byte,size);for i:=range uploaded{uploaded[i]=byte(i*71+37)}
 upload:=make(chan error,1);go func(){_,e:=fresh.Write(uploaded);if e==nil{e=fresh.Close()};upload<-e}()
 got,err:=io.ReadAll(fresh);check(err);check(<-upload);if len(got)!=size{panic(fmt.Sprintf("short response%d",len(got)))};for i,v:=range got{if v!=byte(i*71+19){panic("corrupt response")}}
 select{case<-conn.Context().Done():case<-ctx.Done():panic("server did not complete after real independent FIN")}
 fmt.Printf("mode=%s premature_prefix=%d rejected_streams=%d packet_ACK_before_auth=true auth233=true native_reset0x100=true fresh_stream=%d payload=%d independent_FIN=true\n",os.Args[4],prefix,rounds,fresh.StreamID(),size)
}
