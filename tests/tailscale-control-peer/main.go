package main

import (
 "bufio"
 "bytes"
 "context"
 "crypto/tls"
 "encoding/base64"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "io"
 "net"
 "net/http"
 "net/http/httptest"
 "os"
 "strings"
 "sync/atomic"
 "time"

 "golang.org/x/net/http2"
 "tailscale.com/control/controlbase"
 "tailscale.com/control/controlhttp/controlhttpcommon"
 "tailscale.com/control/controlhttp/controlhttpserver"
 "tailscale.com/control/ts2021"
 "tailscale.com/tailcfg"
 "tailscale.com/types/key"
)

const earlyJSON=`{"nodeKeyChallenge":"chalpub:0000000000000000000000000000000000000000000000000000000000000000"}`

type options struct {
 early bool
 mapBytes int
 truncateMap bool
 uploadWindow int32
 registerHold time.Duration
 auditFile string
 audit *wireAudit
 headerDelay,noiseDelay,mapDelay time.Duration
 rejectHTTP bool
}

type serverState struct {accepted,registered,mapped,updated atomic.Int64; failures chan error}
func fixedMachine(seed byte) key.MachinePrivate {
 raw:=make([]byte,32);for i:=range raw {raw[i]=byte(i)+seed};var result key.MachinePrivate
 if err:=result.UnmarshalText([]byte("privkey:"+hex.EncodeToString(raw)));err!=nil {panic(err)};return result
}
func fixedNode(seed byte) key.NodePrivate {
 raw:=make([]byte,32);for i:=range raw {raw[i]=byte(i)+seed};var result key.NodePrivate
 if err:=result.UnmarshalText([]byte("privkey:"+hex.EncodeToString(raw)));err!=nil {panic(err)};return result
}
func (state *serverState) report(err error) {if err!=nil {select {case state.failures<-err:default:}}}
func writeAll(w io.Writer,data []byte) error {
 for len(data)>0 {n,err:=w.Write(data);if err!=nil {return err};if n<1 || n>len(data) {return io.ErrShortWrite};data=data[n:]};return nil
}
func writeMap(w io.Writer,value *tailcfg.MapResponse,padding int,truncate bool) error {
 data,err:=json.Marshal(value);if err!=nil {return err};if padding>len(data) {data=append(data,bytes.Repeat([]byte{' '},padding-len(data))...)};header:=make([]byte,4);binary.LittleEndian.PutUint32(header,uint32(len(data)))
 if err=writeAll(w,header);err!=nil {return err};if truncate && len(data)>1 {data=data[:len(data)/2]};return writeAll(w,data)
}
func handler(opt options,state *serverState) http.Handler {
 app:=http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
  if r.Method!="POST" {http.Error(w,"method",405);return}
  switch r.URL.Path {
  case "/machine/register":
   if opt.registerHold>0 {select {case <-r.Context().Done():return;case <-time.After(opt.registerHold):}}
   var request tailcfg.RegisterRequest
   if err:=json.NewDecoder(io.LimitReader(r.Body,1<<20)).Decode(&request);err!=nil {state.report(err);http.Error(w,"json",400);return}
   if request.Version!=148 || request.NodeKey.IsZero() || request.Auth==nil || request.Auth.AuthKey!="fixture-auth" {http.Error(w,"register",400);return}
   state.registered.Add(1);w.Header().Set("Content-Type","application/json")
   state.report(json.NewEncoder(w).Encode(&tailcfg.RegisterResponse{MachineAuthorized:true}))
  case "/machine/map":
   var request tailcfg.MapRequest
   if err:=json.NewDecoder(io.LimitReader(r.Body,1<<20)).Decode(&request);err!=nil {state.report(err);http.Error(w,"json",400);return}
   if request.Version!=148 || request.NodeKey.IsZero() || request.Compress!="" {http.Error(w,"map",400);return}
   if !request.Stream && request.OmitPeers {state.updated.Add(1);w.WriteHeader(200);return}
   state.mapped.Add(1);w.Header().Set("Content-Type","application/json")
   state.report(writeMap(w,&tailcfg.MapResponse{MapSessionHandle:"fixture-session",Seq:1,KeepAlive:true},opt.mapBytes,opt.truncateMap));if f,ok:=w.(http.Flusher);ok {f.Flush()}
   if opt.mapDelay>0 {select {case <-r.Context().Done():return;case <-time.After(opt.mapDelay):}}
  default:http.NotFound(w,r)
  }
 })
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request) {
  if r.Method!="POST" || r.URL.Path!="/ts2021" {http.NotFound(w,r);return}
  if opt.headerDelay>0 {time.Sleep(opt.headerDelay)}
  if opt.rejectHTTP {http.Error(w,"rejected",403);return}
  ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel()
  early:=func(version int,w io.Writer) error {
   if version!=148 {return fmt.Errorf("capability version %d",version)}
   if opt.noiseDelay>0 {time.Sleep(opt.noiseDelay)}
   if !opt.early {return nil}
   header:=make([]byte,9);copy(header,ts2021.EarlyPayloadMagic);binary.BigEndian.PutUint32(header[5:],uint32(len(earlyJSON)))
   if err:=writeAll(w,header);err!=nil {return err};return writeAll(w,[]byte(earlyJSON))
  }
  connection,err:=controlhttpserver.AcceptHTTP(ctx,w,r,fixedMachine(71),early);if err!=nil {state.report(err);return};defer connection.Close()
  if connection.Peer()!=fixedMachine(3).Public() || connection.ProtocolVersion()!=148 {state.report(errors.New("Noise identity/version"));return}
  state.accepted.Add(1)
  window:=opt.uploadWindow;if window==0 {window=64<<10}
  server:=http2.Server{MaxConcurrentStreams:8,MaxUploadBufferPerStream:window,MaxUploadBufferPerConnection:256<<10}
  if opt.auditFile!="" {observed:=&h2Audit{Conn:connection,done:make(chan struct{})};server.ServeConn(observed,&http2.ServeConnOpts{Handler:app});saveAudit(opt.auditFile,observed,opt.audit)} else {server.ServeConn(connection,&http2.ServeConnOpts{Handler:app})}
 })
}

// Fixture-only plaintext cork. After TLS, combine HTTP 101 and the first
// Noise response/early bytes in one TLS Write, forcing one-record prefetch.
type startupCorkConn struct {net.Conn;pending []byte;done bool}
func (c *startupCorkConn) Write(p []byte) (int,error) {
 if !c.done && len(c.pending)==0 && bytes.HasPrefix(p,[]byte("HTTP/1.1 101 ")) {c.pending=append([]byte(nil),p...);return len(p),nil}
 if len(c.pending)>0 {c.pending=append(c.pending,p...);err:=writeAll(c.Conn,c.pending);c.pending=nil;c.done=true;if err!=nil {return 0,err};return len(p),nil}
 return c.Conn.Write(p)
}
type startupCorkListener struct {net.Listener}
func (l startupCorkListener) Accept() (net.Conn,error) {c,err:=l.Listener.Accept();if err!=nil {return nil,err};return &startupCorkConn{Conn:c},nil}

type bufferedConn struct {net.Conn;reader *bufio.Reader}
func (c *bufferedConn) Read(p []byte) (int,error) {return c.reader.Read(p)}
func dial(ctx context.Context,address string,tlsConfig *tls.Config) (*controlbase.Conn,error) {
 var raw net.Conn;var err error
 if tlsConfig==nil {raw,err=(&net.Dialer{}).DialContext(ctx,"tcp",address)} else {raw,err=(&tls.Dialer{Config:tlsConfig}).DialContext(ctx,"tcp",address)}
 if err!=nil {return nil,err};ok:=false;defer func() {if !ok {raw.Close()}}()
 initial,continuation,err:=controlbase.ClientDeferred(fixedMachine(3),fixedMachine(71).Public(),148);if err!=nil {return nil,err}
 request,err:=http.NewRequestWithContext(ctx,"POST","http://"+address+"/ts2021",nil);if err!=nil {return nil,err}
 request.Header.Set("Connection","upgrade");request.Header.Set("Upgrade",controlhttpcommon.UpgradeHeaderValue)
 request.Header.Set(controlhttpcommon.HandshakeHeaderName,base64.StdEncoding.EncodeToString(initial))
 if deadline,has:=ctx.Deadline();has {raw.SetDeadline(deadline)}
 if err=request.Write(raw);err!=nil {return nil,err};reader:=bufio.NewReader(raw)
 response,err:=http.ReadResponse(reader,request);if err!=nil {return nil,err}
 if response.StatusCode!=101 || response.Header.Get("Upgrade")!=controlhttpcommon.UpgradeHeaderValue {return nil,fmt.Errorf("Upgrade status %d",response.StatusCode)}
 connection,err:=continuation(ctx,&bufferedConn{Conn:raw,reader:reader});if err!=nil {return nil,err};raw.SetDeadline(time.Time{});ok=true;return connection,nil
}
func post(ctx context.Context,client *http2.ClientConn,path string,body any) ([]byte,error) {
 data,err:=json.Marshal(body);if err!=nil {return nil,err}
 request,err:=http.NewRequestWithContext(ctx,"POST","https://control.test"+path,bytes.NewReader(data));if err!=nil {return nil,err};request.Header.Set("Content-Type","application/json")
 response,err:=client.RoundTrip(request);if err!=nil {return nil,err};defer response.Body.Close()
 data,err=io.ReadAll(response.Body);if err!=nil {return nil,err};if response.StatusCode!=200 {return nil,fmt.Errorf("H2 status %d",response.StatusCode)};return data,nil
}
func selftest(tlsEnabled,early bool) error {
 state:=&serverState{failures:make(chan error,8)};server:=httptest.NewUnstartedServer(handler(options{early:early},state));server.EnableHTTP2=false
 if tlsEnabled {server.StartTLS()} else {server.Start()};defer server.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel()
 var tlsConfig *tls.Config
 if tlsEnabled {tlsConfig=server.Client().Transport.(*http.Transport).TLSClientConfig.Clone();tlsConfig.NextProtos=[]string{"http/1.1"}}
 connection,err:=dial(ctx,strings.TrimPrefix(strings.TrimPrefix(server.URL,"https://"),"http://"),tlsConfig);if err!=nil {return err}
 wrapped:=ts2021.NewConn(connection,func() {});defer wrapped.Close()
 payload,err:=wrapped.GetEarlyPayload(ctx);if err!=nil {return err};if (payload!=nil)!=early {return errors.New("early presence")}
 transport:=http2.Transport{};client,err:=transport.NewClientConn(wrapped);if err!=nil {return err};defer client.Close()
 node:=fixedNode(17).Public();reply,err:=post(ctx,client,"/machine/register",&tailcfg.RegisterRequest{Version:148,NodeKey:node,Auth:&tailcfg.RegisterResponseAuth{AuthKey:"fixture-auth"},Hostinfo:&tailcfg.Hostinfo{Hostname:"fixture",OS:"linux"}});if err!=nil {return err}
 var registered tailcfg.RegisterResponse;if err=json.Unmarshal(reply,&registered);err!=nil || !registered.MachineAuthorized {return errors.New("register response")}
 reply,err=post(ctx,client,"/machine/map",&tailcfg.MapRequest{Version:148,NodeKey:node,Stream:true});if err!=nil {return err}
 if len(reply)<4 || int(binary.LittleEndian.Uint32(reply))!=len(reply)-4 {return errors.New("Map frame")};var mapped tailcfg.MapResponse
 if err=json.Unmarshal(reply[4:],&mapped);err!=nil || mapped.Seq!=1 || !mapped.KeepAlive || mapped.MapSessionHandle!="fixture-session" {return errors.New("Map body")}
 if _,err=post(ctx,client,"/machine/map",&tailcfg.MapRequest{Version:148,NodeKey:node,OmitPeers:true});err!=nil {return err}
 if state.accepted.Load()!=1 || state.registered.Load()!=1 || state.mapped.Load()!=1 || state.updated.Load()!=1 {return errors.New("server counters")}
 select {case err=<-state.failures:return err;default:return nil}
}
func main() {
 check:=flag.Bool("selftest",false,"official Go to Go only");earlyVectors:=flag.Bool("early-vectors",false,"official EarlyNoise encoding vectors");auditCheck:=flag.String("audit-selftest","","official positive authenticated TLS alert audit selftest");early:=flag.Bool("early",false,"send early payload");address:=flag.String("listen","127.0.0.1:0","listener")
 certificate:=flag.String("cert","","TLS certificate");privateKey:=flag.String("key","","TLS private key");reject:=flag.Bool("reject-http",false,"reject before Upgrade");coalesce:=flag.Bool("coalesce",false,"fixture combine HTTP and Noise in one TLS record")
 headerDelay:=flag.Duration("header-delay",0,"delay before HTTP response");noiseDelay:=flag.Duration("noise-delay",0,"delay before Noise response flush");mapDelay:=flag.Duration("map-delay",0,"keep Map stream open");mapBytes:=flag.Int("map-bytes",0,"fixture valid JSON whitespace padding");truncate:=flag.Bool("truncate-map",false,"fixture premature H2 END_STREAM inside Map frame");uploadWindow:=flag.Int("upload-window",0,"fixture H2 upload window");registerHold:=flag.Duration("register-hold",0,"fixture delay reading register body");auditFile:=flag.String("audit","","fixture passive H2 and authenticated TLS close_notify audit result")
 flag.Parse()
 if *auditCheck!="" {if err:=auditSelftest(*auditCheck);err!=nil {panic(err)};fmt.Println("official-audit-positive-selftest-passed");return}
 if *earlyVectors {
  values:=[]tailcfg.EarlyNoise{{},{NodeKeyChallenge:key.NewChallenge().Public()}}
  for _,value:=range values {data,err:=json.Marshal(value);if err!=nil {panic(err)};var decoded tailcfg.EarlyNoise;if err=json.Unmarshal(data,&decoded);err!=nil || decoded.NodeKeyChallenge!=value.NodeKeyChallenge {panic("early roundtrip")};fmt.Println(string(data))};return
 }
 if *check {for _,tlsEnabled:=range []bool{false,true} {for _,earlyEnabled:=range []bool{false,true} {if err:=selftest(tlsEnabled,earlyEnabled);err!=nil {panic(err)};fmt.Printf("official-control-http2-selftest tls=%v early=%v\n",tlsEnabled,earlyEnabled)}};return}
 listener,err:=net.Listen("tcp",*address);if err!=nil {panic(err)}
 if (*certificate=="")!=(*privateKey=="") {panic("TLS certificate/key pair required")}
 audit:=&wireAudit{};if *auditFile!="" {listener=captureListener{Listener:listener,audit:audit}}
 if *certificate!="" {cert,err:=tls.LoadX509KeyPair(*certificate,*privateKey);if err!=nil {panic(err)};listener=tls.NewListener(listener,&tls.Config{MinVersion:tls.VersionTLS13,Certificates:[]tls.Certificate{cert},NextProtos:[]string{"http/1.1"},KeyLogWriter:audit})}
 if *coalesce {listener=startupCorkListener{listener}}
 state:=&serverState{failures:make(chan error,8)}
 ready:=map[string]any{"port":listener.Addr().(*net.TCPAddr).Port,"control":fixedMachine(71).Public().UntypedHexString(),"machine":fixedMachine(3).Public().UntypedHexString(),"node":fixedNode(17).Public().UntypedHexString(),"tls":*certificate!="","early":*early,"coalesce":*coalesce}
 if err=json.NewEncoder(os.Stdout).Encode(ready);err!=nil {panic(err)}
 server:=http.Server{Handler:handler(options{early:*early,rejectHTTP:*reject,headerDelay:*headerDelay,noiseDelay:*noiseDelay,mapDelay:*mapDelay,mapBytes:*mapBytes,truncateMap:*truncate,uploadWindow:int32(*uploadWindow),registerHold:*registerHold,auditFile:*auditFile,audit:audit},state),ReadHeaderTimeout:10*time.Second}
 if err=server.Serve(listener);err!=nil && err!=http.ErrServerClosed {panic(err)}
}
