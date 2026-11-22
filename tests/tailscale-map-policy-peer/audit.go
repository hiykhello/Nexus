package main

import (
 "bytes"
 "crypto/aes"
 "crypto/cipher"
 "crypto/hmac"
 "crypto/tls"
 "context"
 "fmt"
 "crypto/sha256"
 "crypto/sha512"
 "encoding/binary"
 "encoding/hex"
 "encoding/json"
 "errors"
 "hash"
 "io"
 "net"
 "net/http"
 "net/http/httptest"
 "strings"
 "os"
 "sync"
 "time"

 "golang.org/x/crypto/chacha20poly1305"
 "golang.org/x/net/http2"
 "tailscale.com/control/ts2021"
 "tailscale.com/tailcfg"
)

// This passive fixture audit never writes traffic secrets to disk or stdout.
// One test connection is accepted per process. Only booleans/counts are saved.
type wireAudit struct {
 mutex sync.Mutex
 raw,secret []byte
 overflow bool
}
func (a *wireAudit) Write(p []byte) (int,error) {
 fields:=bytes.Fields(p)
 if len(fields)==3 && string(fields[0])=="CLIENT_TRAFFIC_SECRET_0" {
  secret,err:=hex.DecodeString(string(fields[2]));if err!=nil {return 0,err}
  a.mutex.Lock();a.secret=secret;a.mutex.Unlock()
 }
 return len(p),nil
}
type captureConn struct {net.Conn;audit *wireAudit}
func (c *captureConn) Read(p []byte) (int,error) {
 n,err:=c.Conn.Read(p);if n>0 {c.audit.mutex.Lock();if len(c.audit.raw)+n>16<<20 {c.audit.overflow=true} else {c.audit.raw=append(c.audit.raw,p[:n]...)};c.audit.mutex.Unlock()};return n,err
}
type captureListener struct {net.Listener;audit *wireAudit}
func (l captureListener) Accept() (net.Conn,error) {c,err:=l.Listener.Accept();if err!=nil {return nil,err};return &captureConn{Conn:c,audit:l.audit},nil}

type h2Audit struct {
 net.Conn
 mutex sync.Mutex
 bytes []byte
 overflow,eof bool
 readError string
 done chan struct{}
 once sync.Once
}
func (a *h2Audit) Read(p []byte) (int,error) {
 n,err:=a.Conn.Read(p);a.mutex.Lock()
 if n>0 {if len(a.bytes)+n>16<<20 {a.overflow=true} else {a.bytes=append(a.bytes,p[:n]...)}}
 if err!=nil {a.eof=errors.Is(err,io.EOF);if !a.eof {a.readError=err.Error()};a.once.Do(func() {close(a.done)})}
 a.mutex.Unlock();return n,err
}
type auditResult struct {
 H2Preface bool `json:"h2_preface"`
 H2Frames int `json:"h2_frames"`
 H2RequestEnds int `json:"h2_request_ends"`
 H2Goaway bool `json:"h2_goaway"`
 H2GoawayCode uint32 `json:"h2_goaway_code"`
 H2Partial bool `json:"h2_partial"`
 NoiseEOF bool `json:"noise_eof"`
 NoiseReadError string `json:"noise_read_error,omitempty"`
 RawTLSPartial bool `json:"raw_tls_partial"`
 TLSApplicationRecords int `json:"tls_application_records"`
 TLSDecryptErrors int `json:"tls_decrypt_errors"`
 TLSCloseNotify bool `json:"tls_close_notify"`
 TLSSuite uint16 `json:"tls_suite"`
 Overflow bool `json:"overflow"`
}
func expand(secret []byte,label string,length int,newHash func() hash.Hash) []byte {
 label="tls13 "+label;info:=[]byte{byte(length>>8),byte(length),byte(len(label))};info=append(info,label...);info=append(info,0,1)
 mac:=hmac.New(newHash,secret);mac.Write(info);return append([]byte(nil),mac.Sum(nil)[:length]...)
}
func recordCipher(secret []byte,suite uint16) (cipher.AEAD,[]byte,error) {
 var newHash func() hash.Hash=sha256.New;length:=16
 if suite==0x1302 {newHash=sha512.New384;length=32};if suite==0x1303 {length=32}
 key:=expand(secret,"key",length,newHash);iv:=expand(secret,"iv",12,newHash)
 var aead cipher.AEAD;var err error
 if suite==0x1303 {aead,err=chacha20poly1305.New(key)} else {var block cipher.Block;block,err=aes.NewCipher(key);if err==nil {aead,err=cipher.NewGCM(block)}}
 for i:=range key {key[i]=0};return aead,iv,err
}
func openRecord(aead cipher.AEAD,iv []byte,sequence uint64,header,body []byte) ([]byte,error) {
 nonce:=append([]byte(nil),iv...);for i:=0;i<8;i++ {nonce[len(nonce)-1-i]^=byte(sequence>>(i*8))};return aead.Open(nil,nonce,body,header)
}
func auditTLS(result *auditResult,a *wireAudit) {
 a.mutex.Lock();wire:=append([]byte(nil),a.raw...);secret:=append([]byte(nil),a.secret...);result.Overflow=result.Overflow||a.overflow;a.mutex.Unlock()
 defer func() {for i:=range secret {secret[i]=0}}()
 if len(secret)==0 {result.TLSDecryptErrors++;return}
 var aead cipher.AEAD;var iv []byte;var sequence uint64
 for len(wire)>0 {
  if len(wire)<5 {result.RawTLSPartial=true;break};size:=int(binary.BigEndian.Uint16(wire[3:5]));if size>len(wire)-5 {result.RawTLSPartial=true;break}
  header,body:=wire[:5],wire[5:5+size];wire=wire[5+size:];if header[0]!=23 {continue}
  var plain []byte;var err error
  if aead==nil {
   suites:=[]uint16{0x1301,0x1303};if len(secret)==48 {suites=[]uint16{0x1302}}
   for _,suite:=range suites {candidate,nonce,makeError:=recordCipher(secret,suite);if makeError!=nil {continue};plain,err=openRecord(candidate,nonce,0,header,body);if err==nil {aead,iv,result.TLSSuite=candidate,nonce,suite;break}}
   if aead==nil {continue} // Client Finished still uses the handshake epoch.
  } else {plain,err=openRecord(aead,iv,sequence,header,body);if err!=nil {result.TLSDecryptErrors++;break}}
  sequence++;result.TLSApplicationRecords++
  end:=len(plain)-1;for end>=0 && plain[end]==0 {end--};if end<0 {result.TLSDecryptErrors++;break};kind:=plain[end];content:=plain[:end]
  if kind==21 && len(content)==2 && content[1]==0 {result.TLSCloseNotify=true}
  if kind==22 && len(content)==5 && content[0]==24 && content[1]==0 && content[2]==0 && content[3]==1 {
   newHash:=sha256.New;if result.TLSSuite==0x1302 {newHash=sha512.New384};updated:=expand(secret,"traffic upd",len(secret),newHash);for i:=range secret {secret[i]=0};secret=updated;aead,iv,err=recordCipher(secret,result.TLSSuite);if err!=nil {result.TLSDecryptErrors++;break};sequence=0
  }
 }
}
func saveAudit(path string,noise *h2Audit,tls *wireAudit) {
 select {case <-noise.done:case <-time.After(200*time.Millisecond):}
 noise.mutex.Lock();wire:=append([]byte(nil),noise.bytes...);result:=auditResult{NoiseEOF:noise.eof,NoiseReadError:noise.readError,Overflow:noise.overflow};noise.mutex.Unlock()
 if bytes.HasPrefix(wire,[]byte(http2.ClientPreface)) {result.H2Preface=true;wire=wire[len(http2.ClientPreface):]}
 for len(wire)>0 {
  if len(wire)<9 {result.H2Partial=true;break};length:=int(wire[0])<<16|int(wire[1])<<8|int(wire[2]);if length>len(wire)-9 {result.H2Partial=true;break}
  kind,flags,id:=wire[3],wire[4],binary.BigEndian.Uint32(wire[5:9])&0x7fffffff;body:=wire[9:9+length];wire=wire[9+length:];result.H2Frames++
  if id>0 && (kind==0 || kind==1) && flags&1!=0 {result.H2RequestEnds++}
  if kind==7 && id==0 && len(body)>=8 {result.H2Goaway=true;result.H2GoawayCode=binary.BigEndian.Uint32(body[4:8])}
 }
 auditTLS(&result,tls);data,_:=json.MarshalIndent(result,"","  ");os.WriteFile(path,append(data,'\n'),0600)
}

func auditSelftest(path string) error {
 audit:=&wireAudit{};state:=&serverState{failures:make(chan error,8)}
 server:=httptest.NewUnstartedServer(handler(options{early:true,auditFile:path,audit:audit},state))
 server.Listener=captureListener{Listener:server.Listener,audit:audit};server.TLS=&tls.Config{KeyLogWriter:audit};server.EnableHTTP2=false;server.StartTLS();defer server.Close()
 ctx,cancel:=context.WithTimeout(context.Background(),5*time.Second);defer cancel()
 config:=server.Client().Transport.(*http.Transport).TLSClientConfig.Clone();config.NextProtos=[]string{"http/1.1"}
 connection,err:=dial(ctx,strings.TrimPrefix(server.URL,"https://"),config);if err!=nil {return err};wrapped:=ts2021.NewConn(connection,func() {})
 transport:=http2.Transport{};client,err:=transport.NewClientConn(wrapped);if err!=nil {return err}
 if _,err=post(ctx,client,"/machine/register",&tailcfg.RegisterRequest{Version:148,NodeKey:fixedNode(17).Public(),Auth:&tailcfg.RegisterResponseAuth{AuthKey:"fixture-auth"}});err!=nil {return err}
 // x/net v0.59 on Go1.27 uses transport_wrap.shutdown, which waits
 // and calls ClientConn.Close without emitting GOAWAY. This positive
 // calibration is for authenticated TLS alert/EOF, not Nexus H2 shutdown.
 if err=client.Shutdown(ctx);err!=nil {return err};wrapped.Close()
 for i:=0;i<200;i++ {if data,err:=os.ReadFile(path);err==nil {var result auditResult;if err=json.Unmarshal(data,&result);err!=nil {return err};if !result.TLSCloseNotify || !result.NoiseEOF || result.H2Goaway || result.H2Partial || result.RawTLSPartial || result.TLSDecryptErrors!=0 {return fmt.Errorf("audit positive selftest: %+v",result)};return nil};time.Sleep(10*time.Millisecond)}
 return errors.New("audit positive selftest timed out")
}
