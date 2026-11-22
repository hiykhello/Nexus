package main

import (
 "crypto/tls"
 "crypto/x509"
 "fmt"
 "io"
 "net"
 "os"
 "strconv"
 "strings"
 "time"
)

func main() {
 if len(os.Args)!=5 {panic("PORT CA_PEM CURVE CLEAR")}
 port:=os.Args[1];pem,err:=os.ReadFile(os.Args[2]);if err!=nil {panic(err)}
 roots:=x509.NewCertPool();if !roots.AppendCertsFromPEM(pem){panic("invalid CA")}
 curve,err:=strconv.Atoi(os.Args[3]);if err!=nil{panic(err)}
 clear,err:=strconv.ParseBool(os.Args[4]);if err!=nil{panic(err)}
 config:=&tls.Config{RootCAs:roots,ServerName:"server.example",NextProtos:[]string{"http/1.1"},MinVersion:tls.VersionTLS13,MaxVersion:tls.VersionTLS13,ClientSessionCache:tls.NewLRUClientSessionCache(8),CurvePreferences:[]tls.CurveID{tls.CurveID(curve)}}
 dialer:=&net.Dialer{Timeout:8*time.Second}
 for round:=0;round<3;round++ {
  conn,err:=tls.DialWithDialer(dialer,"tcp",net.JoinHostPort("127.0.0.1",port),config);if err!=nil{panic(err)}
  if err=conn.SetDeadline(time.Now().Add(8*time.Second));err!=nil{panic(err)}
  state:=conn.ConnectionState();expected:=round>0&&!(clear&&round==1)
  if state.DidResume!=expected||state.NegotiatedProtocol!="http/1.1"||len(state.VerifiedChains)==0{panic(fmt.Sprintf("invalid authenticated negotiation round=%d resume=%v",round,state.DidResume))}
  if _,err=io.WriteString(conn,"GET / HTTP/1.1\r\nHost: server.example\r\nConnection: close\r\n\r\n");err!=nil{panic(err)}
  response,err:=io.ReadAll(conn);if err!=nil{panic(err)}
  if !strings.HasPrefix(string(response),"HTTP/1.1 200 OK")||!strings.Contains(string(response),"Nexus PSK OK"){panic("missing authenticated HTTP response")}
  if err=conn.Close();err!=nil{panic(err)}
  fmt.Printf("round=%d resumed=%v verified_chains=%d cipher=%04x authenticated_bytes=%d close passed\n",round,state.DidResume,len(state.VerifiedChains),state.CipherSuite,len(response))
 }
}
