package main
import (
 "bytes"
 "encoding/hex"
 "fmt"
 "github.com/xtls/xray-core/common/protocol"
 "github.com/xtls/xray-core/common/uuid"
 "github.com/xtls/xray-core/proxy/vless"
 "github.com/xtls/xray-core/proxy/vless/encoding"
)
func main() {
 id:=uuid.UUID{0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15}
 request:=&protocol.RequestHeader{Version:0,Command:protocol.RequestCommandMux,User:&protocol.MemoryUser{Account:&vless.MemoryAccount{ID:protocol.NewID(id)}}}
 for _,flow:=range []string{"", "xtls-rprx-vision"} {
  var out bytes.Buffer
  if err:=encoding.EncodeRequestHeader(&out,request,&encoding.Addons{Flow:flow}); err!=nil { panic(err) }
  fmt.Println(hex.EncodeToString(out.Bytes()))
 }
}
