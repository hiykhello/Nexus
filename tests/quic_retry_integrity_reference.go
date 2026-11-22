package main
import("bytes";"crypto/aes";"crypto/cipher";"encoding/hex";"fmt";"os")
func decode(s string)[]byte{b,e:=hex.DecodeString(s);if e!=nil{panic(e)};return b}
func main(){
 key:=decode("be0c690b9f66575a1d766b54e368c84e");nonce:=decode("461599d35d632bf2239825bb");original:=decode("8394c8f03e515708")
 block,e:=aes.NewCipher(key);if e!=nil{panic(e)};aead,e:=cipher.NewGCM(block);if e!=nil{panic(e)}
 check:=func(packet []byte){if len(packet)<16{panic("short Retry")};pseudo:=append(append([]byte{byte(len(original))},original...),packet[:len(packet)-16]...);tag:=aead.Seal(nil,nonce,nil,pseudo);if !bytes.Equal(tag,packet[len(packet)-16:]){panic("independent Retry integrity mismatch")}}
 check(decode("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"))
 if len(os.Args)!=2{panic("native Retry hex required")};check(decode(os.Args[1]));fmt.Println("Go AES128GCM independent RFC9001 A.4 vector and native ngtcp2 Retry output integrity both valid")
}
