"""Independent pinned wireguard-go kernel TUN peer with real UDP/TCP DNS service."""
from pathlib import Path
import ast,os,subprocess,sys
import wireguard_tun_network as tun
import wireguard_network as common

DNS=r'''
var dnsUDP,dnsTCP atomic.Uint64
func dnsReply(query []byte)[]byte{
 if len(query)<12 || query[4]!=0 || query[5]!=1{return nil};end:=12
 for {if end>=len(query){return nil};n:=int(query[end]);end++;if n==0{break};if n>63 || end+n>len(query){return nil};end+=n}
 if end+4!=len(query) && end+4>len(query){return nil};if end+4>len(query){return nil}
 qtype:=binary.BigEndian.Uint16(query[end:]);end+=4
 out:=append([]byte(nil),query[:end]...);out[2]=0x81;out[3]=0x80;out[6]=0;out[7]=1;out[8]=0;out[9]=0;out[10]=0;out[11]=0
 answer:=[]byte{0xc0,0x0c,byte(qtype>>8),byte(qtype),0,1,0,0,0,1,0,0}
 if qtype==1{answer[11]=4;answer=append(answer,198,18,42,7)}else if qtype==28{answer[11]=16;answer=append(answer,0xfd,0x42,0x99,0,0,0,0,0,0,0,0,0,0,0,0,7)}else{out[7]=0;return out}
 return append(out,answer...)
}
func dnsServices(node int){
 for _,host:=range addresses(node){
  udp,err:=net.ListenPacket("udp",net.JoinHostPort(host,"53"));if err!=nil{panic(err)}
  go func(){buffer:=make([]byte,4096);for{n,source,err:=udp.ReadFrom(buffer);if err!=nil{return};reply:=dnsReply(buffer[:n]);if reply==nil{continue};if strings.Contains(string(buffer[:n]),"wg-tcp-"){reply=append([]byte(nil),buffer[:n]...);reply[2]=0x83;reply[3]=0x80;reply[6]=0;reply[7]=0;reply[8]=0;reply[9]=0;reply[10]=0;reply[11]=0};dnsUDP.Add(1);if _,err=udp.WriteTo(reply,source);err!=nil{return}}}()
  tcp,err:=net.Listen("tcp",net.JoinHostPort(host,"53"));if err!=nil{panic(err)}
  go func(){for{stream,err:=tcp.Accept();if err!=nil{return};go func(stream net.Conn){defer stream.Close();stream.SetDeadline(time.Now().Add(5*time.Second));for{header:=make([]byte,2);if _,err:=io.ReadFull(stream,header);err!=nil{return};size:=int(binary.BigEndian.Uint16(header));if size<12 || size>4096{return};query:=make([]byte,size);if _,err:=io.ReadFull(stream,query);err!=nil{return};reply:=dnsReply(query);if reply==nil{return};dnsTCP.Add(1);binary.BigEndian.PutUint16(header,uint16(len(reply)));if _,err:=stream.Write(append(header,reply...));err!=nil{return}}}(stream)}}()
 }
}
'''
def build_peer(root,provider=False):
 root=Path(root);root.mkdir(exist_ok=True,parents=True)
 source=tun.SOURCE.replace(' "encoding/hex"',' "encoding/binary"\n "encoding/hex"')
 source=source.replace('func main() {',DNS+'\nfunc main() {')
 source=source.replace('services(node); announce','services(node); dnsServices(node); announce')
 source=source.replace('case "stop": return',r'''case "dns-stats": announce(map[string]uint64{"udp":dnsUDP.Load(),"tcp":dnsTCP.Load()})
 case "refresh":
  if err=dev.IpcSet(fmt.Sprintf("public_key=%x\nendpoint=%s\n",corePublic,remote)); err!=nil { panic(err) }; announce(map[string]bool{"refreshed":true})
 case "rebind":
  if err=dev.IpcSet("listen_port=0\n"); err!=nil { panic(err) }
  current,err=dev.IpcGet(); if err!=nil { panic(err) }; next:=0
  for _,line:=range strings.Split(current,"\n") { if strings.HasPrefix(line,"listen_port=") { next,_=strconv.Atoi(strings.TrimPrefix(line,"listen_port=")) } }
  if next==0 { panic("rebind port") }; announce(map[string]int{"port":next})
 case "stop": return''')
 if provider:
  import wireguard_provider_peer as reference
  tree=ast.parse(Path(reference.__file__).read_text())
  wrappers=[ast.literal_eval(node.value) for node in ast.walk(tree) if isinstance(node,ast.Assign) and any(isinstance(target,ast.Name) and target.id=='wrapper' for target in node.targets)]
  if len(wrappers)!=1:raise RuntimeError('fixed independent provider bind wrapper changed')
  old='dev:=device.NewDevice(adapter,conn.NewDefaultBind(),'
  if source.count(old)!=1:raise RuntimeError('reference default bind constructor changed')
  source=source.replace(old,'provider:=&providerBind{Bind:conn.NewDefaultBind()}; dev:=device.NewDevice(adapter,provider,')
  source=source.replace('func main() {',wrappers[0]+'\nfunc main() {')
  source=source.replace('case "dns-stats":','case "profile-stats": announce(provider.stats())\n case "dns-stats":')
 (root/'go.mod').write_text(f'module nexus-wireguard-host-dns-peer\n\ngo 1.23.1\n\nrequire golang.zx2c4.com/wireguard {common.REVISION}\n');(root/'main.go').write_text(source);binary=root/'wireguard-host-dns-peer'
 done=subprocess.run(['go','build','-mod=mod','-o',binary,'main.go'],cwd=root,env=dict(os.environ,GOPROXY='off',GOTOOLCHAIN='local'),capture_output=True,text=True,timeout=120)
 if done.returncode:raise RuntimeError(done.stderr)
 return binary
if __name__=='__main__':print(build_peer(Path(sys.argv[1]).resolve(),'--provider' in sys.argv[2:]))
