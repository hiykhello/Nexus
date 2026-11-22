"""Pinned wireguard-go TUN peer with explicit authenticated endpoint rebinding."""
import os
import subprocess
from pathlib import Path
import wireguard_tun_network as tun
import wireguard_network as common


def build_peer(root):
    root=Path(root);root.mkdir(parents=True,exist_ok=True)
    source=tun.SOURCE.replace('case "stop": return',r'''case "refresh":
  if err=dev.IpcSet(fmt.Sprintf("public_key=%x\nendpoint=%s\n",corePublic,remote)); err!=nil { panic(err) }
  announce(map[string]bool{"refreshed":true})
 case "rebind":
  if err=dev.IpcSet("listen_port=0\n"); err!=nil { panic(err) }
  current,err=dev.IpcGet(); if err!=nil { panic(err) }; next:=0
  for _,line:=range strings.Split(current,"\n") { if strings.HasPrefix(line,"listen_port=") { next,_=strconv.Atoi(strings.TrimPrefix(line,"listen_port=")) } }
  if next==0 { panic("rebind port") }; announce(map[string]int{"port":next})
 case "stop": return''')
    if source==tun.SOURCE:raise RuntimeError('pinned Go TUN peer source changed')
    wrapper = r"""
type providerBind struct { conn.Bind; inbound [5]atomic.Uint64; outbound [5]atomic.Uint64 }
func (b *providerBind) Open(port uint16) ([]conn.ReceiveFunc,uint16,error) {
 fns,actual,err:=b.Bind.Open(port); if err!=nil{return nil,actual,err}
 wrapped:=make([]conn.ReceiveFunc,len(fns))
 for i,fn:=range fns { receive:=fn;wrapped[i]=func(packets [][]byte,sizes []int,eps []conn.Endpoint)(int,error){
  n,err:=receive(packets,sizes,eps)
  for j:=0;j<n;j++ { if sizes[j]<4 {continue};wire:=packets[j][:sizes[j]]
   if wire[0]<1 || wire[0]>4 || wire[1]!=17 || wire[2]!=34 || wire[3]!=51 {panic("unexpected provider header")}
   b.inbound[wire[0]].Add(1);wire[1]=0;wire[2]=0;wire[3]=0
  };return n,err
 }};return wrapped,actual,nil
}
func(b *providerBind) Send(packets [][]byte,ep conn.Endpoint)error{
 for _,wire:=range packets {if len(wire)<4 || wire[0]<1 || wire[0]>4 || wire[1]!=0 || wire[2]!=0 || wire[3]!=0 {panic("noncanonical reference output")};b.outbound[wire[0]].Add(1);wire[1]=173;wire[2]=190;wire[3]=239}
 defer func(){for _,wire:=range packets{wire[1]=0;wire[2]=0;wire[3]=0}}()
 return b.Bind.Send(packets,ep)
}
func(b *providerBind) stats()any{
 in,out:=make([]uint64,5),make([]uint64,5);for i:=0;i<5;i++{in[i]=b.inbound[i].Load();out[i]=b.outbound[i].Load()};return map[string]any{"inbound":in,"outbound":out,"reserved_outbound":[]int{173,190,239},"required_inbound":[]int{17,34,51}}
}
"""
    old='dev:=device.NewDevice(adapter,conn.NewDefaultBind(),'
    if source.count(old)!=1:raise RuntimeError('reference bind constructor changed')
    source=source.replace(old,'provider:=&providerBind{Bind:conn.NewDefaultBind()}; dev:=device.NewDevice(adapter,provider,')
    source=source.replace('case "probe":','case "profile-stats": announce(provider.stats())\n case "probe":')
    source=source.replace('func main() {',wrapper+'\nfunc main() {')
    (root/'go.mod').write_text(f'module nexus-wireguard-endpoint-peer\n\ngo 1.23.1\n\nrequire golang.zx2c4.com/wireguard {common.REVISION}\n')
    (root/'main.go').write_text(source)
    executable=root/'wireguard-endpoint-peer'
    result=subprocess.run(['go','build','-mod=mod','-o',executable,'main.go'],cwd=root,capture_output=True,text=True,timeout=120,env=dict(os.environ,GOPROXY='off',GOTOOLCHAIN='local'))
    if result.returncode:raise RuntimeError(result.stderr)
    return str(executable)
