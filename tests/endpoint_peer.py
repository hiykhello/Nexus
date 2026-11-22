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
    (root/'go.mod').write_text(f'module nexus-wireguard-endpoint-peer\n\ngo 1.23.1\n\nrequire golang.zx2c4.com/wireguard {common.REVISION}\n')
    (root/'main.go').write_text(source)
    executable=root/'wireguard-endpoint-peer'
    result=subprocess.run(['go','build','-mod=mod','-o',executable,'main.go'],cwd=root,capture_output=True,text=True,timeout=120,env=dict(os.environ,GOPROXY='off',GOTOOLCHAIN='local'))
    if result.returncode:raise RuntimeError(result.stderr)
    return str(executable)
