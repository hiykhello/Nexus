import base64,json,os,pathlib,socket,subprocess,sys,tempfile,threading
from detour_network import Dns,exact,reserve,running,socks
from dns_rule_support import Echo,udp_client
binary=pathlib.Path(sys.argv[1]).resolve();revision='824dbcfb4dd0a95921840b1737b950cde590241e'
if f'Revision: {revision}' not in subprocess.check_output(['sing-box','version'],text=True):raise RuntimeError('unexpected sing-box revision')
with tempfile.TemporaryDirectory(prefix='snell-tfo-') as folder:
    root=pathlib.Path(folder);psk=root/'psk';psk.write_text('nexus-snell-test\n');psk.chmod(0o600);sskey=root/'sskey';password=base64.b64encode(bytes(range(16))).decode();sskey.write_text(password);sskey.chmod(0o600)
    snell_port,ss_port=reserve(),reserve();box=root/'box.json'
    box_snell={'type':'snell','listen':'127.0.0.1','listen_port':snell_port,'version':5,'psk':'nexus-snell-test'}
    obfs='obfs "http"; obfs-host "example.test";' if os.getenv('NEXUS_TEST_SNELL_HTTP_OBFS') else ''
    reuse='reuse #true;' if os.getenv('NEXUS_TEST_SNELL_REUSE') else ''
    if obfs:box_snell['obfs_mode']='http'
    box.write_text(json.dumps({'log':{'level':'warn'},'inbounds':[box_snell, {'type':'shadowsocks','listen':'127.0.0.1','listen_port':ss_port,'method':'2022-blake3-aes-128-gcm','password':password}], 'outbounds':[{'type':'direct','tag':'direct'}],'route':{'final':'direct'}}))
    subprocess.run(['sing-box','check','-c',box],check=True,capture_output=True)
    dns=Dns()
    try:
      with running(['sing-box','run','-c',str(box)],snell_port,root/'box.log'):
       for detour in (False,True):
        for workers in (1,2):
         front=reserve(); config=root/'nexus.kdl'; direct_fast=os.getenv('NEXUS_TEST_TFO_DIRECT') and not detour
         extra=f'detour "lower";' if detour else 'detour "direct";' if direct_fast else 'tcp-fast-open #true;'
         direct='outbound "direct" type="direct" { tcp-fast-open #true; }' if direct_fast else 'outbound "direct" type="direct"'
         lower=f'outbound "lower" type="shadowsocks" {{ server host="ss.test" port={ss_port}; bootstrap-resolver "boot"; method "2022-blake3-aes-128-gcm"; key-file "{sskey}"; }}' if detour else ''
         config.write_text(f'''schema-version 1
role "client"
workers {workers}
dns {{ server "boot" type="udp" host="127.0.0.1" port={dns.port}; strategy "ipv4_only"; }}
inbound "in" type="mixed" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
{direct}
{lower}
outbound "edge" type="snell" {{ server host="snell.test" port={snell_port}; version 4; psk-file "{psk}"; bootstrap-resolver "boot"; {extra} {obfs} {reuse} }}
routing {{ final "edge"; }}
''')
         with socket.socket() as origin:
          origin.bind(('127.0.0.1',0));origin.listen();origin.settimeout(8);out=[]
          def echo():
           with origin.accept()[0] as conn:
            data=bytearray()
            while part:=conn.recv(16384):data.extend(part)
            out.append(bytes(data));conn.sendall(data);conn.shutdown(socket.SHUT_WR)
          thread=threading.Thread(target=echo);thread.start()
          with running([str(binary),'run','--config',str(config)],front,root/'nexus.log'):
           client,_=socks(front,1,('127.0.0.1',origin.getsockname()[1]));client.settimeout(8);payload=bytes(i%251 for i in range(131072));client.sendall(payload);client.shutdown(socket.SHUT_WR)
           if exact(client,len(payload))!=payload or client.recv(1)!=b'':raise RuntimeError('payload/FIN mismatch')
           client.close()
          thread.join(timeout=8)
          if thread.is_alive() or out!=[payload]:raise RuntimeError('origin mismatch')
         print(f'Snell production TCP detour={detour} workers={workers} DNS+FIN passed',flush=True)
         with socket.socket() as idle_origin:
          idle_origin.bind(('127.0.0.1',0));idle_origin.listen();idle_origin.settimeout(8)
          with running([str(binary),'run','--config',str(config)],front,root/'nexus-stop.log'):
           idle,_=socks(front,1,('127.0.0.1',idle_origin.getsockname()[1]));idle.settimeout(4)
           remote,_=idle_origin.accept();remote.settimeout(4)
          try:
           if idle.recv(1)!=b'':raise RuntimeError('client survived stop')
          except ConnectionResetError:pass
          idle.close();remote.close()
         print(f'Snell production TCP detour={detour} workers={workers} pending stop passed',flush=True)
         psk.write_text('wrong-secret\n')
         wrong_front=reserve();config.write_text(config.read_text().replace(f'listen host="127.0.0.1" port={front}',f'listen host="127.0.0.1" port={wrong_front}'))
         try:
          with socket.socket() as denied_origin:
           denied_origin.bind(('127.0.0.1',0));denied_origin.listen();denied_origin.settimeout(.5)
           with running([str(binary),'run','--config',str(config)],wrong_front,root/'nexus-wrong.log'):
            rejected,_=socks(wrong_front,1,('127.0.0.1',denied_origin.getsockname()[1]));rejected.settimeout(4);rejected.sendall(b'must-not-arrive')
            try:
             if rejected.recv(1)!=b'':raise RuntimeError('wrong PSK yielded application bytes')
            except ConnectionResetError:pass
            rejected.close()
            try:denied_origin.accept();raise RuntimeError('wrong PSK reached origin')
            except TimeoutError:pass
         finally:psk.write_text('nexus-snell-test\n')
         print(f'Snell production TCP detour={detour} workers={workers} wrong PSK rejected',flush=True)
         udp_front=reserve();config.write_text(config.read_text().replace(f'listen host="127.0.0.1" port={wrong_front}',f'listen host="127.0.0.1" port={udp_front}'))
         with Echo() as echo, running([str(binary),'run','--config',str(config)],udp_front,root/'nexus-udp.log'):
          with udp_client(udp_front) as (client,relay):
           for family,host in ((socket.AF_INET,'127.0.0.1'),(socket.AF_INET6,'::1')):
            address=bytes([1 if family==socket.AF_INET else 4])+socket.inet_pton(family,host)+echo.port.to_bytes(2,'big')
            for payload in (b'packet',b'',bytes(range(256))*4):
             client.sendto(b'\0\0\0'+address+payload,relay);reply,_=client.recvfrom(65535);end=10 if reply[3]==1 else 22
             if reply[:3]!=b'\0\0\0' or int.from_bytes(reply[end-2:end],'big')!=echo.port or reply[end:]!=payload:raise RuntimeError(f'UDP mismatch family={family} sent={len(payload)} reply={len(reply)} prefix={reply[:24].hex()}')
         print(f'Snell production UDP detour={detour} workers={workers} dual family/empty passed',flush=True)
      if not {'snell.test','ss.test'}.issubset(dns.names):raise RuntimeError(f'bootstrap resolver not observed {dns.names}')
    finally:dns.close()
