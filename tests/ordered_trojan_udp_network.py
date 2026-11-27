import hashlib
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from dns_rule_support import DnsPeer, exact, free_port, nexus_process


def main(binary):
    with tempfile.TemporaryDirectory() as directory, DnsPeer() as dns:
        root=Path(directory);port=free_port()
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key'),'-out',str(root/'cert'),'-days','1','-subj','/CN=localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (root/'key').chmod(0o600);(root/'password').write_text('secret');(root/'password').chmod(0o600)
        dns.delays['slow.test',1]=.5
        dns.delays['terminal.test',1]=.5
        for stem,name in (('slow','slow.test'),('terminal','terminal.test')):
            (root/f'{stem}.kdl').write_text(f'schema-version 2\nkind "predicate"\nrule type="domain" value="{name}"\n')
        (root/'rule.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="blocked.example"\n')
        (root/'config.kdl').write_text(f'''schema-version 1
role "server"
inbound "trojan" type="trojan" {{ listen host="127.0.0.1" port={port}; authentication {{ user "bob" password-file="{root/'password'}"; }}; tls {{ certificate-file "{root/'cert'}"; private-key-file "{root/'key'}"; }}; }}
outbound "direct" type="direct"
dns {{ servers {{ udp "resolver" host="127.0.0.1" port={dns.port}; }}; final "resolver"; strategy "ipv4_only"; disable-cache #true; }}
routing {{
  rulesets {{
      "blocked" path="rule.kdl" format="kdl"
      "slow" path="slow.kdl" format="kdl"
      "terminal" path="terminal.kdl" format="kdl"
  }}
  tcp-program sniff-timeout-ms=100 unknown="skip" udp=#true {{
    rule action="bypass"
    rule action="route-options" rule-set="slow" connect-timeout-ms=120
    rule action="route-options" rule-set="slow" connect-timeout-ms=1000
    rule action="bypass" rule-set="terminal" outbound="direct" connect-timeout-ms=120
    rule action="sniff"
    rule action="reject" rule-set="blocked" domain-source="sniffed"
    rule action="resolve"
    rule action="route" outbound="direct"
  }}
  final "direct"
}}
''')
        echo=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);echo.bind(('127.0.0.1',0));echo.settimeout(5);target=echo.getsockname()[1]
        errors=[]
        def serve():
            try:
                for expected in (b'one',b'',b'three'):
                    data,peer=echo.recvfrom(1024);assert data==expected,(data,expected);echo.sendto(data,peer)
            except Exception as exc:errors.append(exc)
        thread=threading.Thread(target=serve);thread.start()
        try:
            with nexus_process(binary,str(root/'config.kdl')):
                context=ssl.create_default_context(cafile=str(root/'cert'))
                with context.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=5),server_hostname='localhost') as client:
                    client.settimeout(5)
                    key=hashlib.sha224(b'secret').hexdigest().encode()
                    client.sendall(key+b'\r\n\x03\x01\x00\x00\x00\x00\x00\x00\r\n')
                    name=b'allowed.example';addr=b'\x03'+bytes([len(name)])+name+struct.pack('!H',target)
                    for late in (b'slow.test',b'terminal.test'):
                        late_address=b'\x03'+bytes([len(late)])+late+struct.pack('!H',target)
                        client.sendall(late_address+b'\x00\x04\r\nlate')
                        client.settimeout(.65)
                        try:
                            raise AssertionError(f'expired {late!r} produced a reply: {client.recv(1)!r}')
                        except TimeoutError:
                            pass
                        assert dns.count(late.decode(),1)==1,dns.seen
                    client.settimeout(4)
                    for payload in (b'one',b'',b'three'):
                        client.sendall(addr+struct.pack('!H',len(payload))+b'\r\n'+payload)
                        family=exact(client,1);assert family==b'\x01',family
                        assert exact(client,4)==socket.inet_aton('127.0.0.1')
                        assert int.from_bytes(exact(client,2),'big')==target
                        length=int.from_bytes(exact(client,2),'big');assert exact(client,2)==b'\r\n';assert exact(client,length)==payload
                    blocked=bytes.fromhex('123401000001000000000000')+b'\x07blocked\x07example\x00\x00\x01\x00\x01'
                    client.sendall(addr+struct.pack('!H',len(blocked))+b'\r\n'+blocked)
                    client.settimeout(.3)
                    try:client.recv(1);raise AssertionError('blocked packet replied')
                    except TimeoutError:pass
                    assert dns.count('allowed.example',1)==3,dns.seen
            thread.join(5);assert not thread.is_alive() and not errors,errors
            print('ordered Trojan UDP continuing and terminal deadlines, recovery, empty datagram and sniff reject passed')
        finally:
            echo.close();thread.join(5)


if __name__=='__main__':main(sys.argv[1])
