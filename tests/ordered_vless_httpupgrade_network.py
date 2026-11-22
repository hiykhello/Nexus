import os
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from ordered_tcp_network import headers, exact
from pathlib import Path
from dns_rule_support import free_port, nexus_process


def main(binary):
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory);port=free_port()
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key'),'-out',str(root/'cert'),'-days','1','-subj','/CN=localhost'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        (root/'key').chmod(0o600);(root/'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f');(root/'uuid').chmod(0o600)
        (root/'rule.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="blocked.example"\n')
        direct_options = '{ tcp-fast-open #true; }' if os.getenv("NEXUS_TEST_TFO_DIRECT") else ""
        (root/'config.kdl').write_text(f'''schema-version 1
role "server"
inbound "vless" type="vless" {{ listen host="127.0.0.1" port={port}; authentication {{ user "bob" uuid-file="{root/'uuid'}"; }}; tls {{ certificate-file "{root/'cert'}"; private-key-file "{root/'key'}"; }}; transport "httpupgrade" {{ host "cover.example"; path "/upgrade"; }}; }}
outbound "direct" type="direct" {direct_options}
routing {{ rule-set "blocked" path="rule.kdl" format="kdl"; tcp-program sniff-timeout-ms=100 unknown="skip" {{ rule action="sniff"; rule action="reject" rule-set="blocked" domain-source="sniffed"; rule action="route" outbound="direct"; }}; default-outbound "direct"; }}
''')
        target=socket.socket();target.bind(('127.0.0.1',0));target.listen(2);target.settimeout(5);target_port=target.getsockname()[1]
        errors=[];request=b'GET / HTTP/1.1\r\nHost: ok.example\r\n\r\nbody'
        def server():
            try:
                conn,_=target.accept()
                with conn:
                    conn.settimeout(4);received=b''
                    while len(received)<len(request): received+=conn.recv(len(request)-len(received))
                    assert received==request,received
                    conn.sendall(b'OK')
                conn,_=target.accept()
                with conn: conn.sendall(b'FIRST')
            except Exception as exc: errors.append(exc)
        thread=threading.Thread(target=server);thread.start()
        try:
            with nexus_process(binary,str(root/'config.kdl')):
                context=ssl.create_default_context(cafile=str(root/'cert'));context.set_alpn_protocols(['http/1.1'])
                def open_client(payload=b''):
                    sock=context.wrap_socket(socket.create_connection(('127.0.0.1',port),timeout=5),server_hostname='localhost')
                    sock.settimeout(5)
                    header=b'\x00'+bytes(range(16))+b'\x00\x01'+target_port.to_bytes(2,'big')+b'\x01\x7f\x00\x00\x01'
                    upgrade=b"GET /upgrade HTTP/1.1\r\nHost: cover.example\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n"
                    sock.sendall(upgrade+header+payload)
                    assert headers(sock).startswith(b"HTTP/1.1 101 ")
                    return sock
                with open_client(request) as sock:
                    assert exact(sock,2)==b'\x00\x00';assert exact(sock,2)==b'OK'
                with open_client() as sock:
                    assert exact(sock,2)==b'\x00\x00';assert exact(sock,5)==b'FIRST'
                with open_client(b'GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n') as sock:
                    assert not sock.recv(1)
            thread.join(5);assert not thread.is_alive() and not errors,errors
            print('ordered VLESS HTTPUpgrade prefetched sniff, replay, timeout fallback and reject passed')
        finally:
            target.close();thread.join(5)


if __name__=='__main__':main(sys.argv[1])
