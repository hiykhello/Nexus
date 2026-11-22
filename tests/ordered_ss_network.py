import os
import base64
import socket
import struct
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from dns_rule_support import connect, exact, free_port, nexus_process, proxy_client


def main(binary):
    revision='824dbcfb4dd0a95921840b1737b950cde590241e'
    if f'Revision: {revision}' not in subprocess.run(['sing-box','version'],check=True,capture_output=True,text=True).stdout:
        raise RuntimeError('unexpected sing-box revision')
    with tempfile.TemporaryDirectory() as directory:
        root=Path(directory);front=free_port();password=base64.b64encode(bytes(range(16))).decode()
        (root/'key').write_text(password);(root/'key').chmod(0o600)
        (root/'rule.kdl').write_text('schema-version 2\nkind "predicate"\nrule type="domain" value="blocked.example"\n')
        direct_options = '{ tcp-fast-open #true; }' if os.getenv("NEXUS_TEST_TFO_DIRECT") else ""
        (root/'config.kdl').write_text(f'''schema-version 1
role "server"
inbound "ss" type="shadowsocks" {{ listen host="127.0.0.1" port={front}; method "2022-blake3-aes-128-gcm"; key-file "{root/'key'}"; }}
outbound "direct" type="direct" {direct_options}
routing {{ rule-set "blocked" path="rule.kdl" format="kdl"; tcp-program sniff-timeout-ms=100 unknown="skip" {{ rule action="sniff"; rule action="reject" rule-set="blocked" domain-source="sniffed"; rule action="route" outbound="direct"; }}; default-outbound "direct"; }}
''')
        target=socket.socket();target.bind(('127.0.0.1',0));target.listen(4);target.settimeout(5);port=target.getsockname()[1]
        errors=[];payload=b'GET / HTTP/1.1\r\nHost: ok.example\r\n\r\nbody'
        def serve():
            try:
                conn,_=target.accept()
                with conn: conn.settimeout(5);assert exact(conn,len(payload))==payload;conn.sendall(b'OK')
                conn,_=target.accept()
                with conn: conn.sendall(b'FIRST')
            except Exception as exc: errors.append(exc)
        worker=threading.Thread(target=serve);worker.start()
        try:
            with nexus_process(binary,str(root/'config.kdl')), proxy_client(root,{'type':'shadowsocks','server':'127.0.0.1','server_port':front,'method':'2022-blake3-aes-128-gcm','password':password}) as socks:
                def open_client():
                    sock=connect(socks);sock.settimeout(5);sock.sendall(b'\x05\x01\x00');assert exact(sock,2)==b'\x05\x00'
                    sock.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+struct.pack('!H',port))
                    reply=exact(sock,4);assert reply[:2]==b'\x05\x00';exact(sock,6 if reply[3]==1 else 18);return sock
                with open_client() as client:
                    client.sendall(payload);assert exact(client,2)==b'OK'
                with open_client() as client: assert exact(client,5)==b'FIRST'
                with open_client() as client:
                    client.sendall(b'GET / HTTP/1.1\r\nHost: blocked.example\r\n\r\n')
                    try: assert not client.recv(1)
                    except ConnectionResetError: pass
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                    # Exclusive bind proves there is no SS UDP listener.
                    udp.bind(('127.0.0.1',front))
            worker.join(5);assert not worker.is_alive() and not errors,errors
            print('ordered SS TCP sniff, replay, server-first fallback and reject passed')
        finally:
            target.close();worker.join(5)


if __name__=='__main__':main(sys.argv[1])
