"""Pinned sing-box SOCKS UDP client through Nexus VLESS Mux inbound."""
from test_paths import require_nexus
import json
import base64
import sys
import pathlib
import socket
import subprocess
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
REVISION = '824dbcfb4dd0a95921840b1737b950cde590241e'
UUID = '00010203-0405-0607-0809-0a0b0c0d0e0f'


def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]


def exact(sock, size):
    data = bytearray()
    while len(data) < size:
        part = sock.recv(size - len(data))
        if not part:
            raise RuntimeError('unexpected EOF')
        data.extend(part)
    return bytes(data)


def run(root, vision, reality=False):
    front, socks = free_port(), free_port()
    while socks == front:
        socks = free_port()
    flow = ' flow "xtls-rprx-vision";' if vision else ''
    generated='--generated' in sys.argv[1:]
    if reality:
        credentials='' if generated else f'certificate-file "{root/"reality-cert.der"}"; signing-key-file "{root/"reality-key.der"}";'
        tls=f'reality {{ private-key-file "{root/"reality-secret"}"; {credentials} server-name "localhost"; short-id "0102030405060708"; fallback host="127.0.0.1" port=9; }}'
    else:
        tls=f'certificate-file "{root/"cert"}"; private-key-file "{root/"key"}";'
    source_rule='--source' in sys.argv[1:]
    inbound_rule='--inbound' in sys.argv[1:]
    auth_rule='--auth-user' in sys.argv[1:]
    block_rule=source_rule or inbound_rule or auth_rule or '--block' in sys.argv[1:]
    recovery='--recovery' in sys.argv[1:]
    if block_rule:
        (root/'source.kdl').write_text('''schema-version 2
kind "predicate"
rule type="and" { rule type="auth-user" value="test"; rule type="ip-cidr" value="127.0.0.2/32"; rule type="network" value="udp"; }
''' if auth_rule else '''schema-version 2
kind "predicate"
rule type="and" { rule type="inbound" value="edge"; rule type="ip-cidr" value="127.0.0.2/32"; rule type="network" value="udp"; }
''' if inbound_rule else '''schema-version 2
kind "predicate"
rule type="and" { rule type="source-ip-cidr" value="127.0.0.0/8"; rule type="source-port-range" value="1-65535"; rule type="ip-cidr" value="127.0.0.2/32"; rule type="network" value="udp"; }
''' if source_rule else 'schema-version 2\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.2/32"\n')
    routing=('rule-set "source" path="source.kdl" format="kdl"; rules { - kind="rule-set" value="source" outbound="reject"; }; ' if block_rule else '')
    (root/'server.kdl').write_text(f'''schema-version 1
role "server"
workers 2
inbound "edge" type="vless" {{ listen host="127.0.0.1" port={front};{flow} authentication {{ user "test" uuid-file="{root/'uuid'}"; }}; tls {{ {tls} }}; }}
outbound "direct" type="direct"
outbound "reject" type="block"
routing {{ {routing}default-outbound "direct"; }}
''')
    out = {'type': 'vless', 'server': '127.0.0.1', 'server_port': front, 'uuid': UUID,
           'tls': {'enabled': True, 'server_name': 'localhost', 'certificate_path': str(root/'cert')}}
    if reality:
        out['tls']={'enabled':True,'server_name':'localhost','utls':{'enabled':True,'fingerprint':'chrome'},'reality':{'enabled':True,'public_key':(root/'public').read_text(),'short_id':'0102030405060708'}}
    if vision:
        out['flow'] = 'xtls-rprx-vision'
    if '--packetaddr' in sys.argv[1:]:
        out['packet_encoding'] = 'packetaddr'
    config = {'log': {'level': 'warn'}, 'inbounds': [{'type': 'socks', 'listen': '127.0.0.1', 'listen_port': socks}], 'outbounds': [out]}
    (root/'box.json').write_text(json.dumps(config))
    subprocess.run(['sing-box', 'check', '-c', root/'box.json'], check=True, capture_output=True)
    server = subprocess.Popen([require_nexus(), 'run', '--config', root/'server.kdl'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    client = subprocess.Popen(['sing-box', 'run', '-c', root/'box.json'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    origins = []
    try:
        for family in (socket.AF_INET, socket.AF_INET6):
            origin = socket.socket(family, socket.SOCK_DGRAM)
            origin.bind(('127.0.0.1' if family == socket.AF_INET else '::1', 0))
            origin.settimeout(10)
            origins.append(origin)
        errors = []
        def echo(origin):
            try:
                for _ in range(2):
                    data, peer = origin.recvfrom(65535)
                    origin.sendto(data, peer)
            except Exception as exc:
                errors.append(exc)
        threads = [threading.Thread(target=echo, args=(origin,), daemon=True) for origin in origins]
        for thread in threads:
            thread.start()
        deadline = time.monotonic()+10
        while True:
            if server.poll() is not None or client.poll() is not None:
                raise RuntimeError('proxy exited before start')
            try:
                control = socket.create_connection(('127.0.0.1', socks), timeout=1)
                break
            except ConnectionRefusedError:
                if time.monotonic() >= deadline:
                    raise
                time.sleep(.05)
        with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
            control.settimeout(10)
            control.sendall(b'\x05\x01\x00')
            if exact(control, 2) != b'\x05\x00':
                raise RuntimeError('SOCKS auth')
            control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
            reply = exact(control, 10)
            if reply[:4] != b'\x05\x00\x00\x01':
                raise RuntimeError(f'SOCKS association {reply!r}')
            relay = (socket.inet_ntoa(reply[4:8]), int.from_bytes(reply[8:10], 'big'))
            udp.settimeout(10)
            def probe_packet(expect_blocked):
                with socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as blocked:
                    blocked.bind(('127.0.0.2',0)); blocked.settimeout(.5 if expect_blocked else 5)
                    packet=b'\0\0\0\x01\x7f\x00\x00\x02'+blocked.getsockname()[1].to_bytes(2,'big')+b'blocked'
                    udp.sendto(packet,relay)
                    try: data,_=blocked.recvfrom(1024)
                    except TimeoutError:
                        if not expect_blocked: raise
                    else:
                        if expect_blocked or data!=b'blocked': raise RuntimeError(f'unexpected XUDP target payload: {data!r}')
            if block_rule and recovery: probe_packet(True)
            for round_no in range(2):
                for index, origin in enumerate(origins):
                    family = origin.family
                    address = socket.inet_pton(family, '127.0.0.1' if family == socket.AF_INET else '::1')
                    payload = f'{vision}:{round_no}:{index}'.encode()
                    packet = b'\0\0\0' + (b'\x01' if family == socket.AF_INET else b'\x04') + address + origin.getsockname()[1].to_bytes(2, 'big') + payload
                    udp.sendto(packet, relay)
                    response, _ = udp.recvfrom(65535)
                    if response != packet:
                        raise RuntimeError(f'UDP mismatch {response!r} != {packet!r}')
            if block_rule and not recovery: probe_packet(True)
            if '--probe' in sys.argv[1:]: probe_packet(False)
        if block_rule and '--reconnect' in sys.argv[1:]:
            with socket.create_connection(('127.0.0.1',socks),timeout=3) as control, \
                 socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp, \
                 socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as target:
                control.settimeout(5); udp.settimeout(5); target.settimeout(5); target.bind(('127.0.0.1',0))
                control.sendall(b'\x05\x01\x00')
                if exact(control,2)!=b'\x05\x00': raise RuntimeError('reconnect greeting')
                control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
                reply=exact(control,10)
                if reply[:4]!=b'\x05\x00\x00\x01': raise RuntimeError('reconnect association')
                relay=(socket.inet_ntoa(reply[4:8]),int.from_bytes(reply[8:10],'big'))
                packet=b'\x00\x00\x00\x01\x7f\x00\x00\x01'+target.getsockname()[1].to_bytes(2,'big')+b'new-session'
                udp.sendto(packet,relay); payload,peer=target.recvfrom(1024)
                if payload!=b'new-session': raise RuntimeError('reconnect target payload')
                target.sendto(payload,peer)
                if udp.recvfrom(1024)[0]!=packet: raise RuntimeError('reconnect reply')
        for thread in threads:
            thread.join(10)
        if errors or any(thread.is_alive() for thread in threads):
            raise RuntimeError(f'origin failure {errors!r}')
    finally:
        for origin in origins:
            origin.close()
        for process in (client, server):
            if process.poll() is None:
                process.terminate()
            try:
                process.wait(5)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait()
            if process.returncode not in (0, -15):
                print(process.stderr.read().decode(errors='replace'))


def main():
    version = subprocess.run(['sing-box', 'version'], check=True, capture_output=True, text=True).stdout
    if f'Revision: {REVISION}' not in version:
        raise RuntimeError('unexpected sing-box revision')
    with tempfile.TemporaryDirectory(prefix='nexus-xudp-inbound-') as directory:
        root = pathlib.Path(directory)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root/'key'), '-out', str(root/'cert'), '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost', '-days', '1'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        (root/'key').chmod(0o600)
        (root/'uuid').write_text(UUID)
        (root/'uuid').chmod(0o600)
        reality='--reality' in sys.argv[1:]
        if reality:
            subprocess.run(['openssl','genpkey','-algorithm','ED25519','-out',root/'reality-key.pem'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
            subprocess.run(['openssl','pkey','-in',root/'reality-key.pem','-outform','DER','-out',root/'reality-key.der'],check=True)
            subprocess.run(['openssl','req','-new','-x509','-key',root/'reality-key.pem','-out',root/'reality-cert.der','-outform','DER','-subj','/CN=localhost','-days','1'],check=True)
            (root/'reality-key.der').chmod(0o600)
            (root/'reality-secret').write_text('25'+'00'*31+'\n'); (root/'reality-secret').chmod(0o600)
            (root/'x.der').write_bytes(bytes.fromhex('302e020100300506032b656e04220420'+'25'+'00'*31))
            public=subprocess.run(['openssl','pkey','-inform','DER','-in',root/'x.der','-pubout','-outform','DER'],check=True,capture_output=True).stdout[-32:]
            (root/'public').write_text(base64.urlsafe_b64encode(public).decode().rstrip('='))
        packetaddr = '--packetaddr' in sys.argv[1:]
        for vision in ((False,) if packetaddr else (False, True)):
            run(root, vision, reality)
    mode = 'packetaddr' if packetaddr else 'XUDP'
    print(f'Pinned sing-box {mode} to Nexus inbound passed IPv4/IPv6 (reality={reality})')


if __name__ == '__main__':
    main()
