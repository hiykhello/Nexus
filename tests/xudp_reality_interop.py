"""Exercise two Mux UDP sessions over Reality against pinned independent servers."""
from test_paths import require_fixture, require_nexus
import argparse
import base64
import concurrent.futures
import json
import pathlib
import socket
import subprocess
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
REVISION = '824dbcfb4dd0a95921840b1737b950cde590241e'

def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--xray', help='Xray v1.260327.0 executable')
    parser.add_argument('--fixture', type=pathlib.Path, help='path to the direct XUDP fixture')
    parser.add_argument('--proxy', action='store_true', help='exercise the proxy tunnel factory')
    parser.add_argument('--proxy-fixture', type=pathlib.Path, help='path to the proxy tunnel fixture')
    parser.add_argument('--socks', action='store_true', help='exercise the SOCKS UDP production path')
    parser.add_argument('--nexus', type=pathlib.Path, help='path to the Nexus server used with --socks')
    parser.add_argument('--cancel', action='store_true', help='stop Nexus while the UDP tunnel reader is blocked')
    parser.add_argument('--concurrent', action='store_true', help='run eight concurrent SOCKS UDP associations')
    parser.add_argument('--policy', action='store_true', help='verify local IP policy before the tunnel')
    parser.add_argument('--restart-session', action='store_true', help='send to a closed UDP port before the next datagram')
    parser.add_argument('--tls', action='store_true', help='use certificate-authenticated TLS rather than Reality')
    parser.add_argument('--ipv6', action='store_true', help='use real IPv6 UDP origins through SOCKS')
    parser.add_argument('--dual', action='store_true', help='use IPv4 and IPv6 origins in each SOCKS association')
    args = parser.parse_args()
    if args.fixture and (args.proxy or args.socks): parser.error('--fixture is for the direct XUDP path')
    if args.proxy_fixture and not args.proxy: parser.error('--proxy-fixture requires --proxy')
    if args.nexus and not args.socks: parser.error('--nexus requires --socks')
    if args.concurrent and (not args.socks or args.cancel): parser.error('--concurrent requires --socks and cannot be combined with --cancel')
    if args.policy and not args.socks: parser.error('--policy requires --socks')
    if args.restart_session and (not args.socks or args.concurrent or args.proxy): parser.error('--restart-session requires single --socks')
    if args.tls and (args.xray or not args.socks): parser.error('--tls requires --socks and sing-box')
    if (args.ipv6 or args.dual) and (not args.socks or args.policy or args.restart_session or (args.ipv6 and args.dual)): parser.error('--ipv6/--dual requires --socks and cannot combine with --policy or --restart-session')
    if args.xray:
        version = subprocess.run(['go', 'version', '-m', args.xray], check=True, capture_output=True, text=True).stdout
        if '\tmod\tgithub.com/xtls/xray-core\tv1.260327.0\th1:g4TzxMwyPrxslZh6uD+FiG3lXKTrnNO+b4ky2OhogHE=' not in version:
            raise RuntimeError('unexpected Xray version')
        keys = subprocess.run([args.xray, 'x25519'], check=True, capture_output=True, text=True).stdout
        values = dict(line.split(': ', 1) for line in keys.splitlines() if ': ' in line)
        public = base64.urlsafe_b64decode(values['Password (PublicKey)'] + '=')
    else:
        version = subprocess.run(['sing-box', 'version'], check=True, capture_output=True, text=True).stdout
        if f'Revision: {REVISION}' not in version: raise RuntimeError('unexpected sing-box version')
        keys = subprocess.run(['sing-box', 'generate', 'reality-keypair'], check=True, capture_output=True, text=True).stdout
        values = dict(line.split(': ', 1) for line in keys.splitlines() if ': ' in line)
        public = base64.urlsafe_b64decode(values['PublicKey'] + '=')
    with tempfile.TemporaryDirectory(prefix='nexus-xudp-') as tmp:
        root = pathlib.Path(tmp)
        subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-keyout', str(root/'key'), '-out', str(root/'cert'), '-subj', '/CN=cover.example', '-addext', 'subjectAltName=DNS:cover.example', '-days', '1'], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        uuid = root/'uuid'; uuid.write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n'); uuid.chmod(0o600)
        backend, front = free_port(), free_port()
        while backend == front: front = free_port()
        cover = subprocess.Popen(['openssl', 's_server', '-quiet', '-accept', str(backend), '-cert', str(root/'cert'), '-key', str(root/'key')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        try:
            for mode in ('plain', 'vision'):
                user = {'id': '00010203-0405-0607-0809-0a0b0c0d0e0f'}
                if mode == 'vision': user['flow'] = 'xtls-rprx-vision'
                if args.xray:
                    config = {'log': {'loglevel': 'error'}, 'inbounds': [{'listen': '127.0.0.1', 'port': front, 'protocol': 'vless', 'settings': {'decryption': 'none', 'clients': [user]}, 'streamSettings': {'network': 'tcp', 'security': 'reality', 'realitySettings': {'target': f'127.0.0.1:{backend}', 'serverNames': ['cover.example'], 'privateKey': values['PrivateKey'], 'shortIds': ['0123456789abcdef']}}}], 'outbounds': [{'protocol': 'freedom'}]}
                    check = [args.xray, 'run', '-test', '-config', str(root/'config.json')]
                    command = [args.xray, 'run', '-config', str(root/'config.json')]
                else:
                    user['uuid'] = user.pop('id')
                    config = {'log': {'level': 'warn'}, 'inbounds': [{'type': 'vless', 'listen': '127.0.0.1', 'listen_port': front, 'users': [user], 'tls': {'enabled': True, 'server_name': 'cover.example', 'reality': {'enabled': True, 'handshake': {'server': '127.0.0.1', 'server_port': backend}, 'private_key': values['PrivateKey'], 'short_id': ['0123456789abcdef']}}}], 'outbounds': [{'type': 'direct'}]}
                    if args.tls: config['inbounds'][0]['tls'] = {'enabled': True, 'certificate_path': str(root/'cert'), 'key_path': str(root/'key')}
                    check = ['sing-box', 'check', '-c', str(root/'config.json')]
                    command = ['sing-box', 'run', '-c', str(root/'config.json')]
                (root/'config.json').write_text(json.dumps(config))
                subprocess.run(check, check=True, capture_output=True)
                families = [socket.AF_INET6 if args.ipv6 or (args.dual and i == 1) else socket.AF_INET for i in range(2)]
                origins = [socket.socket(family, socket.SOCK_DGRAM) for family in families]
                for sock in origins: sock.bind(('::1' if sock.family == socket.AF_INET6 else '127.0.0.1', 0)); sock.settimeout(12)
                closed_socket=None
                if args.restart_session:
                    closed_socket=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); closed_socket.bind(('127.0.0.1',0)); closed_port=closed_socket.getsockname()[1]; closed_socket.close()
                errors = []
                def echo(sock, expected):
                    try:
                        remaining = list(expected)
                        while remaining:
                            data, peer = sock.recvfrom(65535)
                            if data not in remaining: raise RuntimeError(f'wrong datagram {data!r}')
                            remaining.remove(data); sock.sendto(data, peer)
                    except Exception as exc: errors.append((exc, remaining))
                payloads = ((bytes([1,2,3]),), (bytes([4,5,6]),)) if args.proxy else ((b'first', b'again1'), (b'second', b'again2'))
                if args.concurrent: payloads = tuple(tuple(f'{i}:{j}'.encode() for j in range(8)) for i in range(2))
                threads = [threading.Thread(target=echo, args=(sock, payload), daemon=True) for sock, payload in zip(origins, payloads)]
                for thread in threads: thread.start()
                server = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                try:
                    time.sleep(.5)
                    if server.poll() is not None: raise RuntimeError('server exited')
                    ports = [str(sock.getsockname()[1]) for sock in origins]
                    if args.proxy:
                        proxy_fixture = args.proxy_fixture.resolve() if args.proxy_fixture else require_fixture('nexus-proxy-xudp-fixture')
                        command_fixture = [proxy_fixture, str(front), *ports, str(uuid), public.hex(), '1' if mode == 'vision' else '0']
                    elif not args.socks:
                        command_fixture = [(args.fixture or require_fixture('xudp-reality-fixture')).resolve(), str(front), public.hex(), *ports, mode]
                    if args.socks:
                        proxy_port=free_port(); flow=' flow "xtls-rprx-vision"' if mode=='vision' else ''
                        config_path=root/'nexus.kdl'
                        (root/'block.kdl').write_text('schema-version 1\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.2/32"\n')
                        tls = f'server-name "cover.example"; ca-file "{root/"cert"}"; verify #true;' if args.tls else f'server-name "cover.example"; reality {{ public-key "{public.hex()}"; short-id "0123456789abcdef"; }};'
                        policy = f'rule-set "blocked" path="{root/"block.kdl"}" format="kdl"; rule kind="rule-set" value="blocked" outbound="reject";' if args.policy else ''
                        config_path.write_text(f'''schema-version 1
role "client"
workers 2
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={proxy_port}; authentication "none"; }}
outbound "direct" type="direct"
outbound "reject" type="block"
outbound "edge" type="vless" {{ server host="127.0.0.1" port={front};{flow}
 authentication {{ uuid-file "{uuid}"; }}
 tls {{ {tls} }}
}}
routing {{ {policy} default-outbound "edge"; }}
''')
                        nexus = args.nexus.resolve() if args.nexus else require_nexus()
                        proxy=subprocess.Popen([nexus,'run','--config',config_path],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                        try:
                            deadline=time.monotonic()+10
                            while True:
                                if proxy.poll() is not None: raise RuntimeError(f'proxy exited: {proxy.stderr.read()!r}')
                                try: control=socket.create_connection(('127.0.0.1',proxy_port),timeout=1); break
                                except ConnectionRefusedError:
                                    if time.monotonic()>deadline: raise
                                    time.sleep(.05)
                            def associate(control, number):
                              with control, socket.socket(socket.AF_INET,socket.SOCK_DGRAM) as udp:
                                  control.settimeout(10); udp.settimeout(10); udp.bind(('127.0.0.1',0))
                                  def exact(n):
                                      data=b''
                                      while len(data)<n:
                                          piece=control.recv(n-len(data))
                                          if not piece: raise RuntimeError('SOCKS control EOF')
                                          data+=piece
                                      return data
                                  control.sendall(b'\x05\x01\x00')
                                  if exact(2)!=b'\x05\x00': raise RuntimeError('SOCKS authentication')
                                  control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
                                  response=exact(10)
                                  if response[:4]!=b'\x05\x00\x00\x01': raise RuntimeError(f'SOCKS association {response!r}')
                                  relay=(socket.inet_ntoa(response[4:8]),int.from_bytes(response[8:10],'big'))
                                  if args.restart_session:
                                      closed_header=b'\x00\x00\x00\x01\x7f\x00\x00\x01'+closed_port.to_bytes(2,'big')
                                      udp.sendto(closed_header+b'no listener',relay); time.sleep(1)
                                  if args.policy:
                                      blocked=b'\x00\x00\x00\x01\x7f\x00\x00\x02'+int(ports[0]).to_bytes(2,'big')
                                      udp.sendto(blocked+b'blocked',relay); udp.settimeout(.2)
                                      try: raise RuntimeError(f'blocked UDP reply {udp.recvfrom(65535)!r}')
                                      except socket.timeout: pass
                                      udp.settimeout(10)
                                  for index in range(2):
                                      for payload in ([payloads[index][number]] if args.concurrent else payloads[index]):
                                          header=b'\x00\x00\x00'+(b'\x04'+socket.inet_pton(socket.AF_INET6,'::1') if families[index] == socket.AF_INET6 else b'\x01\x7f\x00\x00\x01')+int(ports[index]).to_bytes(2,'big')
                                          udp.sendto(header+payload,relay)
                                          data,_=udp.recvfrom(65535)
                                          if data!=header+payload: raise RuntimeError(f'bad UDP reply {data!r}')
                                  if args.cancel:
                                      proxy.terminate(); proxy.wait(timeout=5)
                                      if proxy.returncode: raise RuntimeError(f'proxy shutdown {proxy.returncode}')
                                      if control.recv(1): raise RuntimeError('SOCKS control survived shutdown')
                            if args.concurrent:
                                controls=[control]+[socket.create_connection(('127.0.0.1',proxy_port),timeout=5) for _ in range(7)]
                                with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                                    list(pool.map(associate,controls,range(8)))
                            else: associate(control,0)
                        finally:
                            if proxy.poll() is None: proxy.terminate(); proxy.wait(timeout=5)
                    else:
                        result = subprocess.run(command_fixture, capture_output=True, timeout=18)
                        if result.returncode:
                            raise RuntimeError(f'{mode} fixture exit {result.returncode}, stderr {result.stderr!r}, origin errors {errors}')
                    for thread in threads: thread.join(13)
                    if errors or any(thread.is_alive() for thread in threads):
                        raise RuntimeError(f'{mode} origin errors {errors}')
                finally:
                    if server.poll() is None: server.terminate(); server.wait(timeout=5)
                    for sock in origins: sock.close()
        finally:
            cover.terminate(); cover.wait(timeout=5)
    path = 'SOCKS UDP' if args.socks else 'proxy factory' if args.proxy else 'client fixture'
    security = 'TLS' if args.tls else 'Reality'
    print(f'XUDP {path} {"dual-stack" if args.dual else "IPv6" if args.ipv6 else "IPv4"} over plain and Vision {security} passed with {"Xray" if args.xray else "sing-box"}')

if __name__ == '__main__': main()
