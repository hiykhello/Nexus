"""Exercise the Reality server primitives over a real TLS/VLESS socket."""
from test_paths import optional_fixture
import argparse
import pathlib
import base64
import json
import time
import socket
import subprocess
import tempfile

root = pathlib.Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument('--server', type=pathlib.Path,
                    default=optional_fixture('reality-server-fixture'), required=optional_fixture('reality-server-fixture') is None)
parser.add_argument('--client', type=pathlib.Path,
                    default=optional_fixture('reality-client-fixture'), required=optional_fixture('reality-client-fixture') is None)
parser.add_argument('--xray', type=pathlib.Path, help='also exercise this pinned Xray client')
args = parser.parse_args()
server = args.server.resolve()
client_fixture = args.client.resolve()
xray = (args.xray or pathlib.Path('/tmp/nexus-xray-bin/main')).resolve()
if args.xray and not xray.is_file():
    parser.error(f'Xray client does not exist: {xray}')
with tempfile.TemporaryDirectory(prefix='nexus-reality-server-') as directory:
    path = pathlib.Path(directory)
    (path/'secret').write_text('25'+'00'*31+'\n'); (path/'secret').chmod(0o600)
    def run(*args):
        subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    run('openssl', 'genpkey', '-algorithm', 'ED25519', '-out', str(path/'key.pem'))
    run('openssl', 'pkey', '-in', str(path/'key.pem'), '-outform', 'DER', '-out', str(path/'key.der'))
    (path/'key.der').chmod(0o600)
    run('openssl', 'req', '-new', '-x509', '-key', str(path/'key.pem'), '-out', str(path/'cert.der'), '-outform', 'DER', '-subj', '/CN=localhost', '-days', '1')
    with socket.socket() as listener:
        listener.bind(('127.0.0.1', 0)); listener.listen(1)
        fixture = subprocess.Popen([server, str(listener.fileno()), path/'cert.der', path/'key.der', path/'secret'], pass_fds=(listener.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            public = fixture.stdout.readline().strip()
            if len(public) != 64: raise RuntimeError('fixture did not produce its public key')
            client = subprocess.run([client_fixture, str(listener.getsockname()[1]), public, 'localhost', '12345', '0102030405060708'], timeout=15, capture_output=True)
            stdout, stderr = fixture.communicate(timeout=15)
            if client.returncode or fixture.returncode:
                raise RuntimeError(f'client={client.returncode} {client.stderr!r} server={fixture.returncode} {stdout!r} {stderr!r}')
        finally:
            if fixture.poll() is None: fixture.kill(); fixture.wait()
    if xray.exists():
        version = subprocess.run(['go', 'version', '-m', xray], check=True, capture_output=True, text=True).stdout
        if '\tmod\tgithub.com/xtls/xray-core\tv1.260327.0\th1:g4TzxMwyPrxslZh6uD+FiG3lXKTrnNO+b4ky2OhogHE=' not in version: raise RuntimeError('unexpected Xray version')
        with socket.socket() as listener, socket.socket() as reserve:
            listener.bind(('127.0.0.1', 0)); listener.listen(1); reserve.bind(('127.0.0.1', 0)); socks_port = reserve.getsockname()[1]; reserve.close()
            fixture = subprocess.Popen([server, str(listener.fileno()), path/'cert.der', path/'key.der', path/'secret'], pass_fds=(listener.fileno(),), stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            proxy = None
            try:
                public = bytes.fromhex(fixture.stdout.readline().strip())
                config = {'log': {'loglevel':'error'}, 'inbounds':[{'listen':'127.0.0.1','port':socks_port,'protocol':'socks','settings':{'auth':'noauth','udp':False}}], 'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':listener.getsockname()[1],'users':[{'id':'00010203-0405-0607-0809-0a0b0c0d0e0f','encryption':'none'}]}]},'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':'localhost','fingerprint':'chrome','password':base64.urlsafe_b64encode(public).decode().rstrip('='),'shortId':'0102030405060708'}}}]}
                (path/'xray.json').write_text(json.dumps(config))
                proxy = subprocess.Popen([xray,'run','-config',path/'xray.json'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
                deadline=time.monotonic()+10
                while True:
                    if proxy.poll() is not None: raise RuntimeError(f'Xray exited {proxy.stderr.read()!r}')
                    try: conn=socket.create_connection(('127.0.0.1',socks_port),timeout=1); break
                    except ConnectionRefusedError:
                        if time.monotonic()>deadline: raise
                        time.sleep(.05)
                with conn:
                    conn.settimeout(10); conn.sendall(b'\x05\x01\x00')
                    if conn.recv(2)!=b'\x05\x00': raise RuntimeError('Xray SOCKS auth')
                    conn.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01\x30\x39')
                    reply=conn.recv(10)
                    if len(reply)!=10 or reply[:2]!=b'\x05\x00': raise RuntimeError(f'Xray SOCKS request {reply!r}')
                    conn.sendall(b'independent Xray client')
                    received=b''
                    while len(received)<23:
                        data=conn.recv(23-len(received))
                        if not data: raise RuntimeError('Xray EOF')
                        received+=data
                    if received!=b'independent Xray client': raise RuntimeError('Xray data mismatch')
                _,stderr=fixture.communicate(timeout=10)
                if fixture.returncode: raise RuntimeError(f'server failed {fixture.returncode}: {stderr}')
            finally:
                if proxy and proxy.poll() is None: proxy.terminate(); proxy.wait(timeout=5)
                if fixture.poll() is None: fixture.kill(); fixture.wait()
                if fixture.returncode: print('fixture stderr:',fixture.stderr.read())
        print('Pinned Xray client Reality TLS/VLESS data round trip passed')
print('Reality server probe, credential, TLS Finished and VLESS data round trip passed')
