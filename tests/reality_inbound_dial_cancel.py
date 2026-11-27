"""Reality cover dialing under a saturated TCP accept queue (Linux)."""
from test_paths import require_nexus
import pathlib
import socket
import struct
import subprocess
import tempfile
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def pending(pid, port):
    owned = set()
    for fd in pathlib.Path(f'/proc/{pid}/fd').iterdir():
        try: target = str(fd.readlink())
        except FileNotFoundError: continue
        if target.startswith('socket:['): owned.add(target[8:-1])
    dest = f'0100007F:{port:04X}'
    return sum(fields[2] == dest and fields[3] == '02' and fields[9] in owned
               for line in pathlib.Path('/proc/net/tcp').read_text().splitlines()[1:]
               if len(fields := line.split()) > 9)


def scenario(mode):
    with tempfile.TemporaryDirectory(prefix='nexus-reality-dial-') as directory, socket.socket() as cover, socket.socket() as reserve:
        path = pathlib.Path(directory)
        cover.bind(('127.0.0.1', 0)); cover.listen(1); cover.settimeout(2)
        port = cover.getsockname()[1]
        fillers = [socket.create_connection(cover.getsockname(), timeout=2) for _ in range(2)]
        reserve.bind(('127.0.0.1', 0)); front = reserve.getsockname()[1]; reserve.close()
        (path/'secret').write_text('25'+'00'*31+'\n'); (path/'secret').chmod(0o600)
        (path/'uuid').write_text('00010203-0405-0607-0809-0a0b0c0d0e0f\n'); (path/'uuid').chmod(0o600)
        (path/'server.kdl').write_text(f'''schema-version 1
role "server"
workers 2
inbound "edge" type="vless" {{ listen host="127.0.0.1" port={front}; authentication {{ user "test" uuid-file="{path/'uuid'}"; }}; tls {{ reality {{ private-key-file "{path/'secret'}"; server-name "localhost"; short-id ""; fallback host="127.0.0.1" port={port}; }}; }}; }}
outbound "direct" type="direct"
routing {{ final "direct"; }}
''')
        server = subprocess.Popen([require_nexus(), 'run', '--config', path/'server.kdl'], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        try:
            limit = time.monotonic()+8
            while True:
                if server.poll() is not None: raise RuntimeError(server.stderr.read())
                try: client = socket.create_connection(('127.0.0.1', front), timeout=1); break
                except ConnectionRefusedError:
                    if time.monotonic()>limit: raise
                    time.sleep(.02)
            with client:
                client.settimeout(13); started=time.monotonic(); client.sendall(b'not TLS!')
                limit=time.monotonic()+3
                while pending(server.pid, port)!=1:
                    if server.poll() is not None or time.monotonic()>limit: raise RuntimeError('cover connect did not become pending')
                    time.sleep(.02)
                if mode == 'stop':
                    started_stop=time.monotonic(); server.terminate(); server.wait(timeout=5)
                    if server.returncode or time.monotonic()-started_stop>2: raise RuntimeError('stop did not cancel cover dial')
                    if client.recv(1): raise RuntimeError('client survived stop')
                elif mode == 'reset':
                    client.setsockopt(socket.SOL_SOCKET,socket.SO_LINGER,struct.pack('ii',1,0)); client.close()
                    limit=time.monotonic()+3
                    while pending(server.pid, port):
                        if server.poll() is not None or time.monotonic()>limit: raise RuntimeError('reset did not cancel cover dial')
                        time.sleep(.02)
                else:
                    if client.recv(1): raise RuntimeError('client survived dial deadline')
                    if not 8 <= time.monotonic()-started < 12: raise RuntimeError('dial deadline was not enforced')
                    if pending(server.pid,port): raise RuntimeError('timed-out dial retained its socket')
            with cover.accept()[0], cover.accept()[0]:
                cover.settimeout(.5)
                try: unexpected,_=cover.accept()
                except TimeoutError: pass
                else: unexpected.close(); raise RuntimeError('canceled dial reached cover')
        finally:
            if server.poll() is None: server.terminate(); server.wait(timeout=5)
            for filler in fillers: filler.close()
            diagnostics=server.stderr.read(); server.stderr.close()
            if server.returncode: raise RuntimeError(f'server exited {server.returncode}: {diagnostics!r}')


for mode in ('stop','timeout','reset'): scenario(mode)
print('Reality cover pending dial stop, deadline, and client reset passed')
