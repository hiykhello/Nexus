#!/usr/bin/env python3
"""Observe negotiated send rates on actual Hy2 client and server sockets."""
import argparse
from pathlib import Path
import socket
import sys
import tempfile
import threading
import time

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / 'tests'))
from detour_network import exact, reserve, socks
from dns_rule_support import nexus_process, udp_client
from hy2_outbound_detour import udp_port
from udp_bind_port_network import certificate


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path)
    parser.add_argument('--family', choices=('4', '6'), default='4')
    parser.add_argument('--mode', choices=('fixed', 'ignore', 'ignore-fixed', 'asymmetric', 'unknown', 'reject', 'stop-client', 'stop-server'), default='fixed')
    args = parser.parse_args()
    binary = args.binary.resolve(strict=True)
    host = '::1' if args.family == '6' else '127.0.0.1'
    with tempfile.TemporaryDirectory(prefix='hy2-brutal-cli-') as directory:
        root = Path(directory); certificate(root)
        password = root / 'password'; password.write_text('test-password\n'); password.chmod(0o600)
        port, front = udp_port(host), reserve()
        server, client = root / 'server.kdl', root / 'client.kdl'
        ignore = 'ignore-client-bandwidth #true;' if args.mode in ('ignore', 'ignore-fixed', 'reject') else ''
        client_receive = 0 if args.mode in ('unknown', 'reject') else 600000
        client_send = 0 if args.mode == 'asymmetric' else 600000
        server_receive = 0 if args.mode == 'ignore' else 300000
        server.write_text(f'''schema-version 1
role "server"
workers 1
inbound "edge" type="hysteria2" {{ listen host="{host}" port={port};
 authentication {{ user "test" password-file="{password}"; }}
 tls {{ certificate-file "{root / 'cert'}"; private-key-file "{root / 'key'}"; }}
 quic {{ send-bps 400000; receive-bps {server_receive}; {ignore} }}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
        client.write_text(f'''schema-version 1
role "client"
workers 1
inbound "local" type="socks5" {{ listen host="127.0.0.1" port={front}; authentication "none"; }}
outbound "direct" type="direct"
outbound "edge" type="hysteria2" {{ server host="{host}" port={port};
 authentication {{ password-file "{password}"; }}
 tls {{ server-name "localhost"; ca-file "{root / 'cert'}"; verify #true; }}
 quic {{ send-bps {client_send}; receive-bps {client_receive}; }}
}}
routing {{ default-outbound "edge"; }}
''')
        if args.mode == 'reject':
            with nexus_process(str(binary), str(server)), nexus_process(str(binary), str(client)):
                with socket.socket() as listener:
                    listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(.3)
                    with socket.create_connection(('127.0.0.1',front),timeout=6) as stream:
                        stream.settimeout(6);stream.sendall(b'\x05\x01\x00')
                        if exact(stream,2)!=b'\x05\x00':raise RuntimeError('SOCKS greeting failed')
                        stream.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+listener.getsockname()[1].to_bytes(2,'big'))
                        if exact(stream,10)[1]==0:raise RuntimeError('unknown rate unexpectedly accepted')
                    try: accepted,_=listener.accept()
                    except TimeoutError: pass
                    else: accepted.close();raise RuntimeError('rejected request reached target')
            print(f'IPv{args.family} server fixed receive rate and ignored unknown client: rejected',flush=True)
            return
        if args.mode in ('stop-client', 'stop-server'):
            with socket.socket() as listener:
                listener.bind(('127.0.0.1',0));listener.listen(1);listener.settimeout(8)
                with nexus_process(str(binary), str(server)) as server_process, nexus_process(str(binary), str(client)) as client_process:
                    with socks(front,1,('127.0.0.1',listener.getsockname()[1]))[0] as stream, listener.accept()[0] as target:
                        stream.settimeout(5);target.settimeout(5)
                        stream.sendall(b'ready')
                        if exact(target,5)!=b'ready': raise RuntimeError('active stream not established')
                        target.sendall(b'go')
                        if exact(stream,2)!=b'go':raise RuntimeError('active stream reply mismatch')
                        stream.sendall(bytes(range(256))*128)
                        if not target.recv(4096):raise RuntimeError('no active transfer')
                        process=client_process if args.mode=='stop-client' else server_process
                        started=time.monotonic();process.terminate();process.wait(timeout=5)
                        if process.returncode:raise RuntimeError(f'{args.mode} exit {process.returncode}')
                        deadline=time.monotonic()+5
                        for sock in (stream,target):
                            while True:
                                sock.settimeout(max(.01,deadline-time.monotonic()))
                                try:
                                    if not sock.recv(65536):break
                                except ConnectionResetError:break
                        print(f'IPv{args.family} {args.mode}: active fixed-rate stream drained in {time.monotonic()-started:.3f}s',flush=True)
            with socket.socket(socket.AF_INET6 if args.family=='6' else socket.AF_INET,socket.SOCK_DGRAM) as released:
                released.bind((host,port))
            return
        payload = bytes(range(256)) * 2048
        errors = []
        timings = {}
        with socket.socket() as origin:
            origin.bind(('127.0.0.1', 0)); origin.listen(1); origin.settimeout(12)
            def serve():
                try:
                    with origin.accept()[0] as conn:
                        conn.settimeout(12)
                        uploaded = exact(conn, len(payload))
                        if uploaded != payload: raise RuntimeError('upload mismatch')
                        timings['upload_done'] = time.monotonic()
                        timings['download_start'] = time.monotonic()
                        conn.sendall(payload); conn.shutdown(socket.SHUT_WR)
                except BaseException as error: errors.append(repr(error))
            thread = threading.Thread(target=serve); thread.start()
            try:
                with nexus_process(str(binary), str(server)), nexus_process(str(binary), str(client)):
                    with socks(front, 1, ('127.0.0.1', origin.getsockname()[1]))[0] as stream:
                        stream.settimeout(12)
                        start = time.monotonic(); stream.sendall(payload)
                        if exact(stream, len(payload)) != payload: raise RuntimeError('download mismatch')
                        download_done = time.monotonic()
                        elapsed = download_done-start
                        stream.shutdown(socket.SHUT_WR)
                        if stream.recv(1): raise RuntimeError('unexpected trailing bytes')
                    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp_origin, udp_client(front) as (udp, relay):
                        udp_origin.bind(('127.0.0.1', 0)); udp_origin.settimeout(8); udp.settimeout(8)
                        address=b'\0\0\0\1'+socket.inet_aton('127.0.0.1')+udp_origin.getsockname()[1].to_bytes(2,'big')
                        packet=address+bytes(range(256))*16
                        udp.sendto(packet,relay)
                        data,peer=udp_origin.recvfrom(65535)
                        if data!=packet[len(address):]: raise RuntimeError('UDP origin mismatch')
                        udp_origin.sendto(data,peer)
                        if udp.recvfrom(65535)[0]!=packet: raise RuntimeError('UDP reply mismatch')
            finally: thread.join(15)
            if thread.is_alive() or errors: raise RuntimeError(f'origin error: {errors!r}')
        # Include generous allowance for the initial ten-packet burst; each
        # direction is measured from the actual receiver's boundary.
        upload = timings['upload_done'] - start
        download = download_done - timings['download_start']
        fixed = args.mode in ('fixed', 'ignore-fixed')
        if fixed and (upload < 1.0 or download < .75):
            raise RuntimeError(f'directional pacing missing: upload={upload:.3f}s download={download:.3f}s')
        if args.mode == 'asymmetric' and (upload >= 1.5 or download < .75):
            raise RuntimeError(f'asymmetric pacing wrong: upload={upload:.3f}s download={download:.3f}s')
        if args.mode not in ('fixed', 'ignore-fixed', 'asymmetric') and elapsed >= 1.5:
            raise RuntimeError(f'auto unexpectedly paced: {elapsed:.3f}s')
        if elapsed >= 9: raise RuntimeError(f'transfer too slow: {elapsed:.3f}s')
        print(f'IPv{args.family} {args.mode}: 512 KiB each way upload={upload:.3f}s download={download:.3f}s total={elapsed:.3f}s and fragmented UDP', flush=True)

if __name__ == '__main__': main()
