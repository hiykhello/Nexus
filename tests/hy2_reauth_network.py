#!/usr/bin/env python3
"""Run two H3 authentication requests and a TCP exchange on one Hy2 connection."""
import argparse
import contextlib
import os
import select
import shlex
import signal
import json
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time

from dns_rule_support import nexus_process
from hy2_outbound_detour import udp_port
from hy2_outbound_singbox import REVISION
from udp_bind_port_network import certificate


@contextlib.contextmanager
def traced_nexus(binary, config, logpath, expected_rate):
    """Count actual native controller installations in one CLI process."""
    output_read, output_write = os.pipe()
    inferior_log = Path(str(logpath) + '.inferior.log')
    with open(logpath, 'wb') as log, open(inferior_log, 'wb') as diagnostics, tempfile.NamedTemporaryFile(mode='w', prefix='hy2-gdb-', suffix='.txt') as commands:
        script = f'''set pagination off
set confirm off
set debuginfod enabled off
set exec-wrapper stdbuf -oL
handle SIGTERM pass nostop noprint
break nexus_ngtcp2_set_brutal
commands
silent
printf "BRUTAL_INSTALL=%llu\\n", (unsigned long long)$rsi
continue
end
set args run --config {shlex.quote(str(config))} > /proc/self/fd/{output_write} 2> /proc/self/fd/{diagnostics.fileno()}
run
quit $_exitcode
'''
        commands.write(script); commands.flush()
        process = subprocess.Popen(['gdb', '-q', '--batch', '-x', commands.name, '--args', str(binary)],
                                   stdout=log, stderr=subprocess.STDOUT, pass_fds=(output_write, diagnostics.fileno()))
        os.close(output_write)
        output = os.fdopen(output_read, 'rb', buffering=0)
        try:
            if not select.select([output], [], [], 10)[0] or b'listening' not in output.readline():
                raise RuntimeError(f'traced Nexus failed to start; inspect {logpath}')
            children = Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text().split()
            if len(children) != 1: raise RuntimeError(f'expected one gdb inferior, found {children!r}')
            yield process
        finally:
            if process.poll() is None:
                children = Path(f'/proc/{process.pid}/task/{process.pid}/children').read_text().split()
                for child in children:
                    try: os.kill(int(child), signal.SIGTERM)
                    except ProcessLookupError: pass
                try: process.wait(timeout=8)
                except subprocess.TimeoutExpired:
                    process.kill(); process.wait()
            output.close()
            if process.returncode:
                raise RuntimeError(f'traced Nexus exit {process.returncode}; inspect {logpath}')
    markers = [line for line in Path(logpath).read_text(errors='replace').splitlines() if line.startswith('BRUTAL_INSTALL=')]
    if markers != [f'BRUTAL_INSTALL={expected_rate}']:
        raise RuntimeError(f'expected one Brutal installation at {expected_rate}, got {markers!r}; inspect {logpath}')
    print(markers[0], flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('binary', type=Path, help='Nexus CLI; ignored in --reference mode')
    parser.add_argument('peer', type=Path, help='independent quic-go H3 client')
    parser.add_argument('--family', choices=('4', '6'), default='4')
    parser.add_argument('--case', choices=('same', 'zero', 'changed', 'wrong', 'first-wrong'), default='zero')
    parser.add_argument('--first-rate', type=int, default=600000, help='client receive rate in first authentication')
    parser.add_argument('--second-status', type=int, default=233, help='use 404 to reproduce the older zero-rate defect')
    parser.add_argument('--assert-pacing', action='store_true', help='require server download pacing')
    parser.add_argument('--max-download-ms', type=int, default=0, help='optional maximum for retained-rate comparison')
    parser.add_argument('--reference', action='store_true', help='use fixed sing-box as server')
    parser.add_argument('--gdb-log', type=Path, help='count native controller installs via gdb')
    args = parser.parse_args()
    binary, peer = args.binary.resolve(strict=True), args.peer.resolve(strict=True)
    if not 100 <= args.second_status <= 599 or args.max_download_ms < 0 or args.first_rate < 0:
        parser.error('invalid status')
    if args.reference and args.gdb_log: parser.error('--gdb-log only applies to Nexus')
    if args.case != 'zero' and args.second_status != 233:
        parser.error('--second-status override is available only for zero')
    host = '127.0.0.1' if args.family == '4' else '::1'
    with tempfile.TemporaryDirectory(prefix='hy2-reauth-') as directory:
        root = Path(directory); certificate(root)
        password = root / 'password'; password.write_text('test-password\n'); password.chmod(0o600)
        port = udp_port(host)
        with socket.socket() as origin:
            origin.bind(('127.0.0.1', 0)); origin.listen(1); origin.settimeout(20)
            target = f'127.0.0.1:{origin.getsockname()[1]}'
            errors, count = [], []
            def serve():
                try:
                    with origin.accept()[0] as stream:
                        stream.settimeout(20); data = bytearray()
                        while chunk := stream.recv(65536): data.extend(chunk)
                        expected = bytes((i*71+37) & 255 for i in range(65536))
                        if data != expected: raise RuntimeError('origin received incorrect upload')
                        count.append(len(data)); stream.sendall(data); stream.shutdown(socket.SHUT_WR)
                except BaseException as error: errors.append(repr(error))
            thread = threading.Thread(target=serve, daemon=True); thread.start()
            second_rate = {'same': 600000, 'zero': 0, 'changed': 10000, 'wrong': 10000, 'first-wrong': 600000}[args.case]
            command = [str(peer), '-family', args.family, '-port', str(port), '-cert', str(root/'cert'),
                       '-target', target, '-size', '65536', '-first-rate', str(args.first_rate), '-second-rate', str(second_rate), '-second-status', str(args.second_status)]
            if args.case == 'wrong': command.extend(['-second-password', 'wrong-password'])
            if args.case == 'first-wrong': command.extend(['-first-password', 'wrong-password', '-first-status', '404'])
            if args.assert_pacing: command.append('-assert-pacing')
            if args.max_download_ms: command.extend(['-max-download-ms', str(args.max_download_ms)])
            process = None
            try:
                if args.reference:
                    version = subprocess.check_output(['sing-box', 'version'], text=True)
                    if f'Revision: {REVISION}' not in version: raise RuntimeError('unexpected sing-box revision')
                    config = root/'singbox.json'
                    config.write_text(json.dumps({'log': {'level': 'warn'},
                        'inbounds': [{'type': 'hysteria2', 'listen': host, 'listen_port': port,
                                      'users': [{'password': 'test-password'}], 'up_mbps': 3, 'down_mbps': 3,
                                      'ignore_client_bandwidth': True,
                                      'tls': {'enabled': True, 'certificate_path': str(root/'cert'), 'key_path': str(root/'key'), 'alpn': ['h3']}}],
                        'outbounds': [{'type': 'direct', 'tag': 'direct'}], 'route': {'final': 'direct'}}))
                    process = subprocess.Popen(['sing-box', 'run', '-c', str(config)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
                    time.sleep(.3)
                    if process.poll() is not None: raise RuntimeError(f'sing-box failed to start: {process.communicate()}')
                    done = subprocess.run(command, capture_output=True, text=True, timeout=25)
                else:
                    config = root/'nexus.kdl'
                    config.write_text(f'''schema-version 1
role "server"
workers 1
inbound "edge" type="hysteria2" {{ listen host="{host}" port={port};
 authentication {{ user "test" password-file="{password}"; }}
 tls {{ certificate-file "{root/'cert'}"; private-key-file "{root/'key'}"; }}
 quic {{ send-bps 40000; receive-bps 300000; ignore-client-bandwidth #true; }}
}}
outbound "direct" type="direct"
routing {{ default-outbound "direct"; }}
''')
                    selected_rate = min(40000, second_rate if args.case == 'first-wrong' else args.first_rate)
                    context = traced_nexus(binary, config, args.gdb_log.resolve(), selected_rate) if args.gdb_log else nexus_process(str(binary), str(config))
                    with context:
                        done = subprocess.run(command, capture_output=True, text=True, timeout=25)
                if done.returncode: raise RuntimeError(f'peer exit {done.returncode}: {done.stdout} {done.stderr}')
                thread.join(20)
                if thread.is_alive() or errors or count != [65536]:
                    raise RuntimeError(f'origin failed: active={thread.is_alive()} errors={errors} count={count}')
                print(f"{'sing-box' if args.reference else 'Nexus'} IPv{args.family} {args.case}: {done.stdout.strip()}", flush=True)
            finally:
                if process:
                    if process.poll() is None: process.terminate()
                    _, diagnostics = process.communicate(timeout=5)
                    if process.returncode: raise RuntimeError(f'sing-box exit {process.returncode}: {diagnostics!r}')


if __name__ == '__main__':
    main()
