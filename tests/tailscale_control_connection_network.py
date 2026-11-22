#!/usr/bin/env python3
"""Pinned controlbase peer: real TLS/Upgrade/Noise/H2, backpressure and shutdown."""
import argparse
import contextlib
import hashlib
import json
from pathlib import Path
import select
import socket
import subprocess
import tempfile
import threading
import time


@contextlib.contextmanager
def slow_relay(port):
    listener = socket.socket()
    listener.bind(('127.0.0.1', 0))
    listener.listen()
    listener.settimeout(8)
    state = {'directions': [{'bytes': 0, 'eof': False, 'error': None} for _ in range(2)]}
    sockets = []
    def transfer(source, target, index):
        try:
            while True:
                data = source.recv(4096)
                if not data:
                    state['directions'][index]['eof'] = True
                    target.shutdown(socket.SHUT_WR)
                    break
                time.sleep(.002)
                target.sendall(data)
                state['directions'][index]['bytes'] += len(data)
        except OSError as error:
            state['directions'][index]['error'] = str(error)
    def accept():
        try:
            incoming, _ = listener.accept()
            outgoing = socket.create_connection(('127.0.0.1', port), timeout=8)
            incoming.settimeout(8)
            sockets.extend((incoming, outgoing))
            threads = [threading.Thread(target=transfer, args=(a, b, i), daemon=True)
                       for a, b, i in ((incoming, outgoing, 0), (outgoing, incoming, 1))]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(9)
        except OSError as error:
            state['accept_error'] = str(error)
    thread = threading.Thread(target=accept, daemon=True)
    thread.start()
    try:
        yield listener.getsockname()[1], state, thread
    finally:
        for connection in sockets:
            with contextlib.suppress(OSError):
                connection.close()
        listener.close()
        thread.join(1)


class Runner:
    def __init__(self, args):
        self.args = args
        self.records = []
        self.complete = False
        self.root = Path(tempfile.mkdtemp(prefix='nexus-ts-control-'))
        for prefix in ('', 'untrusted-'):
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'ec', '-pkeyopt',
                'ec_paramgen_curve:P-256', '-nodes', '-keyout', self.root / (prefix+'key'),
                '-out', self.root / (prefix+'cert'), '-subj', '/CN=localhost',
                '-addext', 'subjectAltName=DNS:localhost', '-days', '1'],
                check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            (self.root / (prefix+'key')).chmod(0o600)
    def save(self):
        self.args.evidence.parent.mkdir(parents=True, exist_ok=True)
        self.args.evidence.write_text(json.dumps({'complete': self.complete,
            'peer_sha256': hashlib.sha256(self.args.peer.read_bytes()).hexdigest(),
            'fixtures': {name: {'path': str(path), 'sha256': hashlib.sha256(path.read_bytes()).hexdigest()}
                for name in ('fixture', 'startup', 'lifecycle', 'layered', 'resources')
                if (path := getattr(self.args, name)) is not None},
            'driver_sha256': hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            'artifacts': str(self.root), 'runs': self.records}, indent=2)+'\n')
    @contextlib.contextmanager
    def peer(self, early=False, tls=True, extra=()):
        argv = [str(self.args.peer)] + (['--early'] if early else [])
        if tls:
            argv += ['--cert', str(self.root/'cert'), '--key', str(self.root/'key')]
        argv += list(map(str, extra))
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        try:
            if not select.select([process.stdout], [], [], 8)[0]:
                raise RuntimeError('peer did not announce readiness')
            ready = json.loads(process.stdout.readline())
            yield ready, argv
        finally:
            if process.poll() is None:
                process.terminate()
            process.communicate(timeout=5)
    def run(self, label, binary, arguments, peer_argv, marker, timeout=12):
        argv = [str(binary), *map(str, arguments)]
        began = time.monotonic()
        result = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        record = {'label': label, 'argv': argv, 'peer_argv': peer_argv,
            'exit_code': result.returncode, 'stdout': result.stdout, 'stderr': result.stderr,
            'elapsed_seconds': time.monotonic()-began}
        self.records.append(record)
        self.save()
        if result.returncode or marker not in result.stdout:
            raise RuntimeError(json.dumps(record, indent=2))
        print(label+' passed', flush=True)
        return record
    def startup(self):
        binary = self.args.startup
        if binary is None:
            raise ValueError('--startup required')
        def trial(backend, tls, early, limit=4096, mode='ok', extra=(), bad_pin=False,
                  ca='cert', name='localhost', budget=3000):
            with self.peer(early, tls, extra) as (ready, peer):
                pin = ready['control']
                if bad_pin:
                    pin = ('0' if pin[0]!='0' else '1')+pin[1:]
                record = self.run(f'startup/{backend}/{tls}/{early}/{limit}/{mode}/{name}', binary,
                    [ready['port'], pin, backend, int(early), limit, mode, budget,
                     self.root/ca if tls else '-', name], peer, 'control-startup-passed')
                if mode=='timeout' and record['elapsed_seconds']>1:
                    raise RuntimeError('absolute startup budget was exceeded')
        for backend in (0, 1):
            for tls in (False, True):
                for early in (False, True):
                    for limit in (1, 3, 4096):
                        trial(backend, tls, early, limit)
                trial(backend, tls, False, mode='http', extra=['--reject-http'])
                trial(backend, tls, False, mode='reject', bad_pin=True)
                trial(backend, tls, False, mode='timeout', extra=['--header-delay', '400ms'], budget=300)
                trial(backend, tls, True, mode='timeout', extra=['--noise-delay', '400ms'], budget=300)
            for early in (False, True):
                trial(backend, True, early, mode='coalesced', extra=['--coalesce'])
            trial(backend, True, False, mode='tls', name='wrong.example')
            trial(backend, True, False, mode='tls', ca='untrusted-cert')
    def application(self, suite):
        binary = getattr(self.args, suite) if suite in ('layered', 'resources') else self.args.fixture
        if binary is None:
            raise ValueError('--'+suite+' fixture required')
        for backend in (0, 1):
            for early in (False, True):
                modes = ('parallel', 'rst', 'limit', 'truncated') if suite=='parallel' else ('basic',)
                for mode in modes:
                    for coalesce in ((False, True) if suite=='sequential' else (False,)):
                        extra = ['--coalesce'] if coalesce else []
                        if suite=='parallel':
                            extra += ['--map-bytes', str(4194305 if mode=='limit' else 786432)]
                            if mode=='truncated':
                                extra += ['--truncate-map']
                        with self.peer(early, extra=extra) as (ready, peer):
                            self.run(f'{suite}/{backend}/{early}/{mode}/{coalesce}', binary,
                                [ready['port'], ready['control'], backend, self.root/'cert', int(early), mode],
                                peer, 'control-connection-passed')
    def lifecycle(self):
        if self.args.lifecycle is None:
            raise ValueError('--lifecycle required')
        for backend in (0, 1):
            for mode in ('start-cancel', 'start-abandon', 'upload-cancel', 'upload-abandon'):
                extra = ['--header-delay', '5s'] if mode.startswith('start') else ['--upload-window', '4096', '--register-hold', '5s']
                with self.peer(extra=extra) as (ready, peer):
                    self.run(f'lifecycle/{backend}/{mode}', self.args.lifecycle,
                        [ready['port'], ready['control'], backend, self.root/'cert', mode],
                        peer, 'control-connection-lifecycle-passed')
    def shutdown(self):
        for backend in (0, 1):
            for early in (False, True):
                for mode in ('basic', 'parallel'):
                    audit = self.root/f'wire-{backend}-{int(early)}-{mode}.json'
                    extra = ['--audit', str(audit)] + (['--map-bytes', '786432'] if mode=='parallel' else [])
                    with self.peer(early, extra=extra) as (ready, peer):
                        with slow_relay(ready['port']) as (port, relay, thread):
                            record = self.run(f'shutdown/{backend}/{early}/{mode}', self.args.fixture,
                                [port, ready['control'], backend, self.root/'cert', int(early), mode],
                                peer, 'control-connection-passed')
                            thread.join(2)
                            end = time.monotonic()+2
                            while not audit.exists() and time.monotonic()<end:
                                time.sleep(.01)
                            wire = json.loads(audit.read_text())
                            record.update(wire=wire, relay=relay)
                            self.save()
                            clean = wire['h2_preface'] and wire['h2_request_ends']==(4 if mode=='parallel' else 3)
                            clean = clean and wire['h2_goaway'] and wire['h2_goaway_code']==0
                            clean = clean and not any(wire[key] for key in ('h2_partial', 'raw_tls_partial', 'overflow', 'tls_decrypt_errors'))
                            clean = clean and wire['noise_eof'] and not wire.get('noise_read_error')
                            clean = clean and wire['tls_close_notify'] and wire['tls_application_records']>0
                            if not clean or any(not d['eof'] or d['error'] for d in relay['directions']):
                                raise RuntimeError(json.dumps(record, indent=2))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture', type=Path)
    parser.add_argument('--peer', type=Path, required=True)
    parser.add_argument('--startup', type=Path)
    parser.add_argument('--lifecycle', type=Path)
    parser.add_argument('--layered', type=Path)
    parser.add_argument('--resources', type=Path)
    parser.add_argument('--evidence', type=Path, required=True)
    parser.add_argument('--suites', default='startup,sequential,parallel,lifecycle,shutdown')
    args = parser.parse_args()
    for name in ('fixture', 'peer', 'startup', 'lifecycle', 'layered', 'resources'):
        if (value := getattr(args, name)) is not None:
            setattr(args, name, value.resolve(strict=True))
    runner = Runner(args)
    try:
        for suite in args.suites.split(','):
            if suite in ('startup', 'lifecycle', 'shutdown'):
                getattr(runner, suite)()
            elif suite in ('sequential', 'parallel', 'layered', 'resources'):
                runner.application(suite)
            else:
                raise ValueError('unknown suite '+suite)
        runner.complete = True
    finally:
        runner.save()


if __name__ == '__main__':
    main()
