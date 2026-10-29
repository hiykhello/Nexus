#!/usr/bin/env python3
"""Exercise numeric UDP ASSOCIATE through a real SOCKS server."""
import pathlib
import socket
import subprocess
import sys
import time

server = str(pathlib.Path(sys.argv[1]).resolve())
with socket.socket() as reserve:
    reserve.bind(('127.0.0.1', 0))
    port = reserve.getsockname()[1]
proc = subprocess.Popen([server, 'run', str(port)], stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
try:
    deadline = time.monotonic() + 8
    while True:
        try:
            control = socket.create_connection(('127.0.0.1', port), timeout=.2)
            break
        except OSError:
            if proc.poll() is not None or time.monotonic() >= deadline:
                raise RuntimeError('proxy did not start')
            time.sleep(.02)
    with control, socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as client, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as upstream, \
            socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as attacker:
        control.settimeout(3); client.settimeout(3); upstream.settimeout(3)
        client.bind(('127.0.0.1', 0)); upstream.bind(('127.0.0.1', 0)); attacker.bind(('127.0.0.1', 0))
        control.sendall(b'\x05\x01\x00')
        if control.recv(2) != b'\x05\x00': raise RuntimeError('greeting')
        control.sendall(b'\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00')
        response = b''
        while len(response) < 10:
            part = control.recv(10-len(response))
            if not part: raise RuntimeError('association closed early')
            response += part
        if response[:4] != b'\x05\x00\x00\x01': raise RuntimeError(f'association: {response!r}')
        relay = (socket.inet_ntoa(response[4:8]), int.from_bytes(response[8:10], 'big'))
        dest = upstream.getsockname()
        wire = b'\x00\x00\x00\x01' + socket.inet_aton(dest[0]) + dest[1].to_bytes(2,'big') + b'hello'
        client.sendto(wire, relay)
        data, source = upstream.recvfrom(100)
        if data != b'hello': raise RuntimeError('bad forwarded payload')
        upstream_source = source
        attacker.sendto(wire, relay)
        upstream.sendto(b'world', source)
        reply, source = client.recvfrom(100)
        if reply != wire[:-5] + b'world' or source != relay: raise RuntimeError(f'bad reply {reply!r} {source!r}')
        upstream.settimeout(.15)
        try:
            upstream.recvfrom(100)
            raise RuntimeError('other client port forwarded')
        except socket.timeout:
            pass
        upstream.settimeout(3)
        name = b'127.0.0.1'
        domain_wire = b'\x00\x00\x00\x03' + bytes([len(name)]) + name + dest[1].to_bytes(2, 'big') + b'domain'
        client.sendto(domain_wire, relay)
        data, domain_source = upstream.recvfrom(100)
        if data != b'domain' or domain_source != upstream_source: raise RuntimeError('system resolution failed')
        upstream.sendto(b'resolved', domain_source)
        reply, reply_source = client.recvfrom(100)
        if reply != wire[:-5] + b'resolved' or reply_source != relay: raise RuntimeError('resolved reply failed')
        # A burst should not be limited to one packet per 5 ms timer tick.
        header = wire[:-5]
        count = 200
        start = time.monotonic()
        for i in range(count):
            client.sendto(header + i.to_bytes(2, 'big'), relay)
        for i in range(count):
            data, source = upstream.recvfrom(100)
            if data != i.to_bytes(2, 'big') or source != upstream_source:
                raise RuntimeError('burst input was lost or reordered')
        if time.monotonic() - start >= .8:
            raise RuntimeError('burst input was limited by the polling interval')
        start = time.monotonic()
        for i in range(count):
            upstream.sendto(i.to_bytes(2, 'big'), upstream_source)
        for i in range(count):
            data, source = client.recvfrom(100)
            if data != header + i.to_bytes(2, 'big') or source != relay:
                raise RuntimeError('burst reply was lost or reordered')
        if time.monotonic() - start >= .8:
            raise RuntimeError('burst replies were limited by the polling interval')
        unspecified = b'\x00\x00\x00\x04' + bytes(10) + b'\xff\xff' + bytes(4) + dest[1].to_bytes(2, 'big') + b'invalid'
        client.sendto(unspecified, relay)
        upstream.settimeout(.2)
        try:
            data, _ = upstream.recvfrom(100)
            raise RuntimeError(f'mapped unspecified target forwarded: {data!r}')
        except socket.timeout:
            pass
        control.close()
        deadline = time.monotonic()+3
        while True:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
                try:
                    probe.bind(relay)
                    break
                except OSError:
                    if time.monotonic()>=deadline: raise RuntimeError('relay not released')
                    time.sleep(.01)
    print('SOCKS UDP control, numeric relay, source filter and close passed')
finally:
    proc.terminate()
    try: proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill(); proc.wait()
