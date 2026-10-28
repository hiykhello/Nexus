#!/usr/bin/env python3
import select
import hashlib
import hmac
import os
import subprocess
import sys
import tempfile
from pathlib import Path

if len(sys.argv) not in (2, 3) or (len(sys.argv) == 3 and sys.argv[2] != 'aes256'):
    raise SystemExit('usage: probe.py <nexus-beve-snapshot-experiment> [aes256]')
binary = sys.argv[1]
secret = b'B' * 32
instance = b'I' * 16
proxy_key = bytes(range(32 if len(sys.argv) == 3 else 16))
prk = hmac.digest(b'nexus/beve-snapshot/v1', secret, hashlib.sha256)
key = hmac.digest(prk, instance + bytes([len(proxy_key)]) + proxy_key + b'\x01', hashlib.sha256)

def setup(directory, secret_value=secret, instance_value=instance, proxy_value=proxy_key):
    directory.mkdir(mode=0o700)
    for name, value in (('auth.key', secret_value), ('instance.id', instance_value), ('proxy.key', proxy_value)):
        fd = os.open(directory / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, 'wb') as out:
            out.write(value)

def frame(payload):
    content = b'NXB1' + payload
    return content + hmac.digest(key, content, hashlib.sha256)

with tempfile.TemporaryDirectory(prefix='nexus-beve-snapshot-') as root:
    root = Path(root)
    sessions = root / 'sessions'
    setup(sessions)
    subprocess.run([binary, str(sessions), 'session'], check=True, timeout=15)
    invalid = root / 'invalid-key'
    setup(invalid)
    (invalid / 'auth.key').chmod(0o644)
    if subprocess.run([binary, str(invalid), 'init'], timeout=10).returncode != 39:
        raise AssertionError('insecure key permissions accepted')
    (invalid / 'auth.key').unlink()
    (invalid / 'auth.key').symlink_to(sessions / 'auth.key')
    if subprocess.run([binary, str(invalid), 'init'], timeout=10).returncode != 39:
        raise AssertionError('key symlink accepted')
    for length in (0, 15, 17, 31, 33):
        invalid_length = root / f'invalid-length-{length}'
        setup(invalid_length, proxy_value=b'P' * length)
        if subprocess.run([binary, str(invalid_length), 'init'], timeout=10).returncode != 39:
            raise AssertionError(f'proxy key length {length} accepted')
    for stage in ('before-rename', 'after-rename', 'after-sync'):
        directory = root / ('id-' + stage)
        setup(directory)
        subprocess.run([binary, str(directory), 'id-init'], check=True, timeout=10)
        process = subprocess.Popen([binary, str(directory), 'id-' + stage], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            if not select.select([process.stdout], [], [], 10)[0] or process.stdout.readline().strip() != 'ready':
                raise RuntimeError(f'ID writer failed to reach {stage}')
            process.kill()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        expected = 'id-verify-old' if stage == 'before-rename' else 'id-verify-new'
        subprocess.run([binary, str(directory), expected], check=True, timeout=10)
    directory = root / 'id-ambiguous'
    setup(directory)
    subprocess.run([binary, str(directory), 'id-init'], check=True, timeout=10)
    subprocess.run([binary, str(directory), 'id-ambiguous'], check=True, timeout=10)
    subprocess.run([binary, str(directory), 'id-verify-new'], check=True, timeout=10)
    for kind in ('session', 'id'):
        for stage in ('write', 'file-sync', 'rename', 'dir-sync'):
            directory = root / f'{kind}-fail-{stage}'
            setup(directory)
            subprocess.run([binary, str(directory), f'{kind}-init'], check=True, timeout=10)
            subprocess.run([binary, str(directory), f'{kind}-fail-{stage}'], check=True, timeout=10)
            expected = 'new' if stage == 'dir-sync' else 'old'
            subprocess.run([binary, str(directory), f'{kind}-verify-{expected}'], check=True, timeout=10)
    for stage in ('before-rename', 'after-rename', 'after-sync'):
        directory = root / ('session-' + stage)
        setup(directory)
        subprocess.run([binary, str(directory), 'session-init'], check=True, timeout=10)
        process = subprocess.Popen([binary, str(directory), 'session-' + stage], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            if not select.select([process.stdout], [], [], 10)[0] or process.stdout.readline().strip() != 'ready':
                raise RuntimeError(f'session writer failed to reach {stage}')
            process.kill()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        expected = 'session-verify-old' if stage == 'before-rename' else 'session-verify-new'
        subprocess.run([binary, str(directory), expected], check=True, timeout=10)
    for stage in ('before-rename', 'after-rename', 'after-sync'):
        directory = root / stage
        setup(directory)
        subprocess.run([binary, str(directory), 'init'], check=True, timeout=10)
        process = subprocess.Popen([binary, str(directory), stage], stdout=subprocess.PIPE,
                                   stderr=subprocess.PIPE, text=True)
        try:
            if not select.select([process.stdout], [], [], 10)[0] or process.stdout.readline().strip() != 'ready':
                raise RuntimeError(f'writer failed to reach {stage}')
            process.kill()
            process.wait(timeout=5)
        finally:
            if process.poll() is None:
                process.kill()
                process.wait()
        expected = 'verify-old' if stage == 'before-rename' else 'verify-new'
        subprocess.run([binary, str(directory), expected], check=True, timeout=10)
        if stage == 'before-rename':
            subprocess.run([binary, str(directory), 'update'], check=True, timeout=10)
            subprocess.run([binary, str(directory), 'verify-new'], check=True, timeout=10)
        state = directory / 'state.beve'
        raw = state.read_bytes()
        if secret in raw or proxy_key in raw:
            raise AssertionError('key material appeared in snapshot')
        for name, secret_value, identity, proxy in (('different-key', b'C' * 32, instance, proxy_key),
                                                    ('different-instance', secret, b'J' * 16, proxy_key),
                                                    ('different-proxy-key', secret, instance, b'P' * len(proxy_key)),
                                                    ('different-key-length', secret, instance,
                                                     bytes(range(16 if len(proxy_key) == 32 else 32)))):
            other = root / (stage + '-' + name)
            setup(other, secret_value, identity, proxy)
            (other / 'state.beve').write_bytes(raw)
            if subprocess.run([binary, str(other), 'verify-new'], timeout=10).returncode == 0:
                raise AssertionError(f'{name} accepted snapshot')
        if not raw.startswith(b'NXB1') or len(raw) <= 36:
            raise AssertionError('unexpected authenticated envelope')
        damaged = bytearray(raw)
        damaged[10] ^= 1
        state.write_bytes(damaged)
        if subprocess.run([binary, str(directory), 'verify-new'], timeout=10).returncode == 0:
            raise AssertionError('modified payload accepted')
        damaged = bytearray(raw)
        damaged[-1] ^= 1
        state.write_bytes(damaged)
        if subprocess.run([binary, str(directory), 'verify-new'], timeout=10).returncode == 0:
            raise AssertionError('modified MAC accepted')
        state.write_bytes(raw[:-32] + hmac.digest(b'C' * 32, raw[:-32], hashlib.sha256))
        if subprocess.run([binary, str(directory), 'verify-new'], timeout=10).returncode == 0:
            raise AssertionError('wrong key accepted')
        original = raw[4:-32]
        flag = b'\x30id_exhausted\x08'
        if original.count(flag) != 1:
            raise AssertionError('unexpected exhausted flag')
        state.write_bytes(frame(original.replace(flag, b'\x30id_exhausted\x18', 1)))
        subprocess.run([binary, str(directory), 'verify-new'], check=True, timeout=10)
        if not original.startswith(b'\x03\x14'):
            raise AssertionError('unexpected top-level BEVE shape')
        # Duplicate a valid top-level wall field; missing/unknown-key checks
        # alone do not reliably reject repeated keys.
        duplicate = b'\x03\x18' + original[2:] + b'\x10wall\x71' + (1060).to_bytes(8, 'little')
        state.write_bytes(frame(duplicate))
        if subprocess.run([binary, str(directory), 'verify-new'], timeout=10).returncode == 0:
            raise AssertionError('duplicate top-level field accepted')
        marker = b'\x03\x08\x08id\x14\x20'
        if original.count(marker) != 1:
            raise AssertionError('unexpected entry BEVE shape')
        duplicate = original.replace(marker, b'\x03\x0c\x08id\x14\x20', 1) + b'\x08id\x14\x20' + bytes(8)
        state.write_bytes(frame(duplicate))
        if subprocess.run([binary, str(directory), 'verify-new'], timeout=10).returncode == 0:
            raise AssertionError('duplicate session field accepted')
        state.write_bytes(raw[:-1])
        if subprocess.run([binary, str(directory), 'verify-new'], timeout=10).returncode == 0:
            raise AssertionError('truncated snapshot accepted')
    print('BEVE multi-session, storage failures, crash recovery, ambiguous commit and truncation passed')
