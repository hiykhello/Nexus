"""Load an isolated local DNS configuration snapshot from real files."""
import pathlib
import os
import subprocess
import sys
import tempfile

client = pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory(prefix='nexus-local-dns-snapshot-') as directory:
    path = pathlib.Path(directory)
    (path/'resolv.conf').write_text('nameserver 127.0.0.53\nsearch .\n')
    (path/'hosts').write_text('127.0.0.1 Example.Test\n')
    subprocess.run([client, path/'resolv.conf', path/'hosts'], check=True)
    subprocess.run([client, '--watch', path/'resolv.conf', path/'hosts'], check=True, timeout=8)
    (path/'hosts').write_bytes(b'x'*(1024*1024+1))
    if subprocess.run([client, path/'resolv.conf', path/'hosts']).returncode == 0:
        raise RuntimeError('oversized hosts file accepted')
    (path/'hosts').unlink(); os.mkfifo(path/'hosts')
    if subprocess.run([client, path/'resolv.conf', path/'hosts'],timeout=2).returncode == 0:
        raise RuntimeError('FIFO hosts file accepted')
print('local DNS snapshot file loading and size limit passed')
