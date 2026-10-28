#!/usr/bin/env python3
"""Build and test the experimental local lock using isolated processes."""
import errno
import os
import select
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent


def start(binary, directory):
    proc = subprocess.Popen([binary, directory], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.PIPE, text=True)
    if not select.select([proc.stdout], [], [], 5)[0]:
        proc.kill()
        proc.wait()
        raise TimeoutError('owner fixture did not respond')
    return proc, proc.stdout.readline().strip()


def denied(binary, directory, expected):
    proc, result = start(binary, directory)
    try:
        assert proc.wait(timeout=5) == 1 and result == f'error {expected}', result
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def main():
    with tempfile.TemporaryDirectory(prefix='nexus-owner-') as root:
        root = Path(root)
        binary, directory = root / 'fixture', root / 'state'
        subprocess.run(['g++', '-std=c++26', '-Wall', '-Wextra', '-Werror',
                        str(HERE / 'fixture.cpp'), '-o', str(binary)], check=True)
        directory.mkdir(mode=0o700)
        proc, result = start(binary, directory)
        try:
            assert result == 'acquired'
            denied(binary, directory, errno.EWOULDBLOCK)
            proc.kill()
            proc.wait(timeout=5)
            successor, result = start(binary, directory)
            try:
                assert result == 'acquired'
                denied(binary, directory, errno.EWOULDBLOCK)
            finally:
                successor.stdin.close()
                assert successor.wait(timeout=5) == 0
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
        # Replacing the path cannot redirect operations made through the
        # directory descriptor owned by the original lock holder.
        holder, result = start(binary, directory)
        assert result == 'acquired'
        moved = root / 'moved-state'
        try:
            directory.rename(moved)
            directory.mkdir(mode=0o700)
            holder.stdin.write('w')
            holder.stdin.close()
            assert holder.wait(timeout=5) == 0
            assert (moved / 'marker').is_file()
            assert not (directory / 'marker').exists()
        finally:
            if holder.poll() is None:
                holder.kill()
                holder.wait()
            directory.rmdir()
            moved.rename(directory)
        lock = directory / 'owner.lock'
        # A same-user actor can replace the inode: this deliberately shows
        # why stable directory ownership is a prerequisite, not a guarantee.
        first, result = start(binary, directory)
        assert result == 'acquired'
        try:
            lock.unlink()
            replacement, result = start(binary, directory)
            try:
                assert result == 'acquired'
            finally:
                replacement.stdin.close()
                assert replacement.wait(timeout=5) == 0
        finally:
            first.stdin.close()
            assert first.wait(timeout=5) == 0
        lock.chmod(0o644)
        denied(binary, directory, errno.EACCES)
        lock.chmod(0o600)
        link = directory / 'other'
        os.link(lock, link)
        denied(binary, directory, errno.EACCES)
        link.unlink()
        lock.unlink()
        lock.symlink_to(root / 'target')
        denied(binary, directory, errno.ELOOP)
        lock.unlink()
        directory.chmod(0o755)
        denied(binary, directory, errno.EACCES)
        directory.chmod(0o700)
        (root / 'symlink').symlink_to(directory, target_is_directory=True)
        denied(binary, root / 'symlink', errno.ENOTDIR)
        print('local owner lock: contention, SIGKILL recovery, path checks and replacement limitation passed')


if __name__ == '__main__':
    main()
