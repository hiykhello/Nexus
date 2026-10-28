#!/usr/bin/env python3
"""Isolated SQLite transaction probe; not a production state backend."""
import signal
import select
import sqlite3
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def connect(path):
    db = sqlite3.connect(path, timeout=0, isolation_level=None)
    assert db.execute('PRAGMA journal_mode=WAL').fetchone()[0] == 'wal'
    db.execute('PRAGMA synchronous=FULL')
    assert db.execute('PRAGMA synchronous').fetchone()[0] == 2
    return db


def child(path, stage):
    db = connect(path)
    db.execute('BEGIN IMMEDIATE')
    db.execute('UPDATE state SET snapshot=?, watermark=? WHERE id=1', (b'new', 1060))
    if stage == 'committed':
        db.execute('COMMIT')
    print('ready', flush=True)
    signal.pause()


def state(path):
    db = connect(path)
    try:
        return db.execute('SELECT snapshot,watermark FROM state WHERE id=1').fetchone()
    finally:
        db.close()


def kill_at(path, stage):
    proc = subprocess.Popen([sys.executable, __file__, 'child', str(path), stage],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        if not select.select([proc.stdout], [], [], 5)[0]:
            raise TimeoutError('writer did not reach crash point')
        if proc.stdout.readline().strip() != 'ready':
            raise RuntimeError('writer exited before crash point')
        if stage == 'uncommitted':
            other = connect(path)
            try:
                try:
                    other.execute('BEGIN IMMEDIATE')
                    raise AssertionError('other process acquired writer lock')
                except sqlite3.OperationalError as error:
                    assert error.sqlite_errorcode == sqlite3.SQLITE_BUSY, error
            finally:
                other.close()
        proc.kill()
        proc.wait(timeout=5)
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait()


def main():
    if len(sys.argv) > 1:
        child(Path(sys.argv[2]), sys.argv[3])
        return
    with tempfile.TemporaryDirectory(prefix='nexus-sqlite-probe-') as tmp:
        path = Path(tmp) / 'state.db'
        db = connect(path)
        db.execute('CREATE TABLE state(id INTEGER PRIMARY KEY, snapshot BLOB NOT NULL, watermark INTEGER NOT NULL)')
        db.execute('INSERT INTO state VALUES(1,?,?)', (b'old', 1000))
        db.close()
        kill_at(path, 'uncommitted')
        assert state(path) == (b'old', 1000), 'uncommitted transaction survived'
        kill_at(path, 'committed')
        assert state(path) == (b'new', 1060), 'committed transaction lost'
        first, second = connect(path), connect(path)
        try:
            first.execute('BEGIN IMMEDIATE')
            try:
                second.execute('BEGIN IMMEDIATE')
                raise AssertionError('concurrent writer acquired transaction')
            except sqlite3.OperationalError as error:
                assert error.sqlite_errorcode == sqlite3.SQLITE_BUSY, error
            first.execute('ROLLBACK')
            second.execute('BEGIN IMMEDIATE')
            second.execute('UPDATE state SET watermark=watermark+1')
            second.execute('ROLLBACK')
            assert state(path) == (b'new', 1060), 'rollback changed state'
        finally:
            first.close()
            second.close()
        db = connect(path)
        start = time.monotonic()
        for _ in range(100):
            db.execute('BEGIN IMMEDIATE')
            db.execute('UPDATE state SET watermark=watermark+1')
            db.execute('COMMIT')
        elapsed = time.monotonic() - start
        print(f'SQLite {sqlite3.sqlite_version}: crash, atomicity, busy and rollback passed; '
              f'100 FULL WAL commits: {elapsed:.3f}s')
        db.close()


if __name__ == '__main__':
    main()
