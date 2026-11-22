#!/usr/bin/env python3
"""Real local search candidate is retained across evaluations and families."""
import pathlib
import subprocess
import sys
import tempfile
from dns_rule_support import DnsPeer

binary = pathlib.Path(sys.argv[1]).resolve()
if '--inside' not in sys.argv:
    subprocess.run(['unshare', '-Urn', sys.executable, __file__, str(binary), '--inside'], check=True)
    sys.exit(0)
subprocess.run(['ip', 'link', 'set', 'lo', 'up'], check=True)
with tempfile.TemporaryDirectory(prefix='nexus-race-local-') as directory, DnsPeer() as peer:
    peer.no_data.update({('short.one.test', 1), ('short.one.test', 28)})
    resolv = pathlib.Path(directory) / 'resolv'
    resolv.write_text('nameserver 127.0.0.2\nsearch one.test two.test\noptions timeout:1 attempts:1\n')
    with DnsPeer(host='127.0.0.2', port=53) as tcp_peer:
        tcp_peer.no_data.update({('short.one.test', 1), ('short.one.test', 28)})
        for backend in ('epoll', 'uring'):
            for kind, active in (('udp', peer), ('tcp', tcp_peer)):
                active.seen.clear()
                result = subprocess.run([str(binary), backend, kind, str(peer.port), str(resolv)], capture_output=True, timeout=8)
                if result.returncode == 77:
                    print(f'{backend}: unavailable'); break
                seen = [(name, qtype) for name, qtype, _ in active.seen]
                # Repeated evaluates share the response cache. TCP searches
                # both families for each candidate; the UDP fixture calls
                # the per-family entry directly and reuses its first candidate.
                expected = ([('short.one.test', 1), ('short.two.test', 1), ('short.two.test', 28)] if kind == 'udp' else
                            [('short.one.test', 1), ('short.one.test', 28), ('short.two.test', 1), ('short.two.test', 28)])
                if result.returncode or seen != expected:
                    raise RuntimeError(f'{backend}/{kind}: exit={result.returncode} stderr={result.stderr!r} seen={seen!r}')
                print(f'{backend}/{kind}: local search candidate retained across evaluates and families')
