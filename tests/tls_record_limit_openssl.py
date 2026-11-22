#!/usr/bin/env python3
"""Authenticated TLS 1.3 negotiation against a separate OpenSSL custom-extension peer."""
import argparse
import pathlib
import socket
import subprocess
import tempfile

parser=argparse.ArgumentParser()
parser.add_argument('client',type=pathlib.Path)
parser.add_argument('server',type=pathlib.Path)
args=parser.parse_args();client=args.client.resolve();server=args.server.resolve()
with tempfile.TemporaryDirectory(prefix='nexus-record-limit-') as directory:
    root=pathlib.Path(directory);cert=root/'cert.pem';key=root/'key.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),
                    '-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],check=True,capture_output=True)
    for mode in ('valid','overflow','invalid'):
        a,b=socket.socketpair()
        with a,b:
            peer=subprocess.Popen([str(server),str(cert),str(key),mode],stdin=a,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            candidate=subprocess.Popen([str(client),str(cert),mode],stdin=b,stdout=b,stderr=subprocess.PIPE)
            a.close();b.close()
            try:
                _,client_err=candidate.communicate(timeout=15);_,peer_err=peer.communicate(timeout=15)
            except subprocess.TimeoutExpired:
                candidate.kill();peer.kill();candidate.communicate();peer.communicate();raise
            if candidate.returncode or peer.returncode:
                raise RuntimeError(f'{mode}: client={candidate.returncode} {client_err!r}, peer={peer.returncode} {peer_err!r}')
            print(f'{mode}: '+('OpenSSL decrypted fatal '+('record_overflow' if mode=='overflow' else 'illegal_parameter') if mode!='valid' else 'authenticated TLS, fragmented bidirectional traffic and close'),flush=True)
