#!/usr/bin/env python3
"""Real Linux TCP/UDP/ICMP over Nexus TUN and two official wireguard-go TUNs.

All addresses, devices, veth links and routes live in disposable user/network
namespaces. No relay replaces the shared Nexus UDP socket.
"""
import argparse
import json
import os
import pathlib
import select
import socket
import subprocess
import sys
import tempfile
import threading
import time

import wireguard_network as common
import wireguard_port_network as port_common

SOURCE = r'''package main
import (
 "bufio"
 "bytes"
 "crypto/ecdh"
 "crypto/rand"
 "encoding/hex"
 "encoding/json"
 "fmt"
 "io"
 "net"
 "os"
 "strconv"
 "strings"
 "sync/atomic"
 "time"
 "golang.zx2c4.com/wireguard/conn"
 "golang.zx2c4.com/wireguard/device"
 "golang.zx2c4.com/wireguard/tun"
)
var paused atomic.Bool
func announce(value any) { encoded,err:=json.Marshal(value); if err!=nil { panic(err) }; fmt.Println(string(encoded)) }
func addresses(node int) []string { return []string{fmt.Sprintf("10.42.0.%d",node),fmt.Sprintf("fd42::%d",node)} }
func services(node int) {
 for _,host:=range addresses(node) {
  listener,err:=net.Listen("tcp",net.JoinHostPort(host,"22222")); if err!=nil { panic(err) }
  go func(){ for { peer,err:=listener.Accept(); if err!=nil { return }; go func(c net.Conn) {
   defer c.Close(); c.SetDeadline(time.Now().Add(45*time.Second)); tcp:=c.(*net.TCPConn); tcp.SetReadBuffer(4096)
   for paused.Load() { time.Sleep(time.Millisecond) }
   data,err:=io.ReadAll(c); if err!=nil { return }; if n,err:=c.Write(data); err!=nil || n!=len(data) { return }; tcp.CloseWrite()
  }(peer) } }()
  address,err:=net.ResolveUDPAddr("udp",net.JoinHostPort(host,"22223")); if err!=nil { panic(err) }
  udp,err:=net.ListenUDP("udp",address); if err!=nil { panic(err) }
  go func(){ buffer:=make([]byte,2048); for { n,source,err:=udp.ReadFromUDP(buffer); if err!=nil { return }; if _,err=udp.WriteToUDP(buffer[:n],source); err!=nil { return } } }()
 }
}
func probe(node int) {
 for family,host:=range addresses(1) {
  data:=bytes.Repeat([]byte{byte(node),byte(family),0,255},16384)
  connection,err:=net.DialTimeout("tcp",net.JoinHostPort(host,"22222"),10*time.Second); if err!=nil { panic(err) }
  connection.SetDeadline(time.Now().Add(15*time.Second)); if n,err:=connection.Write(data); err!=nil || n!=len(data) { panic("TCP write") }
  connection.(*net.TCPConn).CloseWrite(); got,err:=io.ReadAll(connection); connection.Close(); if err!=nil || !bytes.Equal(got,data) { panic("TCP echo/half close") }
  udp,err:=net.DialTimeout("udp",net.JoinHostPort(host,"22223"),time.Second); if err!=nil { panic(err) }; udp.SetDeadline(time.Now().Add(10*time.Second))
  for _,size:=range []int{0,1,63,512,1372} {
   payload:=make([]byte,size); for i:=range payload { payload[i]=byte(i+node+family) }
   if n,err:=udp.Write(payload); err!=nil || n!=len(payload) { panic("UDP write") }; buffer:=make([]byte,2048); n,err:=udp.Read(buffer)
   if err!=nil || !bytes.Equal(buffer[:n],payload) { panic("UDP echo") }
  }; udp.Close()
 }
}
func main() {
 if len(os.Args)!=3 { panic("usage: peer NODE CORE_OUTER_IP") }; node,err:=strconv.Atoi(os.Args[1]); if err!=nil || (node!=2 && node!=3) { panic("node") }
 input:=bufio.NewScanner(os.Stdin); if !input.Scan() { panic("core public") }; corePublic,err:=hex.DecodeString(input.Text()); if err!=nil || len(corePublic)!=32 { panic("core key") }
 local,err:=ecdh.X25519().GenerateKey(rand.Reader); if err!=nil { panic(err) }; psk:=make([]byte,32); if _,err=rand.Read(psk); err!=nil { panic(err) }
 adapter,err:=tun.CreateTUN("wg-go",1420); if err!=nil { panic(err) }
 dev:=device.NewDevice(adapter,conn.NewDefaultBind(),&device.Logger{Verbosef:device.DiscardLogf,Errorf:device.DiscardLogf}); defer dev.Close()
 config:=fmt.Sprintf("private_key=%x\nlisten_port=0\nreplace_peers=true\npublic_key=%x\npreshared_key=%x\nprotocol_version=1\nreplace_allowed_ips=true\nallowed_ip=10.42.0.1/32\nallowed_ip=fd42::1/128\n",local.Bytes(),corePublic,psk)
 if err=dev.IpcSet(config); err!=nil { panic(err) }; if err=dev.Up(); err!=nil { panic(err) }
 current,err:=dev.IpcGet(); if err!=nil { panic(err) }; port:=0
 for _,line:=range strings.Split(current,"\n") { if strings.HasPrefix(line,"listen_port=") { port,_=strconv.Atoi(strings.TrimPrefix(line,"listen_port=")) } }
 if port==0 { panic("UDP port") }; announce(map[string]any{"port":port,"public":hex.EncodeToString(local.PublicKey().Bytes()),"psk":hex.EncodeToString(psk)})
 if !input.Scan() { panic("endpoint") }; remote:=net.JoinHostPort(os.Args[2],input.Text()); if err=dev.IpcSet(fmt.Sprintf("public_key=%x\nendpoint=%s\n",corePublic,remote)); err!=nil { panic(err) }
 if !input.Scan() || input.Text()!="start" { panic("start") }; services(node); announce(map[string]bool{"ready":true})
 for input.Scan() { switch input.Text() {
 case "probe": probe(node); announce(map[string]bool{"probed":true})
 case "pause": paused.Store(true); announce(map[string]bool{"paused":true})
 case "resume": paused.Store(false); announce(map[string]bool{"resumed":true})
 case "stop": return
 default: panic("command")
 } }
}
'''


def build_peer(root):
    (root / 'go.mod').write_text(f'module nexus-wireguard-tun-network\n\ngo 1.23.1\n\nrequire golang.zx2c4.com/wireguard {common.REVISION}\n')
    (root / 'main.go').write_text(SOURCE)
    executable = root / 'wireguard-tun-peer'
    result = subprocess.run(['go', 'build', '-mod=mod', '-o', executable, 'main.go'], cwd=root,
                            capture_output=True, text=True, timeout=120,
                            env=dict(os.environ, GOPROXY='off', GOTOOLCHAIN='local'))
    if result.returncode:
        raise RuntimeError(f'official wireguard-go TUN peer build failed: {result.stderr}')
    return str(executable)


def run(command, prefix=()):
    result = subprocess.run([*prefix, *map(str, command)], capture_output=True, text=True, timeout=30)
    if result.returncode:
        raise RuntimeError(f'command failed: {command}: {result.stdout} {result.stderr}')
    return result.stdout


def send(process, text):
    process.stdin.write(text + '\n'); process.stdin.flush()


def receive(process, timeout=15):
    if not select.select([process.stdout], [], [], timeout)[0]:
        raise RuntimeError(f'process {process.pid} output timed out')
    line = process.stdout.readline()
    if not line:
        raise RuntimeError(f'process {process.pid} closed: {process.stderr.read()}')
    return json.loads(line)


def address(node, ipv6):
    return f'fd42::{node}' if ipv6 else f'10.42.0.{node}'


def configure_tun(name, node, prefix=()):
    run(['ip', 'link', 'set', name, 'mtu', '1420', 'up'], prefix)
    run(['ip', 'addr', 'add', f'10.42.0.{node}/24', 'dev', name], prefix)
    run(['ip', '-6', 'addr', 'add', f'fd42::{node}/64', 'dev', name, 'nodad'], prefix)


class Echo:
    def __init__(self):
        self.sockets = []
        self.errors = []
        self.stopping = False
        for family, host in ((socket.AF_INET, address(1, False)), (socket.AF_INET6, address(1, True))):
            for kind, port in ((socket.SOCK_STREAM, 22222), (socket.SOCK_DGRAM, 22223)):
                listener = socket.socket(family, kind); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listener.bind((host, port)); listener.settimeout(.2)
                if kind == socket.SOCK_STREAM: listener.listen(8)
                self.sockets.append(listener)
                threading.Thread(target=self.serve, args=(listener, kind), daemon=True).start()

    def serve(self, listener, kind):
        while not self.stopping:
            try:
                if kind == socket.SOCK_DGRAM:
                    data, source = listener.recvfrom(2048); listener.sendto(data, source)
                else:
                    peer, _ = listener.accept()
                    threading.Thread(target=self.stream, args=(peer,), daemon=True).start()
            except TimeoutError:
                continue
            except OSError as error:
                if not self.stopping: self.errors.append(error)
                break

    def stream(self, peer):
        try:
            with peer:
                peer.settimeout(20); data = bytearray()
                while part := peer.recv(65536): data.extend(part)
                peer.sendall(data); peer.shutdown(socket.SHUT_WR)
        except OSError as error:
            if not self.stopping: self.errors.append(error)

    def close(self):
        self.stopping = True
        for listener in self.sockets: listener.close()


def probe(node, ipv6, payload=None, started=None, connection=None):
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    data = payload if payload is not None else bytes((i + node + ipv6) % 256 for i in range(65536))
    with socket.socket(family, socket.SOCK_STREAM) as peer:
        peer.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 32768); peer.settimeout(30)
        peer.connect((address(node, ipv6), 22222))
        if connection is not None: connection.append(peer)
        if started is not None: started.set()
        peer.sendall(data); peer.shutdown(socket.SHUT_WR); received = bytearray()
        while part := peer.recv(65536): received.extend(part)
        if received != data:
            raise RuntimeError(f'kernel TCP echo/half close mismatch node={node} IPv{6 if ipv6 else 4}')
    if payload is not None: return
    with socket.socket(family, socket.SOCK_DGRAM) as peer:
        peer.settimeout(10)
        for size in (0, 1, 63, 512, 1372, 1372 if ipv6 else 1392):
            data = bytes((i + node + ipv6) % 256 for i in range(size)); peer.sendto(data, (address(node, ipv6), 22223))
            got, source = peer.recvfrom(2048)
            if got != data or source[0] != address(node, ipv6): raise RuntimeError('kernel UDP bytes/source mismatch')


def inner(fixture, reference, outer_family, mode, host_inode):
    if os.stat('/proc/self/ns/net').st_ino == host_inode: raise RuntimeError('network namespace was not isolated')
    run(['ip', 'link', 'set', 'lo', 'up'])
    peers, prefixes, setup, processes = [], [], [], []
    core, echo = None, None
    try:
        with tempfile.TemporaryDirectory(prefix='nexus-wireguard-tun-keys-') as keydir:
            keys = port_common.prepare(pathlib.Path(keydir))
        for node in (2, 3):
            host = f'fd00:42:{node}::1' if outer_family == 6 else f'192.0.2.{(node-2)*4+1}'
            peer = subprocess.Popen(['unshare', '-n', reference, str(node), host], stdin=subprocess.PIPE,
                                    stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            peers.append(peer); processes.append(peer); send(peer, keys['public']); setup.append(receive(peer))
            prefix = ['nsenter', '-t', str(peer.pid), '-n']; prefixes.append(prefix)
            if os.stat(f'/proc/{peer.pid}/ns/net').st_ino == os.stat('/proc/self/ns/net').st_ino: raise RuntimeError('peer namespace missing')
            first, second = f'n{node}', f'p{node}'
            run(['ip', 'link', 'add', first, 'type', 'veth', 'peer', 'name', second])
            run(['ip', 'link', 'set', second, 'netns', str(peer.pid)])
            for commands, endpoint in (([], first), (prefix, second)):
                run(['ip', 'link', 'set', endpoint, 'up'], commands)
                suffix = (node-2)*4 + (2 if commands else 1)
                run(['ip', 'addr', 'add', f'192.0.2.{suffix}/30', 'dev', endpoint], commands)
                run(['ip', '-6', 'addr', 'add', f'fd00:42:{node}::{2 if commands else 1}/64', 'dev', endpoint, 'nodad'], commands)
            run(['ip', 'link', 'set', 'lo', 'up'], prefix); configure_tun('wg-go', node, prefix)
        if os.stat(f'/proc/{peers[0].pid}/ns/net').st_ino == os.stat(f'/proc/{peers[1].pid}/ns/net').st_ino: raise RuntimeError('peers share a network namespace')
        core = subprocess.Popen([fixture, str(outer_family), mode], stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True); processes.append(core)
        send(core, ' '.join((keys['private'], setup[0]['public'], setup[1]['public'], setup[0]['psk'], setup[1]['psk'])))
        core_setup = receive(core)
        send(core, f"{setup[0]['port']} {setup[1]['port']}")
        device = receive(core); configure_tun(device['device'], 1)
        echo = Echo()
        send(core, 'start')
        for peer in peers:
            send(peer, str(core_setup['port'])); send(peer, 'start')
            if receive(peer) != {'ready': True}: raise RuntimeError('Go services not ready')
        for node in (2, 3):
            for ipv6 in (False, True):
                run(['ping', '-6' if ipv6 else '-4', '-n', '-c', '1', '-W', '25' if mode == 'cookie' else '3', address(node, ipv6)])
                if mode in ('plain', 'cookie'):
                    run(['ping', '-6' if ipv6 else '-4', '-n', '-c', '1', '-W', '25' if mode == 'cookie' else '3', address(1, ipv6)], prefixes[node-2])
                    probe(node, ipv6)
        if mode in ('plain', 'cookie'):
            for peer in peers:
                send(peer, 'probe')
                if receive(peer, 30) != {'probed': True}: raise RuntimeError('reverse kernel TCP/UDP probe failed')
        if mode in ('backpressure', 'stop', 'deadline'):
            for peer in peers:
                send(peer, 'pause')
                if receive(peer) != {'paused': True}: raise RuntimeError('reference pause failed')
            errors, done, sockets, threads = [], [], [], []
            data = bytes(range(256)) * 16384
            for node, ipv6 in ((2, False), (3, True)):
                event, finished = threading.Event(), threading.Event(); connections = []
                def transfer(node=node, ipv6=ipv6, event=event, finished=finished, connections=connections):
                    try: probe(node, ipv6, data, event, connections)
                    except Exception as error: errors.append(error)
                    finally: finished.set()
                thread = threading.Thread(target=transfer, daemon=True); thread.start()
                if not event.wait(5): raise RuntimeError('blocked kernel TCP connection never established')
                done.append(finished); sockets.extend(connections); threads.append(thread)
            time.sleep(1.2)
            if any(event.is_set() for event in done): raise RuntimeError(f'kernel TCP did not sustain backpressure: {errors}')
            if mode == 'backpressure':
                for peer in peers:
                    send(peer, 'resume')
                    if receive(peer) != {'resumed': True}: raise RuntimeError('reference resume failed')
                for thread in threads: thread.join(30)
                if any(thread.is_alive() for thread in threads) or errors: raise RuntimeError(f'kernel TCP recovery failed: {errors}')
            else:
                if mode == 'stop': send(core, 'stop')
                core.wait(15)
                for peer in sockets:
                    try: peer.shutdown(socket.SHUT_RDWR)
                    except OSError: pass
                for thread in threads: thread.join(3)
                if any(thread.is_alive() for thread in threads): raise RuntimeError('kernel clients did not terminate after adapter stop')
        if core.poll() is None: send(core, 'stop')
        output, error = core.communicate(timeout=15)
        if core.returncode: raise RuntimeError(f'Nexus TUN failed {core.returncode}: {output} {error}')
        report = json.loads(output)
        if not report['stopped'] or not report['drained'] or report['deadline'] != (mode == 'deadline'): raise RuntimeError('TUN owner did not drain')
        if subprocess.run(['ip', 'link', 'show', device['device']], capture_output=True).returncode == 0: raise RuntimeError('owned TUN device leaked after stop')
        if echo.errors: raise RuntimeError(f'kernel origin errors: {echo.errors}')
        print(json.dumps({'outer': outer_family, 'mode': mode, 'two_peers': True, 'kernel': 'ICMP/TCP/UDP IPv4+IPv6',
                          'report': report, 'adapter_size': device['adapter_size'],
                          'tcp_pressure_bytes': len(data) if mode in ('backpressure', 'stop', 'deadline') else 0}), flush=True)
    finally:
        if echo: echo.close()
        for process in reversed(processes):
            if process.poll() is None:
                try: send(process, 'stop'); process.wait(2)
                except (BrokenPipeError, subprocess.TimeoutExpired): process.kill(); process.wait(3)
            process.stdin.close(); process.stdout.close(); process.stderr.close()


def main():
    if len(sys.argv) > 2 and sys.argv[2] == '--inner':
        inner(str(pathlib.Path(sys.argv[1]).resolve()), sys.argv[3], int(sys.argv[4]), sys.argv[5], int(sys.argv[6])); return
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('fixture'); parser.add_argument('--peer'); parser.add_argument('--family', choices=(4, 6), type=int)
    parser.add_argument('--mode', choices=('plain', 'cookie', 'backpressure', 'stop', 'deadline'))
    args = parser.parse_args(); fixture = str(pathlib.Path(args.fixture).resolve())
    with tempfile.TemporaryDirectory(prefix='nexus-wireguard-tun-reference-') as directory:
        reference = str(pathlib.Path(args.peer).resolve()) if args.peer else build_peer(pathlib.Path(directory))
        for family in ((args.family,) if args.family else (4, 6)):
            for mode in ((args.mode,) if args.mode else ('plain', 'cookie', 'backpressure', 'stop', 'deadline')):
                subprocess.run(['unshare', '-Urn', sys.executable, __file__, fixture, '--inner', reference, str(family), mode,
                                str(os.stat('/proc/self/ns/net').st_ino)], check=True, timeout=120)


if __name__ == '__main__': main()
