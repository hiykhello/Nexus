#!/usr/bin/env python3
"""Test SS-2022 inbound routed through an SS-2022 outbound to sing-box."""
import base64
import concurrent.futures
import json
import pathlib
import socket
import subprocess
import sys
import tempfile
import time

nexus=pathlib.Path(sys.argv[1]).resolve()
client=nexus.with_name("nexus-shadowsocks-singbox-client")
revision="824dbcfb4dd0a95921840b1737b950cde590241e"
if f"Revision: {revision}" not in subprocess.run(["sing-box","version"],check=True,capture_output=True,text=True).stdout:
    raise RuntimeError("unexpected sing-box revision")

def exact(sock,size):
    data=bytearray()
    while len(data)<size:
        part=sock.recv(size-len(data))
        if not part: raise RuntimeError("unexpected EOF")
        data.extend(part)
    return bytes(data)

def start_and_connect(command,port):
    process=subprocess.Popen(command,stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
    deadline=time.monotonic()+5
    while True:
        if process.poll() is not None: raise RuntimeError(process.stderr.read().decode())
        try: return process,socket.create_connection(("127.0.0.1",port),timeout=.2)
        except OSError:
            if time.monotonic()>=deadline:
                process.kill(); process.communicate(); raise
            time.sleep(.02)

def stop(process):
    if process is None: return
    process.terminate()
    try: _,err=process.communicate(timeout=5)
    except subprocess.TimeoutExpired: process.kill(); _,err=process.communicate()
    if process.returncode!=0: raise RuntimeError(f"process exited {process.returncode}: {err.decode()}")

def scenario(root,in_size,out_size):
    with socket.socket() as target, socket.socket() as endpoint, socket.socket() as reservation:
        target.bind(("127.0.0.1",0)); target.listen(8); target.settimeout(.3)
        endpoint.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
        endpoint.bind(("127.0.0.1",0)); endpoint.listen(2); endpoint.settimeout(.3)
        reservation.bind(("127.0.0.1",0)); port=reservation.getsockname()[1]; reservation.close()
        upstream_port=endpoint.getsockname()[1]
        for name,size in (("in",in_size),("out",out_size)):
            key=root/f"{name}.key"; key.write_text(base64.b64encode(bytes(range(size))).decode()+"\n"); key.chmod(0o600)
        (root/"deny.kdl").write_text('schema-version 1\nkind "predicate"\nrule type="ip-cidr" value="127.0.0.1/32"\n')
        config=root/"nexus.kdl"
        def write_config(block):
            rule='rule-set "deny" path="deny.kdl" format="kdl"; rule kind="rule-set" value="deny" outbound="reject";' if block else ''
            config.write_text(f'''schema-version 1
role "server"
workers 2
inbounds {{ shadowsocks "input" {{ listen host="127.0.0.1" port={port}; method "2022-blake3-aes-{in_size*8}-gcm"; key-file "{root/'in.key'}"; }} }}
outbounds {{ direct "direct"; block "reject"; shadowsocks "edge" {{ server host="127.0.0.1" port={upstream_port}; method "2022-blake3-aes-{out_size*8}-gcm"; key-file "{root/'out.key'}"; }} }}
routing {{ {rule} default-outbound "edge"; }}
''')
        proxy=None; box=None; peer=None; client_box=None
        try:
            write_config(True)
            proxy,connection=start_and_connect([nexus,"run","--config",config],port)
            with connection:
                connection.setblocking(True)
                peer=subprocess.Popen([client,str(connection.fileno()),str(in_size),str(target.getsockname()[1]),"half-close"],pass_fds=(connection.fileno(),))
                if peer.wait(timeout=5)==0: raise RuntimeError("blocked connection succeeded")
            for listener in (target,endpoint):
                try: unexpected,_=listener.accept()
                except TimeoutError: pass
                else: unexpected.close(); raise RuntimeError("blocked request reached target or outbound node")
            stop(proxy); proxy=None
            # An upstream that accepts a request but returns a forged response
            # must close the session without retrying the target directly.
            write_config(False)
            proxy,connection=start_and_connect([nexus,"run","--config",config],port)
            with connection:
                connection.setblocking(True)
                peer=subprocess.Popen([client,str(connection.fileno()),str(in_size),str(target.getsockname()[1]),"half-close"],pass_fds=(connection.fileno(),))
                endpoint.settimeout(5)
                with endpoint.accept()[0] as fake:
                    fake.settimeout(5)
                    if not fake.recv(4096): raise RuntimeError("upstream did not receive request")
                    fake.sendall(bytes(128)); fake.shutdown(socket.SHUT_WR)
                    if peer.wait(timeout=5)==0: raise RuntimeError("forged upstream response was accepted")
            endpoint.settimeout(.3)
            for listener in (target,endpoint):
                try: unexpected,_=listener.accept()
                except TimeoutError: pass
                else: unexpected.close(); raise RuntimeError("forged response triggered retry or direct dial")
            stop(proxy); proxy=None
            endpoint.close()
            # With no upstream listener, a routable request must fail rather
            # than silently falling back to a direct connection.
            write_config(False)
            proxy,connection=start_and_connect([nexus,"run","--config",config],port)
            with connection:
                connection.setblocking(True)
                peer=subprocess.Popen([client,str(connection.fileno()),str(in_size),str(target.getsockname()[1]),"half-close"],pass_fds=(connection.fileno(),))
                if peer.wait(timeout=5)==0: raise RuntimeError("unavailable upstream unexpectedly succeeded")
            try: unexpected,_=target.accept()
            except TimeoutError: pass
            else: unexpected.close(); raise RuntimeError("unavailable upstream fell back to direct")
            stop(proxy); proxy=None
            server={"log":{"level":"warn"},"inbounds":[{"type":"shadowsocks","listen":"127.0.0.1","listen_port":upstream_port,
                "method":f"2022-blake3-aes-{out_size*8}-gcm","password":base64.b64encode(bytes(range(out_size))).decode()}],
                "outbounds":[{"type":"direct","tag":"direct"}],"route":{"final":"direct"}}
            box_config=root/"server.json"; box_config.write_text(json.dumps(server))
            box,check=start_and_connect(["sing-box","run","-c",box_config],upstream_port); check.close()
            write_config(False)
            proxy,connection=start_and_connect([nexus,"run","--config",config],port)
            with connection:
                connection.setblocking(True)
                peer=subprocess.Popen([client,str(connection.fileno()),str(in_size),str(target.getsockname()[1]),"half-close"],pass_fds=(connection.fileno(),))
                target.settimeout(10)
                with target.accept()[0] as upstream:
                    upstream.settimeout(10)
                    if exact(upstream,10)!=b"helloagain" or upstream.recv(1)!=b"": raise RuntimeError("chained upload or FIN failed")
                    upstream.sendall(b"worldagain"); upstream.shutdown(socket.SHUT_WR)
                if peer.wait(timeout=10)!=0: raise RuntimeError(f"chained client failed: {peer.returncode}")
            with socket.socket() as reserved:
                reserved.bind(("127.0.0.1",0)); socks_port=reserved.getsockname()[1]
            client_config={"log":{"level":"warn"},"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":socks_port}],
                "outbounds":[{"type":"shadowsocks","tag":"edge","server":"127.0.0.1","server_port":port,
                    "method":f"2022-blake3-aes-{in_size*8}-gcm","password":base64.b64encode(bytes(range(in_size))).decode()}],
                "route":{"final":"edge"}}
            client_path=root/"client.json"; client_path.write_text(json.dumps(client_config))
            client_box,check=start_and_connect(["sing-box","run","-c",client_path],socks_port); check.close()
            def connect_socks():
                sock=socket.create_connection(("127.0.0.1",socks_port),timeout=15)
                sock.settimeout(15); sock.sendall(b"\x05\x01\x00")
                if exact(sock,2)!=b"\x05\x00": raise RuntimeError("SOCKS greeting failed")
                sock.sendall(b"\x05\x01\x00\x01\x7f\x00\x00\x01"+target.getsockname()[1].to_bytes(2,"big"))
                head=exact(sock,4)
                if head[1]: raise RuntimeError("SOCKS connect failed")
                exact(sock,6 if head[3]==1 else 18)
                return sock
            payload=bytes(range(256))*2048; reply=payload[::-1]; count=4
            with concurrent.futures.ThreadPoolExecutor(max_workers=count*2+1) as pool:
                def serve(sock):
                    with sock:
                        sock.settimeout(15); time.sleep(.1)
                        if exact(sock,len(payload))!=payload: raise RuntimeError("chained upload mismatch")
                        sock.sendall(reply)
                def accept_all():
                    return [pool.submit(serve,target.accept()[0]) for _ in range(count)]
                def send():
                    with connect_socks() as sock:
                        sock.sendall(payload); time.sleep(.1)
                        if exact(sock,len(reply))!=reply: raise RuntimeError("chained download mismatch")
                accepting=pool.submit(accept_all)
                clients=[pool.submit(send) for _ in range(count)]
                servers=accepting.result(timeout=20)
                for future in clients+servers: future.result(timeout=30)
            # Drop the upstream node only after a request has reached the target.
            with connect_socks() as active:
                active.sendall(b"ready")
                with target.accept()[0] as upstream:
                    upstream.settimeout(5); active.settimeout(5)
                    if exact(upstream,5)!=b"ready": raise RuntimeError("active chain not ready")
                    stop(box); box=None
                    for sock in (active,upstream):
                        try: remaining=sock.recv(1)
                        except ConnectionResetError: remaining=b""
                        if remaining: raise RuntimeError("chain remained active after upstream stopped")
            target.settimeout(.3)
            try: unexpected,_=target.accept()
            except TimeoutError: pass
            else: unexpected.close(); raise RuntimeError("upstream loss caused a direct retry")
            box,check=start_and_connect(["sing-box","run","-c",box_config],upstream_port); check.close()
            target.settimeout(10)
            with connect_socks() as active:
                active.sendall(b"ready")
                with target.accept()[0] as upstream:
                    upstream.settimeout(5); active.settimeout(5)
                    if exact(upstream,5)!=b"ready": raise RuntimeError("active chain not ready")
                    stop(proxy); proxy=None
                    for sock in (active,upstream):
                        try: remaining=sock.recv(1)
                        except ConnectionResetError: remaining=b""
                        if remaining: raise RuntimeError("active chain not closed on stop")
        finally:
            if peer is not None and peer.poll() is None: peer.kill(); peer.wait()
            stop(client_box); stop(proxy); stop(box)

with tempfile.TemporaryDirectory(prefix="nexus-ss-chain-") as directory:
    for in_size,out_size in ((16,16),(16,32),(32,16),(32,32)):
        scenario(pathlib.Path(directory),in_size,out_size)
print("SS-2022 inbound to SS-2022 outbound chain with sing-box passed")
