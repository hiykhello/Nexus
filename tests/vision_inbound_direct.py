"""Observe both Vision direct switches with a real sing-box TLS client."""
from test_paths import optional_fixture
import json
import argparse
import pathlib
import socket
import ssl
import subprocess
import tempfile
import threading
import time
ROOT=pathlib.Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser(description=__doc__)
parser.add_argument('--fixture',type=pathlib.Path,default=optional_fixture('vision-inbound-direct-fixture'), required=optional_fixture('vision-inbound-direct-fixture') is None)
fixture_binary=parser.parse_args().fixture.resolve()
REVISION='824dbcfb4dd0a95921840b1737b950cde590241e'
if f'Revision: {REVISION}' not in subprocess.run(['sing-box','version'],check=True,capture_output=True,text=True).stdout: raise RuntimeError('unexpected sing-box revision')
def exact(sock,n):
    data=bytearray()
    while len(data)<n:
        part=sock.recv(n-len(data))
        if not part: raise RuntimeError('unexpected EOF')
        data.extend(part)
    return bytes(data)
with tempfile.TemporaryDirectory(prefix='nexus-vision-direct-') as directory:
    root=pathlib.Path(directory)
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(root/'key'),'-out',str(root/'cert'),'-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost','-days','1'],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
    (root/'key').chmod(0o600); uuid=root/'uuid'; uuid.write_text('00010203-0405-0607-0809-0a0b0c0d0e0f'); uuid.chmod(0o600)
    listener=socket.socket(); listener.bind(('127.0.0.1',0)); listener.listen(1)
    origin=socket.socket(); origin.bind(('127.0.0.1',0)); origin.listen(1); origin.settimeout(15)
    with socket.socket() as reserve: reserve.bind(('127.0.0.1',0)); port=reserve.getsockname()[1]
    config={'log':{'level':'warn'},'inbounds':[{'type':'socks','listen':'127.0.0.1','listen_port':port}],
        'outbounds':[{'type':'vless','server':'127.0.0.1','server_port':listener.getsockname()[1],'uuid':'00010203-0405-0607-0809-0a0b0c0d0e0f','flow':'xtls-rprx-vision','tls':{'enabled':True,'server_name':'localhost','certificate_path':str(root/'cert')}}]}
    path=root/'box.json'; path.write_text(json.dumps(config)); subprocess.run(['sing-box','check','-c',path],check=True,capture_output=True)
    fixture=subprocess.Popen([fixture_binary,str(listener.fileno()),root/'cert',root/'key',uuid],pass_fds=(listener.fileno(),),stdout=subprocess.PIPE,stderr=subprocess.PIPE)
    box=subprocess.Popen(['sing-box','run','-c',path],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE); errors=[]; payload=bytes(range(256))*256
    def serve():
        try:
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER); context.minimum_version=ssl.TLSVersion.TLSv1_3; context.load_cert_chain(root/'cert',root/'key')
            with origin.accept()[0] as conn:
                conn.settimeout(12)
                with context.wrap_socket(conn,server_side=True) as stream:
                    data=exact(stream,len(payload)); stream.sendall(data); stream.unwrap().close()
        except Exception as exc: errors.append(exc)
    worker=threading.Thread(target=serve,daemon=True); worker.start()
    try:
        deadline=time.monotonic()+10
        while True:
            if box.poll() is not None: raise RuntimeError(f'sing-box exited: {box.stderr.read()!r}')
            try: conn=socket.create_connection(('127.0.0.1',port),timeout=1); break
            except ConnectionRefusedError:
                if time.monotonic()>deadline: raise
                time.sleep(.05)
        with conn:
            conn.settimeout(15); conn.sendall(b'\x05\x01\x00')
            if exact(conn,2)!=b'\x05\x00': raise RuntimeError('SOCKS auth failed')
            conn.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01'+origin.getsockname()[1].to_bytes(2,'big'))
            if exact(conn,10)[:2]!=b'\x05\x00': raise RuntimeError('SOCKS connect failed')
            context=ssl.create_default_context(cafile=str(root/'cert')); context.minimum_version=ssl.TLSVersion.TLSv1_3
            with context.wrap_socket(conn,server_hostname='localhost') as stream:
                stream.sendall(payload)
                if exact(stream,len(payload))!=payload: raise RuntimeError('inner TLS mismatch')
                stream.unwrap().close()
        _,log=fixture.communicate(timeout=15); worker.join(15)
        if fixture.returncode or errors or worker.is_alive() or b'send_direct=1 receive_direct=1 up=1 down=1' not in log:
            raise RuntimeError(f'fixture exit {fixture.returncode}, {log!r}, origin {errors}, alive {worker.is_alive()}')
    finally:
        listener.close(); origin.close(); box.terminate(); box.wait(timeout=5)
        if fixture.poll() is None: fixture.kill()
        _,debug=fixture.communicate()
        if fixture.returncode: print(f"fixture={fixture.returncode} log={debug!r} origin={errors}")
print('Nexus Vision inbound switches both directions to direct with pinned sing-box and inner TLS')
