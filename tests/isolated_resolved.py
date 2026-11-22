#!/usr/bin/env python3
"""Run a real resolved and private bus only inside verified owned user/net/mount namespaces."""
from pathlib import Path
import argparse,json,os,subprocess,sys,tempfile,time,signal,select,shlex

def call(args,**kw):
 p=subprocess.run([str(x) for x in args],capture_output=True,text=True,timeout=15,**kw)
 if p.returncode:raise RuntimeError((args,p.returncode,p.stdout,p.stderr))
 return p.stdout

def inner(a):
 parent=json.loads(a.parents)
 for name,old in parent.items():assert os.stat('/proc/self/ns/'+name).st_ino!=old,name
 root=Path(a.evidence).resolve().parent/'environment';root.mkdir(exist_ok=False)
 call(['mount','--make-rprivate','/'])
 for label,target in [('bus','/run/dbus'),('resolve','/run/systemd/resolve'),('netif','/run/systemd/netif')]:
  source=root/label;source.mkdir();call(['mount','--bind',source,target])
 passwd=root/'passwd';passwd.write_text('root:x:0:0:root:/root:/bin/sh\nsystemd-resolve:x:0:0:resolved:/:/usr/bin/nologin\n');call(['mount','--bind',passwd,'/etc/passwd'])
 config=root/'resolved.conf';config.write_text('[Resolve]\nDNS=\nFallbackDNS=\nLLMNR=no\nMulticastDNS=no\nDNSSEC=no\nCache=no\nReadEtcHosts=no\nDNSStubListener=yes\n');call(['mount','--bind',config,'/etc/systemd/resolved.conf'])
 xml=root/'bus.conf';xml.write_text('''<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN" "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen><auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/><allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>''')
 call(['ip','link','set','lo','up']);processes=[];report={'complete':False,'namespaces':{name:os.stat('/proc/self/ns/'+name).st_ino for name in parent},'parent_namespaces':parent,'artifacts':str(root)}
 env=dict(os.environ,DBUS_SYSTEM_BUS_ADDRESS='unix:path=/run/dbus/system_bus_socket',SYSTEMD_LOG_LEVEL='debug',SYSTEMD_LOG_TARGET='console')
 for name in ('NOTIFY_SOCKET','WATCHDOG_USEC','WATCHDOG_PID','LISTEN_FDS','LISTEN_PID','LISTEN_FDNAMES','DBUS_SESSION_BUS_ADDRESS','CREDENTIALS_DIRECTORY'):env.pop(name,None)
 try:
  for name,command in [('bus',['dbus-daemon','--nofork','--nopidfile','--config-file',xml]),('resolved',['/usr/lib/systemd/systemd-resolved'])]:
   log=(root/(name+'.log')).open('w');p=subprocess.Popen([str(x) for x in command],stdout=log,stderr=subprocess.STDOUT,env=env);processes.append((name,p,log))
   begin=time.monotonic()
   while time.monotonic()-begin<8:
    if p.poll() is not None:raise RuntimeError((name,p.returncode,(root/(name+'.log')).read_text()))
    if name=='bus' and Path('/run/dbus/system_bus_socket').exists():break
    if name=='resolved':
     ready=subprocess.run(['busctl','--system','--timeout=0.2','status','org.freedesktop.resolve1'],capture_output=True,env=env)
     if ready.returncode==0:break
    time.sleep(.03)
   else:raise RuntimeError(name+' startup timeout')
  report['introspection']=call(['busctl','--system','introspect','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager'],env=env)
  report['resolv_conf']=Path('/etc/resolv.conf').read_text()
  if a.tun_binary:
   report['tun']=call([sys.executable,Path(__file__).with_name('tun_resolved_network.py'),a.tun_binary],env=env)
  if a.network_binary:
   network_env=dict(env)
   network_env['NEXUS_HOST_DNS_SERVER_FAMILY']=str(a.dns_family)
   if a.provider:network_env['NEXUS_HOST_DNS_PROVIDER']='warp'
   conf=root/'nsswitch.conf'
   base=Path('/etc/nsswitch.conf').read_text();lines=base.splitlines();assert any(line.startswith('hosts:') for line in lines)
   conf.write_text('\n'.join('hosts: files dns' if line.startswith('hosts:') else line for line in lines)+'\n');call(['mount','--bind',conf,'/etc/nsswitch.conf'])
  if a.probe:
   call(['ip','link','add','nx-dns','type','dummy']);call(['ip','link','set','nx-dns','up'])
   index=json.loads(call(['ip','-j','link','show','nx-dns']))[0]['ifindex']
   begin=time.monotonic()
   while time.monotonic()-begin<2:
    found=subprocess.run(['busctl','--system','call','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager','GetLink','i',str(index)],capture_output=True,env=env)
    if found.returncode==0:break
    time.sleep(.01)
   else:raise RuntimeError('resolved did not observe owned link')
   report['probe_read']=call([a.probe,'read',index],env=env)
   resolved=next(process for name,process,_ in processes if name=='resolved')
   report['probe_cases']=[]
   for mode in ('timeout','cancel'):
    resolved.send_signal(signal.SIGSTOP)
    probe=subprocess.Popen([str(a.probe),mode,str(index)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
    try:
     if not select.select([probe.stdout],[],[],3)[0]:raise RuntimeError('bounded native RPC probe did not finish')
     line=probe.stdout.readline();case=json.loads(line);assert case['mode']==mode
     resolved.send_signal(signal.SIGCONT);probe.stdin.write('resume\n');probe.stdin.flush()
     output,error=probe.communicate(timeout=4);case.update(exit=probe.returncode,stdout=output,stderr=error);report['probe_cases'].append(case)
     if probe.returncode:raise RuntimeError(case)
    finally:
     resolved.send_signal(signal.SIGCONT)
     if probe.poll() is None:probe.kill();probe.communicate(timeout=3)
  if a.client_probe:
   if not a.probe:
    call(['ip','link','add','nx-dns','type','dummy']);call(['ip','link','set','nx-dns','up'])
    index=json.loads(call(['ip','-j','link','show','nx-dns']))[0]['ifindex']
   manager=['busctl','--system','call','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager']
   link=shlex.split(call(manager+['GetLink','i',str(index)],env=env))[1]
   get=['busctl','--system','get-property','org.freedesktop.resolve1',link,'org.freedesktop.resolve1.Link']
   report['client_cases']=[]
   for default in ('false','true'):
    call(manager+['SetLinkDefaultRoute','ib',str(index),default],env=env)
    call(manager+['SetLinkLLMNR','is',str(index),'no'],env=env)
    before=call(get+['DefaultRoute'],env=env)
    probe=subprocess.Popen([str(a.client_probe),str(index)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
    try:
     if not select.select([probe.stdout],[],[],4)[0]:raise RuntimeError('settings native probe did not commit')
     line=probe.stdout.readline();committed=json.loads(line);assert committed['readback']
     foreign='true' if default=='false' else 'false'
     call(manager+['SetLinkDefaultRoute','ib',str(index),foreign],env=env)
     foreign_default=call(get+['DefaultRoute'],env=env)
     probe.stdin.write('cleanup\n');probe.stdin.flush();output,error=probe.communicate(timeout=4)
     case={'default_route':default,'before_default':before,'after_default':call(get+['DefaultRoute'],env=env),'foreign_default_before_cleanup':foreign_default,'exit':probe.returncode,'stdout':output,'stderr':error};report['client_cases'].append(case)
     assert case['exit']==0 and case['foreign_default_before_cleanup']==case['after_default'] and case['before_default']!=case['after_default'],case
    finally:
     if probe.poll() is None:probe.kill();probe.communicate(timeout=3)
  if a.lease_probe:
   manager=['busctl','--system','call','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager']
   probe=subprocess.Popen([str(a.lease_probe),str(parent['net']),str(parent['user']),a.lease_mode],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
   transcript=[];report['lease']={'mode':a.lease_mode,'transcript':transcript}
   def receive():
    if not select.select([probe.stdout],[],[],6)[0]:raise RuntimeError('host DNS lease probe timeout')
    line=probe.stdout.readline();transcript.append(line)
    if not line:raise RuntimeError(('host DNS probe ended',probe.poll(),probe.stderr.read()))
    return json.loads(line)
   def send(line):probe.stdin.write(line+'\n');probe.stdin.flush()
   def property(name):
    return call(['busctl','--system','get-property','org.freedesktop.resolve1',link,'org.freedesktop.resolve1.Link',name],env=env)
   def servers(index,octets):
    return call(manager+['SetLinkDNS','ia(iay)',str(index),'1','2','4',*[str(x) for x in octets]],env=env)
   try:
    index=receive()['ifindex']
    until=time.monotonic()+3
    while True:
     found=subprocess.run(manager+['GetLink','i',str(index)],capture_output=True,text=True,env=env)
     if found.returncode==0:link=shlex.split(found.stdout)[1];break
     if time.monotonic()>=until:raise RuntimeError('real resolved did not see sealed TUN')
     time.sleep(.01)
    other=None
    if a.lease_mode=='conflict':servers(index,[8,8,4,4])
    elif a.lease_mode.startswith('conflict-domain'):
     call(['ip','link','add','nx-other','type','dummy']);call(['ip','link','set','nx-other','up']);other=json.loads(call(['ip','-j','link','show','nx-other']))[0]['ifindex']
     call(manager+['SetLinkDomains','ia(sb)',str(other),'1','.' if a.lease_mode=='conflict-domain-root' else 'foreign.test','true'],env=env)
    original={name:property(name) for name in ('DNSEx','Domains','DefaultRoute')};report['lease']['original']=original
    send('start');state=receive()
    if a.lease_mode.startswith('conflict') or a.lease_mode in ('uncovered','startup-cancel','startup-timeout'):
     assert state['rejected'] and state['no_mutation'],state
     after={name:property(name) for name in original};assert after==original,(after,original);report['lease']['after_rejection']=after
    else:
     assert state['ready'],state
     if a.lease_mode=='foreign-dns':servers(index,[8,8,4,4])
     elif a.lease_mode=='foreign-domain':call(manager+['SetLinkDomains','ia(sb)',str(index),'1','foreign.test','true'],env=env)
     elif a.lease_mode=='restart':
      previous=next(process for name,process,_ in reversed(processes) if name.startswith('resolved'));previous.terminate();previous.wait(timeout=4)
      log=(root/'resolved-restart.log').open('w');current=subprocess.Popen(['/usr/lib/systemd/systemd-resolved'],stdout=log,stderr=subprocess.STDOUT,env=env);processes.append(('resolved-restart',current,log))
      until=time.monotonic()+5
      while True:
       if current.poll() is not None:raise RuntimeError(('restarted resolved exited',current.returncode))
       ready=subprocess.run(manager+['GetLink','i',str(index)],capture_output=True,text=True,env=env)
       if ready.returncode==0:break
       if time.monotonic()>=until:raise RuntimeError('restarted resolved did not become ready')
       time.sleep(.02)
     before_stop={name:property(name) for name in ('DNSEx','Domains','DefaultRoute')}
     send('check');state=receive();report['lease']['cleanup']=state
     after={name:property(name) for name in original};report['lease']['after_dns_stop']=after
     if a.lease_mode in ('normal','cancel-stop'):
      assert state['restored'] and not state['uncertain'] and after==original,(state,after,original)
     else:assert after==before_stop,(after,before_stop)
    # The independent fixture actor explicitly withdraws its own replacement
    # before testing a fresh DNS owner against the same still-live TUN lease.
    call(manager+['SetLinkDomains','ia(sb)',str(index),'0'],env=env)
    call(manager+['SetLinkDNS','ia(iay)',str(index),'0'],env=env)
    if other is not None:call(manager+['SetLinkDomains','ia(sb)',str(other),'0'],env=env)
    send('finish');output,error=probe.communicate(timeout=6);report['lease'].update(exit=probe.returncode,stdout=output,stderr=error)
    assert probe.returncode==0,report['lease']
    until=time.monotonic()+2
    while True:
     deleted=subprocess.run(manager+['GetLink','i',str(index)],capture_output=True,text=True,env=env)
     if deleted.returncode!=0:break
     if time.monotonic()>=until:raise RuntimeError('resolved retained deleted owned link')
     time.sleep(.01)
    report['lease']['removed_link']=True
   finally:
    if probe.poll() is None:probe.kill();probe.communicate(timeout=3)
  if a.network_binary:
   if not a.peer:raise RuntimeError('supply fixed independently built DNS peer')
   command=[sys.executable,str(Path(__file__).with_name('host_dns_network.py')),str(a.network_binary),'--peer',str(a.peer),'--family',str(a.family),'--role',a.role,'--mode',a.network_mode,'--evidence',str(root/'network.json'),'--inner','--parent-net',str(parent['net']),'--parent-user',str(parent['user']),*(['--parent-mount',str(parent['mnt'])] if a.hostname else []),*(['--default-route'] if a.default_route else []),*(['--hostname'] if a.hostname else [])]
   done=subprocess.run(command,capture_output=True,text=True,timeout=170,env=network_env);(root/'network.log').write_text(done.stdout+done.stderr);report['network']={'exit':done.returncode,'command':command}
   if done.returncode:raise RuntimeError(done.stderr+'\n'+done.stdout)
  if a.native_probe:
   manager=['busctl','--system','call','org.freedesktop.resolve1','/org/freedesktop/resolve1','org.freedesktop.resolve1.Manager']
   child_env=dict(env,LD_PRELOAD=str(a.preload))
   probe=subprocess.Popen([str(a.native_probe),str(parent['net']),str(parent['user']),a.native_stage,str(a.fail_at),'persistent' if a.persistent else 'single'],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=child_env)
   try:
    if not select.select([probe.stdout],[],[],9)[0]:raise RuntimeError('native allocation probe timeout')
    line=probe.stdout.readline()
    try:row=json.loads(line)
    except Exception:raise RuntimeError(('invalid native result',line,probe.poll(),probe.stderr.read()))
    report['native']=row
    # Keep the original failure state as evidence before fixture-only recovery.
    links=json.loads(call(['ip','-j','link','show']))
    selected=[link for link in links if link['ifname']=='nx-dnsalloc'];assert len(selected)==1
    index=selected[0]['ifindex']
    link=shlex.split(call(manager+['GetLink','i',str(index)],env=env))[1]
    report['native']['dns_before_recovery']=call(['busctl','--system','get-property','org.freedesktop.resolve1',link,'org.freedesktop.resolve1.Link','DNSEx'],env=env)
    report['native']['domains_before_recovery']=call(['busctl','--system','get-property','org.freedesktop.resolve1',link,'org.freedesktop.resolve1.Link','Domains'],env=env)
    call(manager+['SetLinkDomains','ia(sb)',str(index),'0'],env=env)
    call(manager+['SetLinkDNS','ia(iay)',str(index),'0'],env=env)
    if probe.poll() is None:probe.stdin.write('recover\n');probe.stdin.flush()
    output,error=probe.communicate(timeout=6);report['native'].update(exit=probe.returncode,stdout=output,stderr=error)
    if probe.returncode:raise RuntimeError(report['native'])
   finally:
    if probe.poll() is None:probe.kill();probe.communicate(timeout=3)
  if a.new_probe:
   done=subprocess.run([str(a.new_probe),str(parent['net']),str(parent['user'])],capture_output=True,text=True,timeout=15,env=env);report['cpp_new']={'exit':done.returncode,'stdout':done.stdout,'stderr':done.stderr}
   if done.returncode:raise RuntimeError(report['cpp_new'])
  if a.epoch_probe:
   running=next(process for name,process,_ in reversed(processes) if name.startswith('resolved'))
   running.terminate();running.wait(timeout=4)
   from owner_epoch import run as epoch
   report['owner_epoch']=epoch(a.epoch_probe,env)
  report['complete']=True
 finally:
  for name,p,log in reversed(processes):
   if p.poll() is None:p.terminate()
   try:p.wait(timeout=4)
   except subprocess.TimeoutExpired:p.kill();p.wait(timeout=4)
   log.close();report[name+'_exit']=p.returncode
  Path(a.evidence).write_text(json.dumps(report,indent=2)+'\n')
 print('isolated real resolved/privateDBus startup/readiness/drain passed',flush=True)

def main():
 p=argparse.ArgumentParser();p.add_argument('--evidence',required=True);p.add_argument('--inner',action='store_true');p.add_argument('--parents');p.add_argument('--probe',type=Path);p.add_argument('--client-probe',type=Path);p.add_argument('--lease-probe',type=Path);p.add_argument('--lease-mode',default='normal');p.add_argument('--network-binary',type=Path);p.add_argument('--tun-binary',type=Path);p.add_argument('--peer',type=Path);p.add_argument('--family',type=int,default=4);p.add_argument('--dns-family',type=int,default=4);p.add_argument('--role',default='client');p.add_argument('--network-mode',default='plain');p.add_argument('--default-route',action='store_true');p.add_argument('--hostname',action='store_true');p.add_argument('--native-probe',type=Path);p.add_argument('--preload',type=Path);p.add_argument('--native-stage',choices=['start','stop'],default='start');p.add_argument('--fail-at',type=int,default=0);p.add_argument('--persistent',action='store_true');p.add_argument('--new-probe',type=Path);p.add_argument('--epoch-probe',type=Path);p.add_argument('--provider',action='store_true');a=p.parse_args()
 if a.inner:inner(a);return
 assert not a.parents
 parents={name:os.stat('/proc/self/ns/'+name).st_ino for name in ('user','net','mnt')};Path(a.evidence).resolve().parent.mkdir(exist_ok=False,parents=True)
 command=['unshare','-Urnm',sys.executable,str(Path(__file__).resolve()),'--evidence',str(Path(a.evidence).resolve()),'--inner','--parents',json.dumps(parents),*(['--probe',str(a.probe.resolve())] if a.probe else []),*(['--client-probe',str(a.client_probe.resolve())] if a.client_probe else []),*(['--lease-probe',str(a.lease_probe.resolve()),'--lease-mode',a.lease_mode] if a.lease_probe else []),*(['--network-binary',str(a.network_binary.resolve()),'--peer',str(a.peer.resolve()),'--family',str(a.family),'--dns-family',str(a.dns_family),'--role',a.role,'--network-mode',a.network_mode,*(['--provider'] if a.provider else []),*(['--default-route'] if a.default_route else []),*(['--hostname'] if a.hostname else [])] if a.network_binary else []),*(['--native-probe',str(a.native_probe.resolve()),'--preload',str(a.preload.resolve()),'--native-stage',a.native_stage,'--fail-at',str(a.fail_at),*(['--persistent'] if a.persistent else [])] if a.native_probe else []),*(['--new-probe',str(a.new_probe.resolve())] if a.new_probe else []),*(['--epoch-probe',str(a.epoch_probe.resolve())] if a.epoch_probe else [])]
 if a.tun_binary:command+=['--tun-binary',str(a.tun_binary.resolve())]
 subprocess.run(command,check=True,timeout=210 if a.network_binary else 55 if a.tun_binary else 30)
if __name__=='__main__':main()
