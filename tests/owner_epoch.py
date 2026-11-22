"""Deterministic well-known-name handover while both real private D-Bus connections stay live."""
import ctypes as c,json,os,select,subprocess,time
from pathlib import Path

def run(binary,env):
 lib=c.CDLL('libsystemd.so.0')
 ptr=c.c_void_p
 lib.sd_bus_new.argtypes=[c.POINTER(ptr)];lib.sd_bus_set_address.argtypes=[ptr,c.c_char_p];lib.sd_bus_set_bus_client.argtypes=[ptr,c.c_int];lib.sd_bus_start.argtypes=[ptr];lib.sd_bus_request_name.argtypes=[ptr,c.c_char_p,c.c_uint64];lib.sd_bus_release_name.argtypes=[ptr,c.c_char_p];lib.sd_bus_get_unique_name.argtypes=[ptr,c.POINTER(c.c_char_p)];lib.sd_bus_close_unref.argtypes=[ptr];lib.sd_bus_close_unref.restype=ptr
 buses=[];probe=None
 def connection():
  bus=ptr();assert lib.sd_bus_new(c.byref(bus))>=0
  buses.append(bus);assert lib.sd_bus_set_address(bus,b'unix:path=/run/dbus/system_bus_socket')>=0;assert lib.sd_bus_set_bus_client(bus,1)>=0;assert lib.sd_bus_start(bus)>=0;return bus
 try:
  first=connection();assert lib.sd_bus_request_name(first,b'org.freedesktop.resolve1',0)>=0
  old=c.c_char_p();assert lib.sd_bus_get_unique_name(first,c.byref(old))>=0
  probe=subprocess.Popen([str(binary)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env=env)
  assert select.select([probe.stdout],[],[],3)[0];assert probe.stdout.readline()=='watch-gap\n'
  assert lib.sd_bus_release_name(first,b'org.freedesktop.resolve1')>=0
  second=connection();assert lib.sd_bus_request_name(second,b'org.freedesktop.resolve1',0)>=0
  new=c.c_char_p();assert lib.sd_bus_get_unique_name(second,c.byref(new))>=0;assert old.value!=new.value
  # The first connection still exists and retains its original unique name.
  still=c.c_char_p();assert lib.sd_bus_get_unique_name(first,c.byref(still))>=0 and still.value==old.value
  probe.stdin.write('replaced\n');probe.stdin.flush();output,error=probe.communicate(timeout=4);assert probe.returncode==0,(probe.returncode,output,error)
  return {'exit':probe.returncode,'stdout':output,'stderr':error,'old_unique':old.value.decode(),'new_unique':new.value.decode(),'old_connection_still_live':True}
 finally:
  if probe and probe.poll() is None:probe.kill();probe.communicate(timeout=3)
  for bus in reversed(buses):lib.sd_bus_close_unref(bus)
