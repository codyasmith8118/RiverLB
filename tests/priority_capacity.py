"""Real primary/backup routing and admission bounds across reload/removal/re-add."""
from auth_helpers import bootstrap
from smoke import Backend,BINARY,free_port,wait_until
import copy
import json
import signal
import socket
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

def run():
    class HeldBackend(Backend):
        def reply(self,client):
            with client:
                client.settimeout(60)
                try:
                    data=b''
                    while chunk:=client.recv(4096):data+=chunk
                    if data:client.sendall(self.label+b':'+data)
                except OSError:pass
    primary,backup=HeldBackend(b'primary'),HeldBackend(b'backup')
    admin,proxy,other=free_port(),free_port(),free_port()
    process=None; held=[]
    def api(route='/api/v1/config',body=None,method=None,expected=200):
        req=urllib.request.Request(f'http://127.0.0.1:{admin}'+route,data=json.dumps(body).encode() if body is not None else None,method=method,headers={'Content-Type':'application/json','X-RiverLB-Request':'configure'})
        try:res=urllib.request.urlopen(req,timeout=10)
        except urllib.error.HTTPError as e:res=e
        with res:
            text=res.read().decode();assert res.code==expected,(res.code,text);return json.loads(text)
    def apply(config):return api(body=dict(revision=api()['revision'],config=config),method='PUT')
    def status():return next(v for v in api('/api/v1/status')['virtual_servers'] if v['name']=='service')
    def transfer(stream=None):
        with stream or socket.create_connection(('127.0.0.1',proxy),timeout=3) as client:
            client.sendall(b'data');client.shutdown(socket.SHUT_WR);result=b''
            while chunk:=client.recv(4096):result+=chunk
            return result
    def rejected():
        with socket.create_connection(('127.0.0.1',proxy),timeout=3) as client:
            try:client.sendall(b'data');assert client.recv(4096)==b''
            except (ConnectionResetError,BrokenPipeError):pass
    try:
        with tempfile.TemporaryDirectory(prefix='riverlb-capacity-') as folder:
            path=Path(folder)/'config.toml'
            a,b=f'127.0.0.1:{primary.port}',f'127.0.0.1:{backup.port}'
            path.write_text(f'''management="127.0.0.1:{admin}"
connect_timeout_ms=200
session_timeout_secs=60
health_interval_secs=1
max_connections=64
[[pools]]
name="primary-backup"
algorithm="round_robin"
members=["{a}","{b}"]
member_priorities={{"{a}"=100,"{b}"=10}}
member_connection_limits={{"{a}"=1,"{b}"=1}}
priority_group_min_active=1
[[virtual_servers]]
name="service"
listen="127.0.0.1:{proxy}"
default_pool="primary-backup"
connection_limit=2
[[virtual_servers]]
name="other"
listen="127.0.0.1:{other}"
default_pool="primary-backup"
''')
            bootstrap(BINARY,path)
            with (Path(folder)/'log').open('w+') as log:
                process=subprocess.Popen([BINARY,'serve','-c',path],stdout=log,stderr=log)
                wait_until(lambda:api()['revision']==1)
                assert transfer()==b'primary:data'
                wait_until(lambda:status()['admission_active']==0)
                first=socket.create_connection(('127.0.0.1',proxy),timeout=3);held.append(first)
                wait_until(lambda:status()['members'][0]['admission_active']==1)
                assert transfer()==b'backup:data'
                wait_until(lambda:status()['admission_active']==1)
                config=api()['config'];apply(config) # Keep the primary slot through hot apply.
                # Logical member statistics include the connection from the previous generation.
                assert status()['members'][0]['active']==1
                assert status()['members'][0]['total_connections']>=2
                assert status()['members'][0]['admission_active']==1
                with urllib.request.urlopen(f'http://127.0.0.1:{admin}/metrics',timeout=5) as response:
                    metrics=response.read().decode()
                assert 'riverlb_virtual_admission_active{virtual_server="service"} 1' in metrics
                assert 'riverlb_virtual_connection_limit{virtual_server="service"} 2' in metrics
                assert 'riverlb_member_priority' in metrics and 'riverlb_member_connection_limit' in metrics
                assert transfer()==b'backup:data'
                wait_until(lambda:status()['admission_active']==1)
                # Remove/re-add a server while its original connection is still alive.
                removed=copy.deepcopy(config);removed['virtual_servers']=removed['virtual_servers'][1:]
                apply(removed);apply(config)
                assert status()['members'][0]['admission_active']==1
                second=socket.create_connection(('127.0.0.1',proxy),timeout=3);held.append(second)
                wait_until(lambda:status()['admission_active']==2)
                rejected();assert status()['traffic']['rejected']>=1
                # Lowering limits never closes old sessions and must not allow new ones.
                config['virtual_servers'][0]['connection_limit']=1;apply(config)
                assert status()['admission_active']==2;rejected()
                assert transfer(second)==b'backup:data';held.remove(second)
                wait_until(lambda:status()['admission_active']==1);rejected()
                assert transfer(first)==b'primary:data';held.remove(first)
                wait_until(lambda:status()['admission_active']==0)
                assert transfer()==b'primary:data'
                wait_until(lambda:status()['admission_active']==0)
                primary_port=primary.port;primary.close()
                wait_until(lambda:not status()['members'][0]['healthy'])
                assert transfer()==b'backup:data'
                primary=HeldBackend(b'primary',primary_port)
                wait_until(lambda:status()['members'][0]['healthy'])
                assert transfer()==b'primary:data'
                wait_until(lambda:status()['admission_active']==0)
                # Administrative drain opens the backup group despite healthy primary probes.
                config['pools'][0]['draining_members']=[a];apply(config)
                assert transfer()==b'backup:data'
                config['pools'][0].pop('draining_members');apply(config)
                assert transfer()==b'primary:data'
                for mutate in [lambda c:c['pools'][0]['member_connection_limits'].update({a:0}),lambda c:c['pools'][0].update(priority_group_min_active=3),lambda c:c['virtual_servers'][0].update(member_priorities={a:1})]:
                    bad=copy.deepcopy(config);mutate(bad);api('/api/v1/config/validate',bad,expected=422)
                revision=api()['revision'];process.send_signal(signal.SIGTERM);process.wait(timeout=15);process=None
                process=subprocess.Popen([BINARY,'serve','-c',path],stdout=log,stderr=log)
                wait_until(lambda:api()['revision']==revision)
                assert transfer()==b'primary:data'
                assert api()['config']['pools'][0]['priority_group_min_active']==1
                print('PASS priority/capacity: primary/backup, member/virtual bounds, reload/removal/re-add, limit decrease, existing sessions, drain and restart')
    finally:
        for client in held:client.close()
        if process and process.poll() is None:process.send_signal(signal.SIGTERM);process.wait(timeout=15)
        primary.close();backup.close()

if __name__=='__main__':run()
