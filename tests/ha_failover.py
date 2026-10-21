"""Real two-node data-plane failover in isolated namespaces.

Pacemaker ownership/fencing decisions and SSH transport are deterministic test
fixtures. These tests do not qualify a real platform fencing controller or live Corosync.
"""
import copy
import json
import os
import signal
import socket
import subprocess
import tempfile
import time
import urllib.request
from pathlib import Path
from smoke import BINARY, wait_until
from auth_helpers import bootstrap, management_tls_fixture

IP='/usr/sbin/ip'
ROOT=Path(__file__).resolve().parents[1]


def run():
    parent=os.environ.get('RIVERLB_TEST_PARENT_NETNS')
    if parent is None:parent=os.readlink('/proc/1/ns/net')
    assert os.readlink('/proc/self/ns/net') != parent
    assert {l['ifname'] for l in json.loads(subprocess.check_output([IP,'-j','link','show']))}=={'lo'}
    subprocess.run([IP,'link','set','lo','up'],check=True)
    subprocess.run([IP,'link','add','bridge0','type','bridge'],check=True)
    subprocess.run([IP,'link','set','bridge0','address','02:00:00:00:ff:fe'],check=True)
    subprocess.run([IP,'link','set','bridge0','up'],check=True)
    for family,address in [('', '192.0.2.254/24'),('-6','2001:db8:100::254/64')]:
        subprocess.run([IP,*([family]if family else[]),'address','add',address,'dev','bridge0',*(['nodad']if family else[])],check=True)
    nodes={};processes=[]
    try:
        with tempfile.TemporaryDirectory(prefix='riverlb-ha-') as directory:
            folder=Path(directory);authority=folder/'authority.json'
            cert,key,tls_context=management_tls_fixture(folder,['192.0.2.10','192.0.2.20'])
            def set_authority(value):
                temporary=authority.with_suffix('.new');temporary.write_text(value);temporary.replace(authority)
            set_authority(json.dumps(dict(quorate=False,fencing=True,owner=None)))
            authority_program=folder/'authority'
            authority_program.write_text('#!/usr/bin/python3\nimport pathlib\nprint(pathlib.Path('+repr(str(authority))+').read_text())\n');authority_program.chmod(0o700)
            transport=folder/'ssh'
            # Strict transport arguments are checked; only the encryption layer is mocked.
            transport.write_text('''#!/usr/bin/python3
import sys,subprocess
args=sys.argv[1:]
assert args[:2]==['-F','/dev/null']
assert 'StrictHostKeyChecking=yes' in args
assert any(a.startswith('UserKnownHostsFile=')for a in args)
command=args[-1].split(' ')
result=subprocess.run(command,input=sys.stdin.buffer.read(),capture_output=True)
sys.stdout.buffer.write(result.stdout);sys.exit(result.returncode)
''');transport.chmod(0o700)
            # Backend remains alive across traffic-owner changes.
            backend_code='''import http.server,socketserver
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  body=(self.server.label+' '+self.path).encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
 def log_message(self,*args):pass
class Server(socketserver.ThreadingTCPServer):allow_reuse_address=True
import threading
for port,label in [(8001,'one'),(8002,'two')]:
 server=Server(('192.0.2.254',port),Handler);server.label=label;threading.Thread(target=server.serve_forever,daemon=True).start()
def echo(client):
 with client:
  while True:
   data=client.recv(4096)
   if not data:return
   client.sendall(data)
def echo_server():
 import socket
 listener=socket.socket();listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1);listener.bind(('192.0.2.254',9001));listener.listen()
 while True:
  client,_=listener.accept();threading.Thread(target=echo,args=(client,),daemon=True).start()
threading.Thread(target=echo_server,daemon=True).start()
threading.Event().wait()
''' 
            backend=subprocess.Popen(['python3','-c',backend_code]);processes.append(backend)
            for letter,last,device in [('a',10,'eth1'),('b',20,'eth9')]:
                node=folder/letter;node.mkdir();control_socket=node/'ha.sock';config=node/'config.toml';settings=node/'ha.json';log=node/'log'
                config.write_text(f'''management="192.0.2.{last}:18090"
management_tls={{certificate="{cert}",private_key="{key}"}}
connect_timeout_ms=500
session_timeout_secs=60
health_interval_secs=1
max_connections=100
[[virtual_servers]]
name="web"
listen="192.0.2.70:8080"
algorithm="round_robin"
ingress_vlan="external"
persistence={{timeout_secs=0,max_entries=1000}}
http={{cookie={{method="insert",name="HA_BACKEND",ttl_secs=60,max_entries=1000}}}}
members=["192.0.2.254:8001","192.0.2.254:8002"]
[[virtual_servers]]
name="web-source"
listen="192.0.2.70:8081"
algorithm="round_robin"
ingress_vlan="external"
persistence={{timeout_secs=60,max_entries=1000}}
http={{}}
members=["192.0.2.254:8001","192.0.2.254:8002"]
[[virtual_servers]]
name="tcp"
listen="192.0.2.70:9000"
algorithm="round_robin"
ingress_vlan="external"
members=["192.0.2.254:9001"]
[[virtual_servers]]
name="web-v6"
listen="[2001:db8:100::70]:8080"
algorithm="round_robin"
ingress_vlan="external"
members=["192.0.2.254:8001"]
[[network.vlans]]
name="external"
interface="{device}"
[[network.self_ips]]
name="local"
address="192.0.2.{last}/24"
vlan="external"
[[network.self_ips]]
name="local-v6"
address="2001:db8:100::{last}/64"
vlan="external"
[[network.self_ips]]
name="external-floating"
address="192.0.2.69/24"
vlan="external"
[[network.self_ips]]
name="external-floating-v6"
address="2001:db8:100::69/64"
vlan="external"
''')
                bootstrap(BINARY,config)
                if letter=='b':subprocess.run([BINARY,'admin','--database',str(config.with_suffix('.db'))],input=b'fixture-node-b-password-123\n',capture_output=True,check=True)
                ha=dict(cluster_id='test',node_id='riverlb-'+letter,peer_id='riverlb-'+('b'if letter=='a'else'a'),socket=str(control_socket),state_file=str(node/'state.json'),authority=str(authority_program),floating_self_ips=['external-floating','external-floating-v6'],ssh_target='root@192.0.2.'+str(20 if letter=='a'else 10),ssh_program=str(transport),ssh_identity=str(node/'identity'),ssh_known_hosts=str(node/'known-hosts'),peer_socket=str(folder/('b'if letter=='a'else'a')/'ha.sock'),peer_binary=str(Path(BINARY).resolve()),sync_interval_secs=1,max_sync_age_secs=120)
                settings.write_text(json.dumps(ha));settings.chmod(0o600)
                nodes[letter]=dict(folder=node,config=config,settings=settings,socket=control_socket,log=log,device=device,last=last)

            def namespace(letter):
                n=nodes[letter];holder=subprocess.Popen(['unshare','-n','sleep','600']);n['holder']=holder;processes.append(holder)
                wait_until(lambda:os.readlink(f'/proc/{holder.pid}/ns/net')!=os.readlink('/proc/self/ns/net'))
                subprocess.run([IP,'link','add','host-'+letter,'type','veth','peer','name',n['device']],check=True)
                subprocess.run([IP,'link','set',n['device'],'netns',str(holder.pid)],check=True)
                subprocess.run([IP,'link','set','host-'+letter,'master','bridge0'],check=True);subprocess.run([IP,'link','set','host-'+letter,'up'],check=True)
                for device in ['lo',n['device']]:subprocess.run(['nsenter','-t',str(holder.pid),'-n','--',IP,'link','set',device,'up'],check=True)

            def start(letter):
                n=nodes[letter];log=n['log'].open('a');process=subprocess.Popen(['nsenter','-t',str(n['holder'].pid),'-n','--',BINARY,'serve','-c',n['config'],'--ha-config',n['settings']],stdout=log,stderr=log);log.close();n['process']=process;processes.append(process)
                def ready():
                    if process.poll()is not None:raise RuntimeError(n['log'].read_text())
                    try:return n['socket'].exists()and ha(letter,'status')['role']=='standby'
                    except AssertionError:return False
                wait_until(ready)

            def ha(letter,action,bundle=None,success=True):
                command=[BINARY,'ha','--socket',str(nodes[letter]['socket']),action]
                output=subprocess.run(command,input=json.dumps(bundle).encode()if bundle else None,capture_output=True,timeout=65)
                if success:assert output.returncode==0,output.stderr;return json.loads(output.stdout)
                assert output.returncode!=0,output.stdout;return output.stderr.decode()

            import http.cookiejar
            api_clients={}
            def api(letter,path,body=None,method=None,expected=200):
                client=api_clients.get(letter)
                if client is None:
                    client=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPSHandler(context=tls_context),urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
                    password='fixture-node-b-password-123'if letter=='b'else'fixture-password-only-123'
                    client.open(urllib.request.Request(f'https://192.0.2.{nodes[letter]["last"]}:18090/api/v1/auth/login',data=json.dumps(dict(username='admin',password=password)).encode(),headers={'Content-Type':'application/json','X-RiverLB-Request':'configure'})).close()
                    api_clients[letter]=client
                request=urllib.request.Request(f'https://192.0.2.{nodes[letter]["last"]}:18090/api/v1/'+path,data=json.dumps(body).encode()if body is not None else None,method=method,headers={'Content-Type':'application/json','X-RiverLB-Request':'configure'})
                try:response=client.open(request,timeout=5)
                except urllib.error.HTTPError as error:response=error
                with response:
                    payload=json.load(response);assert response.code==expected,(response.code,payload);return payload

            def addresses(letter):
                n=nodes[letter];values=json.loads(subprocess.check_output(['nsenter','-t',str(n['holder'].pid),'-n','--',IP,'-j','address','show']))
                return {a['local']for d in values for a in d['addr_info']}

            def fetch(ip='192.0.2.70',path='/',cookie=None,port=8080):
                host='['+ip+']'if ':'in ip else ip
                request=urllib.request.Request(f'http://{host}:{port}'+path,headers={'Cookie':cookie}if cookie else{})
                opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
                with opener.open(request,timeout=3)as response:return response.read().decode(),response.headers.get('Set-Cookie')

            for letter in nodes:namespace(letter);start(letter)
            for letter in nodes:
                assert '192.0.2.70'not in addresses(letter)and'192.0.2.69'not in addresses(letter)
                assert '2001:db8:100::70'not in addresses(letter)
            ha('a','seed')
            assert 'quorum' in ha('a','activate',success=False)
            set_authority(json.dumps(dict(quorate=True,fencing=False,owner=None)))
            assert 'fencing' in ha('a','activate',success=False)
            set_authority(json.dumps(dict(quorate=True,fencing=True,owner=None)))
            ha('a','activate');set_authority(json.dumps(dict(quorate=True,fencing=True,owner='riverlb-a')))
            assert ha('a','status')['data_ready']
            assert '192.0.2.70'in addresses('a')and'192.0.2.70'not in addresses('b')
            assert 'another cluster owner' in ha('b','activate',success=False)
            source_backend=fetch(path='/source',port=8081)[0].split(' ')[0]
            for letter in nodes:
                api(letter,'device-certificates/self-signed',dict(name='device-local',names=['node-'+letter+'.test'],days=30))
            local_fingerprint=api('b','device-certificates')[0]['fingerprint_sha256']
            api('b','administrators',dict(username='local-helper',action='create',current_password='fixture-node-b-password-123',new_password='local-helper-password-123'))
            assert 'local-helper'in api('b','administrators')['administrators']
            assert 'local-helper'not in api('a','administrators')['administrators']

            api('a','certificates/self-signed',dict(name='shared-traffic',names=['application.test'],days=30))
            api('a','certificates/requests',dict(name='shared-csr',names=['pending.test']))
            current=api('a','config');current['config']['virtual_servers'][0]['description']='Replicated configuration'
            api('a','config',dict(revision=current['revision'],config=current['config']),method='PUT')
            ha('a','sync')
            assert api('b','config')['config']['virtual_servers'][0]['description']=='Replicated configuration'
            assert api('b','config')['config']['management']=='192.0.2.20:18090'
            assert api('b','config')['config']['network']['vlans'][0]['interface']=='eth9'
            assert api('b','certificates')[0]['name']=='shared-traffic'
            assert api('b','certificates/requests')[0]['name']=='shared-csr'
            assert api('b','device-certificates')[0]['fingerprint_sha256']==local_fingerprint
            assert 'local-helper'in api('b','administrators')['administrators']
            api('b','config',dict(revision=api('b','config')['revision'],config=current['config']),method='PUT',expected=409)
            # Keep an obsolete VIP in the ownership journal after a committed edit.
            change=api('a','config');change['config']['virtual_servers'][0]['listen']='192.0.2.71:8080'
            api('a','config',dict(revision=change['revision'],config=change['config']),method='PUT')
            change=api('a','config');change['config']['virtual_servers'][0]['listen']='192.0.2.70:8080'
            api('a','config',dict(revision=change['revision'],config=change['config']),method='PUT');ha('a','sync')
            assert nodes['a']['folder'].joinpath('state.ownership.json').exists()
            # Applying config clears source persistence; create new assignments now.
            source_backend=fetch(path='/source',port=8081)[0].split(' ')[0]
            body,cookie=fetch(path='/before');cookie=cookie.split(';')[0];backend_name=body.split(' ')[0]
            assert fetch('2001:db8:100::70')[0].startswith('one')
            # Authenticated HA group administration is available on standby as well.
            groups={}
            for letter in ['a','b']:
                groups[letter]=dict(cluster_id='test',node_id='riverlb-'+letter,peer_id='riverlb-'+('b'if letter=='a'else'a'),
                    local_address='192.0.2.'+('10'if letter=='a'else'20'),peer_address='192.0.2.'+('20'if letter=='a'else'10'),
                    automatic_sync=False,floating_self_ips=['external-floating','external-floating-v6'],
                    fencing_resources=['fence-node-a','fence-node-b'])
                result=api(letter,'ha',groups[letter],method='PUT');assert result['restart_required']is False,result
                assert api(letter,'ha')['settings']['automatic_sync']is False
            # Manual mode keeps checkpoints fresh without sending a pending traffic edit.
            before=api('b','config')['config']['virtual_servers'][0]['description']
            changed=api('a','config');changed['config']['virtual_servers'][0]['description']='Manual pending'
            api('a','config',dict(revision=changed['revision'],config=changed['config']),method='PUT')
            time.sleep(3)
            assert api('b','config')['config']['virtual_servers'][0]['description']==before
            assert api('a','ha')['configuration_sync']=='pending changes'
            status=api('a','status')['ha'];assert status['configuration_sync']=='pending changes'and status['local_configuration_acknowledged']is False;assert status['hostname']
            api('a','ha/action',dict(action='sync'))
            assert api('b','config')['config']['virtual_servers'][0]['description']=='Manual pending'
            assert api('a','ha')['configuration_sync']=='synchronized'
            assert api('a','status')['ha']['local_configuration_acknowledged']is True
            bad=copy.deepcopy(groups['a']);bad['peer_id']='different-peer'
            api('a','ha',bad,method='PUT',expected=422)
            bad=copy.deepcopy(groups['b']);bad['fencing_resources']=['fence-node-a','fence-node-a']
            api('b','ha',bad,method='PUT',expected=422)
            # Manual configuration sync must never suspend ownership protection.
            # Exercise each authority failure with real VIPs and an open session.
            for invalid in [dict(quorate=False,fencing=True,owner='riverlb-a'),
                            dict(quorate=True,fencing=False,owner='riverlb-a'),
                            dict(quorate=True,fencing=True,owner='riverlb-b')]:
                assert api('a','ha')['settings']['automatic_sync']is False
                connection=socket.create_connection(('192.0.2.70',9000),timeout=3)
                connection.sendall(b'manual-sync');assert connection.recv(100)==b'manual-sync'
                set_authority(json.dumps(invalid))
                wait_until(lambda:ha('a','status')['role']=='standby')
                for letter in ['a','b']:
                    assert not {'192.0.2.69','192.0.2.70','2001:db8:100::69','2001:db8:100::70'}&addresses(letter)
                assert {'192.0.2.10','2001:db8:100::10'}<=addresses('a')
                connection.settimeout(3)
                try:assert connection.recv(100)==b''
                except ConnectionResetError:pass
                finally:connection.close()
                set_authority(json.dumps(dict(quorate=True,fencing=True,owner='riverlb-a')))
                ha('a','activate')
                assert ha('a','status')['data_ready']
                assert fetch(path='/manual-recovery')[0].startswith(('one','two'))
            for letter in ['a','b']:
                groups[letter]['automatic_sync']=True
                assert api(letter,'ha',groups[letter],method='PUT')['restart_required']is False
            changed=api('a','config');changed['config']['virtual_servers'][0]['description']='Automatic edit'
            api('a','config',dict(revision=changed['revision'],config=changed['config']),method='PUT')
            wait_until(lambda:api('b','config')['config']['virtual_servers'][0]['description']=='Automatic edit')
            # Capture an old/new VIP transaction after the additional configuration edits.
            change=api('a','config');change['config']['virtual_servers'][0]['listen']='192.0.2.71:8080'
            api('a','config',dict(revision=change['revision'],config=change['config']),method='PUT')
            change=api('a','config');change['config']['virtual_servers'][0]['listen']='192.0.2.70:8080'
            api('a','config',dict(revision=change['revision'],config=change['config']),method='PUT')
            # Traffic applies reset source assignments; create assignments after the sync-mode edits.
            source_backend=fetch(path='/source',port=8081)[0].split(' ')[0]
            body,cookie=fetch(path='/before');cookie=cookie.split(';')[0];backend_name=body.split(' ')[0]
            # Explicit sync exercises the same receiver as periodic SSH synchronization.
            ha('a','sync');wait_until(lambda:ha('b','status')['peer_revision']is not None)
            exported=ha('a','export');replicas={p['virtual_server']:p for p in exported['persistence']};assert replicas['web-source']['source'];assert replicas['web']['cookies']
            assert nodes['b']['folder'].joinpath('state.json').stat().st_mode&0o077==0
            # Durable checkpoint restores persistence before the next sync after restart.
            nodes['b']['process'].terminate();assert nodes['b']['process'].wait(timeout=15)==0
            api_clients.pop('b',None);start('b')
            assert ha('b','status')['peer_revision']is not None
            expired=copy.deepcopy(exported);expired['created']=int(time.time())-121
            assert 'expired' in ha('b','receive',expired,success=False)
            wrong=copy.deepcopy(exported);wrong['cluster_id']='wrong'
            assert 'identity mismatch' in ha('b','receive',wrong,success=False)
            assert 'confirmed active owner' in ha('a','receive',dict(exported,source_id='riverlb-b'),success=False)
            # Simulate an orphan address from the prior transaction, then a process
            # crash without destroying its namespace. Restart must withdraw old
            # and current floating ownership before exposing standby control.
            subprocess.run(['nsenter','-t',str(nodes['a']['holder'].pid),'-n','--',IP,'address','add','192.0.2.71/32','dev','eth1'],check=True)
            nodes['a']['process'].kill();nodes['a']['process'].wait(timeout=10);api_clients.pop('a',None);start('a')
            assert '192.0.2.71'not in addresses('a')and'192.0.2.70'not in addresses('a')
            ha('a','activate');ha('a','sync')
            # Planned handoff cancels established TCP sessions and waits for release.
            connection=socket.create_connection(('192.0.2.70',9000),timeout=3)
            connection.sendall(b'before-demotion');assert connection.recv(100)==b'before-demotion'
            ha('a','deactivate');connection.settimeout(3)
            try:assert connection.recv(100)==b''
            except ConnectionResetError:pass
            connection.close();assert '192.0.2.70'not in addresses('a')
            set_authority(json.dumps(dict(quorate=True,fencing=True,owner='riverlb-b')))
            ha('b','activate');ha('b','sync')
            assert fetch(path='/planned',cookie=cookie)[0].split(' ')[0]==backend_name
            ha('b','deactivate');assert '192.0.2.70'not in addresses('b')
            set_authority(json.dumps(dict(quorate=True,fencing=True,owner='riverlb-a')))
            ha('a','activate');ha('a','sync')
            # Partition/paused owner: promotion remains blocked until fencing confirms ownership release.
            nodes['a']['process'].send_signal(signal.SIGSTOP)
            assert 'another cluster owner' in ha('b','activate',success=False)
            nodes['a']['process'].kill();nodes['a']['process'].wait(timeout=10)
            nodes['a']['holder'].kill();nodes['a']['holder'].wait(timeout=10)
            # In-flight fixture transport children can briefly retain the old
            # namespace. Confirm its link is gone before declaring power off.
            wait_until(lambda:'host-a'not in {l['ifname']for l in json.loads(subprocess.check_output([IP,'-j','link','show']))})
            set_authority(json.dumps(dict(quorate=True,fencing=True,owner='riverlb-b')))
            ha('b','activate');assert ha('b','status')['data_ready']
            assert '192.0.2.70'in addresses('b')and'2001:db8:100::70'in addresses('b')
            # No neighbor-cache flush: announcements must repair the old owner's MAC.
            assert fetch(path='/after',cookie=cookie)[0].split(' ')[0]==backend_name
            assert fetch(path='/source-after',port=8081)[0].split(' ')[0]==source_backend
            assert fetch('2001:db8:100::70')[0].startswith('one')
            namespace('a');start('a');ha('b','sync');assert '192.0.2.70'not in addresses('a')
            assert 'another cluster owner' in ha('a','activate',success=False)
            # Quorum loss withdraws IPs and listeners automatically.
            set_authority(json.dumps(dict(quorate=False,fencing=True,owner='riverlb-b')))
            wait_until(lambda:ha('b','status')['role']=='standby')
            assert '192.0.2.70'not in addresses('b')and'2001:db8:100::70'not in addresses('b')
            print('PASS HA failover: GUI group API, manual/automatic sync, authority-loss withdrawal in manual mode, real two-node IPv4/IPv6 ownership, quorum/fencing gates, paused owner, failover without ARP/NDP flush, encrypted-transport arguments, source/cookie replication, rejoin and quorum-loss withdrawal (cluster/SSH fixtures)')
    finally:
        for process in reversed(processes):
            if process.poll()is None:
                process.kill();process.wait(timeout=10)


if __name__=='__main__':run()
