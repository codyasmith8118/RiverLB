"""Real TCP/HTTP/UDP churn, hard diagnostic bounds and privileged HTTPS inspection."""
import asyncio
import concurrent.futures
import copy
import http.client
import json
import os
from pathlib import Path
import resource
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.parse
from auth_release import BINARY, PASSWORD, free_port


class Backends:
    def __init__(self):
        self.loop=asyncio.new_event_loop();self.thread=threading.Thread(target=self.loop.run_forever,daemon=True);self.thread.start()
        async def echo(reader,writer):
            try:
                while data:=await reader.read(65536):writer.write(data);await writer.drain()
            except (OSError,asyncio.CancelledError):pass
            finally:writer.close()
        async def http(reader,writer):
            try:
                while await reader.readuntil(b'\r\n\r\n'):
                    writer.write(b'HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok');await writer.drain()
            except (OSError,asyncio.IncompleteReadError,asyncio.CancelledError):pass
            finally:writer.close()
        class UDP(asyncio.DatagramProtocol):
            def connection_made(self,transport):self.transport=transport
            def datagram_received(self,data,address):self.transport.sendto(data,address)
        async def start():
            self.tcp=await asyncio.start_server(echo,'127.0.0.1',0,backlog=8192)
            self.http=await asyncio.start_server(http,'127.0.0.1',0,backlog=8192)
            self.udp,_=await self.loop.create_datagram_endpoint(UDP,local_addr=('127.0.0.1',0))
            return self.tcp.sockets[0].getsockname()[1],self.http.sockets[0].getsockname()[1],self.udp.get_extra_info('sockname')[1]
        self.ports=asyncio.run_coroutine_threadsafe(start(),self.loop).result(5)
    def close(self):
        async def close():
            self.tcp.close();self.http.close();self.udp.close()
            tasks=[t for t in asyncio.all_tasks() if t is not asyncio.current_task()]
            for task in tasks:task.cancel()
            await asyncio.gather(*tasks,return_exceptions=True)
        asyncio.run_coroutine_threadsafe(close(),self.loop).result(10);self.loop.call_soon_threadsafe(self.loop.stop);self.thread.join(5);self.loop.close()


def run():
    soft,hard=resource.getrlimit(resource.RLIMIT_NOFILE)
    if soft<16384:resource.setrlimit(resource.RLIMIT_NOFILE,(min(hard,16384),hard))
    assert resource.getrlimit(resource.RLIMIT_NOFILE)[0]>=16384,'Flow fixture requires 16384 file descriptors'
    backend=Backends();process=None;clients=[];datagrams=[];frontend=None
    secret=b'payload-password-and-cookie-not-for-inspection'
    with tempfile.TemporaryDirectory(prefix='riverlb-flow-inspection-') as folder:
        root=Path(folder);config=root/'config.toml';cert,key=root/'cert.pem',root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=fixture',
            '-addext','subjectAltName=IP:127.0.0.1','-addext','basicConstraints=critical,CA:FALSE','-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
        context=ssl.create_default_context(cafile=cert)
        admin,tcp,http_port,udp,idle=[free_port() for _ in range(5)]
        config.write_text(f'''management="127.0.0.1:{admin}"
connect_timeout_ms=1000
session_timeout_secs=300
health_interval_secs=1
max_connections=10000
[management_tls]
certificate="{cert}"
private_key="{key}"
[[health_monitors]]
name="udp-ready"
kind="udp"
send="probe"
receive="probe"
interval_secs=1
timeout_ms=300
rise=1
fall=1
[[virtual_servers]]
name="tcp"
listen="127.0.0.1:{tcp}"
members=["127.0.0.1:{backend.ports[0]}"]
[[virtual_servers]]
name="http"
listen="127.0.0.1:{http_port}"
members=["127.0.0.1:{backend.ports[1]}"]
[virtual_servers.http]
[[virtual_servers]]
name="udp"
server_type="udp"
listen="127.0.0.1:{udp}"
members=["127.0.0.1:{backend.ports[2]}"]
monitor="udp-ready"
udp_idle_timeout_secs=120
[[virtual_servers]]
name="idle"
server_type="udp"
listen="127.0.0.1:{idle}"
members=["127.0.0.1:{backend.ports[2]}"]
monitor="udp-ready"
udp_idle_timeout_secs=3
''')
        subprocess.run([BINARY,'admin','--database',config.with_suffix('.db')],input=PASSWORD+'\n',text=True,check=True,capture_output=True)
        admin_token=None
        def api(path='/api/v1/config',body=None,method=None,token=None,bearer=False,expected=200,retry=True):
            for attempt in range(10):
                c=http.client.HTTPSConnection('127.0.0.1',admin,context=context,timeout=15)
                headers={'Content-Type':'application/json','X-RiverLB-Request':'configure'}
                if token is None:token=admin_token
                if token:headers['Authorization' if bearer else 'Cookie']=('Bearer ' if bearer else 'riverlb_session=')+token
                try:
                    c.request(method or ('POST' if body is not None else 'GET'),path,None if body is None else json.dumps(body),headers)
                    r=c.getresponse();data=r.read();status=r.status;response_headers=dict(r.getheaders())
                finally:c.close()
                if expected==200 and status in (429,503) and retry:time.sleep(1.05);continue
                assert status==expected,(path,status,data[:500])
                return (json.loads(data) if data.startswith((b'{',b'[')) else data.decode()),response_headers
            raise AssertionError('Inspection stayed busy')
        def get(path='/api/v1/config',**kw):return api(path,**kw)[0]
        def inspect(**query):return get('/api/v1/connections?'+urllib.parse.urlencode(query))
        def wait(check,seconds=15):
            deadline=time.monotonic()+seconds
            while time.monotonic()<deadline:
                if check():return
                time.sleep(.05)
            raise AssertionError('Flow fixture condition timed out')
        def start():
            nonlocal process,admin_token
            with (root/'daemon.log').open('ab') as log:process=subprocess.Popen([BINARY,'serve','-c',config,'--external-network'],stdout=log,stderr=log)
            deadline=time.monotonic()+20
            while time.monotonic()<deadline:
                try:
                    _,headers=api('/api/v1/auth/login',{'username':'admin','password':PASSWORD})
                    admin_token=headers['set-cookie'].split(';')[0].split('=',1)[1];return
                except (OSError,http.client.HTTPException):time.sleep(.05)
            raise AssertionError(('Flow daemon startup failed',(root/'daemon.log').read_text()[-2000:]))
        def tcp_client(source='127.0.0.1'):
            s=socket.create_connection(('127.0.0.1',tcp),timeout=5,source_address=(source,0));clients.append(s);return s
        def exchange(s):s.sendall(secret);assert s.recv(len(secret))==secret
        def datagram(port):
            s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);s.bind(('127.0.0.1',0));s.settimeout(5);datagrams.append(s)
            s.sendto(secret,('127.0.0.1',port));assert s.recv(4096)==secret;return s
        try:
            start();wait(lambda:all(m['healthy'] for v in get('/api/v1/status')['virtual_servers'] for m in v['members']))
            get('/api/v1/connections',token='0'*64,expected=401)
            tokens={}
            for scope in ('monitoring','read','configure'):
                tokens[scope]=get('/api/v1/security/tokens',body={'name':scope,'scope':scope,'lifetime_secs':3600,'current_password':PASSWORD})['token']
                get('/api/v1/connections',token=tokens[scope],bearer=True,expected=403 if scope=='monitoring' else 200)
            for role in ('operator','read_only'):
                get('/api/v1/administrators',body={'username':role,'action':'create','role':role,'current_password':PASSWORD,'new_password':PASSWORD})
                _,headers=api('/api/v1/auth/login',{'username':role,'password':PASSWORD});session=headers['set-cookie'].split(';')[0].split('=',1)[1]
                get('/api/v1/connections',token=session,expected=403 if role=='read_only' else 200)
            get('/api/v1/connections',method='DELETE',expected=405)
            get('/api/v1/connections?limit=201',expected=400)
            get('/api/v1/connections?unknown=1',expected=400)
            frontend=http.client.HTTPConnection('127.0.0.1',http_port,timeout=5)
            frontend.request('GET','/private?secret='+secret.decode(),headers={'Authorization':'Bearer '+secret.decode(),'Cookie':'secret='+secret.decode()})
            assert frontend.getresponse().read()==b'ok'
            special=tcp_client('127.0.0.2');exchange(special)
            for _ in range(3499):tcp_client()
            for _ in range(1200):datagram(udp)
            wait(lambda:next(v for v in get('/api/v1/statistics')['virtual_servers'] if v['name']=='tcp')['traffic']['current']>=3500)
            time.sleep(1.1)
            first=inspect(limit=200);assert first['capacity']==4096 and 4000<=first['total']<=4096,first['total']
            assert first['admission_and_coverage']['observation_skipped_capacity']>0
            # Unobserved flows still forward correctly beyond the diagnostic cap.
            exchange(clients[-1]);exchange(special)
            ids=[];page=first;cursor=first['next_cursor']
            for s in clients[1:101]:s.close()
            while True:
                assert page['snapshot']==first['snapshot'] and page['total']==first['total']
                ids.extend(r['id'] for r in page['rows'])
                if page['next_cursor'] is None:break
                page=inspect(limit=200,cursor=page['next_cursor'])
            assert len(ids)==len(set(ids))==first['total']
            initial_cursor=cursor.split(':');initial_cursor[2]='0'
            replay=inspect(limit=200,cursor=':'.join(initial_cursor));assert replay['rows']==first['rows']
            get('/api/v1/connections?'+urllib.parse.urlencode({'cursor':cursor,'protocol':'udp'}),expected=400)
            for snapshot in (first,replay,page):
                text=json.dumps(snapshot);assert secret.decode()not in text and PASSWORD not in text and admin_token not in text
                for token in tokens.values():assert token not in text
                for row in snapshot['rows']:
                    assert set(row)=={'id','virtual_server','source','protocol','generation','previous_generation','state','age_ms','backend','backend_observation','backend_observed_age_ms','backend_available'}
            time.sleep(1.1)
            assert inspect(protocol='udp',backend=f'127.0.0.1:{backend.ports[2]}')['total']>0
            source=inspect(source='127.0.0.2')['rows'];assert len(source)==1 and source[0]['source']==f'127.0.0.2:{special.getsockname()[1]}'
            assert source[0]['state']=='forwarding' and source[0]['backend']==f'127.0.0.1:{backend.ports[0]}' and source[0]['age_ms']>0
            assert inspect(source='127.0.0.2',state='forwarding')['total']==1
            h=inspect(protocol='http')['rows'];assert len(h)==1 and h[0]['backend_observation']=='sampled_last_http_selection'
            assert h[0]['backend']==f'127.0.0.1:{backend.ports[1]}' and h[0]['state']=='http'
            session_file=root/'session';session_file.write_text(admin_token);session_file.chmod(0o600)
            output=subprocess.run([BINARY,'manage','--url',f'https://127.0.0.1:{admin}','--ca',cert,'--session-file',session_file,'connections','--protocol','http','--limit','1'],check=True,capture_output=True,text=True)
            assert json.loads(output.stdout)['result']['rows'][0]['protocol']=='http'
            # A cursor expires instead of mixing rows from another snapshot.
            time.sleep(5.2);get('/api/v1/connections?'+urllib.parse.urlencode({'cursor':cursor}),expected=410)
            limited=False
            for _ in range(25):
                try:api('/api/v1/connections',retry=False)
                except AssertionError as error:
                    if error.args[0][1]==503:continue
                    assert error.args[0][1]==429;limited=True;break
            assert limited
            time.sleep(1.1)
            old=inspect(source='127.0.0.2')['rows'][0]
            current=get();changed=copy.deepcopy(current['config']);changed['max_connections']=10001
            get(body={'revision':current['revision'],'config':changed},method='PUT')
            time.sleep(1.1);exchange(special)
            after=inspect(source='127.0.0.2')['rows'][0];assert after['id']==old['id'] and after['previous_generation'] and after['age_ms']>=old['age_ms']
            # UDP flows are closed by apply; a datagram creates a distinct new flow.
            datagrams[0].sendto(secret,('127.0.0.1',udp));assert datagrams[0].recv(4096)==secret
            time.sleep(1.1);new_udp=inspect(protocol='udp')['rows'];assert len(new_udp)==1 and not new_udp[0]['previous_generation']
            for s in clients:s.close()
            frontend.close();time.sleep(1.2)
            # New captures hide closed rows; admission counters preserve only fixed reasons.
            assert inspect(protocol='tcp')['total']==0
            current=get();limits=copy.deepcopy(current['config']);limits['max_connections']=1
            get(body={'revision':current['revision'],'config':limits},method='PUT')
            wait(lambda:all(m['healthy'] for v in get('/api/v1/status')['virtual_servers'] for m in v['members']))
            held=tcp_client();exchange(held)
            def denied(port):
                with socket.create_connection(('127.0.0.1',port),timeout=5) as rejected:
                    try:rejected.sendall(secret);assert rejected.recv(4096)==b''
                    except (ConnectionResetError,BrokenPipeError):pass
            denied(tcp);time.sleep(1.1)
            assert inspect()['admission_and_coverage']['global_limit']>0;exchange(held)
            current=get();limits=copy.deepcopy(current['config']);limits['max_connections']=10
            for v in limits['virtual_servers']:
                if v['name']in('tcp','http'):v['connection_limit']=1
            get(body={'revision':current['revision'],'config':limits},method='PUT')
            wait(lambda:all(m['healthy'] for v in get('/api/v1/status')['virtual_servers'] for m in v['members']))
            denied(tcp)
            frontend=http.client.HTTPConnection('127.0.0.1',http_port,timeout=5)
            frontend.request('GET','/');assert frontend.getresponse().read()==b'ok'
            denied(http_port);time.sleep(1.1)
            counters=inspect()['admission_and_coverage']
            assert counters['virtual_limit']>0 and counters['no_eligible_backend_or_capacity']>0
            held.close();frontend.close()
            # Observe a short UDP flow before and after its actual idle deadline.
            datagram(idle);time.sleep(1.1)
            assert inspect(virtual_server='idle')['total']==1
            time.sleep(3.1);assert inspect(virtual_server='idle')['total']==0
            special_new=tcp_client();exchange(special_new)
            datagram(udp)
            time.sleep(1.1);old_cursor=inspect(limit=1)['next_cursor'];assert old_cursor
            for s in clients:s.close()
            process.send_signal(signal.SIGTERM);process.wait(timeout=20);process=None
            for s in datagrams:s.close()
            start();wait(lambda:all(m['healthy'] for v in get('/api/v1/status')['virtual_servers'] for m in v['members']))
            assert inspect()['total']==0
            if old_cursor:get('/api/v1/connections?'+urllib.parse.urlencode({'cursor':old_cursor}),expected=410)
            print('PASS flow inspection: 3500 TCP + 1200 UDP + HTTP, cap/coverage, immutable pagination under churn, filtering, cursor expiry/restart, RBAC/scopes, payload/credential redaction, rate limits, apply/drain/disconnect/UDP idle cleanup and verified HTTPS CLI')
        finally:
            if process is not None and process.poll() is None:process.send_signal(signal.SIGTERM);process.wait(timeout=20)
            for s in clients+datagrams:s.close()
            if frontend is not None:frontend.close()
            backend.close()


if __name__=='__main__':run()
