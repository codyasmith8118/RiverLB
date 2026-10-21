"""Managed TLS assets, certificate rotation, protected keys and reusable persistence profiles."""
import copy
import http.server
import json
import signal
import sqlite3
import socket
import ssl
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path
from smoke import BINARY, free_port, wait_until

def run():
    class Handler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            body = b"managed TLS reached"
            self.send_response(200); self.send_header("Content-Length",str(len(body))); self.end_headers(); self.wfile.write(body)
        def log_message(self,*_): pass
    backend = http.server.ThreadingHTTPServer(("127.0.0.1",0),Handler)
    threading.Thread(target=backend.serve_forever,daemon=True).start()
    process = None
    admin,proxy = free_port(),free_port()
    scheme,token = "http",""
    opener = urllib.request.build_opener()
    def request(route,body=None,method=None,expected=200,auth=True,headers=None):
        h = {"Content-Type":"application/json","X-RiverLB-Request":"configure"}
        if auth: h["Cookie"]="riverlb_session="+token
        h.update(headers or {})
        req = urllib.request.Request(f"{scheme}://127.0.0.1:{admin}"+route,data=json.dumps(body).encode() if body is not None else None,method=method,headers=h)
        try: response = opener.open(req,timeout=10)
        except urllib.error.HTTPError as error: response=error
        with response:
            text=response.read().decode(); assert response.code==expected,(response.code,text)
            return text,response.headers
    def api(route,body=None,method=None,expected=200,**kwargs): return json.loads(request(route,body,method,expected,**kwargs)[0])
    def apply(config,expected=200):
        revision=api('/api/v1/config')['revision']
        return api('/api/v1/config',dict(revision=revision,config=config),'PUT',expected)
    try:
        with tempfile.TemporaryDirectory(prefix="riverlb-certs-") as folder:
            root=Path(folder); path=root/'config.toml'; db=path.with_suffix('.db')
            path.write_text(f'''management="127.0.0.1:{admin}"
connect_timeout_ms=1000
session_timeout_secs=10
health_interval_secs=1
max_connections=64
[[virtual_servers]]
name="app"
listen="127.0.0.1:{proxy}"
members=["127.0.0.1:{backend.server_port}"]
''')
            password="certificate-test-password"
            subprocess.run([BINARY,'admin','--database',db],input=(password+'\n').encode(),check=True,capture_output=True)
            with sqlite3.connect(db) as conn:
                conn.execute('DROP TABLE certificates'); conn.execute('UPDATE schema_version SET version=2')
            conn.close()
            pairs=[]
            for i in range(2):
                cert,key=root/f'cert{i}.pem',root/f'key{i}.pem'
                subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-keyout',key,'-out',cert],check=True,capture_output=True)
                pairs.append((cert.read_text(),key.read_text()))
            def start(log): return subprocess.Popen([BINARY,'serve','-c',path],stdout=log,stderr=log)
            with (root/'log').open('w+') as log:
                process=start(log)
                try: wait_until(lambda:request('/healthz',auth=False)[0]=='ok')
                except AssertionError:
                    log.seek(0); raise AssertionError(log.read())
                api('/api/v1/certificates',expected=401,auth=False)
                _,h=request('/api/v1/auth/login',dict(username='admin',password=password),auth=False)
                token=h['Set-Cookie'].split(';')[0].split('=',1)[1]
                for i,(cert,key) in enumerate(pairs):
                    api('/api/v1/certificates',dict(name=f'home-{i}',certificate=cert,private_key=key))
                api('/api/v1/certificates',dict(name='mismatch',certificate=pairs[0][0],private_key=pairs[1][1]),expected=422)
                api('/api/v1/certificates',dict(name='home-0',certificate=pairs[1][0],private_key=pairs[1][1]),expected=422)
                api('/api/v1/certificates',dict(name='csrf',certificate=pairs[0][0],private_key=pairs[0][1]),expected=403,headers={'X-RiverLB-Request':''})
                inventory=api('/api/v1/certificates'); assert len(inventory)==2
                assert inventory[0]['valid_now'] and 'localhost' in inventory[0]['dns_names']
                assert inventory[0]['fingerprint_sha256']!=inventory[1]['fingerprint_sha256']
                assert 'PRIVATE KEY' not in json.dumps(inventory)
                assert request('/api/v1/certificates/home-0/pem')[0]==pairs[0][0]
                config=api('/api/v1/config')['config']; config['virtual_servers'][0]['certificate']='home-0'
                config['persistence_profiles']=[dict(name='home-affinity',settings=dict(timeout_secs=60,max_entries=100,ipv4_prefix=24,ipv6_prefix=64,refresh_on_use=False))]
                config['virtual_servers'][0]['persistence_profile']='home-affinity'
                api('/api/v1/config/validate',config); apply(config)
                def traffic(i):
                    context=ssl.create_default_context(cadata=pairs[i][0])
                    with socket.create_connection(('127.0.0.1',proxy),timeout=3) as raw:
                        with context.wrap_socket(raw,server_hostname='localhost') as client:
                            assert ssl.DER_cert_to_PEM_cert(client.getpeercert(binary_form=True)).strip()==pairs[i][0].strip()
                            client.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n'); data=b''
                            while chunk:=client.recv(4096): data+=chunk
                            assert b'managed TLS reached' in data
                traffic(0)
                records=api('/api/v1/persistence')['virtual_servers'][0]
                assert records['total_records']==1 and records['records'][0]['source']=='127.0.0.0'
                assert records['profile']=='home-affinity'
                api('/api/v1/persistence/app/clear',{},expected=403,headers={'X-RiverLB-Request':''})
                assert api('/api/v1/persistence/app/clear',{})['cleared']==1
                assert api('/api/v1/persistence')['virtual_servers'][0]['total_records']==0
                api('/api/v1/certificates/home-0',{},'DELETE',409)
                bad=copy.deepcopy(config); bad['virtual_servers'][0]['certificate']='missing'
                api('/api/v1/config/validate',bad,expected=422); apply(bad,409)
                config['virtual_servers'][0]['certificate']='home-1'; apply(config); traffic(1)
                api('/api/v1/certificates/home-0',{},'DELETE')
                assert len(api('/api/v1/certificates'))==1
                # Managed management HTTPS must set Secure cookies and HTTPS origins.
                api('/api/v1/device-certificates',dict(name='home-1',certificate=pairs[1][0],private_key=pairs[1][1]))
                config['management_certificate']='home-1'; next_admin=free_port(); config['management']=f'127.0.0.1:{next_admin}'
                assert apply(config)['management_url']==f'https://127.0.0.1:{next_admin}'
                scheme,admin='https',next_admin
                opener=urllib.request.build_opener(urllib.request.HTTPSHandler(context=ssl.create_default_context(cadata=pairs[1][0])))
                _,h=request('/api/v1/auth/login',dict(username='admin',password=password),auth=False)
                assert 'Secure' in h['Set-Cookie']; token=h['Set-Cookie'].split(';')[0].split('=',1)[1]
                api('/api/v1/config/confirm',dict(revision=api('/api/v1/config')['revision']))
                assert 'PRIVATE KEY' not in request('/api/v1/config')[0]
                for certfile in root.glob('*.pem'): certfile.unlink() # In-memory/database assets work without source files.
                revision=api('/api/v1/config')['revision']; process.send_signal(signal.SIGTERM); process.wait(timeout=15); process=None
                exported=subprocess.run([BINARY,'export','--database',db],check=True,capture_output=True).stdout.decode()
                assert 'PRIVATE KEY' not in exported and 'home-1' in exported
                listed=subprocess.run([BINARY,'certificate','list','--database',db],check=True,capture_output=True).stdout.decode()
                assert 'PRIVATE KEY' not in listed and 'home-1' in listed
                assert subprocess.run([BINARY,'certificate','delete','--database',db,'--name','home-1'],capture_output=True).returncode!=0
                process=start(log); wait_until(lambda:api('/api/v1/config')['revision']==revision); traffic(1)
                assert api('/api/v1/persistence')['virtual_servers'][0]['settings']['ipv4_prefix']==24
                assert 'certificate imported' in request('/api/v1/audit')[0]
                print('PASS certificates/profiles: import, key mismatch, metadata, export secrecy, reference safety, TLS rotation/restart, management HTTPS, masked affinity and clearing')
    finally:
        if process and process.poll() is None: process.send_signal(signal.SIGTERM); process.wait(timeout=15)
        backend.shutdown();backend.server_close()

if __name__=='__main__': run()
