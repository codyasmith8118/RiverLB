"""Verified backend TLS, opaque forwarding, health, timeout, reload and durable profiles."""
from auth_helpers import bootstrap
from smoke import BINARY, free_port, wait_until
import copy
import http.server
import json
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import urllib.error
import urllib.request
from pathlib import Path

def run():
    class Handler(http.server.BaseHTTPRequestHandler):
        sources=[]
        def handle(self):
            try:super().handle()
            except (BrokenPipeError,ConnectionResetError,ssl.SSLError):pass
        def do_GET(self):
            self.sources.append(self.client_address[0])
            body=b'backend TLS verified'
            self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
        def log_message(self,*_):pass
    process = backend = None
    admin,proxy=free_port(),free_port()
    def api(route='/api/v1/config',body=None,method=None,expected=200):
        req=urllib.request.Request(f'http://127.0.0.1:{admin}'+route,data=json.dumps(body).encode() if body is not None else None,method=method,headers={'Content-Type':'application/json','X-RiverLB-Request':'configure'})
        try: response=urllib.request.urlopen(req,timeout=10)
        except urllib.error.HTTPError as error:response=error
        with response:
            text=response.read().decode();assert response.code==expected,(response.code,text);return json.loads(text)
    def apply(config): return api(body={'revision':api()['revision'],'config':config},method='PUT')
    def member():return api('/api/v1/status')['virtual_servers'][0]['members'][0]
    try:
        with tempfile.TemporaryDirectory(prefix='riverlb-server-tls-') as folder:
            root=Path(folder);path=root/'config.toml';cert,key=root/'cert.pem',root/'key.pem'
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost,IP:127.0.0.1','-addext','basicConstraints=critical,CA:FALSE','-keyout',key,'-out',cert],check=True,capture_output=True)
            backend=http.server.ThreadingHTTPServer(('127.0.0.1',0),Handler)
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
            names=[];context.set_servername_callback(lambda _,name,__:names.append(name))
            backend.socket=context.wrap_socket(backend.socket,server_side=True)
            threading.Thread(target=backend.serve_forever,daemon=True).start()
            path.write_text(f'''management="127.0.0.1:{admin}"
connect_timeout_ms=500
session_timeout_secs=5
health_interval_secs=1
max_connections=64
[[server_tls_profiles]]
name="home-https"
server_name="localhost"
ca_certificate="{cert}"
[[virtual_servers]]
name="app"
listen="127.0.0.1:{proxy}"
server_tls_profile="home-https"
algorithm="weighted_least_connections"
members=["127.0.0.1:{backend.server_port}"]
''')
            bootstrap(BINARY,path)
            with (root/'log').open('w+') as log:
                process=subprocess.Popen([BINARY,'serve','-c',path],stdout=log,stderr=log)
                wait_until(lambda:api()['revision']==1);wait_until(lambda:member()['healthy'])
                def transfer(tls=False):
                    with socket.create_connection(('127.0.0.1',proxy),timeout=3) as raw:
                        client=ssl.create_default_context(cafile=cert).wrap_socket(raw,server_hostname='localhost') if tls else raw
                        with client:
                            client.sendall(b'GET / HTTP/1.0\r\nHost: localhost\r\n\r\n');data=b''
                            while chunk:=client.recv(4096):data+=chunk
                            assert b'backend TLS verified' in data,data
                transfer();assert 'localhost' in names
                wait_until(lambda:member()['bytes_to_client']>0)
                config=api()['config']
                by_ip=copy.deepcopy(config);by_ip['server_tls_profiles'][0]['server_name']=''
                apply(by_ip);wait_until(lambda:member()['healthy']);transfer();assert None in names
                system_roots=copy.deepcopy(config);system_roots['virtual_servers'][0]['server_tls_profile']='server_tls'
                apply(system_roots);assert not member()['healthy'];wait_until(lambda:'TLS' in (member()['probe_error'] or ''))
                apply(config);wait_until(lambda:member()['healthy'])
                bad=copy.deepcopy(config);bad['virtual_servers'][0]['server_tls_profile']='missing'
                api('/api/v1/config/validate',bad,expected=422)
                bad=copy.deepcopy(config);bad['server_tls_profiles'][0]['ca_certificate']=str(root/'missing.pem')
                api('/api/v1/config/validate',bad,expected=422)
                bad=copy.deepcopy(config);bad['server_tls_profiles'].append(bad['server_tls_profiles'][0].copy())
                api('/api/v1/config/validate',bad,expected=422)
                bad=copy.deepcopy(config);bad['server_tls_profiles'][0]['server_name']='localhost:443'
                api('/api/v1/config/validate',bad,expected=422)
                other_cert,other_key=root/'other.pem',root/'other.key'
                subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1','-subj','/CN=OtherCA','-keyout',other_key,'-out',other_cert],check=True,capture_output=True)
                bad=copy.deepcopy(config);bad['server_tls_profiles'][0]['ca_certificate']=str(other_cert)
                apply(bad);assert not member()['healthy'];wait_until(lambda:'TLS' in (member()['probe_error'] or ''))
                bad=copy.deepcopy(config);bad['server_tls_profiles'][0]['server_name']='wrong.example'
                apply(bad);assert not member()['healthy'];wait_until(lambda:'TLS' in (member()['probe_error'] or ''))
                # TLS-to-TLS bridging and an explicitly assigned TCP monitor also verify backends.
                config['virtual_servers'][0]['tls']={'certificate':str(cert),'private_key':str(key)}
                config['virtual_servers'][0]['source_nat']={'mode':'snat','addresses':['127.0.0.2']}
                config['health_monitors']=[dict(name='connect',kind='tcp',interval_secs=1,timeout_ms=500,rise=1,fall=1)]
                config['virtual_servers'][0]['monitor']='connect'
                apply(config);wait_until(lambda:member()['healthy']);transfer(tls=True)
                assert Handler.sources[-1]=='127.0.0.2'
                # TCP accept without TLS response must hit the complete connection deadline.
                with socket.socket() as stall:
                    stall.bind(('127.0.0.1',0));stall.listen()
                    stalled=copy.deepcopy(config);stalled['virtual_servers'][0]['members']=[f'127.0.0.1:{stall.getsockname()[1]}']
                    apply(stalled);assert not member()['healthy'];wait_until(lambda:'deadline' in (member()['probe_error'] or ''))
                apply(config);wait_until(lambda:member()['healthy']);transfer(tls=True)
                revision=api()['revision'];process.send_signal(signal.SIGTERM);process.wait(timeout=15);process=None
                process=subprocess.Popen([BINARY,'serve','-c',path],stdout=log,stderr=log)
                wait_until(lambda:api()['revision']==revision);transfer(tls=True)
                assert api()['config']['server_tls_profiles'][0]['name']=='home-https'
                print('PASS server TLS: verified backend/SNI, TLS bridging, health/timeout, validation, reload and durable profiles')
    finally:
        if process and process.poll() is None:process.send_signal(signal.SIGTERM);process.wait(timeout=15)
        if backend:backend.shutdown();backend.server_close()

if __name__=='__main__':run()
