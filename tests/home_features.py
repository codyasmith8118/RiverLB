"""Real upgrades, early streaming, SNI and private backup/recovery; loopback only."""
import base64, copy, hashlib, http.client, http.server, json, signal, socket, ssl
import subprocess, tempfile, threading, urllib.error, urllib.request
from pathlib import Path
from auth_helpers import bootstrap
from smoke import BINARY, free_port, wait_until


class App(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    def handle(self):
        try:super().handle()
        except (BrokenPipeError,ConnectionResetError):pass  # Expected when the proxy enforces a body limit.
    def do_GET(self):
        if self.path == '/over-limit':
            self.send_response(200);self.send_header('Transfer-Encoding','chunked');self.end_headers()
            try:
                for _ in range(32):self.wfile.write(b'10000\r\n'+b'x'*65536+b'\r\n');self.wfile.flush()
                self.wfile.write(b'0\r\n\r\n')
            except OSError:self.close_connection=True
            return
        if self.path in ['/ws','/bad-ws']:
            self.server.ws_headers = {name.lower(): value for name, value in self.headers.items()}
            key = self.headers['Sec-WebSocket-Key']
            accept = base64.b64encode(hashlib.sha1((key+'258EAFA5-E914-47DA-95CA-C5AB0DC85B11').encode()).digest()).decode()
            if self.path == '/bad-ws':accept='invalid-accept'
            self.send_response(101); self.send_header('Upgrade','websocket'); self.send_header('Connection','Upgrade'); self.send_header('Sec-WebSocket-Accept',accept); self.end_headers()
            try:
                while True:
                    header = self.rfile.read(2)
                    if not header: break
                    length = header[1]&127; assert length < 126
                    mask = self.rfile.read(4); data=self.rfile.read(length)
                    data=bytes(b^mask[i%4] for i,b in enumerate(data))
                    self.wfile.write(bytes([header[0],len(data)])+data);self.wfile.flush()
                    if header[0]&15 == 8: break
            except (OSError,AssertionError): pass
            self.close_connection=True;return
        self.send_response(200);self.send_header('Content-Length','10');self.end_headers()
        try:
            self.wfile.write(b'first');self.wfile.flush()
            if self.path == '/stream': self.server.release.wait(5)
            self.wfile.write(b'last!');self.wfile.flush()
        except OSError: pass
    def do_POST(self):
        body=self.rfile.read(1);self.server.upload_started.set()
        body+=self.rfile.read(int(self.headers['Content-Length'])-1)
        self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers()
        try:self.wfile.write(body)
        except OSError:pass
    def log_message(self,*_):pass


def run():
    backend=http.server.ThreadingHTTPServer(('127.0.0.1',0),App)
    backend.release=threading.Event();backend.upload_started=threading.Event()
    threading.Thread(target=backend.serve_forever,daemon=True).start()
    admin,proxy=free_port(),free_port();process=None
    def api(route='/api/v1/config',body=None,method='GET',expected=200):
        req=urllib.request.Request(f'http://127.0.0.1:{admin}'+route,data=json.dumps(body).encode() if body is not None else None,method=method,headers={'Content-Type':'application/json','X-RiverLB-Request':'configure'})
        try:r=urllib.request.urlopen(req,timeout=10)
        except urllib.error.HTTPError as e:r=e
        with r:
            value=json.load(r);assert r.status==expected,(r.status,value);return value
    def apply(config):api(body={'revision':api()['revision'],'config':config},method='PUT')
    def ws(tls=None):
        raw=socket.create_connection(('127.0.0.1',proxy),timeout=3)
        s=tls.wrap_socket(raw,server_hostname='a.home.test') if tls else raw
        s.sendall(b'GET /ws HTTP/1.1\r\nHost: a.home.test\r\nUpgrade: websocket\r\nConnection: keep-alive, Upgrade, X-Forwarded-For, X-Forwarded-Proto, X-WS-Matched\r\nX-Forwarded-For: 203.0.113.9\r\nX-Forwarded-Proto: forged\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n\r\n')
        data=b''
        while b'\r\n\r\n' not in data:data+=s.recv(4096)
        assert b'101 Switching Protocols' in data and b's3pPLMBiTxaQ9kYGzzhZRbK+xOo=' in data,data
        assert backend.ws_headers['x-ws-matched'] == 'matched', backend.ws_headers
        assert backend.ws_headers['x-forwarded-for'] == '127.0.0.1', backend.ws_headers
        assert backend.ws_headers['x-forwarded-proto'] == ('https' if tls else 'http'), backend.ws_headers
        return s
    def echo(s,data=b'hello'):
        mask=b'1234';s.sendall(bytes([0x81,0x80|len(data)])+mask+bytes(v^mask[i%4] for i,v in enumerate(data)))
        got=b''
        while len(got)<len(data)+2:got+=s.recv(4096)
        assert got==bytes([0x81,len(data)])+data,got
    try:
        with tempfile.TemporaryDirectory(prefix='riverlb-home-') as folder:
            root=Path(folder);path=root/'config.toml';db=path.with_suffix('.db')
            path.write_text(f'''management="127.0.0.1:{admin}"
connect_timeout_ms=1000
session_timeout_secs=30
health_interval_secs=1
max_connections=64
[[virtual_servers]]
name="app"
listen="127.0.0.1:{proxy}"
members=["127.0.0.1:{backend.server_port}"]
[virtual_servers.http]
streaming=true
max_body_bytes=1048576
''')
            bootstrap(BINARY,path)
            with (root/'log').open('w') as log:
                process=subprocess.Popen([BINARY,'serve','-c',path],stdout=log,stderr=log)
                wait_until(lambda:api()['revision']==1)
                wait_until(lambda:api('/api/v1/status')['virtual_servers'][0]['members'][0]['healthy'])
                config=api()['config'];config['virtual_servers'][0]['member_connection_limits']={f'127.0.0.1:{backend.server_port}':1}
                config['river_rules']=[{'name':'handshake-metadata','rules':[{'name':'mark-websocket',
                    'when':{'header':{'name':'Upgrade','value':'websocket'}},
                    'actions':[{'kind':'set_request_header','name':'X-WS-Matched','value':'matched'}]}]}]
                config['virtual_servers'][0]['http']['rule_sets']=['builtin-x-forwarded-for','builtin-proxy-headers','handshake-metadata']
                apply(config)
                s=ws();echo(s)
                wait_until(lambda:api('/api/v1/status')['virtual_servers'][0]['members'][0]['bytes_to_backend']>0)
                c=http.client.HTTPConnection('127.0.0.1',proxy);c.request('GET','/');assert c.getresponse().status==503;c.close()
                config['virtual_servers'][0]['description']='reload during websocket';apply(config);echo(s,b'after-reload')
                c=http.client.HTTPConnection('127.0.0.1',proxy);c.request('GET','/');assert c.getresponse().status==503;c.close();s.close()
                wait_until(lambda:api('/api/v1/status')['virtual_servers'][0]['members'][0]['admission_active']==0)
                headers={'Upgrade':'websocket','Connection':'Upgrade','Sec-WebSocket-Version':'13','Sec-WebSocket-Key':'dGhlIHNhbXBsZSBub25jZQ=='}
                c=http.client.HTTPConnection('127.0.0.1',proxy);c.request('GET','/bad-ws',headers=headers);assert c.getresponse().status==502;c.close()
                config['virtual_servers'][0]['http']['websockets']=False;apply(config)
                c=http.client.HTTPConnection('127.0.0.1',proxy);c.request('GET','/ws',headers=headers);assert c.getresponse().status==400;c.close()
                config['virtual_servers'][0]['http']['websockets']=True;apply(config)
                c=http.client.HTTPConnection('127.0.0.1',proxy,timeout=3);c.request('GET','/stream');r=c.getresponse()
                assert r.read(5)==b'first' and not backend.release.is_set();backend.release.set();assert r.read()==b'last!';c.close()
                with socket.create_connection(('127.0.0.1',proxy),timeout=3) as s:
                    s.sendall(b'POST / HTTP/1.1\r\nHost: home\r\nContent-Length: 65536\r\nConnection: close\r\n\r\nx')
                    assert backend.upload_started.wait(3),'upload was buffered'
                    s.sendall(b'x'*65535);data=b''
                    while chunk:=s.recv(65536):data+=chunk
                    assert data.endswith(b'x'*65536),len(data)
                c=http.client.HTTPConnection('127.0.0.1',proxy);c.putrequest('POST','/');c.putheader('Content-Length','1048577');c.endheaders();assert c.getresponse().status==413;c.close()
                c=http.client.HTTPConnection('127.0.0.1',proxy);c.request('GET','/over-limit');r=c.getresponse();assert r.status==200
                try:r.read();raise AssertionError('oversized chunked response completed')
                except http.client.IncompleteRead as e:assert len(e.partial)<=1048576
                c.close();wait_until(lambda:api('/api/v1/status')['virtual_servers'][0]['members'][0]['admission_active']==0)
                # Certificates share one listener; an unknown or absent SNI uses the default.
                pairs={}
                for name in ['a','b']:
                    cert,key=root/(name+'.pem'),root/(name+'.key')
                    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','2','-subj',f'/CN={name}.home.test','-addext',f'subjectAltName=DNS:{name}.home.test','-keyout',key,'-out',cert],check=True,capture_output=True)
                    pairs[name]=(cert.read_text(),key.read_text())
                    api('/api/v1/certificates',{'name':name,'certificate':pairs[name][0],'private_key':pairs[name][1]},'POST')
                vs=config['virtual_servers'][0];vs['certificate']='a';vs['sni_certificates']={'b.home.test':'b'};apply(config)
                context=ssl.create_default_context(cadata=pairs['a'][0]+pairs['b'][0])
                for host,expected in [('a.home.test','a'),('b.home.test','b'),('unknown.home.test','a'),(None,'a')]:
                    unchecked=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT);unchecked.check_hostname=False;unchecked.verify_mode=ssl.CERT_NONE
                    with unchecked.wrap_socket(socket.create_connection(('127.0.0.1',proxy)),server_hostname=host) as s:
                        pem=ssl.PEM_cert_to_DER_cert(pairs[expected][0]);assert s.getpeercert(binary_form=True)==pem
                s=ws(context);echo(s);s.close()
                bad=copy.deepcopy(config);bad['virtual_servers'][0]['sni_certificates']={'wrong.home.test':'b'};api('/api/v1/config/validate',bad,'POST',422)
                api('/api/v1/certificates/b',{},'DELETE',409)
                # Authenticated live logical snapshot includes keys, never active sessions.
                snapshot=api('/api/v1/backup',{},'POST');assert 'sessions' not in snapshot['tables'];assert len(snapshot['tables']['certificates'])==2
                bad=copy.deepcopy(snapshot);bad['tables']['certificates'][0][1]='corrupted';api('/api/v1/restore/stage',bad,'POST',422)
                wrong_format=copy.deepcopy(snapshot);wrong_format['format']=999;api('/api/v1/restore/stage',wrong_format,'POST',422)
                api('/api/v1/restore/stage',snapshot,'POST')
                process.send_signal(signal.SIGINT);process.wait(timeout=15);process=None
                subprocess.run([BINARY,'restore','--database',db,'--staged','--replace'],check=True,capture_output=True)
                offline=root/'backup.json';subprocess.run([BINARY,'backup','--database',db,'--output',offline],check=True,capture_output=True)
                assert offline.stat().st_mode&0o777==0o600
                fresh=root/'fresh.db';subprocess.run([BINARY,'restore','--database',fresh,'--input',offline],check=True,capture_output=True)
                from auth_helpers import jar
                jar.clear()  # Restored sessions are intentionally revoked; sign in afresh.
                process=subprocess.Popen([BINARY,'serve','-c',path,'--database',fresh],stdout=log,stderr=log)
                wait_until(lambda:api()['config']['virtual_servers'][0]['sni_certificates']=={'b.home.test':'b'})
                c=http.client.HTTPSConnection('127.0.0.1',proxy,context=ssl._create_unverified_context());c.request('GET','/');assert c.getresponse().read()==b'firstlast!';c.close()
                # Invalid/rejected restores never replace current records.
                process.send_signal(signal.SIGINT);process.wait(timeout=15);process=None
                malformed=root/'bad.json';malformed.write_text(json.dumps(bad))
                result=subprocess.run([BINARY,'restore','--database',fresh,'--input',malformed,'--replace'],capture_output=True);assert result.returncode!=0
                assert subprocess.run([BINARY,'restore','--database',fresh,'--input',offline],capture_output=True).returncode!=0
            print('PASS home features: WebSocket/reload/TLS, early streaming/upload, limits, SNI/fallback, protected backup/stage/offline restore/clean-host recovery')
    finally:
        backend.release.set()
        if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
        backend.shutdown();backend.server_close()

if __name__=='__main__':run()
