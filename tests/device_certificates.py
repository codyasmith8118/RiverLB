"""Device / virtual-server store isolation, private CSR workflow and live management protocol changes."""
import copy, hashlib, http.client, http.server, json, signal, socket, ssl, subprocess
import tempfile, threading, time, urllib.error, urllib.request
from pathlib import Path
from auth_helpers import bootstrap, opener, jar, session_token
from smoke import BINARY, free_port, wait_until

class App(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=b'backend stays available';self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*_):pass

def run():
    process=None;backend=http.server.ThreadingHTTPServer(('127.0.0.1',0),App)
    threading.Thread(target=backend.serve_forever,daemon=True).start()
    admin,proxy=free_port(),free_port();scheme='http';context=None
    def api(route='/api/v1/config',body=None,method='GET',expected=200,headers=None):
        req=urllib.request.Request(f'{scheme}://127.0.0.1:{admin}'+route,data=json.dumps(body).encode() if body is not None else None,method=method,headers=headers or {'Content-Type':'application/json','X-RiverLB-Request':'configure'})
        try:r=urllib.request.urlopen(req,timeout=10)
        except urllib.error.HTTPError as e:r=e
        with r:
            raw=r.read().decode()
            try:value=json.loads(raw)
            except json.JSONDecodeError:value=raw
            assert r.status==expected,(r.status,value);return value
    def apply(config,expected=200):return api(body={'revision':api()['revision'],'config':config},method='PUT',expected=expected)
    def backend_ok():
        c=http.client.HTTPConnection('127.0.0.1',proxy,timeout=3);c.request('GET','/');r=c.getresponse();assert r.status==200 and r.read()==b'backend stays available';c.close()
    def fingerprint():
        with context.wrap_socket(socket.create_connection(('127.0.0.1',admin),timeout=3),server_hostname='localhost') as s:return hashlib.sha256(s.getpeercert(binary_form=True)).hexdigest()
    try:
        with tempfile.TemporaryDirectory(prefix='riverlb-device-cert-') as folder:
            root=Path(folder);path=root/'config.toml';path.write_text(f'''management="127.0.0.1:{admin}"
connect_timeout_ms=1000
session_timeout_secs=15
health_interval_secs=1
max_connections=64
[[virtual_servers]]
name="app"
listen="127.0.0.1:{proxy}"
members=["127.0.0.1:{backend.server_port}"]
[virtual_servers.http]
''');bootstrap(BINARY,path)
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','5','-subj','/CN=External Fixture Root','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',root/'ca.key','-out',root/'ca.pem'],check=True,capture_output=True)
            with (root/'log').open('w+') as log:
                def start(database=None):return subprocess.Popen([BINARY,'serve','-c',path]+(['--database',str(database)] if database else []),stdout=log,stderr=log)
                process=start();wait_until(lambda:api()['revision']==1);backend_ok()
                bases=['/api/v1/certificates','/api/v1/device-certificates']
                for base in bases:
                    result=api(base+'/self-signed',{'name':'shared-name','names':['localhost','127.0.0.1','2001:0db8::1'],'days':30},'POST')
                    assert 'private_key' not in result
                    api(base+'/self-signed',{'name':'requests','hostname':'localhost'},'POST')
                    assert 'BEGIN CERTIFICATE' in api(base+'/objects/requests/pem')
                    api(base+'/objects/requests',{},'DELETE')
                    api(base+'/self-signed',{'name':'shared-name','hostname':'localhost'},'POST',409)
                    metadata=api(base)[0];assert metadata['dns_names']==['localhost'] and '127.0.0.1' in metadata['ip_addresses']
                    api(base+'/requests',{'name':'external','names':['localhost','127.0.0.1'],'subject':{'organization':'Fixture Org','country':'US'}},'POST',403,headers={'Content-Type':'application/json'})
                    request=api(base+'/requests',{'name':'external','names':['localhost','127.0.0.1'],'subject':{'organization':'Fixture Org','country':'US'}},'POST')
                    assert 'BEGIN CERTIFICATE REQUEST' in request['csr'] and 'PRIVATE KEY' not in json.dumps(request)
                    api(base+'/requests',{'name':'external','hostname':'localhost'},'POST',422)
                    assert api(base+'/requests')[0]['name']=='external'
                    csr=root/('device.csr' if 'device-' in base else 'virtual.csr');csr.write_text(api(base+'/requests/external'))
                    subprocess.run(['openssl','req','-in',csr,'-verify','-noout'],check=True,capture_output=True)
                    api(base+'/self-signed',{'name':'external','hostname':'localhost'},'POST',422)
                    wrong=api(base+'/shared-name/pem');api(base+'/requests/external/complete',{'certificate':wrong},'POST',422)
                    assert len(api(base+'/requests'))==1
                assert api(bases[0])[0]['fingerprint_sha256']!=api(bases[1])[0]['fingerprint_sha256']
                snapshot=api('/api/v1/backup',{},'POST');assert snapshot['format']==3 and len(snapshot['tables']['certificate_requests'])==2
                api('/api/v1/restore/stage',snapshot,'POST')  # Also validates CSR signatures and retained key pairs.
                assert 'PRIVATE KEY' not in json.dumps(api())
                process.send_signal(signal.SIGINT);process.wait(timeout=15);process=start()
                wait_until(lambda:len(api(bases[1]+'/requests'))==1)
                for serial,(base,stem) in enumerate(zip(bases,['virtual','device']),1):
                    for copy_names in [False,True]:
                        cert=root/(stem+'.pem');command=['openssl','x509','-req','-in',root/(stem+'.csr'),'-CA',root/'ca.pem','-CAkey',root/'ca.key','-set_serial',str(serial),'-days','2','-out',cert]
                        if copy_names:command+=['-copy_extensions','copy']
                        subprocess.run(command,check=True,capture_output=True)
                        api(base+'/requests/external/complete',{'certificate':cert.read_text()},'POST',200 if copy_names else 422)
                    assert api(base+'/requests')==[]
                    assert len(api(base))==2
                api(bases[0]+'/self-signed',{'name':'virtual-only','hostname':'localhost'},'POST')
                api(bases[1]+'/self-signed',{'name':'device-only','hostname':'localhost'},'POST')
                config=api()['config'];bad=copy.deepcopy(config);bad['management_protocol']='https'
                api('/api/v1/config/validate',bad,'POST',422)
                bad['management_certificate']='virtual-only';apply(bad,409)
                bad=copy.deepcopy(config);bad['virtual_servers'][0]['certificate']='device-only';apply(bad,409)
                bad=copy.deepcopy(config);bad['management_protocol']='http';bad['management_certificate']='external';api('/api/v1/config/validate',bad,'POST',422)
                # Keep a management HTTP connection alive, then switch that same address to HTTPS.
                old_http=http.client.HTTPConnection('127.0.0.1',admin,timeout=3);old_http.request('GET','/api/v1/config',headers={'Cookie':'riverlb_session='+session_token()});old_http.getresponse().read()
                config.update(management_protocol='https',management_certificate='external')
                result=apply(config);assert result['management_url']==f'https://127.0.0.1:{admin}'
                context=ssl.create_default_context(cafile=root/'ca.pem')
                # Also trust the generated device certificate for the later certificate change.
                # Capture its public certificate through HTTPS after switching the client context.
                trusted=urllib.request.HTTPSHandler(context=context);trusted.handler_order=0;opener.add_handler(trusted);scheme='https'
                wait_until(lambda:api()['config']['management_protocol']=='https')
                api('/api/v1/config/confirm',{'revision':result['revision']},'POST')
                device_pem=api(bases[1]+'/shared-name/pem');context.load_verify_locations(cadata=device_pem)
                first=api(bases[1]);assert fingerprint()==next(c['fingerprint_sha256'] for c in first if c['name']=='external')
                api(bases[1]+'/external',{},'DELETE',409)
                # Same name in the virtual store is independent and can be deleted while management uses the device object.
                api(bases[0]+'/external',{},'DELETE')
                def plaintext_closed():
                    try:old_http.request('GET','/healthz');old_http.getresponse().read();return False
                    except (OSError,http.client.HTTPException):return True
                began=time.monotonic()
                try:wait_until(plaintext_closed);assert time.monotonic()-began<3,'Old plaintext management did not finish its bounded response drain'
                finally:old_http.close()
                backend_ok();config['management_certificate']='shared-name';rotated=apply(config)
                assert fingerprint()==next(c['fingerprint_sha256'] for c in first if c['name']=='shared-name')
                api('/api/v1/config/confirm',{'revision':rotated['revision']},'POST')
                config=api()['config'];process.send_signal(signal.SIGINT);process.wait(timeout=15);process=start()
                wait_until(lambda:api()['config']['management_certificate']=='shared-name');assert fingerprint()==next(c['fingerprint_sha256'] for c in first if c['name']=='shared-name')
                config['management_protocol']='http';config.pop('management_certificate');assert apply(config)['management_url']==f'http://127.0.0.1:{admin}';scheme='http';jar.clear()
                wait_until(lambda:api()['config']['management_protocol']=='http');backend_ok()
                api('/api/v1/config/confirm',{'revision':api()['revision']},'POST')
                # Restore a format-1 backup: a formerly shared management certificate is migrated into the device store.
                legacy=api('/api/v1/backup',{},'POST');legacy['format']=1;legacy['tables'].pop('device_certificates');legacy['tables'].pop('certificate_requests');legacy['tables'].pop('auth_accounts');legacy['tables'].pop('auth_settings')
                latest=max(legacy['tables']['configurations'],key=lambda row:row[0]);old_config=json.loads(latest[1]);old_config.pop('management_protocol',None);old_config['management_certificate']='shared-name';latest[1]=json.dumps(old_config,separators=(',',':'))
                legacy['sha256']=hashlib.sha256(json.dumps([legacy['format'],legacy['created'],legacy['tables']],sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
                legacy_file=root/'legacy.json';legacy_file.write_text(json.dumps(legacy));fresh=root/'legacy.db'
                subprocess.run([BINARY,'restore','--database',fresh,'--input',legacy_file],check=True,capture_output=True)
                process.send_signal(signal.SIGINT);process.wait(timeout=15)
                # Trust the migrated public virtual-store certificate; the legacy device store did not exist.
                source=next(row[1] for row in legacy['tables']['certificates'] if row[0]=='shared-name');context=ssl.create_default_context(cadata=source)
                restored_trust=urllib.request.HTTPSHandler(context=context);restored_trust.handler_order=-10;opener.add_handler(restored_trust)
                process=start(fresh);scheme='https';jar.clear();wait_until(lambda:len(api(bases[1]))==1)
                assert api(bases[1])[0]['name']=='shared-name';backend_ok()
            print('PASS device certificates: isolated stores, DNS/IP SANs, private CSR/signing/import/restart/backup, validation, same-port HTTP/HTTPS and certificate changes, legacy restore/migration')
    finally:
        if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
        backend.shutdown();backend.server_close()
if __name__=='__main__':run()
