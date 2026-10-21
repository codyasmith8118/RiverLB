"""Real HTTP confirm/revert, crash recovery and traffic continuity on disposable state."""
import json, http.client, signal, socket, subprocess, tempfile, time
from pathlib import Path
from smoke import Backend, BINARY, free_port, wait_until
from auth_helpers import PASSWORD

def run():
    backend=Backend(b'confirmed');process=None
    with tempfile.TemporaryDirectory(prefix='riverlb-confirmation-') as directory:
        root=Path(directory);config=root/'config.toml';old_port=free_port();port=old_port
        config.write_text(f'management="127.0.0.1:{port}"\nconnect_timeout_ms=200\nsession_timeout_secs=10\nhealth_interval_secs=1\nmax_connections=64\n[[virtual_servers]]\nname="fixture"\nlisten="127.0.0.1:{free_port()}"\nmembers=["127.0.0.1:{backend.port}"]\n')
        subprocess.run([BINARY,'admin','--database',config.with_suffix('.db')],input=(PASSWORD+'\n').encode(),check=True,capture_output=True)
        cookie=''
        def call(path,body=None,method=None,expected=200):
            c=http.client.HTTPConnection('127.0.0.1',port,timeout=8)
            try:
                c.request(method or ('POST' if body is not None else 'GET'),path,json.dumps(body) if body is not None else None,{'Content-Type':'application/json','X-RiverLB-Request':'configure','Cookie':cookie})
                r=c.getresponse();raw=r.read().decode();assert r.status==expected,(r.status,expected,raw);return json.loads(raw) if raw.startswith(('{','[')) else raw,dict(r.getheaders())
            finally:c.close()
        def start():
            nonlocal process,cookie
            process=subprocess.Popen([BINARY,'serve','--config',config,'--external-network'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
            try:wait_until(lambda:call('/healthz')[0]=='ok')
            except BaseException:
                process.terminate();process.wait(timeout=12)
                raise AssertionError(process.stderr.read().decode())
            _,headers=call('/api/v1/auth/login',{'username':'admin','password':PASSWORD});cookie=headers['set-cookie'].split(';',1)[0]
        def stop(crash=False):
            nonlocal process
            if process and process.poll() is None:
                process.send_signal(signal.SIGKILL if crash else signal.SIGTERM);process.wait(timeout=12)
            process=None
        try:
            start();initial=call('/api/v1/config')[0];changed=json.loads(json.dumps(initial['config']));new_port=free_port();changed['management']=f'127.0.0.1:{new_port}'
            preview=call('/api/v1/config/preview',{'revision':1,'config':changed})[0];assert preview['confirmation_required'] and any(c['path']=='/management' for c in preview['changes'])
            applied=call('/api/v1/config',{'revision':1,'config':changed},'PUT')[0];assert applied['confirmation']['pending'];port=new_port
            call('/api/v1/config',{'revision':2,'config':changed},'PUT',409)
            call('/api/v1/config/confirm',{'revision':1},expected=409)
            call('/api/v1/config/confirm',{'revision':2});assert not call('/api/v1/config/confirmation')[0]['pending']
            third=free_port();changed['management']=f'127.0.0.1:{third}';call('/api/v1/config',{'revision':2,'config':changed},'PUT');port=third
            call('/api/v1/config/revert',{'revision':3});port=new_port;assert call('/api/v1/config')[0]['revision']==4
            changed['management']=f'127.0.0.1:{third}';call('/api/v1/config',{'revision':4,'config':changed},'PUT');port=third;stop(crash=True);port=new_port;start()
            recovered=call('/api/v1/config')[0];assert recovered['revision']==6 and recovered['config']['management']==f'127.0.0.1:{new_port}'
            assert not config.with_suffix('.confirmation.json').exists()
            changed['management']=f'127.0.0.1:{third}'
            call('/api/v1/config',{'revision':6,'config':changed},'PUT');port=third
            call('/api/v1/device-certificates/self-signed',{'name':'blocked','names':['localhost']},expected=409)
            call('/api/v1/backup',{},expected=409)
            # Exercise the real fixed deadline, without a production timeout bypass.
            deadline=time.monotonic()+135
            traffic_port=int(changed['virtual_servers'][0]['listen'].rsplit(':',1)[1])
            with socket.create_connection(('127.0.0.1',traffic_port),timeout=4) as client:
                client.sendall(b'continuity');client.shutdown(socket.SHUT_WR)
                assert client.recv(128)==b'confirmed:continuity'
            port=new_port
            while True:
                try:
                    if call('/api/v1/config')[0]['revision']==8:break
                except (OSError, http.client.HTTPException):pass
                if time.monotonic()>deadline:raise AssertionError('Unconfirmed configuration did not revert at its deadline')
                time.sleep(0.5)
            assert not call('/api/v1/config/confirmation')[0]['pending']
            print('PASS confirmation: review, guarded mutations, confirm, manual revert, crash recovery, real deadline rollback and traffic continuity')
        finally:stop();backend.close()
if __name__=='__main__':run()
