"""Local administrator lifecycle, authentication guards and durable session revocation."""
import json
import signal
import sqlite3
import subprocess
import tempfile
import urllib.error
import urllib.request
from pathlib import Path
from smoke import BINARY, free_port, wait_until


def run():
    process=None
    with tempfile.TemporaryDirectory(prefix='riverlb-admins-') as folder:
        root=Path(folder);config=root/'config.toml';port=free_port()
        config.write_text(f'management = "127.0.0.1:{port}"\nconnect_timeout_ms = 1000\nsession_timeout_secs = 10\nhealth_interval_secs = 1\nmax_connections = 64\n[[virtual_servers]]\nname = "disabled-fixture"\nlisten = "127.0.0.1:{free_port()}"\nenabled = false\nmembers = ["127.0.0.1:9"]\n')
        password='fixture-admin-password-123'
        subprocess.run([BINARY,'admin','--database',str(config.with_suffix('.db'))],input=(password+'\n').encode(),capture_output=True,check=True)
        origin=f'http://127.0.0.1:{port}'
        opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
        def request(path,body=None,token=None,expected=200,csrf=True):
            headers={'Content-Type':'application/json'}
            if csrf:headers['X-RiverLB-Request']='configure'
            if token:headers['Cookie']='riverlb_session='+token
            req=urllib.request.Request(origin+'/api/v1/'+path,data=json.dumps(body).encode()if body is not None else None,headers=headers)
            try:response=opener.open(req,timeout=10)
            except urllib.error.HTTPError as error:response=error
            with response:
                assert response.status==expected,(path,response.status,response.read())
                return json.loads(response.read()),response.headers
        def login(username,pw,expected=200):
            _,headers=request('auth/login',dict(username=username,password=pw),expected=expected)
            return headers.get('Set-Cookie','').split(';')[0].removeprefix('riverlb_session=')
        def action(username,kind,token,pw=password,new=None,expected=200,csrf=True):
            return request('administrators',dict(username=username,action=kind,current_password=pw,**({'new_password':new}if new is not None else{})),token,expected,csrf)[0]
        def start():
            return subprocess.Popen([BINARY,'serve','--config',str(config),'--external-network'],stdout=subprocess.DEVNULL,stderr=subprocess.PIPE)
        try:
            process=start()
            wait_until(lambda:opener.open(origin+'/healthz',timeout=1).status==200)
            request('administrators',expected=401)
            request('appliance',expected=401)
            admin=login('admin',password)
            appliance=request('appliance',token=admin)[0]
            assert appliance['role']=='standalone'and appliance['hostname']
            assert 'virtual_servers'not in appliance
            assert request('administrators',token=admin)[0]==dict(current_user='admin',administrators=['admin'])
            action('operator','create',admin,new='operator-password-123',csrf=False,expected=403)
            action('operator','create',admin,pw='incorrect-password',new='operator-password-123',expected=401)
            action('operator','create',admin,new='short',expected=409)
            action('operator','create',admin,new='operator-password-123')
            action('operator','create',admin,new='operator-password-123',expected=409)
            operator=login('operator','operator-password-123')
            action('operator','password',admin,new='operator-replacement-123')
            request('administrators',token=operator,expected=401)
            login('operator','operator-password-123',expected=401)
            operator=login('operator','operator-replacement-123')
            action('operator','revoke',admin)
            request('administrators',token=operator,expected=401)
            operator=login('operator','operator-replacement-123')
            action('admin','delete',admin,expected=409)
            action('operator','delete',admin)
            request('administrators',token=operator,expected=401)
            assert request('administrators',token=admin)[0]['administrators']==['admin']
            action('missing','password',admin,new='replacement-password-123',expected=409)
            process.send_signal(signal.SIGTERM);process.wait(timeout=12);process=start()
            wait_until(lambda:opener.open(origin+'/healthz',timeout=1).status==200)
            assert request('administrators',token=admin)[0]['administrators']==['admin']
            process.send_signal(signal.SIGTERM);process.wait(timeout=12)
            with sqlite3.connect(config.with_suffix('.db'))as database:
                assert database.execute('SELECT COUNT(*) FROM administrators').fetchone()[0]==1
                audits=' '.join(row[0]for row in database.execute('SELECT action FROM audit'))
                assert 'local administrator create: operator'in audits and 'local administrator delete: operator'in audits
                assert 'operator-password-123'not in audits and password not in audits
            print('PASS local administrators: create/reset/delete/revoke, password confirmation, CSRF/auth, self-deletion guard, revoked sessions, audit and restart')
        finally:
            if process is not None and process.poll()is None:
                process.send_signal(signal.SIGTERM);process.wait(timeout=12)


if __name__=='__main__':run()
