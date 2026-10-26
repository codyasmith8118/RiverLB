"""CLI/API parity over real verified HTTPS and disposable daemon state."""
import copy
import http.client
import json
import os
from pathlib import Path
import signal
import sqlite3
import ssl
import subprocess
import tempfile
import time
from auth_release import BINARY, PASSWORD, free_port, totp


def run():
    process = None
    with tempfile.TemporaryDirectory(prefix='riverlb-cli-') as folder:
        root = Path(folder)
        cert, key = root/'ca.pem', root/'key.pem'
        subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','1',
            '-subj','/CN=fixture','-addext','subjectAltName=IP:127.0.0.1',
            '-addext','basicConstraints=critical,CA:FALSE',
            '-keyout',str(key),'-out',str(cert)],check=True,capture_output=True)
        context = ssl.create_default_context(cafile=cert)
        port, original = free_port(), None
        config = root/'config.toml'
        config.write_text(f'''management="127.0.0.1:{port}"
connect_timeout_ms=200
session_timeout_secs=10
health_interval_secs=1
max_connections=64
[management_tls]
certificate="{cert}"
private_key="{key}"
[[virtual_servers]]
name="fixture"
listen="127.0.0.1:{free_port()}"
enabled=false
members=["127.0.0.1:9"]
[virtual_servers.http]
[[nodes]]
name="parent-node"
address="127.0.0.1:9"
[network]
[[network.vlans]]
name="parent-vlan"
interface="eth0"
''')
        subprocess.run([BINARY,'admin','--database',config.with_suffix('.db')],input=PASSWORD+'\n',text=True,check=True,capture_output=True)
        session = root/'session'
        secrets = [PASSWORD]

        def api(path='/api/v1/config', body=None, method=None, token=None):
            c = http.client.HTTPSConnection('127.0.0.1',port,context=context,timeout=8)
            headers={'Content-Type':'application/json','X-RiverLB-Request':'configure'}
            if token is None and session.exists(): token=session.read_text()
            if token: headers['Cookie']='riverlb_session='+token
            c.request(method or ('POST' if body is not None else 'GET'),path,None if body is None else json.dumps(body),headers)
            r=c.getresponse(); data=r.read(); c.close()
            assert r.status==200,(path,r.status,data)
            return json.loads(data) if data.startswith((b'{',b'[')) else data.decode()

        def start():
            nonlocal process
            with (root/'daemon.log').open('ab') as log:
                process=subprocess.Popen([BINARY,'serve','--config',config,'--external-network'],stdout=log,stderr=log)
            deadline=time.monotonic()+15
            while time.monotonic()<deadline:
                try:
                    if api('/healthz')=='ok': return
                except (OSError,http.client.HTTPException): pass
                time.sleep(.05)
            raise AssertionError(('CLI fixture failed to start',port,process.poll(),(root/'daemon.log').read_text()[-4000:]))

        def stop():
            nonlocal process
            if process is not None and process.poll() is None:
                process.send_signal(signal.SIGTERM);process.wait(timeout=15)
            process=None

        def cli(*args,expected=0,credentials=None,auth=True,ca=True,url=None,token_file=None):
            argv=[str(BINARY),'manage','--url',url or f'https://127.0.0.1:{port}']
            if ca: argv+=['--ca',str(cert)]
            if auth: argv+=['--token-file' if token_file else '--session-file',str(token_file or session)]
            argv+=list(map(str,args))
            result=subprocess.run(argv,input=None if credentials is None else json.dumps(credentials),capture_output=True,text=True,timeout=20,
                                  env={**os.environ,'RUST_LOG':'trace'})
            assert result.returncode==expected,(args,result.returncode,result.stdout,result.stderr)
            assert all(secret not in result.stdout+result.stderr for secret in secrets if secret)
            if expected: return json.loads(result.stderr)['error']
            return json.loads(result.stdout)['result']

        def document(value):
            path=root/'input.json';path.write_text(json.dumps(value));return path

        def login(path=session, code=None, expected=0):
            return cli('login','--output',path,auth=False,expected=expected,
                       credentials={'username':'admin','password':PASSWORD,**({'code':code} if code else {})})

        try:
            start();login();secrets.append(session.read_text());assert session.stat().st_mode&0o777==0o600
            original=port
            assert cli('status')==api('/api/v1/status')
            cli('status',ca=False,expected=7)
            cli('status',url=f'http://127.0.0.1:{port}',expected=2)
            cli('status',url=f'https://localhost:{port}',expected=7)  # correct CA, wrong SAN
            cli('status',url=f'https://user:secret@127.0.0.1:{port}',expected=2)
            session.chmod(0o644);cli('status',expected=2);session.chmod(0o600)
            linked=root/'linked';linked.symlink_to(session);cli('status',token_file=linked,expected=2)
            for scope in ('monitoring','read','configure'):
                token=api('/api/v1/security/tokens',{'name':scope,'scope':scope,'lifetime_secs':3600,'current_password':PASSWORD})['token']
                secrets.append(token);path=root/scope;path.write_text(token);path.chmod(0o600)
                cli('status',token_file=path)
                if scope=='monitoring': cli('get',token_file=path,expected=3)
                else: assert cli('get',token_file=path)==api()
                current=api();cli('apply','--revision',current['revision'],'--input',document(current['config']),token_file=path,expected=0 if scope=='configure' else 3)
            objects={
                'virtual-servers':{'name':'test','listen':f'127.0.0.1:{free_port()}','members':['127.0.0.1:9'],'enabled':False},
                'pools':{'name':'test','algorithm':'round_robin','members':['127.0.0.1:9']},
                'nodes':{'name':'test','address':'127.0.0.1:10'},
                'domain-routes':{'name':'test','virtual_server':'fixture','hostname':'example.test','node':'parent-node'},
                'health-monitors':{'name':'test','interval_secs':1,'timeout_ms':200,'rise':1,'fall':1,'kind':'tcp'},
                'persistence-profiles':{'name':'test','settings':{'timeout_secs':0,'max_entries':0}},
                'server-tls-profiles':{'name':'test','server_name':'localhost','ca_certificate':str(cert)},
                'river-rules':{'name':'test','rules':[]},
                'cookie-profiles':{'name':'test','settings':{}},
                'http-profiles':{'name':'test','settings':{}},
                'vlans':{'name':'test','interface':'eth1'},
                'self-ips':{'name':'test','address':'192.0.2.10/24','vlan':'parent-vlan'},
                'routes':{'name':'test','destination':'198.51.100.0/24','gateway':'192.0.2.1','vlan':'parent-vlan','metric':100},
            }
            for kind,value in objects.items():
                revision=api()['revision']
                cli('object',kind,'create','--input',document(value),'--revision',revision)
                current=api();assert current['revision']==revision+1
                got=cli('object',kind,'get','test');assert got['object']['name']=='test'
                assert any(o['name']=='test' for o in cli('object',kind,'list')['objects'])
                cli('object',kind,'create','--input',document(value),'--revision',current['revision'],expected=5)
                cli('object',kind,'update','test','--input',document(value),'--revision',revision,expected=5)
                changes={
                    'virtual-servers':{'listen':f'127.0.0.1:{free_port()}'},
                    'pools':{'members':['127.0.0.1:11']}, 'nodes':{'description':'updated'},
                    'domain-routes':{'hostname':'updated.example.test'},
                    'health-monitors':{'timeout_ms':400}, 'persistence-profiles':{'settings':{'timeout_secs':0,'max_entries':0,'ipv4_prefix':24}},
                    'server-tls-profiles':{'server_name':'127.0.0.1'}, 'river-rules':{'description':'updated'},
                    'cookie-profiles':{'description':'updated'}, 'http-profiles':{'description':'updated'},
                    'vlans':{'interface':'eth2'}, 'self-ips':{'address':'192.0.2.11/24'}, 'routes':{'metric':101},
                }[kind]
                changed={**got['object'],**changes}
                cli('object',kind,'update','test','--input',document(changed),'--revision',current['revision'])
                updated=cli('object',kind,'get','test')['object']
                for key,value in changes.items():
                    if isinstance(value,dict): assert all(updated[key].get(k)==v for k,v in value.items())
                    else: assert updated[key]==value
                cli('object',kind,'delete','test','--revision',api()['revision'])
                cli('object',kind,'get','test',expected=4)
            current=api();saved=copy.deepcopy(current['config']);desired=copy.deepcopy(saved);desired['max_connections']=65
            cli('validate','--input',document(desired));assert api()['revision']==current['revision']
            assert cli('diff','--revision',current['revision'],'--input',document(desired))==api('/api/v1/config/preview',{'revision':current['revision'],'config':desired})
            cli('apply','--revision',current['revision'],'--input',document(desired))
            cli('apply','--revision',current['revision'],'--input',document(desired),expected=5)
            cli('rollback','--target',current['revision'],'--revision',api()['revision']);assert api()['config']==saved
            assert cli('history')==api('/api/v1/config/history')
            bad=copy.deepcopy(saved);bad['max_connections']=0;cli('validate','--input',document(bad),expected=4)
            # Changing management endpoint must leave a pending decision. Confirm only explicitly.
            changed=copy.deepcopy(saved);changed['management']=f'127.0.0.1:{free_port()}'
            rev=api()['revision'];cli('apply','--revision',rev,'--input',document(changed));port=int(changed['management'].rsplit(':',1)[1])
            assert cli('confirmation')['pending'];cli('confirm','--revision',rev+1)
            confirmed_port=port
            changed['management']=f'127.0.0.1:{original}'
            rev=api()['revision'];cli('apply','--revision',rev,'--input',document(changed));port=original
            assert cli('confirmation')['pending'];cli('revert','--revision',rev+1);port=confirmed_port
            assert not cli('confirmation')['pending']
            # Disconnect/restart during an unconfirmed endpoint change restores the old endpoint.
            rev=api()['revision'];cli('apply','--revision',rev,'--input',document(changed));port=original
            assert cli('confirmation')['pending'];stop();port=confirmed_port;start()
            assert not cli('confirmation')['pending'] and api()['revision']==rev+2
            # Roles cannot be upgraded by going through the CLI.
            api('/api/v1/administrators',{'username':'reader','action':'create','role':'read_only','new_password':PASSWORD,'current_password':PASSWORD})
            reader=root/'reader'
            cli('login','--output',reader,auth=False,credentials={'username':'reader','password':PASSWORD})
            secrets.append(reader.read_text())
            cli('get',token_file=reader,expected=3)  # a session cannot be used as a bearer token
            # Pass it through the session path to exercise the read-only server role.
            admin_secret=session.read_text();session.write_text(reader.read_text())
            assert cli('get')==api()
            cli('apply','--revision',api()['revision'],'--input',document(api()['config']),expected=3)
            assert cli('logout')['authenticated'] is False
            cli('status',expected=3)
            session.write_text(admin_secret)
            enrollment=api('/api/v1/security/mfa/enroll',{'current_password':PASSWORD})
            codes=api('/api/v1/security/mfa/confirm',{'code':totp(enrollment['secret'])})['recovery_codes']
            secrets.extend([enrollment['secret'],*codes]);cli('status',expected=3)
            login(root/'failed-login',expected=3)
            session.unlink();login(code=codes[0]);secrets.append(session.read_text())
            cli('status');login(root/'reused-code',code=codes[0],expected=3)
            api('/api/v1/security/mfa/disable',{'current_password':PASSWORD,'code':codes[1]})
            session.unlink();login();secrets.append(session.read_text())
            api('/api/v1/security/settings',{'settings':{'idle_timeout_secs':60,'source_allowlist':[]},'current_password':PASSWORD},method='PUT')
            stop()
            with sqlite3.connect(config.with_suffix('.db')) as db:
                db.execute('UPDATE auth_session_activity SET last_seen=?',(int(time.time())-61,))
            db.close()
            start();cli('status',expected=3)
            # Completion and help are static and never consult even an invalid credential file.
            help_result=subprocess.run([BINARY,'manage','--help'],capture_output=True,text=True,check=True)
            assert all(s not in help_result.stdout+help_result.stderr for s in secrets)
            for shell in ('bash','zsh'):
                result=subprocess.run([BINARY,'manage','--token-file','/nonexistent','completion','--shell',shell],capture_output=True,text=True,check=True)
                assert 'status' in result.stdout and all(s not in result.stdout+result.stderr for s in secrets)
            print('PASS management CLI: 13 object lifecycles, HTTPS CA/SAN, API parity, revisions, diff/validate/apply/history/rollback, explicit confirm/revert and interrupted recovery, scopes/RBAC, MFA/single-use recovery, durable idle expiry and credential-free output/help/completion')
        finally:
            stop()


if __name__=='__main__':run()
