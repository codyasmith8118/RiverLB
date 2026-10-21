"""Local ACME protocol fixture: real HTTP-01, CSR signing, renewal and failure recovery.
Never contacts a public CA. The fixture is not a production certificate authority.
"""
import base64, http.client, http.server, json, os, signal, socket, ssl, subprocess
import tempfile, threading, urllib.error, urllib.request
from pathlib import Path
from auth_helpers import bootstrap
from smoke import BINARY, free_port, wait_until

def decode(value):return base64.urlsafe_b64decode(value+'='*((-len(value))%4))

class CA(http.server.BaseHTTPRequestHandler):
    def reply(self,value,status=200,location=None,content_type='application/json'):
        body=json.dumps(value).encode() if content_type=='application/json' else value
        self.send_response(status);self.send_header('Content-Type',content_type);self.send_header('Content-Length',str(len(body)))
        self.send_header('Replay-Nonce',base64.urlsafe_b64encode(os.urandom(24)).decode().rstrip('='))
        if location:self.send_header('Location',self.server.origin+location)
        self.end_headers()
        if self.command!='HEAD':self.wfile.write(body)
    def do_HEAD(self):self.reply({})
    def do_GET(self):
        if self.path=='/directory':self.reply({key:self.server.origin+path for key,path in [('newNonce','/nonce'),('newAccount','/account'),('newOrder','/new-order')]})
        else:self.reply({})
    def do_POST(self):
        envelope=json.loads(self.rfile.read(int(self.headers['Content-Length'])))
        protected=json.loads(decode(envelope['protected']));assert protected['url']==self.server.origin+self.path
        payload=json.loads(decode(envelope['payload'])) if envelope['payload'] else None
        if self.path=='/account':
            assert 'jwk' in protected and payload['termsOfServiceAgreed'];self.server.accounts+=1
            self.reply({'status':'valid','contact':payload['contact'],'orders':self.server.origin+'/orders'},201,'/account/1');return
        assert protected['kid']==self.server.origin+'/account/1'
        if self.path=='/new-order':
            if self.server.fail:self.reply({'type':'urn:ietf:params:acme:error:serverInternal','detail':'fixture issuance failure','status':503},503);return
            identifier=payload['identifiers'][0];assert identifier['value']=='issued.home.test'
            i=str(len(self.server.orders)+1);self.server.orders[i]={'status':'pending','identifiers':payload['identifiers'],'authorizations':[self.server.origin+'/auth/'+i+'-'+str(index) for index in range(len(payload['identifiers']))],'finalize':self.server.origin+'/finalize/'+i}
            self.reply(self.server.orders[i],201,'/order/'+i);return
        kind,i=self.path.strip('/').split('/')
        order_id=i.split('-')[0];order=self.server.orders[order_id]
        if kind=='auth':self.reply({'status':'valid' if i in self.server.authorized else 'pending','identifier':order['identifiers'][int(i.split('-')[1])],'challenges':[{'type':'http-01','url':self.server.origin+'/challenge/'+i,'status':'pending','token':'fixture-token-'+i}]});return
        if kind=='challenge':
            c=http.client.HTTPConnection('127.0.0.1',self.server.challenge_port,timeout=3)
            c.request('GET','/.well-known/acme-challenge/fixture-token-'+i);r=c.getresponse();key=r.read().decode();assert r.status==200 and key.startswith('fixture-token-'+i+'.');c.close()
            self.server.authorized.add(i)
            if all(order_id+'-'+str(index) in self.server.authorized for index in range(len(order['identifiers']))):order['status']='ready'
            self.server.challenges+=1;self.reply({'type':'http-01','url':self.server.origin+self.path,'status':'valid','token':'fixture-token-'+i});return
        if kind=='finalize':
            csr=self.server.root/(i+'.csr');cert=self.server.root/(i+'.pem');csr.write_bytes(decode(payload['csr']))
            subprocess.run(['openssl','x509','-req','-inform','DER','-in',csr,'-CA',self.server.root/'ca.pem','-CAkey',self.server.root/'ca.key','-set_serial',str(int(i)+100),'-days','2','-copy_extensions','copy','-out',cert],check=True,capture_output=True)
            order['status']='valid';order['certificate']=self.server.origin+'/cert/'+i;self.reply(order);return
        if kind=='order':self.reply(order);return
        if kind=='cert':self.reply((self.server.root/(i+'.pem')).read_bytes(),content_type='application/pem-certificate-chain');return
        raise AssertionError(self.path)
    def log_message(self,*_):pass

def run():
    process=None;ca=None;admin,proxy,challenge=free_port(),free_port(),free_port();scheme,host='http','127.0.0.1'
    def api(route='/api/v1/config',body=None,method='GET',expected=200):
        req=urllib.request.Request(f'{scheme}://{host}:{admin}'+route,data=json.dumps(body).encode() if body is not None else None,method=method,headers={'Content-Type':'application/json','X-RiverLB-Request':'configure'})
        try:r=urllib.request.urlopen(req,timeout=10)
        except urllib.error.HTTPError as e:r=e
        with r:value=json.load(r);assert r.status==expected,(r.status,value);return value
    try:
        with tempfile.TemporaryDirectory(prefix='riverlb-acme-') as folder:
            root=Path(folder);path=root/'config.toml';db=path.with_suffix('.db')
            subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-days','5','-subj','/CN=Fixture CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign','-keyout',root/'ca.key','-out',root/'ca.pem'],check=True,capture_output=True)
            subprocess.run(['openssl','req','-new','-newkey','rsa:2048','-nodes','-subj','/CN=localhost','-addext','subjectAltName=IP:127.0.0.1','-keyout',root/'server.key','-out',root/'server.csr'],check=True,capture_output=True)
            subprocess.run(['openssl','x509','-req','-in',root/'server.csr','-CA',root/'ca.pem','-CAkey',root/'ca.key','-set_serial','99','-days','2','-copy_extensions','copy','-out',root/'server.pem'],check=True,capture_output=True)
            ca=http.server.ThreadingHTTPServer(('127.0.0.1',0),CA);ca.root=root;ca.origin=f'https://127.0.0.1:{ca.server_port}';ca.orders={};ca.authorized=set();ca.accounts=0;ca.challenges=0;ca.challenge_port=challenge;ca.fail=False
            tls=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);tls.load_cert_chain(root/'server.pem',root/'server.key');ca.socket=tls.wrap_socket(ca.socket,server_side=True)
            threading.Thread(target=ca.serve_forever,daemon=True).start()
            path.write_text(f'''management="127.0.0.1:{admin}"
connect_timeout_ms=1000
session_timeout_secs=15
health_interval_secs=1
max_connections=64
[[virtual_servers]]
name="app"
listen="127.0.0.1:{proxy}"
members=["127.0.0.1:{ca.server_port}"]
''')
            bootstrap(BINARY,path)
            with (root/'log').open('w') as log:
                process=subprocess.Popen([BINARY,'serve','-c',path],stdout=log,stderr=log);wait_until(lambda:api()['revision']==1)
                job={'name':'automatic','domains':['issued.home.test','localhost'],'directory':ca.origin+'/directory','email':'home@example.test','terms_agreed':True,'enabled':True,'challenge_listen':f'127.0.0.1:{challenge}','renew_before_days':1,'ca_certificate':str(root/'ca.pem')}
                bad={**job,'terms_agreed':False};api('/api/v1/renewals',bad,'POST',422)
                bad={**job,'domains':['*.home.test']};api('/api/v1/renewals',bad,'POST',422)
                api('/api/v1/renewals',job,'POST')
                def issued():
                    status=api('/api/v1/renewals')[0]
                    assert status['last_error'] is None,status['last_error']
                    return status['last_success'] is not None
                wait_until(issued)
                first=api('/api/v1/certificates')[0]['fingerprint_sha256'];assert ca.challenges==2 and ca.accounts==1
                config=api()['config'];config['virtual_servers'][0]['certificate']='automatic';config['virtual_servers'][0]['sni_certificates']={'issued.home.test':'automatic'}
                api(body={'revision':api()['revision'],'config':config},method='PUT')
                context=ssl.create_default_context(cafile=root/'ca.pem')
                def fingerprint():
                    with context.wrap_socket(socket.create_connection(('127.0.0.1',proxy)),server_hostname='issued.home.test') as s:return __import__('hashlib').sha256(s.getpeercert(binary_form=True)).hexdigest()
                assert fingerprint()==first
                # Issue a separate device certificate using the same durable CA account.
                device_job={**job,'name':'management-auto','store':'device'}
                api('/api/v1/renewals',device_job,'POST')
                wait_until(lambda:len(api('/api/v1/device-certificates'))==1)
                device_first=api('/api/v1/device-certificates')[0]['fingerprint_sha256']
                assert ca.accounts==1 and ca.challenges==4
                # Management HTTPS also reloads an assigned renewed certificate on its existing port.
                next_admin=free_port();config['management']=f'127.0.0.1:{next_admin}';config['management_certificate']='management-auto'
                api(body={'revision':api()['revision'],'config':config},method='PUT');admin=next_admin;scheme,host='https','localhost'
                from auth_helpers import opener
                trusted=urllib.request.HTTPSHandler(context=context);trusted.handler_order=0;opener.add_handler(trusted)
                wait_until(lambda:api()['config']['management_certificate']=='management-auto')
                api('/api/v1/config/confirm',{'revision':api()['revision']},'POST')
                # Renew through an occupied HTTP domain listener; challenge interception
                # must precede Host matching and HTTPS redirect rules.
                config['virtual_servers'].append({'name':'http-challenges','listen':f'127.0.0.1:{challenge}','server_type':'domain_routing','members':[], 'http':{'rule_sets':['builtin-http-to-https']}})
                api(body={'revision':api()['revision'],'config':config},method='PUT')
                def challenge_status(token):
                    c=http.client.HTTPConnection('127.0.0.1',challenge,timeout=3)
                    c.request('GET','/.well-known/acme-challenge/'+token);r=c.getresponse();status=r.status;r.read();c.close();return status
                assert challenge_status('unknown-token')==404
                # Force renewal while assigned; reuse the durable account and hot rotate TLS.
                job['renew_before_days']=30;api('/api/v1/renewals',job,'POST')
                wait_until(lambda:api('/api/v1/certificates')[0]['fingerprint_sha256']!=first)
                second=fingerprint();assert second!=first and ca.accounts==1 and ca.challenges==6
                assert challenge_status('fixture-token-3-0')==404  # Issued challenge tokens are removed.
                with context.wrap_socket(socket.create_connection(('127.0.0.1',admin)),server_hostname='localhost') as s:assert __import__('hashlib').sha256(s.getpeercert(binary_form=True)).hexdigest()==device_first
                device_job['renew_before_days']=30;api('/api/v1/renewals',device_job,'POST')
                wait_until(lambda:api('/api/v1/device-certificates')[0]['fingerprint_sha256']!=device_first)
                device_second=api('/api/v1/device-certificates')[0]['fingerprint_sha256']
                assert ca.challenges==8 and ca.accounts==1 and fingerprint()==second
                with context.wrap_socket(socket.create_connection(('127.0.0.1',admin)),server_hostname='localhost') as s:assert __import__('hashlib').sha256(s.getpeercert(binary_form=True)).hexdigest()==device_second
                ca.fail=True;api('/api/v1/renewals',job,'POST')
                wait_until(lambda:api('/api/v1/renewals')[0]['last_error'] is not None)
                failed=api('/api/v1/renewals')[0];assert failed['failures']==1 and failed['next_attempt']>0 and fingerprint()==second
                # Restart retains schedule, backoff, credentials and last working certificate.
                process.send_signal(signal.SIGINT);process.wait(timeout=15)
                process=subprocess.Popen([BINARY,'serve','-c',path],stdout=log,stderr=log)
                wait_until(lambda:api('/api/v1/renewals')[0]['failures']==1);assert fingerprint()==second and ca.accounts==1
                snapshot=api('/api/v1/backup',{},'POST');assert len(snapshot['tables']['acme_accounts'])==1
                api('/api/v1/restore/stage',snapshot,'POST')
                api('/api/v1/renewals/automatic',{},'DELETE');api('/api/v1/renewals/management-auto',{},'DELETE');assert api('/api/v1/renewals')==[]
            print('PASS ACME: local HTTP-01/CSR issuance, account reuse, assigned SNI hot renewal, failure/backoff/restart, backup credentials, validation')
    finally:
        if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
        if ca:ca.shutdown();ca.server_close()

if __name__=='__main__':run()
