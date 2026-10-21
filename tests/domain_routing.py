"""Hostname routing to reusable nodes; no external services or DNS changes."""
import copy, http.client, http.server, json, signal, socket, ssl, subprocess, tempfile, threading, urllib.error, urllib.request
from pathlib import Path
from auth_helpers import bootstrap
from smoke import BINARY, free_port, wait_until
class App(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        body=self.server.label.encode();self.send_response(200);self.send_header('Content-Length',str(len(body)));self.end_headers();self.wfile.write(body)
    def log_message(self,*_):pass
def run():
    apps=[http.server.ThreadingHTTPServer(('127.0.0.1',0),App) for _ in range(3)];process=None
    for i,app in enumerate(apps):app.label=str(i);threading.Thread(target=app.serve_forever,daemon=True).start()
    admin,proxy=free_port(),free_port();addresses=[f'127.0.0.1:{a.server_port}' for a in apps]
    def api(route='/api/v1/config',body=None,method='GET',expected=200):
        req=urllib.request.Request(f'http://127.0.0.1:{admin}'+route,data=json.dumps(body).encode() if body is not None else None,method=method,headers={'Content-Type':'application/json','X-RiverLB-Request':'configure'})
        try:r=urllib.request.urlopen(req,timeout=10)
        except urllib.error.HTTPError as e:r=e
        with r:
            raw=r.read().decode()
            try:value=json.loads(raw)
            except json.JSONDecodeError:value=raw
            assert r.status==expected,(r.status,value)
            return value
    def apply(config):api(body={'revision':api()['revision'],'config':config},method='PUT')
    def get(host,cookie=None):
        c=http.client.HTTPConnection('127.0.0.1',proxy,timeout=5);headers={'Host':host}
        if cookie:headers['Cookie']=cookie
        c.request('GET','/',headers=headers);r=c.getresponse();result=(r.status,r.read().decode(),r.getheader('Set-Cookie'));c.close();return result
    try:
        with tempfile.TemporaryDirectory(prefix='riverlb-domain-') as folder:
            path=Path(folder)/'config.toml';path.write_text(f'''management="127.0.0.1:{admin}"
connect_timeout_ms=200
session_timeout_secs=10
health_interval_secs=1
max_connections=64
[[virtual_servers]]
name="web"
listen="127.0.0.1:{proxy}"
members=["{addresses[0]}"]
[virtual_servers.http]
cookie_profile="cookie"
''');bootstrap(BINARY,path)
            with (Path(folder)/'log').open('w') as log:
                process=subprocess.Popen([BINARY,'serve','-c',path],stdout=log,stderr=log);wait_until(lambda:api()['revision']==1)
                config=api()['config'];config['nodes']=[{'name':'app'+str(i),'address':address,'enabled':True} for i,address in enumerate(addresses)]
                config['domain_routes']=[{'name':'photos','virtual_server':'web','hostname':'photos.home.test','node':'app1','enabled':True},{'name':'files','virtual_server':'web','hostname':'files.home.test','node':'app2','enabled':True}];apply(config)
                # Newly configured nodes become eligible after their first health probe.
                wait_until(lambda:all(node['state']=='Up' for node in api('/api/v1/nodes')))
                first=get('PHOTOS.HOME.TEST:8080');assert first[:2]==(200,'1');cookie=first[2].split(';')[0]
                assert get('files.home.test',cookie)[:2]==(200,'2')
                for _ in range(8):assert get('unknown.home.test',cookie)[:2]==(200,'0')  # Route nodes never leak into fallback balancing.
                nodes=api('/api/v1/nodes');assert nodes[1]['state']=='Up' and nodes[1]['completed']>0
                bad=copy.deepcopy(config);bad['nodes'].pop();api('/api/v1/config/validate',bad,'POST',422)
                bad=copy.deepcopy(config);bad['domain_routes'][0]['virtual_server']='missing';api('/api/v1/config/validate',bad,'POST',422)
                bad=copy.deepcopy(config);bad['domain_routes'][1]['hostname']='photos.home.test';api('/api/v1/config/validate',bad,'POST',422)
                bad=copy.deepcopy(config);bad['virtual_servers'][0].pop('http');api('/api/v1/config/validate',bad,'POST',422)
                config['nodes'][1]['enabled']=False;apply(config);assert get('photos.home.test')[0]==503;assert api('/api/v1/nodes')[1]['state']=='Disabled'
                config['nodes'][1]['enabled']=True;config['domain_routes'][0]['node']='app2';apply(config);assert get('photos.home.test')[:2]==(200,'2')
                # Domain-only virtual server: unknown hosts and disabled routes return 404.
                config['virtual_servers'][0]['members']=[];apply(config);assert get('unknown.home.test')[0]==404
                config['domain_routes'][0]['enabled']=False;config['domain_routes'][1]['enabled']=False;apply(config);assert get('photos.home.test')[0]==404
                # Reusable nodes can also form a normal pool; disabling affects every use.
                config['pools']=[{'name':'shared','algorithm':'round_robin','members':[],'node_members':['app0']}]
                config['virtual_servers'][0]['default_pool']='shared';apply(config)
                # A newly introduced pool waits for its first asynchronous probe.
                wait_until(lambda:get('unknown.home.test')[:2]==(200,'0'))
                config['nodes'][0]['enabled']=False;apply(config);assert get('unknown.home.test')[0]==503
                config['nodes'][0]['enabled']=True;apply(config)
                config['virtual_servers'][0]['server_type']='domain_routing'
                config['virtual_servers'][0].pop('default_pool');config['virtual_servers'][0]['members']=[]
                config['virtual_servers'][0]['hostname_miss_body']='No application is configured here.'
                config['domain_routes'][0]['enabled']=True;apply(config)
                assert get('photos.home.test',cookie)[:2]==(200,'2')
                assert get('unknown.home.test',cookie)[:2]==(404,'No application is configured here.')
                bad=copy.deepcopy(config);bad['virtual_servers'][0]['default_pool']='shared';api('/api/v1/config/validate',bad,'POST',422)
                bad=copy.deepcopy(config);bad['virtual_servers'][0]['server_type']='tcp';api('/api/v1/config/validate',bad,'POST',422)
                bad=copy.deepcopy(config);bad['virtual_servers'][0]['hostname_miss_body']='x'*65537;api('/api/v1/config/validate',bad,'POST',422)
                bad=copy.deepcopy(config);bad['virtual_servers'][0]['server_type']='unknown';api('/api/v1/config/validate',bad,'POST',422)
                # Route certificates generate one managed HTTPS listener, with per-host SNI.
                secure_port=free_port()
                for name,host in [('photos-tls','photos.home.test'),('files-tls','files.home.test')]:
                    created=api('/api/v1/certificates/self-signed',{'name':name,'hostname':host,'days':30},'POST')
                    assert created['name']==name and 'private_key' not in created
                    api('/api/v1/certificates/self-signed',{'name':name,'hostname':host},'POST',409)
                api('/api/v1/certificates/self-signed',{'name':'invalid','hostname':'https://photos.home.test'},'POST',422)
                api('/api/v1/certificates/self-signed',{'name':'invalid','hostname':'photos.home.test','days':0},'POST',422)
                for route,name in zip(config['domain_routes'],['photos-tls','files-tls']):
                    route.update(certificate=name,https_port=secure_port,enabled=True)
                config['domain_routes'][1]['node']='app1'
                config['virtual_servers'][0]['http'].pop('cookie_profile',None)
                config['virtual_servers'][0]['http']['rule_sets']=['builtin-http-to-https']
                apply(config)
                assert get('photos.home.test')[0]==302
                active=api()['config'];children=[v for v in active['virtual_servers'] if v.get('domain_tls_parent')]
                assert len(children)==1 and children[0]['listen']==f'127.0.0.1:{secure_port}'
                assert children[0]['sni_certificates']=={'photos.home.test':'photos-tls','files.home.test':'files-tls'}
                assert 'private_key' not in json.dumps(active)
                def https(host):
                    certificate=api('/api/v1/certificates/'+('photos-tls' if host=='photos.home.test' else 'files-tls')+'/pem')
                    context=ssl.create_default_context(cadata=certificate)
                    with context.wrap_socket(socket.create_connection(('127.0.0.1',secure_port)),server_hostname=host) as connection:
                        connection.sendall(('GET / HTTP/1.1\r\nHost: '+host+'\r\nConnection: close\r\n\r\n').encode())
                        response=http.client.HTTPResponse(connection);response.begin();return response.status,response.read().decode()
                assert https('photos.home.test')==(200,'2') and https('files.home.test')==(200,'1')
                api('/api/v1/certificates/photos-tls',{},'DELETE',409)
                bad=copy.deepcopy(config);bad['domain_routes'][0]['certificate']='files-tls'
                api('/api/v1/config',{'revision':api()['revision'],'config':bad},'PUT',409)
                bad=copy.deepcopy(config);bad['domain_routes'][0]['https_port']=0
                api('/api/v1/config/validate',bad,'POST',422)
                bad=copy.deepcopy(config);bad['virtual_servers'].append({**children[0],'name':'collision','domain_tls_parent':None})
                api('/api/v1/config/validate',bad,'POST',422)
                apply(active);assert len([v for v in api()['config']['virtual_servers'] if v.get('domain_tls_parent')])==1
                process.send_signal(signal.SIGINT);process.wait(timeout=15)
                process=subprocess.Popen([BINARY,'serve','-c',path],stdout=log,stderr=log)
                wait_until(lambda:api()['config']['domain_routes'][0].get('certificate')=='photos-tls')
                assert https('photos.home.test')==(200,'2')
                config['virtual_servers'][0]['http']['rule_sets']=[]
                for route in config['domain_routes']:route.pop('certificate');route.pop('https_port')
                apply(config);assert not any(v.get('domain_tls_parent') for v in api()['config']['virtual_servers'])
                config['domain_routes'][0]['enabled']=False;apply(config)
                assert get('photos.home.test',cookie)[:2]==(404,'No application is configured here.')
                config['domain_routes']=[];apply(config)
                assert get('photos.home.test')[:2]==(404,'No application is configured here.')
                process.send_signal(signal.SIGINT);process.wait(timeout=15);process=subprocess.Popen([BINARY,'serve','-c',path],stdout=log,stderr=log)
                wait_until(lambda:api()['config']['nodes'][0]['name']=='app0');assert get('unknown.home.test')[:2]==(404,'No application is configured here.')
            print('PASS domain routing: Host normalization, strict destinations/cookie isolation, fallback, node/pool references, disable/reload, domain-only 404, validation, self-signed route TLS/SNI, managed listener lifecycle and restart')
    finally:
        if process and process.poll() is None:process.send_signal(signal.SIGINT);process.wait(timeout=15)
        for app in apps:app.shutdown();app.server_close()
if __name__=='__main__':run()
