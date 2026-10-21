"""Real HTTP framing, ordered RiverRules, opaque cookie affinity and reload tests."""
import copy
import http.client
import http.server
import json
import signal
import socket
import ssl
import subprocess
import tempfile
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path
from auth_helpers import bootstrap
from smoke import BINARY, free_port, wait_until


class App(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    def do_GET(self):
        if self.path == "/latency": time.sleep(0.06)
        if self.path == "/slow":
            self.server.slow_started.set(); self.server.slow_release.wait(5)
        body = json.dumps({"member": self.server.label, "path": self.path,
            "cookie": self.headers.get("Cookie"), "rule": self.headers.get("X-Rule"),
            "forwarded_for": self.headers.get_all("X-Forwarded-For"),
            "body": self.rfile.read(int(self.headers.get("Content-Length", 0))).decode()}).encode()
        if self.path == "/large": body = b"x" * 4096
        self.send_response(200)
        self.send_header("Transfer-Encoding", "chunked")
        self.send_header("Set-Cookie", "app=yes; Path=/")
        if self.path != '/no-cookie': self.send_header("Set-Cookie", "RIVERLB=" + getattr(self.server,'cookie_value','application-collision') + "; Path=/")
        self.end_headers()
        try:
            for part in [body[:3],body[3:]]:
                if part: self.wfile.write(f"{len(part):x}\r\n".encode()+part+b"\r\n")
            self.wfile.write(b"0\r\n\r\n")
        except (BrokenPipeError,ConnectionResetError): pass
    do_POST = do_GET
    def log_message(self,*_): pass


def run():
    apps = [http.server.ThreadingHTTPServer(("127.0.0.1",0),App) for _ in range(2)]
    for index,app in enumerate(apps):
        app.label = str(index); app.slow_started = threading.Event(); app.slow_release = threading.Event(); threading.Thread(target=app.serve_forever,daemon=True).start()
    process = None
    admin, proxy = free_port(), free_port()
    addresses = [f"127.0.0.1:{a.server_port}" for a in apps]
    def api(path="/api/v1/config",method="GET",body=None):
        request = urllib.request.Request(f"http://127.0.0.1:{admin}"+path,
            data=json.dumps(body).encode() if body is not None else None,method=method,
            headers={"Content-Type":"application/json","X-RiverLB-Request":"configure"})
        with urllib.request.urlopen(request,timeout=10) as r: return json.load(r)
    def apply(config):
        api(method="PUT",body={"revision":api()["revision"],"config":config})
    def request(path="/",cookie=None,headers=None,connection=None,method="GET",body=None,chunked=False):
        own = connection is None; c = connection or http.client.HTTPConnection("127.0.0.1",proxy,timeout=10)
        h = dict(headers or {})
        if cookie: h["Cookie"] = cookie
        c.request(method,path,body=body,headers=h,encode_chunked=chunked)
        r = c.getresponse(); result = (r.status,dict(r.getheaders()),r.read(),r.getheaders())
        if own: c.close()
        return result
    def token(result):
        values = [v.split(';')[0] for k,v in result[3] if k.lower() == "set-cookie" and v.startswith("RIVERLB=")]
        assert len(values) <= 1
        return values[0] if values else None
    try:
        with tempfile.TemporaryDirectory(prefix="riverlb-http-") as folder:
            root = Path(folder); path = root/"config.toml"
            path.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 500
session_timeout_secs = 30
health_interval_secs = 1
max_connections = 100
[[virtual_servers]]
name = "web"
listen = "127.0.0.1:{proxy}"
members = {json.dumps(addresses)}
member_connection_limits = {{"{addresses[0]}" = 1, "{addresses[1]}" = 1}}
http = {{cookie = {{}}}}
''')
            bootstrap(BINARY,path)
            with (root/"log").open("w+") as log:
                process = subprocess.Popen([BINARY,"serve","-c",path],stdout=log,stderr=log)
                wait_until(lambda: api()["revision"] == 1)
                wait_until(lambda: all(m["healthy"] for m in api("/api/v1/status")["virtual_servers"][0]["members"]))
                original = api()['config']
                templated = copy.deepcopy(original)
                templated['river_rules'] = [
                    {'name':'redirect-template','rules':[{'name':'redirect-to-https','when':{},'actions':[{'kind':'redirect_https'}]}]},
                    {'name':'forward-template','rules':[{'name':'forward-client-ip','when':{},'actions':[{'kind':'set_forwarded_for'}]}]}
                ]
                templated['virtual_servers'][0]['http']['rule_sets'] = ['builtin-http-to-https']
                apply(templated)
                redirect = request('/page?q=hello', headers={'Host':'app.example:80'})
                assert redirect[0] == 302 and redirect[1]['location'] == 'https://app.example/page?q=hello'
                templated['virtual_servers'][0]['http']['rule_sets'] = ['redirect-template']
                templated['river_rules'][0]['rules'][0]['actions'][0]['host'] = 'fixed.example:8443'
                apply(templated)
                redirect = request('/page?q=hello', headers={'Host':'app.example:80'})
                assert redirect[1]['location'] == 'https://fixed.example:8443/page?q=hello'
                templated['virtual_servers'][0]['http']['rule_sets'] = ['builtin-x-forwarded-for']
                apply(templated)
                wait_until(lambda: all(m['healthy'] for m in api('/api/v1/status')['virtual_servers'][0]['members']))
                forwarded = request(headers={'X-Forwarded-For':'203.0.113.99, 203.0.113.100'})
                assert forwarded[0] == 200 and json.loads(forwarded[2])['forwarded_for'] == ['127.0.0.1']
                assert request('/latency')[0]==200
                assert api('/api/v1/statistics')['virtual_servers'][0]['traffic']['response_latency']['last_ms']>=50
                bad = copy.deepcopy(templated)
                bad['river_rules'][0]['rules'][0]['actions'][0]['host'] = 'user@evil.example'
                try: api('/api/v1/config/validate', 'POST', bad); raise AssertionError('invalid redirect host accepted')
                except urllib.error.HTTPError as e: assert e.code == 422
                nonsticky = copy.deepcopy(original)
                nonsticky['virtual_servers'][0]['http'].pop('cookie', None)
                nonsticky['virtual_servers'][0]['server_type'] = 'http'
                apply(nonsticky)
                wait_until(lambda: all(m['healthy'] for m in api('/api/v1/status')['virtual_servers'][0]['members']))
                c = http.client.HTTPConnection('127.0.0.1', proxy, timeout=10)
                selected, kept_socket = [], None
                for _ in range(6):
                    result = request('/no-cookie', connection=c)
                    assert result[0] == 200 and token(result) is None
                    selected.append(json.loads(result[2])['member'])
                    if kept_socket is None: kept_socket = c.sock
                    assert c.sock is kept_socket and kept_socket is not None
                c.close()
                latency=api('/api/v1/statistics')['virtual_servers'][0]['traffic']['response_latency']
                assert latency['samples']>=6 and latency['maximum_ms']>=latency['average_ms']>=latency['minimum_ms']>=0
                assert all(a != b for a, b in zip(selected, selected[1:])), selected
                assert set(selected) == {'0', '1'}
                apply(original)
                wait_until(lambda: all(m['healthy'] for m in api('/api/v1/status')['virtual_servers'][0]['members']))
                first,second = request(),request()
                assert first[0] == second[0] == 200
                assert json.loads(first[2])["member"] != json.loads(second[2])["member"]
                sticky = token(first); assert sticky and len(sticky.split('=')[1]) == 64
                assert "HttpOnly" in first[1]["set-cookie"] and "SameSite=Lax" in first[1]["set-cookie"]
                assert first[1]["cache-control"] == "private, no-store"
                c = http.client.HTTPConnection("127.0.0.1",proxy,timeout=10)
                for _ in range(3):
                    result = request(cookie=sticky+"; app=keep",connection=c)
                    assert json.loads(result[2])["member"] == json.loads(first[2])["member"]
                    assert json.loads(result[2])["cookie"] == "app=keep" and token(result) == sticky
                c.close()
                index = int(json.loads(first[2])["member"])
                held = []
                thread = threading.Thread(target=lambda: held.append(request('/slow',cookie=sticky))); thread.start()
                assert apps[index].slow_started.wait(5)
                fallback = request(cookie=sticky); assert json.loads(fallback[2])["member"] != str(index)
                apps[index].slow_release.set(); thread.join(10); assert held and held[0][0] == 200
                saved_port = apps[index].server_port; apps[index].shutdown(); apps[index].server_close()
                wait_until(lambda: not api('/api/v1/status')['virtual_servers'][0]['members'][index]['healthy'])
                fallback = request(cookie=sticky); assert json.loads(fallback[2])["member"] != str(index)
                apps[index] = http.server.ThreadingHTTPServer(('127.0.0.1',saved_port),App)
                apps[index].label = str(index); apps[index].slow_started = threading.Event(); apps[index].slow_release = threading.Event()
                threading.Thread(target=apps[index].serve_forever,daemon=True).start()
                wait_until(lambda: api('/api/v1/status')['virtual_servers'][0]['members'][index]['healthy'])
                assert "RIVERLB" not in json.dumps(api("/api/v1/persistence")["virtual_servers"][0]["records"])
                assert api("/api/v1/persistence")["virtual_servers"][0]["total_records"] >= 2
                config = api()["config"]; vs = config["virtual_servers"][0]
                vs["http"]["rules"] = [
                    {"name":"private","when":{"path_prefix":"/private"},"actions":[{"kind":"respond","status":403,"body":"Denied"}]},
                    {"name":"redirect","when":{"host":"old.home"},"actions":[{"kind":"redirect","location":"https://new.home/"}]},
                    {"name":"rewrite","when":{"path_prefix":"/old","method":"POST","header":{"name":"X-Trigger","value":"yes"}},"actions":[{"kind":"rewrite_path","path":"/new?q=1"},{"kind":"set_request_header","name":"X-Rule","value":"rewritten"},{"kind":"set_response_header","name":"X-Result","value":"ok"}]},
                    {"name":"route","when":{"path_prefix":"/route"},"actions":[{"kind":"select_member","address":addresses[1]}]}
                ]; apply(config)
                denied = request("/private/data"); assert denied[0] == 403 and denied[2] == b"Denied"
                redirected = request(headers={"Host":"old.home"}); assert redirected[0] == 302 and redirected[1]["location"] == "https://new.home/"
                rewritten = request("/old",headers={"X-Trigger":"yes"},method="POST",body=[b"hello",b" world"],chunked=True)
                assert rewritten[0] == 200 and rewritten[1]["x-result"] == "ok"
                data = json.loads(rewritten[2]); assert data["path"] == "/new?q=1" and data["rule"] == "rewritten" and data["body"] == "hello world"
                assert json.loads(request("/route",cookie=sticky)[2])["member"] == "1"
                vs["draining_members"] = [addresses[1]]; apply(config)
                assert request("/route")[0] == 503
                result = request(cookie=token(second)); assert result[0] == 200 and json.loads(result[2])["member"] == "0"
                vs.pop("draining_members"); vs["http"]["max_body_bytes"] = 1024; apply(config)
                assert request("/large")[0] == 502
                assert api("/api/v1/statistics")["virtual_servers"][0]["traffic"]["backend_errors"] >= 1
                assert request(method="POST",body=b"x"*2048)[0] == 413
                assert request(headers={"Connection":"Upgrade","Upgrade":"websocket"})[0] == 400
                assert request(method="CONNECT",path="localhost:443")[0] == 400
                with socket.create_connection(('127.0.0.1',proxy),timeout=5) as raw:
                    raw.sendall(b'POST / HTTP/1.1\r\nHost: app.home\r\nContent-Length: 1\r\nContent-Length: 2\r\nConnection: close\r\n\r\nx')
                    assert b' 400 ' in raw.recv(4096)
                vs['connection_limit'] = 1; apply(config)
                c = http.client.HTTPConnection('127.0.0.1',proxy,timeout=10)
                assert request(connection=c)[0] == 200
                apply(config)  # A held keepalive connection still occupies its slot across reload.
                try:
                    request(); raise AssertionError('HTTP connection limit was lost on reload')
                except (http.client.RemoteDisconnected,ConnectionResetError,BrokenPipeError): pass
                c.close()
                wait_until(lambda: api('/api/v1/status')['virtual_servers'][0]['admission_active'] == 0)
                assert request()[0] == 200
                vs.pop('connection_limit'); apply(config)
                for mutation in [
                    lambda v: v["http"]["cookie"].update(ttl_secs=0),
                    lambda v: v["http"].update(script="exec"),
                    lambda v: v["http"]["rules"][0].update(actions=[{"kind":"set_request_header","name":"Content-Length","value":"1"}]),
                    lambda v: v["http"]["rules"][0].update(actions=[{"kind":"select_member","address":"127.0.0.1:1"}]),
                    lambda v: v.update(persistence={"timeout_secs":10,"max_entries":10}),
                ]:
                    bad = copy.deepcopy(config); mutation(bad["virtual_servers"][0])
                    try: api("/api/v1/config/validate","POST",bad); raise AssertionError("bad rule accepted")
                    except urllib.error.HTTPError as e: assert e.code == 422
                vs["http"]["cookie"].update(ttl_secs=1,max_entries=1); apply(config)
                one = request(); assert token(one)
                assert token(request()) is None
                assert token(request(cookie=token(one))) == token(one)
                replacement = request('/route',cookie=token(one)); assert token(replacement) and token(replacement) != token(one)
                one = replacement
                time.sleep(1.1); assert token(request(cookie=token(one))) != token(one)
                cleared = api("/api/v1/persistence/web/clear","POST",{}); assert cleared["cleared"] == 1
                # Duplicate/malformed/forged tokens have no authority and issue a fresh cookie.
                assert token(request(cookie="RIVERLB=invalid; RIVERLB=invalid"))
                # Incoming TLS still enables Secure cookie attributes.
                subprocess.run(["openssl","req","-x509","-newkey","rsa:2048","-nodes","-keyout",root/"key.pem","-out",root/"cert.pem","-days","1","-subj","/CN=localhost"],check=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
                vs["tls"] = {"certificate":str(root/"cert.pem"),"private_key":str(root/"key.pem")}; apply(config)
                c = http.client.HTTPSConnection("127.0.0.1",proxy,timeout=10,context=ssl._create_unverified_context())
                result = request(connection=c); c.close(); assert result[0] == 200 and "; Secure" in result[1]["set-cookie"]
                process.send_signal(signal.SIGINT); process.wait(timeout=15)
                process = subprocess.Popen([BINARY,"serve","-c",path],stdout=log,stderr=log)
                wait_until(lambda: api()["config"]["virtual_servers"][0].get("http",{}).get("rules"))
                c = http.client.HTTPSConnection("127.0.0.1",proxy,timeout=10,context=ssl._create_unverified_context())
                assert request("/private",connection=c)[0] == 403; c.close()
                # Reusable objects, independent assignments and customizable cookie profiles.
                config = api()['config']; vs = config['virtual_servers'][0]; vs.pop('tls')
                settings = vs['http'].pop('cookie'); settings.update(ttl_secs=120,max_entries=100,always_send=False,refresh_on_use=False,http_only=False,same_site='strict',secure='always',path='/app',domain='home.test',session_cookie=True,expiration_secs=60)
                rules = vs['http'].pop('rules')
                config['cookie_profiles'] = [{'name':'site','description':'Custom clone','settings':settings}, {'name':'site-copy','description':'Independent snapshot','settings':copy.deepcopy(settings)}]
                config['river_rules'] = [{'name':'guard','description':'Reusable rule set','rules':rules[:1]}]
                vs['http'].update(cookie_profile='site',rule_sets=['guard']); apply(config)
                custom = request(); custom_token = token(custom)
                attrs = [v for k,v in custom[3] if k.lower() == 'set-cookie' and v.startswith('RIVERLB=')][0]
                assert 'Path=/app' in attrs and 'Domain=home.test' in attrs and 'SameSite=Strict' in attrs and '; Secure' in attrs and 'HttpOnly' not in attrs and 'Max-Age' not in attrs
                assert token(request(cookie=custom_token)) is None
                settings['ttl_secs'] = 1; apply(config)
                fixed = token(request()); time.sleep(0.6); assert token(request(cookie=fixed)) is None
                time.sleep(0.6); assert token(request(cookie=fixed)) != fixed
                settings['ttl_secs'] = 120; apply(config)
                assert request('/private')[0] == 403
                # No rules are needed for cookies; no cookie profile is needed for rules.
                vs['http']['rule_sets'] = []; apply(config); assert request('/private')[0] == 200
                vs['http'].pop('cookie_profile'); vs['http']['rule_sets'] = ['guard']; apply(config)
                assert request('/private')[0] == 403 and token(request()) == 'RIVERLB=application-collision'
                # Changing a reusable rule object updates its assignments.
                config['river_rules'][0]['rules'][0]['actions'][0]['status'] = 451; apply(config)
                assert request('/private')[0] == 451
                config['river_rules'].append({'name':'stamp','rules':[{'name':'private','when':{'path_prefix':'/private'},'actions':[{'kind':'respond','status':409,'body':'First'}]}]})
                vs['http']['rule_sets'] = ['guard','stamp']; apply(config); assert request('/private')[0] == 451
                vs['http']['rule_sets'] = ['stamp','guard']; apply(config); assert request('/private')[0] == 409
                vs['http']['cookie_profile'] = 'site'; vs['http']['rule_sets'] = []
                settings.update(method='rewrite',always_send=False,session_cookie=False); apply(config)
                assert token(request('/no-cookie')) is None
                rewritten = request(); assert token(rewritten) and 'Max-Age=60' in [v for k,v in rewritten[3] if k.lower() == 'set-cookie' and v.startswith('RIVERLB=')][0]
                assert api()['config']['cookie_profiles'][1]['settings']['session_cookie'] is True  # Clone is independent.
                settings.update(method='passive',refresh_on_use=True)
                for app in apps: app.cookie_value = 'app-' + app.label
                apply(config)
                passive = request(); learned = token(passive); target = json.loads(passive[2])['member']
                assert learned == 'RIVERLB=app-' + target
                for _ in range(3):
                    got = request(cookie=learned); assert json.loads(got[2])['member'] == target and json.loads(got[2])['cookie'] == learned
                assert api('/api/v1/persistence')['virtual_servers'][0]['total_records'] == 1
                settings.update(method='hash',hash_offset=6,hash_length=8); apply(config)
                hashed = [json.loads(request(cookie='RIVERLB=prefixsame-key' + str(i))[2])['member'] for i in range(5)]
                assert len(set(hashed)) == 1
                assert api('/api/v1/persistence')['virtual_servers'][0]['total_records'] == 0
                # Persisted member-limit override is explicit and never disables virtual limits.
                settings.update(method='insert',override_connection_limit=True,path='/',domain='',secure='auto',http_only=True,always_send=True); apply(config)
                initial = request(); sticky = token(initial); index = int(json.loads(initial[2])['member'])
                apps[index].slow_started.clear(); apps[index].slow_release.clear(); held = []
                thread = threading.Thread(target=lambda: held.append(request('/slow',cookie=sticky))); thread.start(); assert apps[index].slow_started.wait(5)
                got = request(cookie=sticky); assert json.loads(got[2])['member'] == str(index)
                apps[index].slow_release.set(); thread.join(10); assert held
                for mutation in [
                    lambda c: c.update(cookie_profiles=[]),
                    lambda c: c['cookie_profiles'][0].update(name='cookie'),
                    lambda c: c['cookie_profiles'][0]['settings'].update(path='/; injected'),
                    lambda c: c['cookie_profiles'][0]['settings'].update(same_site='none',secure='never'),
                    lambda c: c['virtual_servers'][0]['http'].update(rule_sets=['missing']),
                    lambda c: c['virtual_servers'][0]['http'].update(cookie={}),
                ]:
                    bad = copy.deepcopy(config); mutation(bad)
                    try: api('/api/v1/config/validate','POST',bad); raise AssertionError('bad reusable object accepted')
                    except urllib.error.HTTPError as e: assert e.code == 422
                vs['http']['cookie_profile'] = 'cookie'; apply(config)
                assert token(request())  # Built-in works without a saved custom object.
                vs['http']['cookie_profile'] = 'site'; vs['http']['rule_sets'] = ['guard']; apply(config)
                # Named HTTP limits resolve at apply time and survive restart.
                for key in ['max_body_bytes','max_header_bytes','keep_alive']: vs['http'].pop(key,None)
                config['http_profiles'] = [{'name':'small','settings':{'max_body_bytes':4096,'max_header_bytes':8192,'keep_alive':False}}]
                vs['http']['profile'] = 'small'; apply(config)
                assert request('/private')[0] == 451
                connection = http.client.HTTPConnection('127.0.0.1',proxy,timeout=10)
                assert request(connection=connection)[0] == 200
                assert connection.sock is None  # Disabled keepalive closes the client connection.
                connection.close()
                config['http_profiles'][0]['settings']['max_body_bytes'] = 1; apply(config)
                assert request()[0] == 502
                config['http_profiles'][0]['settings']['max_body_bytes'] = 4096; apply(config)
                process.send_signal(signal.SIGINT); process.wait(timeout=15)
                process = subprocess.Popen([BINARY,'serve','-c',path],stdout=log,stderr=log)
                wait_until(lambda: api()['config']['virtual_servers'][0]['http'].get('cookie_profile') == 'site')
                assert request('/private')[0] == 451
                assert api()['config']['http_profiles'][0]['settings']['max_body_bytes'] == 4096
            print("PASS HTTP: cookie affinity/expiry/capacity/clear/TLS, keepalive, chunked framing, RiverRules, limits, reload/restart")
    finally:
        if process and process.poll() is None: process.send_signal(signal.SIGINT); process.wait(timeout=15)
        for app in apps: app.shutdown(); app.server_close()

if __name__ == "__main__": run()
