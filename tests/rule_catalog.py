"""Built-in RiverRules through authenticated config APIs and real HTTP/TLS sockets.

Only disposable state, generated fixture certificates and loopback backends are
used. No host network objects, services or production databases are changed.
"""
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
import urllib.error
import urllib.request
from pathlib import Path

from auth_helpers import bootstrap
from smoke import BINARY, free_port, wait_until

ROOT = Path(__file__).resolve().parents[1]


class App(http.server.BaseHTTPRequestHandler):
    protocol_version = 'HTTP/1.1'
    server_version = 'CatalogFixture'
    sys_version = ''

    def exchange(self):
        data = dict(method=self.command, path=self.path,
                    headers={name.lower(): self.headers.get_all(name) for name in self.headers},
                    body=self.rfile.read(int(self.headers.get('Content-Length', 0))).decode())
        with self.server.observed_lock:
            self.server.observed.append(data)
        if self.path == '/drop':
            self.close_connection = True
            return
        body = json.dumps(data).encode()
        self.send_response(200)
        for name, value in [('Content-Type', 'application/json'), ('Cache-Control', 'public, max-age=60'),
                            ('X-Powered-By', 'fixture'), ('X-AspNet-Version', 'fixture'),
                            ('X-AspNetMvc-Version', 'fixture'), ('X-Order', 'backend'),
                            ('Access-Control-Allow-Origin', '*'), ('Access-Control-Allow-Credentials', 'true'),
                            ('Access-Control-Allow-Methods', 'GET, POST'), ('Access-Control-Allow-Headers', 'X-Test'),
                            ('Access-Control-Expose-Headers', 'X-Test'), ('Access-Control-Max-Age', '60'),
                            ('Access-Control-Allow-Private-Network', 'true')]:
            self.send_header(name, value)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        if self.command != 'HEAD':
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

    do_GET = do_HEAD = do_POST = do_PUT = do_PATCH = do_DELETE = do_OPTIONS = do_TRACE = exchange

    def log_message(self, *_):
        pass


def omit_nulls(value):
    if isinstance(value, dict):
        return {key: omit_nulls(item) for key, item in value.items() if item is not None}
    if isinstance(value, list):
        return [omit_nulls(item) for item in value]
    return value


def run():
    backend = http.server.ThreadingHTTPServer(('127.0.0.1', 0), App)
    backend.daemon_threads = True
    backend.observed = []
    backend.observed_lock = threading.Lock()
    worker = threading.Thread(target=backend.serve_forever, daemon=True)
    worker.start()
    process = secure_backend = secure_worker = None
    admin, proxy = free_port(), free_port()
    address = f'127.0.0.1:{backend.server_port}'

    def api(route='/api/v1/config', method='GET', body=None, expected=200):
        request = urllib.request.Request(f'http://127.0.0.1:{admin}' + route,
            data=json.dumps(body).encode() if body is not None else None, method=method,
            headers={'Content-Type': 'application/json', 'X-RiverLB-Request': 'configure'})
        try:
            response = urllib.request.urlopen(request, timeout=10)
        except urllib.error.HTTPError as error:
            response = error
        with response:
            assert response.status == expected, (route, response.status, expected)
            return json.load(response)

    def count():
        with backend.observed_lock:
            return len(backend.observed)

    def request(path='/', method='GET', headers=None, body=None, tls=False, connection=None):
        own = connection is None
        if connection is None:
            connection = (http.client.HTTPSConnection('127.0.0.1', proxy, timeout=10,
                          context=ssl._create_unverified_context()) if tls else
                          http.client.HTTPConnection('127.0.0.1', proxy, timeout=10))
        connection.request(method, path, body=body, headers=headers or {})
        response = connection.getresponse()
        result = response.status, {key.lower(): value for key, value in response.getheaders()}, response.read()
        if own:
            connection.close()
        return result

    def custom(name, actions, when=None):
        return dict(name=name, description='Disposable fixture',
                    rules=[dict(name=name, when=when or {}, actions=actions)])

    try:
        with tempfile.TemporaryDirectory(prefix='riverlb-rule-catalog-') as directory:
            root = Path(directory)
            config_path = root / 'riverlb.toml'
            config_path.write_text(f'''management = "127.0.0.1:{admin}"
connect_timeout_ms = 500
session_timeout_secs = 30
health_interval_secs = 1
max_connections = 100
[[virtual_servers]]
name = "catalog-fixture"
listen = "127.0.0.1:{proxy}"
server_type = "http"
members = ["{address}"]
http = {{}}
''')
            bootstrap(BINARY, config_path)
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
                            '-keyout', root / 'key.pem', '-out', root / 'cert.pem', '-days', '1',
                            '-subj', '/CN=localhost', '-addext', 'subjectAltName=DNS:localhost,IP:127.0.0.1',
                            '-addext', 'basicConstraints=critical,CA:FALSE'], check=True, capture_output=True)
            secure_backend = http.server.ThreadingHTTPServer(('127.0.0.1', 0), App)
            secure_backend.daemon_threads = True
            secure_backend.observed = []
            secure_backend.observed_lock = threading.Lock()
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(root / 'cert.pem', root / 'key.pem')
            secure_backend.socket = context.wrap_socket(secure_backend.socket, server_side=True)
            secure_worker = threading.Thread(target=secure_backend.serve_forever, daemon=True)
            secure_worker.start()
            with (root / 'daemon.log').open('w+') as log:
                def start():
                    return subprocess.Popen([BINARY, 'serve', '-c', config_path, '--external-network'],
                                            stdout=log, stderr=log)
                process = start()
                wait_until(lambda: api()['revision'] == 1)
                wait_until(lambda: api('/api/v1/status')['virtual_servers'][0]['members'][0]['healthy'])
                original = api()['config']
                assert not original.get('river_rules')
                source = json.loads((ROOT / 'src/river_rules.json').read_text())
                catalog = api('/api/v1/river-rules/builtins')['rule_sets']
                assert len(catalog) >= 20 and len({item['name'] for item in catalog}) == len(catalog)
                assert omit_nulls(catalog) == omit_nulls(source), 'GUI/backend catalog must share the shipped definitions'
                entries = {item['name']: item for item in catalog}

                def config_for(names, objects=None, tls=False):
                    config = copy.deepcopy(original)
                    config['river_rules'] = copy.deepcopy(objects or [])
                    server = config['virtual_servers'][0]
                    server['http'] = dict(rule_sets=names)
                    if tls:
                        server['tls'] = dict(certificate=str(root / 'cert.pem'), private_key=str(root / 'key.pem'))
                    return config

                def apply(names, objects=None, tls=False, configure=None):
                    config = config_for(names, objects, tls)
                    if configure:
                        configure(config)
                    saved = api(method='PUT', body=dict(revision=api()['revision'], config=config))
                    assert omit_nulls(api()['config'].get('river_rules', [])) == omit_nulls(objects or [])
                    return saved

                for entry in catalog:
                    assert set(entry) == {'name', 'description', 'category', 'usage', 'rules'}
                    assert entry['description'] and entry['category'] and entry['usage'] and entry['rules']
                    api('/api/v1/config/validate', 'POST', config_for([entry['name']]))
                    reserved = custom(entry['name'], [dict(kind='respond', status=200, body='fake')])
                    api('/api/v1/config/validate', 'POST', config_for([], [reserved]), expected=422)

                # Redirects preserve URI context, stop before the backend and
                # ignore a client-claimed scheme. Actual TLS avoids redirect loops.
                apply(['builtin-http-to-https'])
                before = count()
                status, headers, _ = request('/page?q=hello', headers={'Host': 'app.example:80',
                                             'X-Forwarded-Proto': 'https'})
                assert status == 302 and headers['location'] == 'https://app.example/page?q=hello'
                assert count() == before
                apply(['builtin-http-to-https'], tls=True)
                assert request('/page?q=hello', tls=True, headers={'Host': 'app.example:443'})[0] == 200

                # Proxy context replaces spoofed values and survives malicious
                # hop-by-hop nominations before reaching the real backend.
                spoofed = {'Host': 'app.example:12345', 'X-Forwarded-For': '203.0.113.99',
                           'X-Real-IP': '203.0.113.98', 'X-Forwarded-Proto': 'spoofed',
                           'X-Forwarded-Host': 'evil.example', 'X-Forwarded-Port': '1',
                           'X-Forwarded-Prefix': '/private', 'X-Forwarded-Unknown': 'spoofed',
                           'Client-IP': '203.0.113.97', 'True-Client-IP': '203.0.113.96',
                           'Forwarded': 'for=203.0.113.99;proto=https', 'X-Hop-Fixture': 'remove-me',
                           'Connection': 'X-Forwarded-For, X-Forwarded-Proto, X-Forwarded-Port, X-Hop-Fixture'}
                for tls in (False, True):
                    apply(['builtin-proxy-headers'], tls=tls)
                    status, _, body = request(headers=spoofed, tls=tls)
                    assert status == 200
                    observed = json.loads(body)['headers']
                    assert observed['x-forwarded-for'] == ['127.0.0.1']
                    assert observed['x-real-ip'] == ['127.0.0.1']
                    assert observed['x-forwarded-proto'] == ['https' if tls else 'http']
                    assert observed['x-forwarded-host'] == ['app.example:12345']
                    assert observed['x-forwarded-port'] == [str(proxy)]
                    assert all(name not in observed for name in ('forwarded', 'x-forwarded-prefix',
                                                                 'x-forwarded-unknown', 'x-hop-fixture'))
                apply(['builtin-x-forwarded-for'])
                assert json.loads(request(headers=spoofed)[2])['headers']['x-forwarded-for'] == ['127.0.0.1']
                for tls in (False, True):
                    apply(['builtin-forwarded-proto-http', 'builtin-forwarded-proto-https'], tls=tls)
                    observed = json.loads(request(headers=spoofed, tls=tls)[2])['headers']
                    assert observed['x-forwarded-proto'] == ['https' if tls else 'http']
                def backend_tls(config):
                    config['server_tls_profiles'] = [dict(name='verified-fixture', server_name='localhost',
                                                          ca_certificate=str(root / 'cert.pem'))]
                    server = config['virtual_servers'][0]
                    server['members'] = [f'127.0.0.1:{secure_backend.server_port}']
                    server['server_tls_profile'] = 'verified-fixture'
                apply(['builtin-proxy-headers', 'builtin-hsts-one-day'], configure=backend_tls)
                wait_until(lambda: api('/api/v1/status')['virtual_servers'][0]['members'][0]['healthy'])
                status, headers, body = request(headers=spoofed)
                assert status == 200 and 'strict-transport-security' not in headers
                assert json.loads(body)['headers']['x-forwarded-proto'] == ['http'], 'Backend TLS must not change client scheme'
                apply(['builtin-proxy-headers'])
                before = count()
                assert request(headers={'Host': ':80'})[0] == 400
                assert count() == before
                apply(['builtin-strip-forwarding-headers', 'builtin-proxy-headers'])
                assert json.loads(request(headers=spoofed)[2])['headers']['x-forwarded-proto'] == ['http']
                apply(['builtin-proxy-headers', 'builtin-strip-forwarding-headers'])
                assert 'x-forwarded-for' not in json.loads(request(headers=spoofed)[2])['headers']
                apply(['builtin-strip-forwarding-headers'])
                observed = json.loads(request(headers=spoofed)[2])['headers']
                assert all(name not in observed for name in ('forwarded', 'x-forwarded-for',
                    'x-forwarded-proto', 'x-forwarded-host', 'x-forwarded-port', 'x-forwarded-prefix',
                    'x-real-ip', 'client-ip', 'true-client-ip'))
                assert observed['x-forwarded-unknown'] == ['spoofed'], 'Explicit cleanup has a documented finite name list'
                for name, matching_tls in [('builtin-forwarded-proto-http', False),
                                           ('builtin-forwarded-proto-https', True)]:
                    for tls in (False, True):
                        apply([name], tls=tls)
                        observed = json.loads(request(headers={'X-Forwarded-Proto': 'unverified'}, tls=tls)[2])['headers']
                        expected = ('https' if tls else 'http') if tls == matching_tls else 'unverified'
                        assert observed['x-forwarded-proto'] == [expected]

                # HSTS is based on incoming TLS, and response policies affect
                # both backend exchanges and deliberately local responses.
                apply(['builtin-hsts-one-day', 'builtin-web-header-baseline'])
                status, headers, _ = request(headers={'X-Forwarded-Proto': 'https'})
                assert status == 200 and 'strict-transport-security' not in headers
                assert headers['x-content-type-options'] == 'nosniff'
                assert headers['x-frame-options'] == 'SAMEORIGIN'
                assert headers['referrer-policy'] == 'strict-origin-when-cross-origin'
                assert all(name not in headers for name in ('server', 'x-powered-by',
                                                             'x-aspnet-version', 'x-aspnetmvc-version'))
                apply(['builtin-hsts-one-day', 'builtin-web-header-baseline'], tls=True)
                assert request(tls=True)[1]['strict-transport-security'] == 'max-age=86400'
                for name, header, value in [
                    ('builtin-frame-deny', 'x-frame-options', 'DENY'),
                    ('builtin-frame-sameorigin', 'x-frame-options', 'SAMEORIGIN'),
                    ('builtin-referrer-no-referrer', 'referrer-policy', 'no-referrer'),
                    ('builtin-referrer-strict-origin', 'referrer-policy', 'strict-origin-when-cross-origin'),
                    ('builtin-robots-noindex', 'x-robots-tag', 'noindex, nofollow')]:
                    apply([name])
                    assert request()[1][header] == value
                apply(['builtin-strip-server-identity'])
                headers = request()[1]
                assert all(name not in headers for name in ('server', 'x-powered-by',
                                                            'x-aspnet-version', 'x-aspnetmvc-version'))
                apply(['builtin-frame-deny', 'builtin-frame-sameorigin'])
                assert request()[1]['x-frame-options'] == 'SAMEORIGIN', 'Later conflicting response policies win'
                apply(['builtin-content-type-nosniff', 'builtin-http-to-https'])
                assert request(headers={'Host': 'app.example'})[1]['x-content-type-options'] == 'nosniff'

                apply(['builtin-content-type-nosniff', 'builtin-listener-liveness', 'builtin-maintenance'])
                before = count()
                live = request('/__riverlb/live?probe=1')
                assert live[0] == 200 and b'HTTP listener' in live[2] and live[1]['cache-control'] == 'no-store'
                maintenance = request('/application')
                assert maintenance[0] == 503 and maintenance[1]['retry-after'] == '60'
                assert maintenance[1]['content-type'] == 'text/plain; charset=utf-8'
                assert maintenance[1]['cache-control'] == 'no-store'
                assert maintenance[1]['x-content-type-options'] == 'nosniff'
                assert b'temporarily unavailable' in maintenance[2]
                assert request('/__riverlb/live/child')[0] == 503
                assert request('/__riverlb/live', method='POST', body=b'fixture')[0] == 503
                connection = http.client.HTTPConnection('127.0.0.1', proxy, timeout=10)
                try:
                    assert request('/application', method='HEAD', connection=connection)[2] == b''
                    assert request('/application', connection=connection)[0] == 503
                finally:
                    connection.close()
                assert count() == before, 'Local maintenance/liveness must not send HTTP to any member'
                apply(['builtin-maintenance', 'builtin-listener-liveness'])
                assert request('/__riverlb/live')[0] == 503

                # Exact paths exclude query strings and do not accidentally
                # block adjacent namespaces. API maintenance is similarly scoped.
                apply(['builtin-api-no-store'])
                for path in ('/api', '/api?x=1', '/api/items'):
                    assert request(path)[1]['cache-control'] == 'private, no-store'
                assert request('/apiculture')[1]['cache-control'] == 'public, max-age=60'
                apply(['builtin-cache-revalidate'])
                assert request()[1]['cache-control'] == 'private, no-cache'
                apply(['builtin-cache-no-store'])
                assert request()[1]['cache-control'] == 'private, no-store'
                apply(['builtin-api-maintenance'])
                before = count()
                assert request('/api?q=1')[0] == 503 and request('/api/item')[0] == 503
                assert count() == before
                assert request('/apiculture')[0] == 200

                apply(['builtin-block-trace', 'builtin-block-rest-writes'])
                before = count()
                for method in ('TRACE', 'PUT', 'PATCH', 'DELETE'):
                    result = request(method=method)
                    assert result[0] == 403 and result[1]['cache-control'] == 'no-store'
                assert count() == before
                assert request(method='POST', body=b'allowed')[0] == 200
                apply(['builtin-deny-root-git', 'builtin-deny-root-env', 'builtin-deny-admin-path'])
                before = count()
                for path, status in (('/.git', 404), ('/.git/HEAD', 404), ('/.env?q=1', 404),
                                     ('/admin', 403), ('/admin/settings', 403)):
                    assert request(path)[0] == status
                assert count() == before
                for path in ('/.gitconfig', '/.env.production', '/administrator', '/nested/.env', '/%2eenv'):
                    assert request(path)[0] == 200, 'Literal path controls must keep their documented boundaries'

                apply(['builtin-robots-disallow', 'builtin-disable-cors', 'builtin-disable-backend-compression',
                       'builtin-remove-request-referer'])
                before = count()
                robots = request('/robots.txt')
                assert robots[0] == 200 and robots[2] == b'User-agent: *\nDisallow: /\n'
                assert count() == before
                status, headers, body = request(headers={'Accept-Encoding': 'gzip', 'Referer': 'https://private.example/token'})
                assert status == 200 and not any(name.startswith('access-control-') for name in headers)
                observed = json.loads(body)['headers']
                assert observed['accept-encoding'] == ['identity'] and 'referer' not in observed

                # Ordered response edits remain ordered for local replies and
                # backend replies; later rules see request rewrites/removals.
                ordered = custom('ordered-copy', [dict(kind='set_response_header', name='X-Order', value='first'),
                    dict(kind='remove_response_header', name='X-Order'),
                    dict(kind='set_response_header', name='X-Order', value='last')])
                apply(['ordered-copy'], [ordered])
                assert request()[1]['x-order'] == 'last'
                apply(['ordered-copy', 'builtin-maintenance'], [ordered])
                assert request()[1]['x-order'] == 'last'
                chain = dict(name='request-chain', description='Disposable ordered conditions', rules=[
                    dict(name='rewrite', when=dict(path='/old'), actions=[
                        dict(kind='rewrite_path', path='/new?rewritten=1'),
                        dict(kind='remove_request_header', name='X-Trigger')]),
                    dict(name='removed-condition', when=dict(header=dict(name='X-Trigger', value='yes')),
                         actions=[dict(kind='respond', status=409, body='must not match')]),
                    dict(name='rewritten-condition', when=dict(path='/new'),
                         actions=[dict(kind='respond', status=202, body='ordered')])])
                apply(['request-chain'], [chain])
                assert request('/old', headers={'X-Trigger': 'yes'})[0] == 202
                assert request('/other')[0] == 200

                # Error replies produced after rule evaluation carry the same
                # response policy as successful exchanges.
                apply(['builtin-content-type-nosniff'], configure=lambda config:
                      config['virtual_servers'][0].update(draining_members=[address]))
                result = request()
                assert result[0] == 503 and result[1]['x-content-type-options'] == 'nosniff'
                def small_body(config):
                    config['http_profiles'] = [dict(name='small-body', settings=dict(max_body_bytes=1))]
                    config['virtual_servers'][0]['http']['profile'] = 'small-body'
                apply(['builtin-content-type-nosniff'], configure=small_body)
                result = request(method='POST', body=b'over-limit')
                assert result[0] == 413 and result[1]['x-content-type-options'] == 'nosniff'
                apply(['builtin-content-type-nosniff'])
                result = request('/drop')
                assert result[0] == 502 and result[1]['x-content-type-options'] == 'nosniff'

                # A copy is a normal editable object. Changes cannot mutate the
                # shared built-in, and references survive database reload.
                editable = copy.deepcopy(entries['builtin-maintenance'])
                editable = {key: editable[key] for key in ('name', 'description', 'rules')}
                editable['name'] = 'maintenance-copy'
                editable['rules'][0]['actions'][-1]['body'] = 'Planned fixture maintenance\n'
                apply(['maintenance-copy'], [editable])
                assert request()[2] == b'Planned fixture maintenance\n'
                assert omit_nulls(api('/api/v1/river-rules/builtins')['rule_sets']) == omit_nulls(source)
                api('/api/v1/config/validate', 'POST', config_for(['missing-builtin']), expected=422)
                for action in ('remove_request_header', 'remove_response_header'):
                    invalid = custom('unsafe-removal', [dict(kind=action, name='Content-Length')])
                    api('/api/v1/config/validate', 'POST', config_for(['unsafe-removal'], [invalid]), expected=422)
                apply(['builtin-proxy-headers', 'builtin-hsts-one-day'], tls=True)
                revision = api()['revision']
                process.send_signal(signal.SIGINT)
                process.wait(timeout=15)
                assert process.returncode == 0
                process = start()
                wait_until(lambda: api()['revision'] == revision)
                assert not api()['config'].get('river_rules')
                result = request(tls=True)
                assert result[0] == 200 and result[1]['strict-transport-security'] == 'max-age=86400'
                assert json.loads(result[2])['headers']['x-forwarded-proto'] == ['https']
    finally:
        if process is not None and process.poll() is None:
            process.send_signal(signal.SIGINT)
            try:
                process.wait(timeout=15)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=5)
                raise AssertionError('Catalog fixture daemon did not stop cleanly')
        backend.shutdown()
        backend.server_close()
        worker.join(timeout=3)
        if secure_backend is not None:
            secure_backend.shutdown()
            secure_backend.server_close()
            secure_worker.join(timeout=3)
    print('PASS RiverRules catalog: every preset resolves; real HTTP/TLS forwarding, redirects, local replies, ordered headers, cache/path/method boundaries, errors, copies and restart')


if __name__ == '__main__':
    run()
