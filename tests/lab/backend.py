#!/usr/bin/env python3
"""Isolated functional backend; deliberately not a capacity benchmark server."""
import argparse
import json
import re
import ssl
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlsplit


def make_server(bind, port, name, unhealthy_file=None):
    class Handler(BaseHTTPRequestHandler):
        protocol_version = 'HTTP/1.1'

        def do_GET(self):
            url = urlsplit(self.path)
            query = parse_qs(url.query)
            status = 200
            try:
                delay = float(query.get('delay_ms', ['0'])[0])
                size = int(query.get('bytes', ['0'])[0])
                if not 0 <= delay <= 10000 or not 0 <= size <= 1048576:
                    raise ValueError('delay 0..10000 ms; bytes 0..1048576')
                time.sleep(delay / 1000)
                if url.path == '/healthz':
                    status = 503 if unhealthy_file and Path(unhealthy_file).exists() else 200
                    body = b'UNHEALTHY\n' if status == 503 else b'OK\n'
                elif url.path == '/fail':
                    status, body = 503, b'deliberate application failure\n'
                elif url.path == '/payload':
                    body = b'x' * size
                elif url.path == '/':
                    body = json.dumps({'node': name, 'peer': self.client_address[0],
                                       'host': self.headers.get('Host'),
                                       'headers': dict(self.headers)}).encode()
                else:
                    status, body = 404, b'unknown test endpoint\n'
            except ValueError as error:
                status, body = 400, str(error).encode()
            self.send_response(status)
            self.send_header('Content-Type', 'application/json' if url.path == '/' else 'text/plain')
            self.send_header('Content-Length', str(len(body)))
            self.send_header('X-Backend-Node', name)
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        def log_message(self, *_):
            pass

    return ThreadingHTTPServer((bind, port), Handler)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bind', default='127.0.0.1')
    parser.add_argument('--port', type=int, default=8080)
    parser.add_argument('--name', required=True)
    parser.add_argument('--unhealthy-file')
    parser.add_argument('--cert')
    parser.add_argument('--key')
    args = parser.parse_args()
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,64}', args.name):
        parser.error('name must contain 1..64 letters, digits, _, . or -')
    if bool(args.cert) != bool(args.key):
        parser.error('--cert and --key must be supplied together')
    server = make_server(args.bind, args.port, args.name, args.unhealthy_file)
    if args.cert:
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(args.cert, args.key)
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print(f'{args.name} listening on {args.bind}:{server.server_port}', flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == '__main__':
    main()
