"""Backend fixture executed in its own disposable network namespace."""
import json
import os
import socketserver
import subprocess
import sys

print(os.getpid(), flush=True)
sys.stdin.readline()  # Parent moves only the test veth peer into this namespace.
for args in [("link", "set", "lo", "up"), ("addr", "add", "192.0.2.100/24", "dev", "srv0"), ("link", "set", "srv0", "up")]:
    subprocess.run(["/usr/sbin/ip", *args], check=True)


class Handler(socketserver.BaseRequestHandler):
    def handle(self):
        data = self.request.recv(100)
        if data:
            self.request.sendall(json.dumps({"source": self.client_address[0], "data": data.decode()}).encode())


with socketserver.ThreadingTCPServer(("192.0.2.100", 0), Handler) as server:
    print(server.server_address[1], flush=True)
    server.serve_forever()
