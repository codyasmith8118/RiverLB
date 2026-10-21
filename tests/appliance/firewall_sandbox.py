#!/usr/bin/env python3
"""Exercise the real daemon's firewall guard under both packaged sandboxes.

Run as root on a disposable systemd machine with firewalld running. Only
loopback listeners and private temporary application databases are created;
the test never creates traffic objects or changes host firewall rules.
"""
import argparse
import json
import os
import shutil
import socket
import subprocess
import tempfile
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
MARKER = "automatic firewall provisioning initialized"
PROBE = """import fcntl,json,os,sys
r={}
try:os.readlink('/proc/1/ns/net');r['pid_one_readable']=True
except PermissionError:r['pid_one_readable']=False
assert os.getenv('LISTEN_PID')==str(os.getpid())
names=os.environ['LISTEN_FDNAMES'].split(':');fd=3+names.index('riverlb-host-netns')
current=os.stat('/proc/self/ns/net');host=os.fstat(fd)
r['host_namespace']=(current.st_dev,current.st_ino)==(host.st_dev,host.st_ino)
r['read_only']=fcntl.fcntl(fd,fcntl.F_GETFL)&os.O_ACCMODE==os.O_RDONLY
r['pid']=os.getpid();r['fd']=fd
print('RIVERLB_NAMESPACE_PROBE '+json.dumps(r),flush=True)
os.execv(sys.argv[1],sys.argv[1:])
"""


def command(*args, check=True):
    return subprocess.run(args, check=check, capture_output=True, text=True, timeout=45)


def check_case(binary, unit_source, private):
    name = "riverlb-firewall-test-" + uuid.uuid4().hex
    unit = Path("/run/systemd/system") / (name + ".service")
    directory = Path(tempfile.mkdtemp(prefix=name + "-", dir="/var/lib"))
    try:
        # PrivateTmp hides both /tmp and /var/tmp. Execute a private copy from
        # the fixture state directory, preserving its SELinux label/xattrs.
        executable = directory / "riverlb"
        shutil.copy2(binary, executable)
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            port = listener.getsockname()[1]
        config = directory / "config.toml"
        config.write_text(f'''management = "127.0.0.1:{port}"
connect_timeout_ms = 1000
session_timeout_secs = 30
health_interval_secs = 2
max_connections = 64
virtual_servers = []
''')
        (directory / "probe.py").write_text(PROBE)
        lines = []
        in_service = False
        excluded = {"ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop", "ExecStopPost",
                    "RuntimeDirectory", "StateDirectory", "WorkingDirectory", "Restart"}
        for line in unit_source.read_text().splitlines():
            if line.startswith("["):
                in_service = line == "[Service]"
                continue
            if not in_service or not line.strip() or line.lstrip().startswith("#"):
                continue
            key = line.split("=", 1)[0]
            if key in excluded:
                continue
            if key == "ReadWritePaths":
                # The CI runner need not have the optional HA packages. Retain
                # path restrictions while allowing absent package directories.
                line = "ReadWritePaths=" + " ".join("-" + p.lstrip("-") for p in line.split("=", 1)[1].split() if p.lstrip("-") != "/etc/riverlb")
            lines.append(line)
        lines.extend([
            "ReadWritePaths=" + str(directory),
            "RuntimeDirectory=" + name,
            "TemporaryFileSystem=/etc/riverlb:ro",  # Hide installed HA discovery.
            "Environment=RUST_LOG=riverlb=debug NO_COLOR=1",
            "Restart=no",
            "PrivateNetwork=" + ("yes" if private else "no"),
            f"ExecStart=/usr/bin/python3 {directory / 'probe.py'} {executable} serve --config {config} --database {directory / 'state.db'}",
        ])
        unit.write_text("[Unit]\nDescription=Read-only RiverLB firewall regression\n[Service]\n" + "\n".join(lines) + "\n")
        command("systemctl", "daemon-reload")
        started = command("systemctl", "start", unit.name, check=False)
        if started.returncode:
            raise AssertionError(command("journalctl", "-u", unit.name, "--no-pager", "-o", "cat").stdout)
        deadline = time.monotonic() + 20
        while True:
            journal = command("journalctl", "-u", unit.name, "--no-pager", "-o", "cat").stdout
            if MARKER in journal and "management portal ready" in journal:
                break
            if time.monotonic() > deadline or command("systemctl", "is-active", unit.name, check=False).returncode:
                raise AssertionError(journal)
            time.sleep(0.2)
        probe_line = next(line for line in journal.splitlines() if line.startswith("RIVERLB_NAMESPACE_PROBE "))
        probe = json.loads(probe_line.split(" ", 1)[1])
        pid = probe.pop("pid")
        fd = probe.pop("fd")
        assert probe == {"pid_one_readable": False, "host_namespace": not private, "read_only": True}, probe
        initialized = next(line for line in journal.splitlines() if MARKER in line)
        assert ("enabled=true" if not private else "enabled=false") in initialized, initialized
        assert "cannot verify host network namespace" not in journal, journal
        descriptor_flags = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/fdinfo/{fd}").read_text().splitlines())
        assert int(descriptor_flags["flags"], 8) & os.O_CLOEXEC, descriptor_flags
        print("PASS", unit_source.name, "private netns" if private else "host netns", probe, flush=True)
    finally:
        command("systemctl", "stop", unit.name, check=False)
        command("systemctl", "reset-failed", unit.name, check=False)
        unit.unlink(missing_ok=True)
        command("systemctl", "daemon-reload")
        shutil.rmtree(directory)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--binary", type=Path, required=True)
    args = parser.parse_args()
    assert os.geteuid() == 0, "requires root on a disposable systemd machine"
    assert os.readlink("/proc/self/ns/net") == os.readlink("/proc/1/ns/net"), "run from the host network namespace"
    command("firewall-cmd", "--state")
    binary = args.binary.resolve(strict=True)
    assert " " not in str(binary), "binary path must have no spaces"
    for source in [ROOT / "packaging/rpm/riverlb.service", ROOT / "deploy/ha/riverlb-ha.service"]:
        for private in [False, True]:
            check_case(binary, source, private)


if __name__ == "__main__":
    main()
