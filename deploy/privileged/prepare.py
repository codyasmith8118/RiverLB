#!/usr/bin/python3 -I
"""Root-only installation preflight. No paths or identities come from RPC."""
import fcntl
import importlib.util
import json
import ipaddress
import os
from pathlib import Path
import pwd
import sqlite3
import socket
import stat
import sys
import tomllib

# Extensionless installed entrypoint needs an explicit loader.
from importlib.machinery import SourceFileLoader
spec = importlib.util.spec_from_loader('broker', SourceFileLoader('broker', str(Path(__file__).with_name('riverlb-privileged'))))
broker = importlib.util.module_from_spec(spec)
spec.loader.exec_module(broker)

ROOT = Path('/etc/riverlb-privileged')
STATE = Path('/var/lib/riverlb-privileged')
CONFIG = Path('/etc/riverlb')
DATA = Path('/var/lib/riverlb')
RUN = Path('/run/riverlb')
SOCKET_DIR = Path('/run/riverlb-privileged')
SYS_NET = Path('/sys/class/net')


def directory(path, mode=0o700):
    if not path.exists() and not path.is_symlink():
        path.mkdir(mode=mode)
    broker.private(path, directory=True)
    os.chmod(path, mode)


def transfer_tree(path, uid, gid):
    """Use directory descriptors: never follow links supplied by the service UID."""
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        transfer_open_directory(descriptor, uid, gid)
    finally:
        os.close(descriptor)


def transfer_open_directory(descriptor, uid, gid):
    info = os.fstat(descriptor)
    broker.policy.require(info.st_uid in {0, uid} and not info.st_mode & 0o022)
    for name in os.listdir(descriptor):
        child = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK, dir_fd=descriptor)
        try:
            info = os.fstat(child)
            broker.policy.require(info.st_uid in {0, uid})
            if stat.S_ISDIR(info.st_mode):
                transfer_open_directory(child, uid, gid)
            else:
                broker.policy.require(stat.S_ISREG(info.st_mode) and info.st_nlink == 1)
                os.fchmod(child, 0o600)
                os.fchown(child, uid, gid)
        finally:
            os.close(child)
    os.fchmod(descriptor, 0o700)
    os.fchown(descriptor, uid, gid)


def initial_policy(uid, gid):
    # This runs once, while legacy configuration is still root-owned. New NICs
    # and subsequent configuration edits cannot expand the delegated scope.
    source = CONFIG / 'riverlb.toml'
    broker.private(CONFIG, directory=True)
    broker.private(source)
    configuration = tomllib.loads(source.read_text())
    database = DATA / 'riverlb.db'
    if database.exists():
        broker.private(DATA, directory=True)
        broker.private(database)
        with sqlite3.connect(f'file:{database}?mode=ro', uri=True) as connection:
            connection.execute('PRAGMA trusted_schema=OFF')
            row = connection.execute('SELECT json FROM configurations ORDER BY revision DESC LIMIT 1').fetchone()
            if row:
                configuration = json.loads(row[0])
    parents = {vlan['interface'] for vlan in configuration.get('network', {}).get('vlans', [])}
    links = json.loads(broker.success(broker.process('/usr/sbin/ip', ['-j', 'address', 'show']))['stdout'])
    management_ip = ipaddress.ip_address(configuration.get('management', '127.0.0.1:18090').rsplit(':', 1)[0].strip('[]'))
    traffic, management = [], []
    for link in links:
        name = link.get('ifname')
        if link.get('link_type') != 'ether':
            continue
        broker.policy.interface(name)
        if not (SYS_NET / name / 'device').exists():
            continue
        assigned = any(entry.get('scope') == 'global' for entry in link.get('addr_info', []))
        broker.policy.require(not (name in parents and any(entry.get('local') == str(management_ip)
                                                          for entry in link.get('addr_info', []))),
                              'Shared management and traffic adapter needs console policy review')
        (traffic if name in parents or not assigned else management).append(name)
    broker.policy.require(parents <= set(traffic), 'Legacy traffic parents need console policy review')
    return dict(version=1, uid=uid, gid=gid, traffic_interfaces=sorted(traffic),
                management_interfaces=sorted(management))


def prepare():
    broker.policy.require(os.geteuid() == 0)
    account = pwd.getpwnam('riverlb')
    broker.policy.require(account.pw_uid > 0 and account.pw_gid > 0)
    for path in [ROOT, STATE]:
        directory(path)
    lock = os.open(STATE / 'prepare.lock', os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600)
    try:
        broker.private(STATE / 'prepare.lock')
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        marker = ROOT / 'migration.json'
        if not marker.exists():
            selection = Path('/usr/lib/riverlb/current')
            broker.policy.require(not selection.exists() and not selection.is_symlink(),
                                  'Clear the active offline selection through console recovery before RPM migration')
            # Legacy HA can reference arbitrary root credential files. Require
            # a console migration of those identities before changing ownership;
            # silently handing the old directory to the web UID would expose them.
            broker.policy.require(not any(path.name.startswith(('ha.', 'ha-')) for path in CONFIG.iterdir()),
                                  'Migrate legacy HA settings and credentials from the console first')
            policy = initial_policy(account.pw_uid, account.pw_gid)
            if broker.POLICY.exists():
                existing = broker.load(broker.POLICY)
                broker.policy.require(existing['uid'] == account.pw_uid and existing['gid'] == account.pw_gid)
            else:
                broker.save(broker.POLICY, policy)
            # Mark the irreversible trust boundary before changing application
            # ownership. A crash cannot cause later app data to seed root policy.
            broker.save(marker, dict(version=1, uid=account.pw_uid, gid=account.pw_gid))
        accepted = broker.load(marker)
        broker.policy.require(accepted == dict(version=1, uid=account.pw_uid, gid=account.pw_gid))
        policy = broker.load(broker.POLICY)
        broker.policy.require(policy['uid'] == account.pw_uid and policy['gid'] == account.pw_gid)
        for path in [CONFIG, DATA]:
            transfer_tree(path, account.pw_uid, account.pw_gid)
        if not RUN.exists():
            RUN.mkdir(mode=0o700)
        runtime = RUN.lstat()
        broker.policy.require(stat.S_ISDIR(runtime.st_mode) and runtime.st_uid in {0, account.pw_uid}
                              and not runtime.st_mode & 0o022)
        os.chown(RUN, account.pw_uid, account.pw_gid, follow_symlinks=False)
        os.chmod(RUN, 0o700)
        for name in ['operations.sock', 'ha.sock']:
            path = RUN / name
            if not path.exists() and not path.is_symlink():
                continue
            info = path.lstat()
            broker.policy.require(stat.S_ISSOCK(info.st_mode) and info.st_uid in {0, account.pw_uid})
            if info.st_uid == 0:
                with socket.socket(socket.AF_UNIX) as probe:
                    probe.settimeout(1)
                    try:
                        probe.connect(str(path))
                    except ConnectionRefusedError:
                        path.unlink()
                    else:
                        raise broker.policy.Rejected('Stop the legacy root daemon before migration')
        directory(SOCKET_DIR, 0o755)
        directory(Path('/run/riverlb-ha-deploy'))
    finally:
        os.close(lock)


if __name__ == '__main__':
    os.umask(0o077)
    try:
        broker.policy.require(sys.argv[1:] == [])
        prepare()
    except Exception as error:
        # No file contents, account secrets or application data enter logs.
        message = str(error) if isinstance(error, broker.policy.Rejected) else type(error).__name__
        sys.exit('RiverLB privileged preparation failed: ' + message)
