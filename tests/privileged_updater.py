#!/usr/bin/env python3
"""Installed updater database isolation; disposable RPM container only."""
import importlib.machinery
import importlib.util
import os
from pathlib import Path
import pwd
import shutil
import stat
import subprocess
import sys

assert os.environ.get('RIVERLB_PACKAGE_TEST') == 'disposable-container'
assert os.geteuid() == 0
os.umask(0o077)
loader = importlib.machinery.SourceFileLoader('updater', '/usr/libexec/riverlb/riverlb-update')
spec = importlib.util.spec_from_loader(loader.name, loader)
helper = importlib.util.module_from_spec(spec)
loader.exec_module(helper)
account = pwd.getpwnam('riverlb')
assert account.pw_uid > 0 and helper.DB.stat().st_uid == account.pw_uid
assert not helper.JOURNAL.exists() and not helper.CHECKPOINT.exists()


def child(arguments, **options):
    return subprocess.run([str(value) for value in arguments], check=True, timeout=30,
                          user=account.pw_uid, group=account.pw_gid, extra_groups=[],
                          capture_output=True, **options)


def account_digest():
    return child([sys.executable, '-c',
        'import sqlite3,sys; c=sqlite3.connect(sys.argv[1]); '
        'print(c.execute("SELECT password_hash FROM administrators WHERE username=?",["admin"]).fetchone()[0])',
        helper.DB]).stdout


original = account_digest()
assert helper.checkpoint_database(helper.BASE) is None
info = helper.CHECKPOINT.stat()
assert info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o600
child([helper.BASE, 'admin', '--database', helper.DB], input=b'Changed-fixture-password-456\n')
assert account_digest() != original
helper.restore_database(helper.BASE)
assert account_digest() == original
assert helper.DB.stat().st_uid == account.pw_uid
assert list(helper.WORK.iterdir()) == []
helper.remove(helper.CHECKPOINT)

# An application-owned DB pathname must not cause the automatic root updater
# to read a different root-private database through a symlink.
protected = helper.UPDATER / 'fixture-protected.db'
saved = helper.DB.with_name('fixture-original.db')
shutil.copyfile(helper.DB, protected)
protected.chmod(0o600)
assert protected.stat().st_uid == 0
helper.DB.rename(saved)
try:
    child([sys.executable, '-c', 'import os,sys;os.symlink(sys.argv[1],sys.argv[2])', protected, helper.DB])
    try:
        helper.checkpoint_database(helper.BASE)
    except subprocess.CalledProcessError:
        pass
    else:
        raise AssertionError('Application reader crossed root-private database boundary')
    assert not helper.CHECKPOINT.exists()
    assert list(helper.WORK.iterdir()) == []
finally:
    helper.DB.unlink(missing_ok=True)
    saved.rename(helper.DB)
    protected.unlink()

print('PASS installed updater: actual service-UID checkpoint/restore, root-private copy, credential rollback and root-database symlink rejection')
