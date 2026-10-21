"""First-boot lifecycle: real certificate/database operations, mocked OS mutation."""
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
from unittest.mock import patch, MagicMock

if os.environ.get('RIVERLB_PACKAGE_TEST') != 'disposable-container':
    raise SystemExit('Run via scripts/test-rpm.sh in a disposable container')
loader = importlib.machinery.SourceFileLoader('setup', '/usr/sbin/riverlb-setup')
spec = importlib.util.spec_from_loader(loader.name, loader)
setup = importlib.util.module_from_spec(spec)
loader.exec_module(setup)
original_run = setup.run

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    setup.CONFIG = root / 'etc' / 'riverlb.toml'
    setup.CONFIG.parent.mkdir(mode=0o700)
    setup.CONFIG.write_text(Path('/etc/riverlb/riverlb.toml').read_text())
    setup.STATE = root / 'state'
    setup.MARKER = setup.STATE / '.firstboot.complete'
    calls = []
    fail_activation = [True]
    assert not setup.startup_ready()
    assert not setup.STATE.joinpath('riverlb.db').exists()

    def run(args, **kwargs):
        calls.append(args)
        if args[0] in ('openssl', 'riverlb'):
            return original_run(args, **kwargs)
        if args[:2] == ['systemctl', 'is-active'] and not setup.STATE.joinpath('riverlb.db').exists():
            return subprocess.CompletedProcess(args, 3, stdout='')
        if args[:3] == ['systemctl', 'enable', '--now'] and fail_activation[0]:
            fail_activation[0] = False
            raise subprocess.CalledProcessError(1, args)
        return subprocess.CompletedProcess(args, 0, stdout='public\n')

    with patch.object(setup, 'run', run), patch.object(setup, 'interfaces', return_value=[('test0', '192.0.2.44')]), \
         patch('builtins.input', side_effect=['lb-test.example', '1', 'admin', 'APPLY']), \
         patch.object(setup.getpass, 'getpass', side_effect=['Admin-password-123', 'Admin-password-123', 'Console-password-123', 'Console-password-123']):
        try:
            setup.main()
        except RuntimeError as error:
            assert 'could not start' in str(error) and 'resume' in str(error)
        else:
            raise AssertionError('Injected activation failure was not surfaced')
    assert not setup.MARKER.exists()
    assert setup.STATE.joinpath('.firstboot.pending').exists()
    assert setup.startup_ready(), 'Committed activation must pass the appliance service gate'
    pending_file = setup.STATE / '.firstboot.pending'
    valid_pending = pending_file.read_text()
    pending_file.write_text('{}')
    assert not setup.startup_ready(), 'Incomplete activation journals must not authorize startup'
    pending_file.write_text(valid_pending)
    response = MagicMock()
    response.__enter__.return_value.status = 200
    opener = MagicMock()
    opener.open.return_value = response
    with patch.object(setup, 'run', run), patch.object(setup.urllib.request, 'build_opener', return_value=opener):
        setup.main()
    assert json.loads(setup.MARKER.read_text())['address'] == '192.0.2.44'
    assert not setup.STATE.joinpath('.firstboot.pending').exists()
    assert setup.startup_ready(), 'Completed appliances must restart without a pending journal'
    for file in [setup.CONFIG, setup.CONFIG.parent / 'device.key', setup.MARKER]:
        assert file.stat().st_mode & 0o777 == 0o600
    assert setup.STATE.joinpath('riverlb.db').exists()
    assert 'management_protocol = "https"' in setup.CONFIG.read_text()
    assert all('password-123' not in str(command) for command in calls)
    try:
        setup.main()
    except SystemExit as error:
        assert 'already completed' in str(error)
    else:
        raise AssertionError('Completed setup must refuse to recreate identity')
    setup.MARKER.unlink()
    assert not setup.startup_ready(), 'An existing DB alone must not authorize bootstrap startup'
    try:
        setup.main()
    except SystemExit as error:
        assert 'Existing application database' in str(error)
    else:
        raise AssertionError('Existing state must not be overwritten')
print('First-boot HTTPS identity, private files, activation resume and overwrite protection passed')
