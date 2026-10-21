"""Console setup navigation tests; never run OS commands or create live accounts."""
from contextlib import redirect_stdout
import importlib.machinery
import importlib.util
import io
from pathlib import Path
from unittest.mock import patch
import subprocess

ROOT = Path(__file__).resolve().parents[1]
loader = importlib.machinery.SourceFileLoader('setup_ui', str(ROOT / 'appliance/firstboot/riverlb-setup'))
spec = importlib.util.spec_from_loader(loader.name, loader)
setup = importlib.util.module_from_spec(spec)
loader.exec_module(setup)
output = io.StringIO()
with redirect_stdout(output), patch('builtins.input', side_effect=['invalid name', '']), patch.object(setup, 'run') as commands:
    assert setup.hostname_prompt() == 'riverlb'
    commands.assert_not_called()
with redirect_stdout(output), patch('builtins.input', side_effect=['bad/name', '']):
    assert setup.administrator_prompt() == 'admin'
with redirect_stdout(output), patch.object(setup, 'interfaces', side_effect=[[], [('eth1', '192.0.2.10')], [('eth1', '192.0.2.10')]]), \
     patch('builtins.input', side_effect=['N', '99', '1']), patch.object(setup, 'run') as commands:
    assert setup.management_prompt() == ('eth1', '192.0.2.10')
    commands.assert_called_once_with(['nmtui'], check=False)
with redirect_stdout(output), patch.object(setup, 'interfaces', return_value=[('eth0', '192.0.2.11')]), patch('builtins.input', return_value='Q'), patch.object(setup, 'run') as commands:
    try:
        setup.management_prompt()
    except SystemExit as error:
        assert 'cancelled' in str(error)
    else:
        raise AssertionError('Cancel must return before appliance mutation')
    commands.assert_not_called()
with redirect_stdout(output), patch.object(setup, 'interfaces', return_value=[('eth0', '192.0.2.10')]), \
     patch('builtins.input', side_effect=['first.example', '1', 'admin', 'BACK', 'second.example', '1', 'operator', 'mistype', 'APPLY']), \
     patch.object(setup, 'password', side_effect=['private-admin', 'private-root', 'private-admin-two', 'private-root-two']), \
     patch.object(setup, 'run') as commands:
    plan = setup.setup_plan()
    assert plan == ('second.example', 'eth0', '192.0.2.10', 'operator', 'private-admin-two', 'private-root-two')
    commands.assert_not_called()
text = output.getvalue()
assert 'Step 4 of 5: Review and apply' in text and 'https://192.0.2.10:18090' in text
assert 'private-' not in text, 'Passwords must not appear in review output'
assert 'Use letters, numbers' in text and 'Choose one of the numbered addresses' in text
with patch.object(setup.sys.stdin, 'isatty', return_value=True), \
     patch.object(setup.Path, 'read_text', return_value='7 4 1 7\n'), \
     patch.object(setup, 'run', return_value=subprocess.CompletedProcess([], 0)) as commands:
    try:
        with setup.quiet_console():
            raise KeyboardInterrupt()
    except KeyboardInterrupt:
        pass
    assert commands.call_args_list[0].args[0] == ['dmesg', '--console-level', '1']
    assert commands.call_args_list[1].args[0] == ['dmesg', '--console-level', '7']
with patch.object(setup.sys.stdin, 'isatty', return_value=True), \
     patch.object(setup.Path, 'read_text', return_value='7 4 1 7\n'), \
     patch.object(setup, 'run', side_effect=FileNotFoundError()):
    with setup.quiet_console():
        pass
with patch.object(setup, 'run', return_value=subprocess.CompletedProcess([], 3, stdout='fixture service failure')) as commands:
    error = setup.service_failure('fixture activation failed')
    assert 'fixture service failure' in str(error) and 'resume' in str(error)
    assert len(commands.call_args_list) == 2
    assert all(call.kwargs['timeout'] == 10 for call in commands.call_args_list)
print('PASS first-boot UI: defaults, input retries, networking tools, cancellation, review/back and hidden credentials')
print('PASS setup diagnostics: console level restored after interruption; bounded service failure details')
