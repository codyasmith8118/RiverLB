"""Guest-only accessibility probe; importable environment discovery for host tests."""
import json
import os
from pathlib import Path


class ProbeFailure(Exception):
    pass


def discover_environment(proc=Path('/proc')):
    for entry in proc.iterdir():
        if not entry.name.isdigit():
            continue
        try:
            args = entry.joinpath('cmdline').read_bytes().split(b'\0')
            if not any(Path(os.fsdecode(arg)).name in ('anaconda', 'anaconda.py') for arg in args):
                continue
            original = dict(item.split(b'=', 1) for item in entry.joinpath('environ').read_bytes().split(b'\0') if b'=' in item)
            keys = ('DISPLAY', 'WAYLAND_DISPLAY', 'XDG_RUNTIME_DIR', 'XAUTHORITY',
                    'PRODBUILDPATH', 'ANACONDA_PRODUCTNAME', 'ANACONDA_PRODUCTVERSION')
            env = {key: os.fsdecode(original[key.encode()]) for key in keys if key.encode() in original}
        except (OSError, ValueError):
            continue
        # Anaconda display.start_user_systemd sets this after exec. proc/environ
        # describes the initial environment, so discover the actual user socket.
        runtime = Path(env.get('XDG_RUNTIME_DIR', '/run/user/0'))
        bus = runtime / 'bus'
        if not bus.is_socket():
            raise ProbeFailure('gui-session-bus-missing')
        env.update(XDG_RUNTIME_DIR=str(runtime), DBUS_SESSION_BUS_ADDRESS='unix:path=' + str(bus))
        return env
    raise ProbeFailure('anaconda-not-found')


def probe():
    os.environ.update(discover_environment())
    try:
        import pyatspi
    except ImportError:
        raise ProbeFailure('accessibility-unavailable') from None
    stylesheet = Path('/run/install/product/anaconda-gtk.css')
    logo = Path('/usr/share/anaconda/pixmaps/riverlb-installer.svg')
    if not stylesheet.is_file() or not logo.is_file():
        raise ProbeFailure('branding-assets-missing')
    if str(logo) not in stylesheet.read_text():
        raise ProbeFailure('branding-stylesheet-invalid')
    names = []
    def visit(item, depth=0):
        if depth > 12 or len(names) > 1000:
            return
        try:
            if item.name:
                names.append(item.name)
            for number in range(item.childCount):
                visit(item.getChildAtIndex(number), depth + 1)
        except Exception:
            pass
    try:
        visit(pyatspi.Registry.getDesktop(0))
    except Exception:
        raise ProbeFailure('accessibility-query-failed') from None
    from pyanaconda.core.product import get_product_name
    print('RIVERLB_GUI_PROBE=' + json.dumps(dict(product=get_product_name(), names=names)), flush=True)


if __name__ == '__main__':
    try:
        probe()
    except ProbeFailure as error:
        print('RIVERLB_GUI_FAILURE=' + str(error), flush=True)
        raise SystemExit(1)
    except Exception:
        print('RIVERLB_GUI_FAILURE=gui-probe-error', flush=True)
        raise SystemExit(1)
