"""Optional Firefox layout audit of disposable portal snapshots, using Marionette.

Generate HTML first with UI_SNAPSHOT_DIR=/tmp/riverlb-ui-review node tests/portal.cjs.
Then run python3 tests/ui_layout.py /tmp/riverlb-ui-review. No live app is accessed.
Protocol: https://firefox-source-docs.mozilla.org/remote/marionette/Protocol.html
"""
import argparse
import base64
import html
import json
import os
from pathlib import Path
import shutil
import socket
import subprocess
import tempfile
import time


class Marionette:
    def __init__(self, connection):
        self.connection = connection
        self.stream = connection.makefile("rb")
        self.counter = 0
        self.read()

    def read(self):
        size = bytearray()
        while (character := self.stream.read(1)) != b":":
            if not character:
                raise RuntimeError("Firefox automation connection closed")
            size.extend(character)
        return json.loads(self.stream.read(int(size)))

    def command(self, name, args=None):
        self.counter += 1
        payload = json.dumps([0, self.counter, name, args or {}]).encode()
        self.connection.sendall(str(len(payload)).encode() + b":" + payload)
        result = self.read()
        if result[2]:
            raise RuntimeError(result[2])
        return result[3]

    def script(self, code):
        result = self.command("WebDriver:ExecuteScript", {
            "script": code, "args": [], "newSandbox": True,
            "sandbox": "default", "filename": "ui_layout.py", "line": 1,
        })
        return result.get("value", result) if isinstance(result, dict) else result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("snapshots", type=Path)
    args = parser.parse_args()
    root = args.snapshots.resolve()
    pages = sorted(p for p in root.glob("*.html") if not p.name.startswith("."))
    if not pages:
        raise SystemExit("Generate the UI snapshots before running the layout audit")
    firefox = shutil.which("firefox")
    if not firefox:
        raise SystemExit("Firefox is required for the optional layout audit")
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    results = []
    connection = None
    with tempfile.TemporaryDirectory(prefix="riverlb-ui-firefox-") as temporary:
        profile = Path(temporary)
        preferences = {
            "marionette.port": port, "marionette.enabled": True,
            "browser.shell.checkDefaultBrowser": False,
            "browser.startup.homepage": "about:blank",
            "browser.newtabpage.enabled": False,
            "datareporting.healthreport.uploadEnabled": False,
            "datareporting.policy.dataSubmissionEnabled": False,
            "toolkit.telemetry.enabled": False,
            "network.proxy.type": 1, "network.proxy.http": "127.0.0.1",
            "network.proxy.http_port": 9, "network.proxy.ssl": "127.0.0.1",
            "network.proxy.ssl_port": 9,
            "security.fileuri.strict_origin_policy": False,
        }
        (profile / "user.js").write_text("\n".join(
            f"user_pref({json.dumps(key)}, {json.dumps(value)});" for key, value in preferences.items()))
        environment = {**os.environ, "GSETTINGS_BACKEND": "memory"}
        with (root / "firefox-layout.log").open("w") as log:
            process = subprocess.Popen([
                firefox, "--headless", "--no-remote", "--marionette",
                "--profile", str(profile), "about:blank",
            ], stdout=log, stderr=log, env=environment)
            try:
                deadline = time.monotonic() + 30
                while time.monotonic() < deadline:
                    try:
                        connection = socket.create_connection(("127.0.0.1", port), timeout=2)
                        break
                    except OSError:
                        if process.poll() is not None:
                            raise RuntimeError("Firefox exited before starting automation")
                        time.sleep(0.1)
                if connection is None:
                    raise RuntimeError("Firefox automation startup timed out")
                connection.settimeout(30)
                browser = Marionette(connection)
                browser.command("WebDriver:NewSession", {"capabilities": {}})
                for width in [1440, 1024, 390]:
                    browser.command("WebDriver:SetWindowRect", {"width": width, "height": 1000})
                    for page in pages:
                        browser.command("WebDriver:SwitchToFrame", {"id": None})
                        # Firefox desktop windows have a minimum width of 450px.
                        # A same-origin local frame provides a real 390px content
                        # viewport without modifying the portal's styles.
                        if width < 450:
                            frame = root / ".ui-frame.html"
                            frame.write_text('<!doctype html><html><body style="margin:0;background:#0b1320">'
                                f'<iframe src="{html.escape(page.as_uri())}" style="border:0;width:{width}px;height:900px"></iframe>'
                                '</body></html>')
                            browser.command("WebDriver:Navigate", {"url": frame.as_uri() + "?page=" + page.stem})
                            browser.command("WebDriver:SwitchToFrame", {"id": 0})
                        else:
                            browser.command("WebDriver:Navigate", {"url": page.as_uri()})
                        report = browser.script("""
                            const width=document.documentElement.clientWidth;
                            const visible=e=>e.getClientRects().length&&getComputedStyle(e).visibility!=='hidden';
                            const escaped=[...document.querySelectorAll('main, .editor, fieldset, .actions, .table-scroll, input, select, textarea, main button')]
                                .filter(e=>visible(e)&&(!e.closest('.table-scroll')||e.classList.contains('table-scroll')))
                                .filter(e=>e.getBoundingClientRect().right>width+1||e.getBoundingClientRect().left < -1)
                                .map(e=>e.id||e.className||e.tagName);
                            const overlaps=[];
                            for(const group of document.querySelectorAll('main .actions, .member-toolbar, .member-row')){
                                const controls=[...group.querySelectorAll('button,input,select,textarea')].filter(visible);
                                for(let i=0;i<controls.length;i++)for(let j=i+1;j<controls.length;j++){
                                    const a=controls[i].getBoundingClientRect(),b=controls[j].getBoundingClientRect();
                                    if(Math.min(a.right,b.right)-Math.max(a.left,b.left)>1 && Math.min(a.bottom,b.bottom)-Math.max(a.top,b.top)>1)
                                        overlaps.push([controls[i].id||controls[i].name||controls[i].textContent,controls[j].id||controls[j].name||controls[j].textContent]);
                                }
                            }
                            // Controls in the same form row should share a
                            // baseline even when their labels wrap. Overflow
                            // checks alone miss uneven margins between columns.
                            const misaligned=[];
                            for(const group of document.querySelectorAll('.config-section, .grid, .settings-grid')){
                                const fields=[...group.children].filter(e=>e.matches('label')&&visible(e))
                                    .map(label=>({label,controls:[...label.querySelectorAll('input,select,textarea')].filter(visible)}))
                                    .filter(field=>field.controls.length===1&&!field.controls[0].matches('textarea,input[type=checkbox],input[type=radio]'));
                                for(let i=0;i<fields.length;i++)for(let j=i+1;j<fields.length;j++){
                                    const a=fields[i].label.getBoundingClientRect(),b=fields[j].label.getBoundingClientRect();
                                    const sameRow=Math.min(a.bottom,b.bottom)-Math.max(a.top,b.top)>Math.min(a.height,b.height)/2
                                        && Math.min(a.right,b.right)-Math.max(a.left,b.left)<1;
                                    const first=fields[i].controls[0],second=fields[j].controls[0];
                                    if(sameRow&&Math.abs(first.getBoundingClientRect().bottom-second.getBoundingClientRect().bottom)>2)
                                        misaligned.push({section:group.querySelector('legend')?.textContent||group.closest('fieldset')?.querySelector('legend')?.textContent||group.id||group.className,fields:[first.name||first.id,second.name||second.id]});
                                }
                            }
                            return {width,documentWidth:document.documentElement.scrollWidth,escaped,overlaps,misaligned};
                        """)
                        report.update(page=page.stem, requested_width=width)
                        results.append(report)
                        representative_fence = page.stem.removesuffix("-dark") in [
                            "fencing-fence_riverlb_hyperv", "fencing-fence_vmware_rest", "fencing-fence_aws", "fencing-fence_pve", "fencing-fence_ipmilan"]
                        if representative_fence:
                            browser.script("window.scrollTo(0,0)")
                        if representative_fence or page.stem.removesuffix("-dark") in ["overview", "virtual-servers", "virtual-servers-editor", "pools-editor", "nodes-editor", "vlans-editor", "self-ips-editor", "routes-editor", "interface-editor", "river-rules", "river-rules-editor", "monitors-editor", "settings", "statistics", "ha", "login", "system-health", "alerts", "backups", "audit-events", "security", "updates", "config-preview"]:
                            screenshot = browser.command("WebDriver:TakeScreenshot", {"full": False})
                            encoded = screenshot.get("value", screenshot) if isinstance(screenshot, dict) else screenshot
                            (root / f"{page.stem}-{width}.png").write_bytes(base64.b64decode(encoded))
                        if representative_fence or page.stem.removesuffix("-dark") in ["virtual-servers-editor", "pools-editor", "nodes-editor", "vlans-editor", "self-ips-editor", "routes-editor", "monitors-editor", "ha", "interface-editor"]:
                            browser.script("document.getElementById('ha-fencing')?.lastElementChild.scrollIntoView({block:'end'})" if representative_fence else "window.scrollTo(0,document.documentElement.scrollHeight)")
                            screenshot = browser.command("WebDriver:TakeScreenshot", {"full": False})
                            encoded = screenshot.get("value", screenshot) if isinstance(screenshot, dict) else screenshot
                            (root / f"{page.stem}-footer-{width}.png").write_bytes(base64.b64decode(encoded))
                browser.command("WebDriver:DeleteSession")
            finally:
                if connection:
                    connection.close()
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)
    (root / "layout-results.json").write_text(json.dumps(results, indent=2) + "\n")
    failures = [r for r in results if r["documentWidth"] > r["width"] + 1 or r["escaped"] or r["overlaps"] or r["misaligned"]]
    if failures:
        print(json.dumps(failures, indent=2))
        raise SystemExit(1)
    print(f"PASS Firefox layout: {len(pages)} pages at desktop, tablet and narrow widths ({len(results)} checks)")


if __name__ == "__main__":
    main()
