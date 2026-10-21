"""Exercise ISO workflow orchestration/rollback using disposable fake build stages."""
from pathlib import Path
import os
import shutil
import subprocess
import tempfile
import fcntl

ROOT = Path(__file__).resolve().parents[2]


def run():
    with tempfile.TemporaryDirectory(prefix="riverlb-build-workflow-") as folder:
        project = Path(folder)
        scripts = project / "scripts"
        scripts.mkdir()
        shutil.copy2(ROOT / "scripts/build-appliance-iso.sh", scripts)
        (project / "appliance").mkdir()
        (project / "appliance/base-media.json").write_text('{"sha256":"' + "0" * 64 + '"}')
        (scripts / "fetch-base-iso.py").write_text('print("/disposable/base.iso")\n')
        for stage, filename in [("rpm", "build-rpm.sh"), ("package-test", "test-rpm.sh"),
                                ("iso", "build-iso.sh"), ("verify", "test-iso.sh")]:
            body = '#!/usr/bin/env bash\nset -eu\n'
            body += f'echo {stage} >> "$TRACE"\n'
            if stage == "iso":
                body += 'mode=$3\necho new-media > "dist/iso/riverlb-$mode.iso"\n'
                body += '(cd dist/iso; sha256sum "riverlb-$mode.iso" > "riverlb-$mode.iso.sha256")\n'
            body += f'[[ "${{FAIL_STAGE:-}}" != {stage} ]]\n'
            path = scripts / filename
            path.write_text(body)
            path.chmod(0o755)
        # The workflow delegates container work to helpers; do not invoke real Podman here.
        fakebin = project / "bin"
        fakebin.mkdir()
        podman = fakebin / "podman"
        podman.write_text('#!/bin/sh\nexit 99\n')
        podman.chmod(0o755)
        media = project / "dist/iso"
        media.mkdir(parents=True)
        iso = media / "riverlb-installer.iso"
        checksum = media / "riverlb-installer.iso.sha256"
        trace = project / "trace"
        env = {**os.environ, "PATH": str(fakebin) + os.pathsep + os.environ["PATH"],
               "TRACE": str(trace), "RIVERLB_RPM_RELEASE": "3"}

        def invoke(failure="", *args):
            trace.write_text("")
            result = subprocess.run([str(scripts / "build-appliance-iso.sh"), *args],
                                    env={**env, "FAIL_STAGE": failure}, capture_output=True, text=True)
            return result

        for failure in ["package-test", "iso", "verify"]:
            iso.write_text("previous-media\n")
            checksum.write_text("previous-checksum\n")
            result = invoke(failure)
            assert result.returncode != 0, result.stdout
            assert iso.read_text() == "previous-media\n"
            assert checksum.read_text() == "previous-checksum\n"
            assert "Build failed" in result.stdout
        assert len(list(media.glob("archive/*/failed/riverlb-installer.iso"))) == 2
        result = invoke()
        assert result.returncode == 0, result.stdout + result.stderr
        assert trace.read_text().splitlines() == ["rpm", "package-test", "iso", "verify"]
        assert iso.read_text() == "new-media\n"
        assert len(list(media.glob("archive/*/riverlb-installer.iso"))) == 1
        subprocess.run(["sha256sum", "-c", checksum.name], cwd=media, check=True, capture_output=True)
        result = invoke("", "--mode", "image")
        assert result.returncode == 0, result.stdout + result.stderr
        assert (media / "riverlb-image.iso").exists()
        result = invoke("", "--mode", "invalid")
        assert result.returncode == 2
        assert not trace.read_text()
        with (project / "dist/.appliance-iso-build.lock").open("w") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            result = invoke()
            assert result.returncode != 0
            assert "Another appliance ISO build" in result.stderr
            assert not trace.read_text()
    print("PASS ISO workflow: ordered stages, media archival, failure restoration, modes, build lock")


if __name__ == "__main__":
    run()
