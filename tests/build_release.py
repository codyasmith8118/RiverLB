"""Check release packaging with fake compiler tools in a disposable repository."""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tarfile
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def run():
    with tempfile.TemporaryDirectory(prefix="riverlb-release-", dir="/tmp") as folder:
        project = Path(folder)
        (project / "scripts").mkdir()
        shutil.copy2(ROOT / "scripts/build-release.sh", project / "scripts")
        for helper in ("software-inventory.py", "software_inventory.py", "package-application.py"):
            shutil.copy2(ROOT / "scripts" / helper, project / "scripts" / helper)
        (project / "Cargo.toml").write_text('[package]\nname="riverlb"\nversion="0.1.0"\nlicense="MIT"\n')
        lock_bytes = b'version=4\n[[package]]\nname="riverlb"\nversion="0.1.0"\n'
        (project / "Cargo.lock").write_bytes(lock_bytes)
        (project / "LICENSE").write_text("fixture license\n")
        (project / "deploy/ha").mkdir(parents=True)
        for name in ("riverlb-authority", "riverlb-cluster", "riverlb-traffic", "riverlb-ha.service"):
            (project / "deploy/ha" / name).write_text("fixture helper\n")
        (project / "deploy/ha/vendor").mkdir()
        shutil.copytree(ROOT / "deploy/ha/vendor/fence-agents", project / "deploy/ha/vendor/fence-agents")
        (project / "deploy/ha/vendor/openstack-requirements.txt").write_text("")
        inputs = project / "inputs"
        (inputs / "cargo-vendor").mkdir(parents=True)
        (inputs / "wheels").mkdir()
        (inputs / "inventory.json").write_text('{"files":{}}')
        (project / "packaging/third-party/cargo").mkdir(parents=True)
        (project / "packaging/third-party/cargo/index.json").write_text('{"schema":1,"crates":[]}')
        (project / "packaging/third-party/python-sources.lock.json").write_text('{"schema":1,"packages":{}}')
        (project / "packaging/build-inputs.lock.json").write_text(json.dumps(dict(
            inventory_sha256=hashlib.sha256((inputs / "inventory.json").read_bytes()).hexdigest(),
            sha256="a"*64,images={"builder":{"id":"sha256:"+"b"*64}})))
        tools = project / "tools"
        tools.mkdir()
        for name, body in {
            "rustc": "#!/bin/sh\necho 'rustc 1.92.0 (fixture)'\necho 'host: x86_64-unknown-linux-gnu'\n",
            "cargo": '#!/bin/sh\nset -eu\nif [ "$1" = metadata ]; then\n' +
                     'echo \'{"packages":[{"id":"root","name":"riverlb","version":"0.1.0"}],"resolve":{"root":"root","nodes":[{"id":"root","deps":[]}]}}\'\nexit 0\nfi\n' +
                     'mkdir -p "${CARGO_TARGET_DIR:-target}/release"\nprintf fresh-binary > "${CARGO_TARGET_DIR:-target}/release/riverlb"\n',
            "gzip": '#!/bin/sh\nif [ "${FAIL_GZIP:-}" = 1 ]; then printf truncated; exit 1; fi\nexec /usr/bin/gzip "$@"\n',
        }.items():
            path = tools / name
            path.write_text(body)
            path.chmod(0o755)
        # Only the fixture injects compression failure; production has no test bypass.
        (project / "scripts/gzip.py").write_text('''import importlib.util, os
from pathlib import Path
spec=importlib.util.spec_from_file_location('_fixture_gzip',Path(os.__file__).with_name('gzip.py'))
module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module)
def GzipFile(*args,**kwargs):
    if os.environ.get('FAIL_GZIP')=='1':raise OSError('fixture compression failure')
    return module.GzipFile(*args,**kwargs)
''')
        env = {**os.environ, "PATH": str(tools) + os.pathsep + os.environ["PATH"],
               "RIVERLB_BUILD_INPUTS_DIR": str(inputs),
               "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null"}
        # Avoid inheriting identity or index overrides from the developer shell.
        for key in list(env):
            if key.startswith("GIT_") and key not in {"GIT_CONFIG_NOSYSTEM", "GIT_CONFIG_GLOBAL"}:
                del env[key]
        def command(*args):
            return subprocess.run(args, cwd=project, env=env, check=True, capture_output=True, text=True)
        command("git", "init")
        command("git", "add", ".")
        command("git", "-c", "user.name=Fixture", "-c", "user.email=fixture@example.test",
                "commit", "-m", "fixture")
        # A stale default binary must not be used when Cargo builds elsewhere.
        (project / "target/release").mkdir(parents=True)
        (project / "target/release/riverlb").write_text("stale-binary")
        (project / "private.key").write_text("must not ship")
        for target in ("custom target", str(project / "absolute target")):
            env["CARGO_TARGET_DIR"] = target
            command("bash", "scripts/build-release.sh")
            archives = list((project / "dist").glob("*.tar.gz"))
            assert len(archives) == 1
            archive = archives[0]
            subprocess.run(["sha256sum", "-c", archive.name + ".sha256"], cwd=archive.parent,
                           check=True, capture_output=True)
            with tarfile.open(archive) as bundle:
                prefix = bundle.getnames()[0].split("/")[0]
                binary = bundle.extractfile(prefix + "/riverlb").read()
                assert binary == b"fresh-binary"
                manifest = json.load(bundle.extractfile(prefix + "/manifest.json"))
                assert manifest["dirty"] is True
                assert manifest["binary_sha256"] == hashlib.sha256(binary).hexdigest()
                assert manifest["cargo_lock_sha256"] == hashlib.sha256(lock_bytes).hexdigest()
                assert bundle.extractfile(prefix + "/software/sbom.cdx.json")
                assert bundle.extractfile(prefix + "/software/notices.tar.gz")
                assert not any(name.endswith("private.key") for name in bundle.getnames())
                assert b"unsigned" in bundle.extractfile(prefix + "/README.md").read()
                checksums = bundle.extractfile(prefix + "/SHA256SUMS").read().decode()
                for line in checksums.splitlines():
                    digest, name = line.split("  ", 1)
                    content = bundle.extractfile(prefix + "/" + name.removeprefix("./")).read()
                    assert hashlib.sha256(content).hexdigest() == digest
        previous = archive.read_bytes()
        checksum = archive.with_suffix(archive.suffix + ".sha256").read_bytes()
        result = subprocess.run(["bash", "scripts/build-release.sh"], cwd=project,
                                env={**env, "FAIL_GZIP": "1"}, capture_output=True)
        assert result.returncode != 0
        assert archive.read_bytes() == previous
        assert archive.with_suffix(archive.suffix + ".sha256").read_bytes() == checksum
        assert not list((project / "dist").glob(".candidate.*"))
    print("PASS release packaging: custom target, fresh binary, dirty identity, checksums, private-file exclusion and failed-build preservation")


if __name__ == "__main__":
    run()
