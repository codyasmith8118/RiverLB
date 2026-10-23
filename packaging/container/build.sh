#!/usr/bin/env bash
set -euo pipefail
cp -a /source/. /build/
cd /build
export CARGO_HOME=/build/cargo-home
mkdir -p "$CARGO_HOME"
cat > "$CARGO_HOME/config.toml" <<'CONFIG'
[source.crates-io]
replace-with = "retained"
[source.retained]
directory = "/inputs/cargo-vendor"
[net]
offline = true
CONFIG
export TZ=UTC LC_ALL=C.UTF-8 PYTHONHASHSEED=0
# Stable source timestamps and paths also stabilize Rust and RPM debug metadata.
find /build -path /build/target -prune -o -exec touch -h -d "@$SOURCE_DATE_EPOCH" {} +
cargo test --offline --locked
cargo build --release --offline --locked
./target/release/riverlb validate --config packaging/rpm/riverlb.toml --database /build/validate.db
version=$(python3 -c 'import tomllib; print(tomllib.load(open("Cargo.toml", "rb"))["package"]["version"])')
install -d /build/rpmbuild/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS} /build/riverlb-payload
install -m 0755 target/release/riverlb /build/riverlb-payload/
install -m 0644 LICENSE README.md /source/build-manifest.json packaging/rpm/riverlb.toml packaging/rpm/riverlb.service /build/riverlb-payload/
install -m 0755 scripts/audit-appliance-security.py /build/riverlb-payload/riverlb-audit-security
install -m 0644 packaging/rpm/riverlb-sandbox.cil /build/riverlb-payload/
install -m 0644 packaging/update/update-trust.json /build/riverlb-payload/
install -m 0755 packaging/update/riverlb-launcher packaging/update/riverlb-update /build/riverlb-payload/
install -m 0644 packaging/update/riverlb-update.service packaging/update/riverlb-update-recovery.service /build/riverlb-payload/
install -m 0644 docs/high-availability.md /build/riverlb-payload/
for file in riverlb-authority riverlb-cluster riverlb-traffic riverlb-ha.service riverlb-ha-deploy riverlb-ha-deploy.service riverlb-ha-activate.service riverlb-ha-sshd.service riverlb-ha-tmpfiles.conf; do
    cp "deploy/ha/$file" /build/riverlb-payload/
done
cp -a deploy/ha/vendor/fence-agents /build/riverlb-payload/fence-agents-source
# EL10 does not package the Proxmox agent. Render the pinned upstream source
# against the vendor fencing library and its bundled Python dependencies.
python3 - <<'PY'
import hashlib
from pathlib import Path
source = Path('deploy/ha/vendor/fence-agents/fence_pve.py.in').read_bytes()
assert hashlib.sha256(source).hexdigest() == '2285ab56ac41b25690e67e1eb2cfc14910e133bca28d24d328b1d7b96e4ae406'
script = source.decode().replace('@PYTHON@', '/usr/bin/python3').replace('@FENCEAGENTSLIBDIR@', '/usr/share/fence')
script = script.replace('import sys\n', 'import sys\n' +
    'for _lib in ("lib64", "lib"):\n' +
    '    sys.path.insert(0, f"/usr/lib/fence-agents/support/common/{_lib}/python{sys.version_info.major}.{sys.version_info.minor}/site-packages")\n', 1)
Path('/build/riverlb-payload/fence_pve').write_text(script)
PY
install -m 0755 deploy/ha/agents/fence_riverlb_hyperv /build/riverlb-payload/
install -m 0755 deploy/ha/agents/fence_riverlb_openstack /build/riverlb-payload/
cp -a deploy/ha/hyperv /build/riverlb-payload/
install -m 0644 deploy/ha/vendor/openstack-requirements.txt /build/riverlb-payload/
python3 -m pip install --no-index --find-links=/inputs/wheels --require-hashes --only-binary=:all: --no-compile \
    --target /build/riverlb-payload/openstack-sdk -r deploy/ha/vendor/openstack-requirements.txt
install -m 0755 appliance/firstboot/riverlb-setup /build/riverlb-payload/
install -m 0755 appliance/firstboot/riverlb-brand-appliance /build/riverlb-payload/
install -m 0755 appliance/firstboot/riverlb-bootstrap-network /build/riverlb-payload/
install -m 0644 appliance/firstboot/riverlb-bootstrap-network.service appliance/firstboot/riverlb-network-defaults.conf /build/riverlb-payload/
install -m 0644 appliance/branding/release-stage /build/riverlb-payload/
install -m 0644 appliance/firstboot/riverlb-firstboot.service /build/riverlb-payload/
install -m 0644 appliance/firstboot/firstboot-gate.conf /build/riverlb-payload/
rpm -qa | sort > /output/build-packages.txt
rustc -vV > /output/compiler.txt
cp /source/build-manifest.json /output/build-manifest.json
cp /source/build-inputs.json /output/build-inputs.json
cargo metadata --offline --locked --format-version 1 --filter-platform x86_64-unknown-linux-gnu > /build/cargo-metadata.json
python3 - <<'PY'
import json
from pathlib import Path
m = json.loads(Path('/build/cargo-metadata.json').read_text())
# Stable package IDs remove private staging paths from the exported build graph.
ids = {p['id']: p['name'] + '@' + p['version'] for p in m['packages']}
graph = dict(packages=[dict(id=ids[p['id']], name=p['name'], version=p['version']) for p in m['packages']],
             resolve=dict(root=ids[m['resolve']['root']], nodes=[dict(id=ids[n['id']],
                 deps=[dict(pkg=ids[d['pkg']]) for d in n['deps']]) for n in m['resolve']['nodes']]))
Path('/output/cargo-graph.json').write_text(json.dumps(graph, sort_keys=True, indent=2) + '\n')
PY
python3 scripts/software-inventory.py source --root /build --inputs /inputs \
    --manifest /source/build-manifest.json --binary target/release/riverlb \
    --metadata /build/cargo-metadata.json --agent /build/riverlb-payload/fence_pve \
    --output /build/riverlb-payload/software
python3 scripts/software-inventory.py verify-source --root /build --inputs /inputs \
    --manifest /source/build-manifest.json --binary target/release/riverlb \
    --metadata /output/cargo-graph.json --agent /build/riverlb-payload/fence_pve \
    --output /build/riverlb-payload/software
install -m 0644 packaging/third-party/runtime-notices.tar.gz packaging/third-party/runtime-packages.lock.json \
    /build/riverlb-payload/software/
cp -a /build/riverlb-payload/software /output/software
python3 scripts/package-application.py --root /build --binary target/release/riverlb \
    --software /output/software --manifest /output/build-manifest.json \
    --compiler /output/compiler.txt --output /output
install -m 0644 packaging/update/update-trust.json /output/update-trust.json
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    -C /build -cf - riverlb-payload | gzip -n > /build/rpmbuild/SOURCES/riverlb-payload.tar.gz
rpmbuild -bb --define '_topdir /build/rpmbuild' --define '_buildhost riverlb-builder' \
    --define 'use_source_date_epoch_as_buildtime 1' --define 'clamp_mtime_to_source_date_epoch 1' --define "riverlb_version $version" \
    --define "riverlb_release $RIVERLB_RPM_RELEASE" packaging/rpm/riverlb.spec
cp /build/rpmbuild/RPMS/x86_64/*.rpm /output/
python3 - <<'PY'
import hashlib, subprocess
from pathlib import Path
expected = {'/usr/lib/riverlb/base/riverlb': Path('target/release/riverlb'),
            '/usr/sbin/fence_pve': Path('/build/riverlb-payload/fence_pve')}
found = {}
for package in Path('/output').glob('*.rpm'):
    rows = subprocess.check_output(['rpm', '-qp', '--qf', '[%{FILENAMES}\\t%{FILEDIGESTS}\\n]', str(package)], text=True)
    for row in rows.splitlines():
        name, digest = row.split('\t')
        if name in expected:
            if name in found:
                raise SystemExit('Duplicate inventoried executable in RPMs')
            found[name] = digest
assert found == {name: hashlib.sha256(path.read_bytes()).hexdigest() for name, path in expected.items()}, 'RPM processing changed an inventoried executable'
print('Verified RPM executable digests match the embedded source inventory')
PY
# Retained signed closure: never consult current DNF repositories during a build.
cp -a /inputs/rpm-repository /output/ha-dependencies
(cd /output; { sha256sum ./*.rpm ./*.tar.gz ./*.tar.gz.sha256 build-manifest.json build-inputs.json build-packages.txt compiler.txt cargo-graph.json update-trust.json; find ha-dependencies software -type f -print0 | sort -z | xargs -0 sha256sum; } > SHA256SUMS)
