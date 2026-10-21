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
install -m 0644 packaging/update/update-trust.json /output/update-trust.json
tar --sort=name --mtime="@$SOURCE_DATE_EPOCH" --owner=0 --group=0 --numeric-owner \
    -C /build -cf - riverlb-payload | gzip -n > /build/rpmbuild/SOURCES/riverlb-payload.tar.gz
rpmbuild -bb --define '_topdir /build/rpmbuild' --define '_buildhost riverlb-builder' \
    --define 'use_source_date_epoch_as_buildtime 1' --define 'clamp_mtime_to_source_date_epoch 1' --define "riverlb_version $version" \
    --define "riverlb_release $RIVERLB_RPM_RELEASE" packaging/rpm/riverlb.spec
cp /build/rpmbuild/RPMS/x86_64/*.rpm /output/
# Retained signed closure: never consult current DNF repositories during a build.
cp -a /inputs/rpm-repository /output/ha-dependencies
(cd /output; { sha256sum ./*.rpm build-manifest.json build-inputs.json build-packages.txt compiler.txt update-trust.json; find ha-dependencies -type f -print0 | sort -z | xargs -0 sha256sum; } > SHA256SUMS)
