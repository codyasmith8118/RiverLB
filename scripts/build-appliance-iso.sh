#!/usr/bin/env bash
# Build the working tree into tested RPMs and verified installer media.
set -euo pipefail
project_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
cd "$project_dir"
mode=installer
usage() {
    cat <<'HELP'
Usage: scripts/build-appliance-iso.sh [--mode installer|image]

Builds current repository changes, including uncommitted changes, using Podman.
Default: interactive installer at dist/iso/riverlb-installer.iso.
The image mode is unattended media for disposable image-builder disks only.
Requires x86_64 Linux, rootless Podman, Python 3.11+, Git, and flock.
Run as your regular user. Builds require internet access.
RIVERLB_RPM_RELEASE optionally sets a positive integer package release;
otherwise each build receives a UTC timestamp release.
Previous media is retained under dist/iso/archive/. Logs: dist/logs/.
Checks include Rust tests, package/first-boot smoke tests, and ISO structure.
Booting the ISO in a VM is a separate qualification step.
HELP
}
while [[ $# -gt 0 ]]; do
    case "$1" in
        --help|-h) usage; exit 0 ;;
        --mode) [[ $# -ge 2 ]] || { usage >&2; exit 2; }; mode=$2; shift 2 ;;
        *) usage >&2; exit 2 ;;
    esac
done
[[ "$mode" == installer || "$mode" == image ]] || { usage >&2; exit 2; }
[[ $(uname -m) == x86_64 ]] || { echo 'This build targets x86_64 Linux.' >&2; exit 1; }
for dependency in podman python3 git flock sha256sum tee; do
    command -v "$dependency" >/dev/null || { echo "Missing dependency: $dependency" >&2; exit 1; }
done
python3 -c 'import tomllib' || { echo 'Python 3.11 or newer is required.' >&2; exit 1; }
export RIVERLB_RPM_RELEASE=${RIVERLB_RPM_RELEASE:-$(date -u +%Y%m%d%H%M%S)}
[[ "$RIVERLB_RPM_RELEASE" =~ ^[1-9][0-9]*$ ]] || { echo 'RIVERLB_RPM_RELEASE must be a positive integer.' >&2; exit 1; }
mkdir -p dist/logs dist/iso/archive
exec 9>dist/.appliance-iso-build.lock
flock -n 9 || { echo 'Another appliance ISO build is running.' >&2; exit 1; }
build_id="$(date -u +%Y%m%dT%H%M%SZ)-$$"
log_file="$project_dir/dist/logs/iso-$build_id.log"
exec > >(tee "$log_file") 2>&1
output="dist/iso/riverlb-$mode.iso"
checksum="$output.sha256"
archive="dist/iso/archive/$build_id"
previous=false
building=false
cleanup() {
    local result=$?
    trap - EXIT
    if [[ $result -ne 0 ]]; then
        if [[ "$building" == true ]]; then
            mkdir -p "$archive/failed"
            for candidate in "$output" "$checksum" "$output.partial"; do
                if [[ -e "$candidate" ]]; then mv -- "$candidate" "$archive/failed/"; fi
            done
            if [[ "$previous" == true ]]; then
                for candidate in "$archive/riverlb-$mode.iso" "$archive/riverlb-$mode.iso.sha256"; do
                    if [[ -e "$candidate" ]]; then mv -- "$candidate" dist/iso/; fi
                done
            fi
        fi
        echo "Build failed. Log: $log_file" >&2
    fi
    exit "$result"
}
trap cleanup EXIT
printf 'Building RiverLB %s ISO; package release %s\n' "$mode" "$RIVERLB_RPM_RELEASE"
echo "Log: $log_file"
echo '[1/5] Fetching and verifying pinned AlmaLinux base media'
base_iso=$(python3 scripts/fetch-base-iso.py)
base_checksum=$(python3 -c 'import json; print(json.load(open("appliance/base-media.json"))["sha256"])')
echo '[2/5] Building application and appliance RPMs from the working tree'
scripts/build-rpm.sh
echo '[3/5] Testing RPM installation, application, and first-boot setup'
scripts/test-rpm.sh
# Lower-level ISO builder deliberately refuses to overwrite existing media.
[[ ! -e "$output.partial" ]] || { echo "Existing partial output: $output.partial; inspect it before retrying." >&2; exit 1; }
if [[ -e "$output" || -e "$checksum" ]]; then
    mkdir -p "$archive"
    for candidate in "$output" "$checksum"; do
        if [[ -e "$candidate" ]]; then mv -- "$candidate" "$archive/"; fi
    done
    previous=true
fi
building=true
echo '[4/5] Generating ISO with freshly built RPMs'
RIVERLB_ISO_USE_CONTAINER=1 scripts/build-iso.sh "$base_iso" "$base_checksum" "$mode"
echo '[5/5] Checking ISO checksum, package payload, and BIOS/UEFI boot structure'
scripts/test-iso.sh "$mode"
building=false
printf '\nISO ready: %s/%s\nChecksum: %s/%s\n' "$project_dir" "$output" "$project_dir" "$checksum"
if [[ "$previous" == true ]]; then echo "Previous media: $project_dir/$archive/"; fi
echo 'Unsigned development candidate; test installation in a VM before deployment.'
