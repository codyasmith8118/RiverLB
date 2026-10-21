#!/usr/bin/env bash
set -euo pipefail
# Pinned upstream Linux x86_64 binary, checked independently of the download site.
version=8.30.1
checksum=551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT
curl --fail --silent --show-error --location \
  "https://github.com/gitleaks/gitleaks/releases/download/v${version}/gitleaks_${version}_linux_x64.tar.gz" \
  -o "$stage/gitleaks.tar.gz"
printf '%s  %s\n' "$checksum" "$stage/gitleaks.tar.gz" | sha256sum --check --status
tar -xzf "$stage/gitleaks.tar.gz" -C "$stage" gitleaks
"$stage/gitleaks" git --log-opts=--all --redact --config .gitleaks.toml .
