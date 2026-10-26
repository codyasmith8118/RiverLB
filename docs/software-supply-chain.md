# Software inventories and signed provenance

Issue [#11](https://github.com/codyasmith8118/RiverLB/issues/11) adds inventory
and signing gates to `release-2.0`. Implementation and fixture results alone
are not a qualified release. A successful protected BIOS/UEFI workflow and its
verified bundles identify the exact tested source; qualification of one commit
does not qualify later changes or production deployment.

## Inventory coverage

The pinned offline RPM builder emits `software/sbom.cdx.json`, `licenses.json`
and `notices.tar.gz`, plus the actual compiler and sanitized Cargo dependency
graph. The main RPM installs the source inventory as documentation and the
notice archives as licenses. The standalone application archive contains its
own inventory, notices, compiler, source manifest and checksums. Host-built
application candidates record their actual host builder and remain unsigned.
The protected workflow uses the application archive made by the pinned RPM
builder from the same executable as the RPM.

The source inventory covers every retained Cargo.lock crate, the pinned Proxmox
agent and every locked OpenStack SDK wheel. Distributions embedded inside other
wheels are separate components. Crates for other compilation targets are
included with `excluded` scope. SHA-256 identifies original crate archives,
wheels, embedded wheel file trees, agent templates and executable bytes; each
component records its hash scope. Source and license metadata come from the
original retained bytes, rather than an online dependency resolution.

Full qualification reconstructs that inventory from the compiled RPM payload,
compares installed SDK METADATA against the original wheels, and checks both ISO
file inventories, embedded RPM sets, signed upstream RPM hashes and installer
runtime package manifests. The two disposable appliance clones must report the
same installed RPM metadata. The aggregate SBOM also includes the reviewed OS
catalog, with occurrence properties distinguishing installer runtime, distributed
packages and installed appliance packages. Unused catalog entries have excluded
scope. `payloads.json.gz` records individual file hashes and installed package
metadata; it does not contain guest files or configuration.

The generator rejects missing, extra, changed and unknown components. Its second
pass reconstructs coverage from the original artifacts rather than trusting the
first SBOM. CycloneDX 1.6 validation uses the retained official schemas offline.

## Licenses, notices and corresponding source

RiverLB is MIT licensed. Dependencies retain their own licenses, including GPL
components and firmware with separate terms. License names and expressions are
preserved as declared upstream; the inventory does not reinterpret them as
license compatibility approval. `licenses.json` maps every component to source
references and the exact preserved notice paths and SHA-256 values.

Cargo sources are retained in the dependency snapshot identified by
`packaging/build-inputs.lock.json`. Cargo archive checksums match Cargo.lock.
Where a crate omits a license file, the committed supplement records the original
upstream repository commit and captured notice bytes. If upstream provides only
its Cargo declaration and README, the record explicitly says
`upstream-declarations-no-license-file`. No copyright statement is invented.
Upstream grants that link a canonical license text retain that text and its
origin as well. Review these declarations when approving redistribution.

Python source references identify the exact PyPI source distribution, SHA-256,
size and originating wheel/embedded metadata; the maintainer capture verifies
the source archive bytes. The vendored Proxmox agent retains its upstream GPL
notice and immutable source commit. OS entries identify the signed binary RPM,
source RPM URL, declared license and original RPM license files. Source RPMs
provide the distribution's corresponding source and packaging patches; firmware
packages can include redistributable binary blobs rather than editable upstream
source. Root RiverLB RPMs and helpers link the exact repository commit archive.
Preserve these files beside redistributed binaries and retain corresponding
sources when required by their terms; upstream URLs alone are not a promise of
perpetual availability or a substitute for redistribution obligations.

Normal builds are disconnected. Only the explicitly invoked maintainer capture
scripts access upstream services to refresh reviewed metadata:

- `capture-cargo-notices.py`: immutable upstream commit notice files.
- `capture-python-sources.py`: wheel and embedded distribution source archives.
- `capture-software-metadata.py`: vendor-key-verified RPMs, notices and source URLs.

Retained metadata lives in [packaging/third-party](../packaging/third-party/README.md).
A dependency/base-media change requires recapture, review and qualification;
there is no online fallback that silently accepts new bytes.

## Protected signing and verification

`appliance-image.yml` admits only manual `release-2.0` runs in this repository.
The existing `appliance-build` environment review remains required for both
firmware jobs. After all ten stages, guest assertions and cleanup succeed,
`prepare-build-provenance.py` binds the exact source, eight artifact digests,
compiler, OCI builder/tools, retained inputs, commands, resource limits and
sanitized test report. Only then do pinned GitHub attestation actions request
OIDC identity and sign SLSA v1 provenance and the CycloneDX SBOM for the same
subject set. The provenance follows the GitHub Actions workflow build type:
external parameters identify the workflow repository, path and ref; internal
parameters retain GitHub numeric identity and RiverLB compiler, builder, platform,
artifact subjects and test bindings. Preparation rejects a signing context that
differs from the qualified source/run. Verification checks both identities. This is build attestation; application update publisher trust and
production release promotion remain separate controls.

The software artifact contains only the explicit public inventory, notices,
payload hashes, manifests, report, predicate, checksum subjects, Sigstore bundles
and verification result. Actions retention is 30 days; copy this allowlist to
durable release evidence before that period expires. Never publish VM overlays,
screenshots, guest logs, accounts, TLS private keys or appliance configuration.

Download the software evidence matching the intended source and firmware, and
the artifact you wish to verify. Use the expected commit from your reviewed
release record, not an untrusted predicate. With an authenticated current GitHub
CLI, run from the corresponding source checkout:

```sh
python3 scripts/verify-build-provenance.py \
  --artifact /downloads/riverlb-image.iso \
  --bundle /evidence/provenance.sigstore.json \
  --predicate /evidence/provenance.json \
  --source REVIEWED_40_CHARACTER_COMMIT --firmware bios \
  --sbom /evidence/sbom.cdx.json --sbom-bundle /evidence/sbom.sigstore.json
```

The verifier checks artifact bytes, identical subject sets, the exact signed
predicate/SBOM, cryptographic signatures, GitHub repository, signer workflow,
source commit/ref and hosted-runner identity. An altered artifact, source,
platform or inventory fails. A local checksum alone does not verify publisher
identity. Keep the original artifact basename, or supply `--subject-name` with
its attested basename when you have renamed it.

## Regression checks

```sh
# Debian/Ubuntu: install python3-jsonschema; source generation itself is stdlib-only.
/usr/bin/python3 tests/software_inventory.py
python3 tests/build_release.py
python3 tests/appliance/qualification.py
python3 scripts/check-docs.py
```

These tests exercise real archive bytes and deterministic reconstruction,
embedded SDK metadata, upstream notices, schema validation, incomplete/altered
inventories, subject/source/platform binding and failed-build preservation.
Synthetic fixtures do not claim actual guest qualification or trusted signatures.
The protected full workflow must supply those results for the intended commit.
