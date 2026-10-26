# Issue #11 signed inventory evidence

Protected [run 40320551997](https://github.com/codyasmith8118/RiverLB/actions/runs/40320551997)
passed for source `168691870ab27e6bc13604992650b745458c3311` on `release-2.0`
after the existing `appliance-build` review. Both firmware jobs completed all ten
build/inventory stages, 11 boot assertions, four installer assertions and private
cleanup, then signed SLSA v1 provenance and CycloneDX inventories and verified
both bundles. Merged-source CI and security scans also passed.

| Firmware | Components | Installed RPMs | Signed subjects | Qualification | Local verification |
|---|---|---|---|---|---|
| BIOS | 1,744 | 526 | 19 | [Report](bios/report.json) | [Result](bios/local-verification.json) |
| UEFI | 1,744 | 553 | 19 | [Report](uefi/report.json) | [Result](uefi/local-verification.json) |

Both used hosted runner image `20261023.334.3`, kernel `6.17.0-1022-azure`,
the pinned compiler/OCI/input identities and the same source RPM/application
artifacts. Each report retains the exact commands, limits, expected assertion
lists, actual results and source/artifact identities. Installed-package counts are recorded separately per firmware. Each firmware's
two appliance clones must agree on its installed inventory. ISO/disk digests differ by firmware;
the [BIOS identity](bios/inventory-identity.json) and
[UEFI identity](uefi/inventory-identity.json) preserve all eight artifact digests.

## Durable publication

The [evidence release](https://github.com/codyasmith8118/RiverLB/releases/tag/issue-11-evidence-40320551997)
is pinned to the tested commit and retains these allowlisted archives beyond the
original Actions artifacts' 30-day expiry:

- `riverlb-issue-11-bios-40320551997.tar.gz`
- `riverlb-issue-11-uefi-40320551997.tar.gz`
- `SHA256SUMS`, also retained as [archives.sha256](archives.sha256).

Archives contain the full SBOM, license/source mapping, notices, payload hashes,
compiler, build/input/graph manifests, qualification report, predicates, subject
checksums, both Sigstore bundles and the workflow verification result. Their
internal `SHA256SUMS` covers every included evidence file. The source predicate
binds eight built artifact digests and eleven public evidence digests. Private
VM disks, configuration, keys, screenshots and guest logs are excluded.

## Independent checks

Both downloaded qualification report checksums passed. The following command was
run independently for **each** extracted firmware archive; expected result was
verified signatures and exact workflow, source/ref, hosted-runner, inventory and
subject binding. Both returned `status: verified`, 19 subjects and the reviewed
source above, as recorded in the local results linked in the table.

```sh
python3 scripts/verify-build-provenance.py \
  --artifact "$evidence/sbom.cdx.json" \
  --bundle "$evidence/provenance.sigstore.json" \
  --predicate "$evidence/provenance.json" \
  --source 168691870ab27e6bc13604992650b745458c3311 --firmware "$firmware" \
  --sbom "$evidence/sbom.cdx.json" --sbom-bundle "$evidence/sbom.sigstore.json"
```

For each firmware, an altered copy of the real attested SBOM (one appended space,
original subject name supplied) was rejected with `Artifact altered or absent
from signed provenance`. This confirms real-evidence tamper rejection alongside
the 22 inventory/provenance regressions for missing/changed components, preserved
notices/source references, wrong source/platform/workflow/run/runner identity and
altered artifacts. The aggregate inventory stage independently reconstructed
coverage from actual RPM/ISO bytes and both installed clone inventories.

Implementation/review: PRs [#85](https://github.com/codyasmith8118/RiverLB/pull/85),
[#86](https://github.com/codyasmith8118/RiverLB/pull/86),
[#87](https://github.com/codyasmith8118/RiverLB/pull/87) and
[#88](https://github.com/codyasmith8118/RiverLB/pull/88).
The offline two-build reproducibility evidence is
[run 40000616617](https://github.com/codyasmith8118/RiverLB/actions/runs/40000616617);
its earlier source identity remains distinct from this signed qualification.

This completes issue #11's inventory, notices, source-reference and signed build
provenance evidence for the specified source. It does not qualify later code,
production deployment, update publisher trust or release promotion. See
[software supply chain](../../software-supply-chain.md) for the build and
verification contract and [release readiness](../../release-readiness.md) for
remaining release gates.
