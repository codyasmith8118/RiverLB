# Isolated KVM qualification

Issue [#10](https://github.com/codyasmith8118/RiverLB/issues/10) provisions the
qualification workflow; successful policy tests alone do not qualify an appliance.
A release still needs successful real BIOS and UEFI guest reports for its exact
source, inputs and artifact hashes, plus the broader release readiness gates.

## Admission and environment protection

`Isolated KVM appliance qualification` accepts manual dispatch only from this
repository's `release-2.0` branch. Admission runs again inside each qualification
job. PR refs, forks, tags, other branches and persistent runners are rejected.
The public safety-policy workflow runs ordinary unit tests for PRs, never guests.

The `appliance-build` GitHub environment must require reviewer `codyasmith8118`,
disable administrator bypass and allow only the exact `release-2.0` branch.
The checked-in [environment configuration](../.github/qualification-environment.json)
is applied with repository administration permissions:

```sh
gh api --method PUT repos/codyasmith8118/RiverLB/environments/appliance-build \
  --input .github/qualification-environment.json
gh api --method POST repos/codyasmith8118/RiverLB/environments/appliance-build/deployment-branch-policies \
  -f name=release-2.0 -f type=branch
```

Inspect existing settings before applying; preserve stronger protections. Verify
required reviewers, disabled bypass and the branch policy through the API and
Settings → Environments. The sole maintainer may explicitly approve their own
dispatch (`prevent_self_review: false`); this is an approval gate, not independent
two-person review. Do not auto-approve deployments from CI or add lab credentials.
See GitHub's [environment protection documentation](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments).

## Dispatch and inspect evidence

Merge reviewed feature changes into `release-2.0` before dispatching. Do not
weaken branch admission to exercise an unmerged feature branch.

```sh
gh workflow run appliance-image.yml --ref release-2.0 -f mode=negative-preflight
gh workflow run appliance-image.yml --ref release-2.0 -f mode=full
```

Approve pending environment deployments in the run's Actions page. Both firmware
jobs may run concurrently (maximum two isolated VMs), so review both pending
deployments together; each retains the same environment protection. Each BIOS or
UEFI cell uses a separate GitHub-hosted Ubuntu 24.04 VM. Runtime checks require
writable `/dev/kvm`; software emulation is not substituted if KVM is unavailable.
Require 40 GiB free disk, 6 GiB available memory and two logical CPUs. Unused
hosted Android/.NET/GHC SDK directories are removed before preflight. Host Podman
comes from Ubuntu; guest build/test tools and source dependencies come from the
hash-verified pinned input snapshot, not a shared mutable cache.

Full mode builds RPMs from the same commit, verifies their manifest against the
source/input lock, then runs real resource-control probes, ISO structure checks,
Packer disk installation, boot/configuration/traffic/reboot checks and interactive
installer checks for each firmware. Installer checks cancel before writing blank
disks; they do not prove existing-disk upgrades, completed graphical installs,
Secure Boot, HA or the entire supported hardware matrix.

Download `qualification-<firmware>-<run>-<attempt>`. Verify `SHA256SUMS` before
reading `report.json`. Evidence records source/run identity, host resources,
input/manifest hashes, pinned tools image, completed stages, fixture assertions,
output hashes and cleanup outcome. Require `status: passed`, `stage: complete`
and `cleanup: passed` in both firmware reports. Artifacts expire after 30 days;
copy verified public evidence to the release evidence store before expiration.
Disks and media are hashed for identity but are not published by this workflow.

Negative mode requests an impossible disk minimum and must record
`status: rejected`, `reason: insufficient-disk`, `expected_negative: true`, real
measured capacity and successful cleanup. A green negative-test job is not a
passing guest qualification. It starts no guest and cannot replace full mode.

## Containment, cancellation and recovery

Containers carry an unpredictable run/attempt/firmware ownership label, with
8 GiB memory (no additional swap), two CPUs, 256 processes and a file-descriptor
limit. Resource probes independently provoke a kernel-enforced OOM in a 64 MiB
container and prove cleanup preserves a differently labeled running container.
No host disk or production network is passed to these probes.

Individual stages have deadlines (5–90 minutes), bounded private logs and owned
process groups. The qualification job has a 120-minute overall deadline; the
separate reusable RPM job has its own deadline. Timeouts and signals terminate
only the stage's process group. An always-run cleanup verifies the workspace
marker and each container's exact ownership label before removing it by ID.
It removes only this job's generated output, preserving the sanitized evidence.
It never performs global container/image/volume pruning or host-wide process kills.

Stage changes also emit Actions notices containing only the fixed stage name.
Normal failures retain a static stage/reason, completed-stage results, and artifact
hashes and validated fixture assertions recorded as each producing stage finishes. Installer failures may include allowlisted case/checkpoint/reason codes; unknown
fields or free text are rejected. Raw
exception strings, console logs, screenshots, private overlays, account data and
guest credentials are excluded. Fix the named stage and rerun a fresh workflow;
do not recover or reuse private guest state. Private logs are bounded to 1 MiB
per stage and destroyed, so reproducing a detailed guest failure requires a
separate isolated local run under the appliance test plan.

Hard cancellation may prevent cleanup or evidence upload. In that case do not
claim cleanup passed or qualification completed. GitHub destroys the disposable
hosted VM after its job; no persistent runner is enrolled. Rerun the workflow with
a new attempt and fresh workspace. See GitHub's
[hosted runner documentation](https://docs.github.com/en/actions/concepts/runners/github-hosted-runners).

Local safety checks (no guest qualification):

```sh
python3 tests/appliance/qualification.py
# Resource integration requires Podman, verified input cache and an admitted
# workflow context; CI runs tests/appliance/qualification_resources.py itself.
```

The unit suite covers admission denial, resource rejection, ownership boundaries,
report allowlisting, bounded output, deadlines and SIGTERM interruption. Record
actual hosted run URLs separately; never label mocked/unit results as KVM evidence.

The installer console probe first requires a nonce shell-readiness response.
Its compressed payload uses lowercase hex to reduce shifted-key traffic; guest
execution has a 30-second deadline and the host waits for completion. Public
failure codes distinguish an unavailable shell (`shell-not-ready`), a missing
completion response (`probe-timeout`), and a timeout at a fixed probe operation
(`gui-timeout-environment`, `gui-timeout-accessibility-import`,
`gui-timeout-accessibility-query`, or `gui-timeout-product`). Raw console output
and accessibility names remain private and are removed during cleanup.
