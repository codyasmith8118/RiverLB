# RiverLB 2.0 development lab

The maintainer reviews completed 2.0 work on **both** RiverLB appliances in
**RiverLB Test Lab**, hosted by EVE at `192.168.1.160`. Each accepted development
commit must pass GitHub CI and installed lab checks before the task is complete.
The appliances retain separate configurations and traffic VIPs; this delivery
process does not configure HA or configuration synchronization.

| Appliance | Browser management | Private SSH from EVE | Client-network VIP |
|---|---|---|---|
| A | `https://192.168.1.92:18090` | `10.77.0.11` | `10.77.10.100:8080` |
| B | `https://192.168.1.25:18090` | `10.77.0.12` | `10.77.10.101:8080` |

Management currently uses stable-MAC DHCP leases. If those leases change, update
and verify the selected management binding and lab inventory before delivery.
Login is `admin`; generated passwords are in the root-only EVE file
`/root/riverlb-eve-lab/credentials.json`. Certificates are private lab trust,
not publicly trusted certificates. Never commit that file or a private key.

## Deliver a completed task

1. Implement on a feature branch and open a PR against `release-2.0`. Run the
   relevant local tests, then wait for the PR checks and integrate the change.
2. Inspect **the integrated commit's** CI and Security scans. Dispatch the
   existing RPM workflow on `release-2.0` and wait for its success:

   ```sh
   gh workflow run rpm.yml --repo codyasmith8118/RiverLB --ref release-2.0
   gh run list --repo codyasmith8118/RiverLB --branch release-2.0
   ```

   Do not substitute PR-head or older green checks for the deployed commit.
   Workflows with path filters need not run when inapplicable; if triggered,
   their latest run for the deployed commit must succeed. Manual guest/platform
   qualification is still required when the task's acceptance criteria require it.
3. Prepare an RPM bundle from the successful GitHub artifact. Use an authenticated
   `gh` installation and Python 3.12 or later:

   ```sh
   python3 scripts/lab/prepare.py --sha FULL_RELEASE_BRANCH_COMMIT \
     --output /tmp/riverlb-development.tar
   ```

   The helper checks current branch identity, exact-commit workflow results,
   artifact source identity and RPM checksums. It prints the bundle SHA-256.
   It refuses missing/pending/failed checks and a branch that has advanced.
4. Copy the bundle and the tracked helpers to EVE using normal SSH authentication:

   ```sh
   scp /tmp/riverlb-development.tar root@192.168.1.160:/root/riverlb-eve-lab/
   scp scripts/lab/*.py root@192.168.1.160:/root/riverlb-eve-lab/
   ```

   Check that the branch is still the intended tested head before applying.
   From EVE's root shell:

   ```sh
   python3 /root/riverlb-eve-lab/apply.py \
     /root/riverlb-eve-lab/riverlb-development.tar --sha256 BUNDLE_SHA256
   ```

   This intentionally explicit deployment keeps GitHub credentials off EVE and
   private SSH off public runners. It is part of task completion by the coding
   agent; no background service promises deployments while the agent is idle.
5. Verify `status: passed`, refresh both browser tabs, and include the commit,
   GitHub run links and EVE receipt path in the completion report. Hard-refresh
   an existing browser tab after UI changes.

## Deployment behavior and recovery

The EVE helper is restricted to the configured standalone A/B inventory. It
checks host identity, active services and verified management HTTPS before
changing either node. It refuses HA installations and active signed application
update selections; those require their separately reviewed lifecycle procedure.
Only the installed core and appliance RPMs are replaced. Their configuration,
accounts and device certificates stay local to each appliance.

Each node is updated in sequence with a stopped-service backup of configuration,
database and updater state, plus cached previous RPMs. Matching executable
hashes and source manifests are required on both. Post-deployment checks cover
verified HTTPS login, management CLI, live flow inspection, backend services,
round-robin distribution, health failure/recovery and short functional load.
A failed update attempts to restore every changed node's previous RPMs and
stopped state; rollback failures are recorded and must be resolved explicitly.
The previous deployment remains the accepted receipt until the entire run passes.

The unsigned development RPM workflow can reuse a package version/release, so
this **lab-only** helper explicitly permits replacement/older RPM releases. It
never changes production updater trust or treats these packages as signed
production releases. Backups contain secrets and stay root-only on EVE/guests.
The baseline package cache and `development-current.json` must exist before the
first deployment; never synthesize a baseline from an unrelated package set.

Accepted receipts are at `/root/riverlb-eve-lab/development-current.json`, with
per-run evidence under `/root/riverlb-eve-lab/deployments/`. Source manifests
are installed at `/usr/share/doc/riverlb/build-manifest.json` on each appliance.
EVE reset images are separate from live guest disks: ordinary deployments update
live guests, not their reset images. After an intentional wipe, restore the last
accepted build and rerun checks before calling either appliance current.

## Running traffic

SSH to EVE, then the client using the EVE-only guest key:

```sh
ssh -i /root/riverlb-eve-lab/id_ed25519 \
  -o UserKnownHostsFile=/root/riverlb-eve-lab/guest-known-hosts root@10.77.0.50
python3 /opt/riverlb-lab/http_load.py http://10.77.10.100:8080/ \
  --duration 60 --rate 100 --workers 32 \
  --expect-nodes backend1,backend2,backend3 --output /tmp/load-test-$(date +%s).json
```

Use `10.77.10.101` for B. Backends are `10.77.20.101`–`103`, each on TCP 8080.
The client and backend traffic networks are isolated. Cloud9 is reserved for
private management (`10.77.0.0/24`). Do not change other labs or the host LAN.
These small shared guests support functional development, not production
capacity or real fenced HA qualification.
