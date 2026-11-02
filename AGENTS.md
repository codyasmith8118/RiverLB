# RiverLB development delivery

The maintainer uses the two EVE appliances to review completed RiverLB 2.0 tasks.
For tasks targeting `release-2.0`:

- Start feature branches from `release-2.0`; target that branch in PRs.
- Run the relevant local checks and resolve all applicable GitHub CI failures.
- After integration, require successful GitHub CI, Security scans, and RPM build
  and qualification for the exact `release-2.0` commit being deployed. All other
  workflows triggered for that commit must also succeed. A pending, failed, or
  missing required run does not count as completion.
- Deploy that accepted commit to **both** EVE RiverLB appliances using
  [the development lab procedure](docs/development-lab.md). Run its installed
  checks and retain the deployment receipt before reporting the task complete.
- Preserve each appliance's management address, accounts, certificates and
  configuration. Updating both executables does not mean copying device state
  between them. Configure synchronization/HA only as explicitly scoped work.
- If GitHub or lab access prevents delivery, report the implementation, CI and
  lab states separately; do not claim the lab was updated or the task completed.

The lab is EVE `192.168.1.160`, lab `RiverLB Test Lab`. RiverLB-A management is
`https://192.168.1.92:18090`; RiverLB-B is `https://192.168.1.25:18090`.
Credentials and guest SSH keys stay outside Git, under `/root/riverlb-eve-lab`
on EVE. Use existing session authorization or normal SSH authentication; never
embed passwords, private keys, tokens or database backups in source or logs.

Do not register this shared EVE host as a runner for arbitrary PR code or expose
its private SSH interfaces to GitHub-hosted runners. Do not operate on other
EVE labs. EVE development results do not replace platform, HA, capacity, or
production release qualification.
