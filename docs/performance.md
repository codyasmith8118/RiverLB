# Configuration apply performance

The October 7 investigation reproduced a slow save with eight loopback HTTP
backends, a 600 ms health-check deadline, and deliberately delayed responses.
Only a virtual server description changed. Linux networking was disabled for
this fixture, so these timings isolate the application transaction:

| Request | Before | After removing synchronous apply probes |
| --- | ---: | ---: |
| Apply configuration | 4.817 s | 0.015 s |
| Concurrent status read | 4.728 s | 0.006 s |

These are local debug-binary measurements, not browser or deployed-VM timings.
Run `python3 tests/apply_performance.py` after `cargo build` to reproduce the
acceptance test. It also verifies that background monitoring detects failures
and recovery. `--measure-only` prints measurements without latency assertions.

## Findings and changes

* Apply previously held the generation lock while awaiting a sequential sweep
  of every backend. Shared backends were probed separately for each virtual
  server. Deadline waits accumulated and configuration/status readers queued
  behind the transaction. Apply now commits without awaiting probes. Retained
  members preserve health when backend/monitoring inputs are unchanged; new or
  changed inputs remain ineligible until successful checks meet the rise threshold.
* Health checks now use bounded concurrency, with at most 16 simultaneous probe
  connections per runtime. Startup still awaits an initial sweep; apply starts
  background checks immediately. Existing rise/fall, TLS verification, source
  selection, deadlines, and cancellation remain in use.
* Firewalld queried the zone again for every VIP on the same device. Each apply
  now queries each device once, using a cache limited to that calculation so
  external zone changes remain visible. Configurations with no eligible firewall
  destinations avoid even the default-zone query.
* Runtime construction rebuilt monitor and backend TLS connectors for each
  virtual server using the same profile. These are now shared within the new
  runtime; a subsequent apply reconstructs them and reads current certificate
  material. Health-state transfer indexes previous members by address.
* Certificate inventory reads held the generation lock across database I/O.
  They now take a runtime snapshot and release that lock before querying inventory.
* The five-second statistics checkpoint held the generation lock during database
  writes. Checkpoints now release it after taking a snapshot. A separate statistics
  write lock keeps checkpoints ordered with resets, preventing old samples from
  overwriting a reset.
* The GUI previously kept Save disabled until its post-apply status refresh
  finished. It now unlocks after configuration reconciliation and updates health
  in the background. Earlier loading improvements batch editor construction,
  parallelize inventory requests, reuse unchanged choices, and deduplicate help scans.

## Diagnose a deployed instance

For a repository checkout, stop the foreground process and restart with:

```bash
sudo env RUST_LOG=riverlb=debug ./target/debug/riverlb serve
```

Apply once and look for `configuration apply timing`. Each message includes
`stage`, the phase's `elapsed_ms`, and the running `total_ms`:

| Stage | Work measured |
| --- | --- |
| validation | Domain-listener expansion and configuration validation |
| transaction_lock | Waiting for the active configuration transaction lock |
| network_provisioning | Ownership checks and transactional Linux network preparation |
| certificate_resolution | Waiting for the database, managed certificate lookup and TLS-key validation |
| runtime_construction | Runtime construction and file-based TLS/monitor setup |
| listeners_and_health_transfer | Device validation, listener binding, retained health |
| firewall_and_ha | Zone discovery, firewall changes, HA announcement/authority checks |
| database_commit | Durable configuration/audit or synchronization commit |
| old_task_drain | Canceling and draining old accept/probe tasks |
| activation | Starting the committed generation |

For saves taking at least one second, the browser Console prints
`RiverLB apply timings (milliseconds)` with collection, request, server-apply,
configuration-read, rendering, and unlock durations. The apply API also returns
`duration_ms`, isolating server work from browser/network overhead.

In browser developer tools, inspect Network timings for `PUT /api/v1/config`
and the following `GET /api/v1/config`. If those finish quickly but the GUI
stalls, record a browser Performance trace for editor reconstruction. The local
loopback test does not measure firewalld, routed backends, HA authority latency,
storage performance, or browser rendering on the installed appliance.

Actual Linux network/firewall commands, HA authority checks, and durable database
writes still complete before apply returns. Transactions remain serialized to
preserve revision checks and rollback; a slow external command or storage device
can therefore still delay configuration/status reads. Debug phase timings identify
that remaining cost without weakening transaction safety.

The VM trace supplied on October 7 showed 10.518 seconds in the original combined
certificate/runtime phase, versus 441 ms for firewall/HA and 3 ms for database
commit. That combined phase now has separate certificate and runtime timings;
`certificate database lock acquired` reports database wait explicitly. Statistics
retention now uses an indexed age cutoff and an ID range cutoff instead of a
full-table `NOT IN` membership filter on every checkpoint. This is a confirmed
query optimization; its share of the VM delay requires the new timing trace.

History JSON decoding now runs outside the shared database lock and on a blocking
worker, and configurations without managed certificate references skip certificate
database access. These changes reduce contention independently of TLS profile setup.
