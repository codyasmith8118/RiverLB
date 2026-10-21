# Weighted round robin

Choose **Weighted round robin** under **Local Traffic → Pools**, or on a virtual server using inline members. Set **Member ratios** using one `IP:port=weight` line per backend, then Save and apply. Unlisted members default to weight 1. Ratios must be integers from 1 to 1000 and reference existing members.

For example, give `192.0.2.10:8000` weight 3 and `192.0.2.11:8000` weight 1. With both healthy and eligible, approximately three quarters of new selections go to the first backend. Weight controls connection selections, not bandwidth, CPU load or session duration.

```toml
[[pools]]
name = "application"
algorithm = "weighted_round_robin"
members = ["192.0.2.10:8000", "192.0.2.11:8000"]
member_weights = { "192.0.2.10:8000" = 3, "192.0.2.11:8000" = 1 }
```

The scheduler uses smooth weighted round robin: add each eligible member's weight to its running score, select the greatest score (member order breaks ties), and subtract the total eligible weight from that member. Selection and active-slot reservation share a lock. Unhealthy and draining members receive no new selections; their score resets when a weighted selection observes them excluded. Hot apply resets scheduler state while existing sessions keep their original backend.

Source-address persistence takes precedence over balancing. Repeated connections with a valid persistence record can therefore produce a different observed ratio. Source hash, ordinary round robin and least connections ignore configured weights. A named pool shares its configuration across referring virtual servers, but each virtual server has independent scheduler state.

Member status objects expose `weight`. Weighted least connections is documented [separately](weighted-least-connections.md). Dynamic capacity inputs and sustained scheduling qualification remain future work.

Runtime tests check a 3:1 distribution and unhealthy-member exclusion/recovery. `tests/draining.py` checks a 30:10 distribution over real TCP sessions before testing weighted named-pool drain and restoration. Portal tests cover ratio save/load behavior.
