# Pool-member drain

In **Local Traffic → Pools**, enter existing backend addresses in **Drain members**, one IP:port per line. For inline backends, use the same field on **Virtual Servers**. Save and apply activates the change. Named-pool drain settings apply to every referring virtual server. Remove an address from the drain list and save to restore its eligibility.

```toml
[[pools]]
name = "application"
algorithm = "round_robin"
members = ["192.0.2.10:8000", "192.0.2.11:8000"]
draining_members = ["192.0.2.10:8000"]
```

Drain excludes a member from all new selections, including source-address persistence. Established sessions retain their backend and finish under their original session timeout. TCP health probes continue; health and administrative drain are independent. Status API member objects expose `draining`; the overview displays **Draining** even when TCP probes succeed. All members may be drained; new connections then close without backend selection. There is no waiting queue.

Drain lists must contain unique addresses present in the associated member list. Inline drain settings cannot be combined with a named pool. Omitted lists preserve previous configuration behavior. Settings persist in the configuration database across restart; TOML examples are initial-import inputs.

Hot apply creates a new runtime generation. Existing sessions are retained in the old generation, whose active counters are not included in the current status snapshot. Do not use the displayed active count as proof that a drained backend has no remaining connections. Network changes can independently interrupt sessions.

Administrative drain prevents new selections while existing TCP sessions finish. Forced session termination is unsupported. Weights, priorities and node enable/disable are separate controls; see [priorities and capacity](priority-and-capacity.md). Applying drain changes restarts UDP flows. `tests/draining.py` verifies actual TCP sessions across named-pool drain and restore; runtime tests cover affinity exclusion and all-members-drained behavior.
