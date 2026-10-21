# Weighted least connections

Choose **Weighted least connections** in a named pool or inline virtual server,
then set member ratios with the existing `IP:port=weight` editor. The persisted
algorithm is `weighted_least_connections`; weights are integers 1–1000 and
unspecified members have weight 1.

Among healthy, non-draining members, selection minimizes `active / weight`.
For example, weight 3 with five active connections has less normalized load than
weight 1 with two. Integer cross products compare ratios without floating-point
rounding; equal ratios rotate in member order. Reservations count during incoming
TLS handshake, backend connect/handshake and forwarding, so simultaneous clients
see already-reserved slots. Dropped sessions release their reservation.

Existing usable source-affinity records take precedence over balancing. Stateless
source-hash persistence profiles override the balancing algorithm. Scheduler state
is per virtual server even when two virtual servers reference the same pool;
reload resets counts for the new generation, while old sessions finish in the old
generation. Long-held equal-duration connections tend toward the configured
weight ratio; short-lived traffic is selected by current load and is not guaranteed
to follow a fixed ratio.

Sustained-load scheduling and interoperability qualification remain release work.
Rust tests verify ratio comparisons, weighted reservations and draining exclusion.
