# 004: Bounded, read-only application flow inspection

Task #27 observes RiverLB-owned traffic rather than capturing packets or querying
arbitrary host connection tables. A registry shared across runtime generations
holds at most 4,096 fixed-shape observations. Flow guards mark liveness on drop;
maintenance reclaims closed metadata once per second. Full or contended
registration skips metadata and increments a fixed counter, preserving existing
traffic admission and forwarding behavior. No inspection lock is awaited on the
data plane. TCP/UDP byte forwarding does not update inspection metadata.

TCP and UDP report the selected backend. HTTP keepalive reports its explicitly
labeled last sampled backend selection, at most once per second. It never stores
request/body/header values. State describes application transport/HTTP phases,
not the kernel TCP state machine. Existing admissions gain only fixed reason
counters; rejected sources and payloads are not retained.

The authenticated read-only API and HTTPS CLI serve immutable, five-second
snapshots, at most one new snapshot per second and six retained allocations.
Pages are limited to 200 rows and 20 requests per second globally. Cursors bind
filters and a random process namespace. Rate, contention and expiry produce
explicit failures rather than unbounded allocations or inconsistent pagination.
Source metadata requires administrator/operator authorization, enforced again at
the handler; Monitoring tokens and read-only accounts cannot inspect it.

Termination is unsupported. Existing apply/drain/timeout policy remains the only
way this feature interacts with connection lifetimes; no new destructive action
or unaudited termination mechanism is added. No metadata is persisted or
replicated. The [operator contract](../flow-inspection.md) specifies retention,
coverage loss, resource bounds and uncertainty of HTTP observations. Real socket
stress and baseline comparisons must identify their source/artifact and scope;
this design alone is not performance or production qualification.
