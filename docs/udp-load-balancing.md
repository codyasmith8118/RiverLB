# UDP load balancing and virtual server types

## What “Standard” means

`server_type = "standard"` is the original compatibility setting. It selects
HTTP processing when an HTTP profile is present, otherwise a TCP byte-stream
proxy. It has never meant UDP, layer 2 switching, a different load-balancing
algorithm or a faster forwarding engine. TLS is an independent TCP setting.

The GUI now labels this **Automatic (legacy TCP / HTTP settings)**. Existing
configurations keep their behavior; new virtual servers default to explicit TCP.
Choose the protocol you actually intend:

| GUI type | Backend selection and processing |
| --- | --- |
| TCP proxy | One backend per TCP connection; optional TLS termination/backend TLS |
| UDP proxy | One backend per client IP/port conversation, expiring after inactivity |
| HTTP proxy | One backend per HTTP/1 request; HTTP profiles, RiverRules and cookie persistence |
| Domain routing only | HTTP hostname route table, without a default pool |
| Automatic | Legacy HTTP-if-configured, otherwise TCP behavior |

## Configure UDP in the GUI

1. Create a UDP request/response, DNS query or ICMP health monitor. Match the
   actual backend protocol; a UDP socket opening successfully does not prove
   that an application is responding. ICMP proves host reachability only.
2. Create the nodes and pool, selecting that monitor on the pool. If a node
   overrides its monitor, its monitor must also use UDP, DNS or ICMP. Give UDP-only
   named nodes an appropriate node monitor too; otherwise their independent
   node status still uses the node's default TCP probe.
3. Create a virtual server, choose **UDP proxy**, enter a specific VIP and port,
   select its pool and traffic VLANs, and set source translation as needed.
   Inline members require the monitor on the virtual server itself.
4. Set **UDP flow idle timeout**, default 30 seconds, allowed 1–3600. Apply and
   confirm both member health and application responses from a real UDP client.

The management interface stays HTTP/HTTPS over TCP. A TCP VIP and a UDP VIP can
use the same IP/port; two UDP VIPs cannot share the same endpoint. Managed mode
provisions destination-scoped **UDP** firewalld permissions for UDP VIPs. Existing
TCP management/listener rules remain TCP. Unmanaged/external-network mode still
requires external network/firewall provisioning.

See [the UDP example](../examples/udp.toml). It uses a text request/response
monitor against two local test backends; replace the endpoints and monitor for
your application. Use a fresh database for developer examples; use the GUI for
an installed appliance's authoritative configuration.

## Flow behavior and limits

For one virtual server, the client source IP **and source port** identify a flow.
Packets from that endpoint keep the same connected backend UDP socket, preserving
datagram boundaries, binary data, empty payloads and the translated source port.
Replies use the VIP's address/port. Connected backend sockets accept traffic only
from the selected backend endpoint. UDP does not provide delivery guarantees or
retransmission; the application remains responsible for those.

Round-robin distributes **new flows**, not every datagram. Least-connections
uses active UDP flows; weights, priority groups, draining, member limits and
source persistence use the existing selection/admission logic. “No persistence”
disables extra source affinity but does not split an active UDP conversation
across servers. For a distribution test use different client source ports, or
wait for flow expiry before reusing one. A failed/draining member is excluded
from new selections; an existing flow remains pinned until expiry or a socket
error, so health changes do not replay datagrams to another server.

The idle timer refreshes on successfully forwarded client or backend datagrams.
Normal idle expiry completes a flow; it is not a session-timeout failure.
Global connection capacity is shared by TCP connections and UDP flows. Virtual
server/member connection limits also bound flows. Queues hold at most 8 packets
per flow, with a shared 8 MiB payload budget across UDP listeners/generations.
Excess work is dropped and counted as rejected. Set capacity and idle timeouts
for the expected client population and available memory/file descriptors.

Current counters reuse session terminology: accepted/current/completed refer to
flows; bytes are forwarded application bytes. UDP connect latency measures socket
setup/source selection, not a handshake. Response latency measures the first
backend response after the first forwarded request in a flow; it is not a
protocol-aware per-transaction latency histogram.

## Operational boundaries

* UDP requires a specific unicast VIP; wildcard and multicast VIPs are rejected.
* HTTP processing, cookies, client/server TCP TLS profiles and SNI certificate
  assignments are unavailable on UDP virtual servers. Encrypted UDP payloads can
  be forwarded opaquely; there is no DTLS termination or QUIC connection-ID-aware
  routing/migration implementation.
* Configuration activation ends the previous generation's UDP flows. Subsequent
  datagrams create new flows using the new configuration. Applications must
  tolerate loss/reselection during apply, restart or failover.
* HA owns/provisions UDP VIPs through the same active/standby lifecycle. Source
  persistence assignments can be checkpointed, but live UDP flow maps/backend
  source ports are **not replicated**. Qualify actual failover with the relevant
  UDP application before release.
* A UDP health check is a separate request. Neither `ping` nor a successful TCP
  test proves that a UDP service is reachable through its firewall.

[Tokio's UDP socket documentation](https://docs.rs/tokio/latest/tokio/net/struct.UdpSocket.html)
describes the connected socket model used here. Run `python3 tests/udp.py` after
building for loopback integration coverage, and add the UDP cases in the
[appliance qualification plan](appliance-test-plan.md) to the real platform run.
