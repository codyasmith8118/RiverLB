# 001: Explicit traffic VLANs and kernel device binding

External and internal networks need enforceable ingress and egress selection,
not just labels. Existing VLANs, self IPs and routes already represent the Linux
network resources and support provisioning plans and compensating rollback.

Extend VLANs with a defaulted descriptive role and virtual servers with optional
`ingress_vlan` and `backend_vlan`. Bind sockets using Linux `SO_BINDTODEVICE`.
Use the same backend connector for application sockets and health probes, choose
an appropriate configured backend self IP, and constrain Automap route lookup
to the output device. Existing configurations retain system routing and their
current listener behavior when selections are absent.

Role-only changes must not recreate kernel resources. Active ingress-device or
tagged-topology changes at the same listener address are rejected until the
listener is disabled and applied, or moved. Device existence and permissions
are checked after managed provisioning and before activation. IPv6 address
readiness is checked before socket binding, with newly created addresses already
recorded for rollback if duplicate-address detection fails.

This provides one ingress device and one backend device per virtual server. It
does not introduce a packet router, multi-port bridges, VLAN inclusion/exclusion
lists, interface link/MTU ownership, HA, or a separate VIP lifecycle. Linux and
Hyper-V remain responsible for physical/vNIC connectivity and link state.
