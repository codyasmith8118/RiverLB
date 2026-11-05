# Diagnostic packet headers

An administrator can use **System → Packet Capture** on an installed appliance.
Captures are local to one appliance and browser session; they are not HA state.
Operators, read-only accounts and API tokens cannot collect or export them.

1. Choose an approved traffic interface and one exact IPv4/IPv6 endpoint address,
   port and TCP/UDP protocol. The address and port match the same endpoint in
   either direction. Free-form filters and network prefixes are not accepted.
2. Choose 1–60 seconds and a file limit of up to 16 MiB. Review the privacy notice,
   explicitly consent, and enter your current password plus an unused authenticator
   or recovery code if MFA is enrolled. Select **Start capture**.
3. Inspect its state. **Stop capture** ends collection and retains the completed
   file; **Delete capture** removes it. A network/address change or management
   reconfiguration stops collection. Confirm/revert pending configuration first.
4. To download a completed PCAP, provide fresh password/MFA proof again and select
   **Download PCAP**. Start proof cannot authorize export. Store the file privately.

The default file contains Ethernet and base IP/TCP/UDP headers, including private
addresses, ports, identifiers and TCP sequence information. Transport payload,
TCP options and Ethernet padding are removed. IPv4 options/fragments, IPv6
extensions/fragments and unsupported or malformed packets are omitted. It is a
restricted diagnostic view, not a complete trace, anonymization or production
packet-loss measurement. Collection does not enable promiscuous mode, change
networking or pause forwarding. Diagnostic packets may be dropped under pressure.

Management interfaces/networks and protected management/SSH/HA ports are excluded
independently of the selector. The server adds its current management ports as
mandatory exclusions. There is no payload mode or override for these protections.

Only one job is retained per appliance. Completed files expire after ten minutes;
worker/helper stop and reboot remove their private runtime files. Signing out,
session expiry or credential changes prevent a replacement browser session from
reading the previous session's capture. Wait for expiry if another session owns
it. Capture bytes are excluded from database backups and HA synchronization.

Both start and export use one-use proofs with a 60-second expiry, bound to the
actor, current session and exact action/request. Proofs, passwords and MFA codes
belong in JSON request bodies, never URLs or logs. The UI clears credential fields
on success, denial and navigation. Downloads are private, bounded streams and
recheck session/account validity while transferring. An expired/deleted file or
revoked session can interrupt a download; repeat collection if needed.

The completed status includes diagnostic kernel receive/drop counters. A busy
capture worker can drop diagnostic copies; this does not indicate forwarding
loss. Audit records cover authorization, collection, stop reason, export and deletion
without packet contents or credentials. Root-owned files use private permissions;
the application neither opens a capture socket nor reads those files directly.
The helper accepts only fixed operations and controls a fixed worker template.
See [the design and qualification plan](decisions/005-restricted-packet-capture.md)
and [installed privilege separation](privileged-helper.md).

Before #55 is complete, require installed enforcing-SELinux IPv4/IPv6 capture,
export/cleanup/resource and traffic-impact evidence, exact-commit CI/security/RPM
acceptance and both [development review-appliance deliveries](development-lab.md).
Source and network-namespace fixtures alone do not establish that qualification.
