# Release preparation

The nine requested release areas have implementation and regression coverage in the repository. This table distinguishes those changes from the appliance qualification required before a production release.

| Area | Implemented behavior | Verification |
|---|---|---|
| 1. Configuration recovery | Review differences; management/network confirmation; automatic/manual rollback; startup recovery | Confirmation API and real deadline tests; transaction regression fixtures |
| 2. Application updates | Signed offline staging; fixed standalone activation; compatible database rollback; monotonic sequence and recovery history | OpenSSL/Rust signature tests and isolated updater failure fixtures |
| 3. Administration | Administrator/operator/read-only roles; TOTP/recovery codes; idle expiry; source allowlists; scoped expiring API tokens | Auth unit and actual API tests; security GUI fixtures |
| 4. Operations | CPU, memory, disk, interfaces, time, certificate, pool and HA health; alert transitions; HTTPS webhook retries; UDP syslog; redacted support export | Health/transport/restart/redaction API tests |
| 5. Backups | Authenticated encrypted downloads and scheduled backups to an operator-mounted separate filesystem; retention; validate/stage/offline restore | Encryption/tampering, owned retention, staging and restore tests |
| 6. Audit | Search, actor filter, pagination, age/count retention and syslog forwarding; stable monotonic IDs | Database and operations API fixtures |
| 7. Service hardening | Bounded capabilities; restricted filesystems, sockets and syscalls; separate read-only publisher trust; inspectable policy audit | Service policy fixtures and systemd directive verification |
| 8. Installer | Graphical RiverLB installer, native disk choice/confirmation, explicit text fallback; reviewed console setup with retry/back/cancel | Branding/runtime/media structure and first-boot fixtures |
| 9. Branding | RiverLB product identity across portal, login, installer/media labels and console; AlmaLinux platform attribution | Branding fixtures and repository review |

See [configuration recovery](configuration-recovery.md), [offline updates](offline-updates.md), [administration](security-and-database.md), [operations and backups](appliance-operations.md), [service hardening](service-hardening.md), [installer experience](installer-experience.md) and [branding](branding.md).

These changes do not by themselves qualify a production image. The management daemon still runs as root for the current networking/HA integration; the restrictions are concrete limits, not a completed privilege-separated network helper. Backup scheduling requires a real mounted destination and its systemd write permission. UDP syslog is best effort. Live TCP/TLS failover replication, HA rolling software updates and OS rollback remain unsupported.

A release must rebuild the RPM and ISO from the final commit and pass full CI, supported BIOS/UEFI VM boots, graphical installation and recovery, network/firewall/SELinux tests, application update interruption/rollback, and HA fencing/failover tests on the intended platforms. Capacity and extended load testing, immutable OS repository inputs, dependency/license inventory, protected signing/promotion and signing-key ownership remain release qualification work. Keep the evidence with the artifact manifest; do not label a converted image or unsigned candidate a qualified release.
