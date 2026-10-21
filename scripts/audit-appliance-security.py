#!/usr/bin/env python3
"""Read-only audit of source service policy or an installed appliance's runtime.

This audit reports restrictions and qualification gaps. It never starts services,
changes SELinux policy, grants privileges or rewrites appliance files.
"""
import argparse
import json
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPABILITIES = {"CAP_NET_ADMIN", "CAP_NET_BIND_SERVICE", "CAP_NET_RAW"}
HA_CAPABILITIES = CAPABILITIES | {"CAP_CHOWN", "CAP_FOWNER", "CAP_SETUID", "CAP_SETGID", "CAP_DAC_OVERRIDE"}
CAPABILITY_MASK = (1 << 10) | (1 << 12) | (1 << 13)
HA_CAPABILITY_MASK = CAPABILITY_MASK | (1 << 0) | (1 << 1) | (1 << 3) | (1 << 6) | (1 << 7)
BOOL_POLICY = ["NoNewPrivileges", "PrivateTmp", "PrivateDevices", "ProtectKernelTunables", "ProtectKernelModules", "ProtectKernelLogs", "ProtectControlGroups", "ProtectClock", "ProtectHostname", "RestrictSUIDSGID", "RestrictRealtime", "RestrictNamespaces", "LockPersonality", "MemoryDenyWriteExecute"]
TRUE_VALUES = {"true", "yes", "1"}


def parse_unit(path):
    values = {}
    section = ""
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if line.startswith("[") and line.endswith("]"):
            section = line[1:-1]
        elif "=" in line and not line.startswith(("#", ";")):
            key, value = line.split("=", 1)
            values[(section, key)] = value.strip()
    return values


def finding(name, passed, detail, warning=False):
    return {"check": name, "result": "pass" if passed else ("warning" if warning else "fail"), "detail": detail}


def check_service(values, ha=False):
    checks = []
    get = lambda key: values.get(("Service", key), "")
    for key in BOOL_POLICY:
        checks.append(finding(key, get(key).lower() in TRUE_VALUES, get(key) or "missing"))
    for key, expected in [("ProtectSystem", "strict"), ("ProtectHome", "read-only"), ("UMask", "0077"), ("KillMode", "control-group")]:
        checks.append(finding(key, get(key) == expected, get(key) or "missing"))
    capabilities = set(get("CapabilityBoundingSet").upper().split())
    checks.append(finding("bounded capabilities", capabilities == (HA_CAPABILITIES if ha else CAPABILITIES), " ".join(sorted(capabilities))))
    checks.append(finding("read-only host network namespace", get("OpenFile").split() == ["/proc/1/ns/net:riverlb-host-netns:read-only"], "A single read-only namespace descriptor permits firewall detection without broader capabilities"))
    if ha:
        checks.append(finding("HA provisioning privileges retained", False, "HA retains ownership, identity switching, and filesystem bypass capabilities for fixed pcs helpers and hacluster IPC. Separating provisioning requires further live qualification.", warning=True))
    families = set(get("RestrictAddressFamilies").split())
    expected = {"AF_INET", "AF_INET6", "AF_UNIX", "AF_NETLINK"} | ({"AF_PACKET"} if ha else set())
    checks.append(finding("socket families", families == expected, " ".join(sorted(families))))
    write_paths = {p.lstrip("-") for p in get("ReadWritePaths").split()}
    expected = {"/etc/riverlb", "/var/lib/riverlb", "/run/riverlb", "/mnt/riverlb-backups", "/run/riverlb-ha-deploy"} | ({"/etc/corosync", "/var/lib/pcsd", "/var/lib/pacemaker", "/dev/shm"} if ha else set())
    checks.append(finding("writable path scope", write_paths == expected, " ".join(sorted(write_paths))))
    trust="/etc/riverlb-updater/update-trust.json"
    trust_writable=any(trust==path or trust.startswith(path.rstrip("/")+"/") for path in write_paths)
    checks.append(finding("publisher trust remains read-only", get("ProtectSystem")=="strict" and not trust_writable, trust+" must remain outside writable daemon paths"))
    checks.append(finding("OS password hashes inaccessible", {"/etc/shadow", "/etc/gshadow"}.issubset({p.lstrip("-") for p in get("InaccessiblePaths").split()}), get("InaccessiblePaths")))
    deny = set(get("SystemCallFilter").removeprefix("~").split())
    checks.append(finding("dangerous syscall groups blocked", get("SystemCallFilter").startswith("~") and {"@mount", "@reboot", "@swap", "@module", "@raw-io"}.issubset(deny), get("SystemCallFilter")))
    checks.append(finding("native syscall architecture", get("SystemCallArchitectures") == "native", get("SystemCallArchitectures")))
    inaccessible = {p.lstrip("-") for p in get("InaccessiblePaths").split()}
    shm_blocked = "/dev/shm" in inaccessible
    if ha:
        shm_blocked = "/dev/shm" in get("NoExecPaths").split() and not get("ExecPaths")
        checks.append(finding("HA local IPC shared memory", get("BindPaths").split() == ["/dev/shm"] and "/dev/shm" not in inaccessible, "Pacemaker IPC requires the host shared-memory mount; execution remains prohibited"))
    checks.append(finding("executable-memory bypasses blocked", "memfd_create" in deny and shm_blocked, get("SystemCallFilter")))
    checks.append(finding("root identity still required", get("User") != "root", "Root identity is retained for firewalld and HA integration. This is a bounded sandbox, not complete privilege separation.", warning=True))
    if not ha:
        requires = values.get(("Unit", "Requires"), "").split()
        after = values.get(("Unit", "After"), "").split()
        checks.append(finding("interrupted-update recovery before traffic", "riverlb-update-recovery.service" in requires and "riverlb-update-recovery.service" in after, "Recovery must run before the standalone daemon"))
        checks.append(finding("preflight on every service start", get("ExecStartPre")=="+/usr/libexec/riverlb/riverlb-update preflight", get("ExecStartPre")))
    return checks


def runtime_checks(service):
    ha = service == "riverlb-ha.service"
    properties = BOOL_POLICY + ["ProtectSystem", "ProtectHome", "CapabilityBoundingSet", "MainPID", "ActiveState", "SubState", "RestrictAddressFamilies", "ReadWritePaths"]
    output = subprocess.check_output(["systemctl", "show", service, *["--property=" + p for p in properties]], text=True, timeout=10)
    values = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    checks = []
    for key in BOOL_POLICY:
        # Some systemd versions report the allowed namespace bit mask as zero;
        # others render that mask as the boolean restriction "yes".
        passed = values.get(key, "").lower() in TRUE_VALUES
        if key == "RestrictNamespaces":
            passed = values.get(key, "").lower() in ("0", "yes", "true")
        checks.append(finding("runtime " + key, passed, values.get(key, "missing")))
    checks.append(finding("runtime ProtectSystem", values.get("ProtectSystem") == "strict", values.get("ProtectSystem", "missing")))
    checks.append(finding("runtime ProtectHome", values.get("ProtectHome") == "read-only", values.get("ProtectHome", "missing")))
    caps = {p.upper() for p in values.get("CapabilityBoundingSet", "").split()}
    checks.append(finding("runtime capability bound", caps == (HA_CAPABILITIES if ha else CAPABILITIES), " ".join(sorted(caps))))
    pid = int(values.get("MainPID", "0"))
    checks.append(finding("service is running", values.get("ActiveState") == "active" and pid > 0, str(values)))
    if pid > 0:
        status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
        effective = int(status.get("CapEff", "0").strip(), 16)
        checks.append(finding("process has no capabilities outside bound", effective & ~(HA_CAPABILITY_MASK if ha else CAPABILITY_MASK) == 0, f"CapEff={effective:016x}"))
        checks.append(finding("process no-new-privileges", status.get("NoNewPrivs", "").strip() == "1", status.get("NoNewPrivs", "missing").strip()))
    enforce = Path("/sys/fs/selinux/enforce")
    checks.append(finding("SELinux enforcing", enforce.exists() and enforce.read_text().strip() == "1", "The audit requires an enforcing AlmaLinux guest; it does not install a policy."))
    for path in [Path("/etc/riverlb"), Path("/var/lib/riverlb"), Path("/run/riverlb")]:
        info = path.lstat()
        checks.append(finding("private " + str(path), stat.S_ISDIR(info.st_mode) and info.st_uid == 0 and stat.S_IMODE(info.st_mode) == 0o700, f"uid={info.st_uid} mode={stat.S_IMODE(info.st_mode):04o}"))
    checks.append(finding("operational qualification still required", False, "Boot, real firewalld/network changes, HA fencing and ARP, SSH sync, update rollback, and SELinux AVC review must be exercised in a disposable appliance VM.", warning=True))
    return checks


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--live", action="store_true", help="Also read an installed appliance's effective unit and process state")
    parser.add_argument("--service", choices=["riverlb.service", "riverlb-ha.service"], default="riverlb.service")
    args = parser.parse_args()
    units = [ROOT / "packaging/rpm/riverlb.service", ROOT / "deploy/ha/riverlb-ha.service"]
    if args.live:
        units = [next((path for path in [Path("/etc/systemd/system") / name, Path("/usr/lib/systemd/system") / name] if path.is_file()), Path("/usr/lib/systemd/system") / name) for name in ["riverlb.service", "riverlb-ha.service"]]
    result = {"mode": "live" if args.live else "source", "services": {}}
    for path in units:
        try:
            result["services"][path.name] = check_service(parse_unit(path), "ha" in path.name)
        except OSError as error:
            result["services"][path.name] = [finding("service policy available", False, str(error))]
    if args.live:
        try:
            result["runtime"] = runtime_checks(args.service)
        except (OSError, ValueError, subprocess.SubprocessError) as error:
            result["runtime"] = [finding("runtime audit available", False, str(error))]
    print(json.dumps(result, indent=2))
    return int(any(item["result"] == "fail" for group in result["services"].values() for item in group) or any(item["result"] == "fail" for item in result.get("runtime", [])))


if __name__ == "__main__":
    raise SystemExit(main())
