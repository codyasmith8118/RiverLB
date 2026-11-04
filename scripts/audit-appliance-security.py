#!/usr/bin/env python3
"""Read-only audit of source service policy or an installed appliance's runtime.

This audit reports restrictions and qualification gaps. It never starts services,
changes SELinux policy, grants privileges or rewrites appliance files.
"""
import argparse
import json
import pwd
import stat
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CAPABILITIES = {"CAP_NET_BIND_SERVICE"}
CAPABILITY_MASK = 1 << 10
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
            value = value.strip()
            previous = values.get((section, key), "")
            if previous and value and key in {"After", "Wants", "Requires", "ExecCondition", "ExecStartPre", "ReadWritePaths", "CapabilityBoundingSet"}:
                value = previous + "\n" + value
            values[(section, key)] = value
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
    checks.append(finding("bounded capabilities", capabilities == CAPABILITIES, " ".join(sorted(capabilities))))
    checks.append(finding("read-only host network namespace", get("OpenFile").split() == ["/proc/1/ns/net:riverlb-host-netns:read-only"], "A single read-only namespace descriptor permits firewall detection without broader capabilities"))
    families = set(get("RestrictAddressFamilies").split())
    expected = {"AF_INET", "AF_INET6", "AF_UNIX", "AF_NETLINK"}
    checks.append(finding("socket families", families == expected, " ".join(sorted(families))))
    write_paths = {p.lstrip("-") for p in get("ReadWritePaths").split()}
    expected = {"/etc/riverlb", "/var/lib/riverlb", "/run/riverlb", "/mnt/riverlb-backups"}
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
    checks.append(finding("executable-memory bypasses blocked", "memfd_create" in deny and shm_blocked, get("SystemCallFilter")))
    checks.append(finding("dedicated non-root identity", get("User") == "riverlb" and get("Group") == "riverlb", get("User") + ":" + get("Group")))
    checks.append(finding("ambient low-port binding only", set(get("AmbientCapabilities").upper().split()) == CAPABILITIES, get("AmbientCapabilities")))
    checks.append(finding("helper-backed startup", "--privileged" in get("ExecStart").split() and "riverlb-privileged-prepare.service" in values.get(("Unit", "Requires"), "").split() and "riverlb-privileged.service" in values.get(("Unit", "After"), "").split(), "Installed service must require preparation and an authenticated helper"))
    checks.append(finding("ownership repair before appliance readiness", get("ExecCondition").splitlines()[:1] == ["+/usr/libexec/riverlb/privileged/prepare.py"], "Repair RPM/restore ownership before conditions execute as the service account"))
    checks.append(finding("protected helper state remains read-only", not any(protected == path or protected.startswith(path.rstrip("/") + "/") for path in write_paths for protected in ["/etc/riverlb-privileged", "/var/lib/riverlb-privileged", "/run/riverlb-privileged", "/var/lib/riverlb-updater"]), "Root policy, identities, ownership and recovery journals are outside application writes"))
    if not ha:
        requires = values.get(("Unit", "Requires"), "").split()
        after = values.get(("Unit", "After"), "").split()
        checks.append(finding("interrupted-update recovery before traffic", "riverlb-update-recovery.service" in requires and "riverlb-update-recovery.service" in after, "Recovery must run before the standalone daemon"))
        checks.append(finding("preflight on every service start", "+/usr/libexec/riverlb/riverlb-update preflight" in get("ExecStartPre").splitlines(), get("ExecStartPre")))
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
    checks.append(finding("runtime capability bound", caps == CAPABILITIES, " ".join(sorted(caps))))
    pid = int(values.get("MainPID", "0"))
    checks.append(finding("service is running", values.get("ActiveState") == "active" and pid > 0, str(values)))
    if pid > 0:
        status = dict(line.split(":", 1) for line in Path(f"/proc/{pid}/status").read_text().splitlines() if ":" in line)
        owner = pwd.getpwnam("riverlb").pw_uid
        checks.append(finding("process uses dedicated non-root UID", owner > 0 and {int(value) for value in status.get("Uid", "0").split()} == {owner}, status.get("Uid", "missing").strip()))
        effective = int(status.get("CapEff", "0").strip(), 16)
        checks.append(finding("process has no capabilities outside bound", effective & ~CAPABILITY_MASK == 0, f"CapEff={effective:016x}"))
        checks.append(finding("process no-new-privileges", status.get("NoNewPrivs", "").strip() == "1", status.get("NoNewPrivs", "missing").strip()))
    enforce = Path("/sys/fs/selinux/enforce")
    checks.append(finding("SELinux enforcing", enforce.exists() and enforce.read_text().strip() == "1", "The audit requires an enforcing AlmaLinux guest; it does not install a policy."))
    for path in [Path("/etc/riverlb"), Path("/var/lib/riverlb"), Path("/run/riverlb")]:
        info = path.lstat()
        checks.append(finding("private " + str(path), stat.S_ISDIR(info.st_mode) and info.st_uid == pwd.getpwnam("riverlb").pw_uid and stat.S_IMODE(info.st_mode) == 0o700, f"uid={info.st_uid} mode={stat.S_IMODE(info.st_mode):04o}"))
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
