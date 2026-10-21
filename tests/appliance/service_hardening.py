"""Source policy regressions; no host services or SELinux state are changed."""
import copy
import importlib.util
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location("appliance_security", ROOT / "scripts/audit-appliance-security.py")
audit = importlib.util.module_from_spec(spec)
spec.loader.exec_module(audit)


def failures(values, ha=False):
    return {item["check"] for item in audit.check_service(values, ha) if item["result"] == "fail"}


def run():
    # Keep compatibility exceptions limited to systemd constructing the
    # password-file and HA policy-store sandboxes: no daemon access, additional
    # read/write permissions or general mount capability.
    policy = ROOT / "packaging/rpm/riverlb-sandbox.cil"
    rules = [line.strip() for line in policy.read_text().splitlines()
             if line.strip() and not line.lstrip().startswith(";")]
    assert rules == [
        "(allow init_t shadow_t (file (mounton)))",
        "(allow init_t semanage_store_t (dir (mounton)))",
    ]
    rpm = (ROOT / "packaging/rpm/riverlb.spec").read_text()
    assert 'semodule -i %{_datadir}/selinux/packages/riverlb-sandbox.cil || exit $?' in rpm
    assert 'semodule -r riverlb-sandbox' in rpm
    standalone = audit.parse_unit(ROOT / "packaging/rpm/riverlb.service")
    ha = audit.parse_unit(ROOT / "deploy/ha/riverlb-ha.service")
    assert not failures(standalone)
    assert not failures(ha, True)
    for field, bad, expected in [
        ("NoNewPrivileges", "false", "NoNewPrivileges"),
        ("CapabilityBoundingSet", "CAP_SYS_ADMIN CAP_NET_ADMIN", "bounded capabilities"),
        ("OpenFile", "", "read-only host network namespace"),
        ("OpenFile", "/proc/1/ns/net:riverlb-host-netns", "read-only host network namespace"),
        ("ReadWritePaths", "/", "writable path scope"),
        ("ReadWritePaths", "/etc/riverlb-updater", "publisher trust remains read-only"),
        ("InaccessiblePaths", "", "OS password hashes inaccessible"),
        ("ProtectSystem", "false", "ProtectSystem"),
        ("SystemCallFilter", "@system-service", "dangerous syscall groups blocked"),
        ("ExecStartPre", "/usr/bin/true", "preflight on every service start"),
    ]:
        altered = copy.deepcopy(standalone)
        altered[("Service", field)] = bad
        assert expected in failures(altered), (field, failures(altered))
    altered = copy.deepcopy(ha)
    altered[("Service", "OpenFile")] = ""
    assert "read-only host network namespace" in failures(altered, True)
    altered = copy.deepcopy(ha)
    altered[("Service", "RestrictAddressFamilies")] = "AF_INET AF_INET6 AF_UNIX AF_NETLINK"
    assert "socket families" in failures(altered, True), "HA gratuitous ARP requires AF_PACKET"
    for field, bad, expected in [
        ("BindPaths", "", "HA local IPC shared memory"),
        ("InaccessiblePaths", "-/etc/shadow -/etc/gshadow -/dev/shm", "HA local IPC shared memory"),
        ("NoExecPaths", "", "executable-memory bypasses blocked"),
        ("ExecPaths", "/dev/shm", "executable-memory bypasses blocked"),
    ]:
        altered = copy.deepcopy(ha)
        altered[("Service", field)] = bad
        assert expected in failures(altered, True), (field, failures(altered, True))
    altered = copy.deepcopy(standalone)
    altered[("Unit", "Requires")] = ""
    assert "interrupted-update recovery before traffic" in failures(altered)
    assert any(item["result"] == "warning" and "privilege separation" in item["detail"] for item in audit.check_service(standalone))
    print("PASS appliance service hardening: bounded capabilities, writable paths, syscall/socket restrictions, immutable publisher trust, HA ARP allowance and update recovery ordering")


if __name__ == "__main__":
    run()
