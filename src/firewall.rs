//! Destination-scoped firewalld permissions owned by the active generation.
use crate::{config::Config, network::Step};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::{IpAddr, SocketAddr},
    path::Path,
    process::Output,
};

const PROGRAM: &str = "/usr/bin/firewall-cmd";
const HOST_NETNS_NAME: &str = "riverlb-host-netns";
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize)]
pub struct Rule {
    pub zone: String,
    pub text: String,
}
pub type Rules = BTreeSet<Rule>;

#[derive(Debug, PartialEq, Eq)]
struct Target {
    address: SocketAddr,
    device: Option<String>,
    management: bool,
    udp: bool,
}
fn targets(config: &Config, network: &crate::network::Network) -> Vec<Target> {
    let mapped = |ip: IpAddr| {
        network
            .self_ips
            .iter()
            .find(|self_ip| {
                crate::network::cidr(&self_ip.address).is_ok_and(|(address, _)| address == ip)
            })
            .map(|self_ip| network.device(&self_ip.vlan).to_owned())
    };
    let usable =
        |address: SocketAddr| !address.ip().is_loopback() && !address.ip().is_unspecified();
    let mut targets = Vec::new();
    if usable(config.management) {
        targets.push(Target {
            address: config.management,
            device: mapped(config.management.ip()),
            management: true,
            udp: false,
        });
    }
    for server in config
        .virtual_servers
        .iter()
        .filter(|server| server.enabled && usable(server.listen))
    {
        let device = server
            .ingress_vlan
            .as_deref()
            .map(|vlan| network.device(vlan).to_owned())
            .or_else(|| mapped(server.listen.ip()));
        targets.push(Target {
            address: server.listen,
            device,
            management: false,
            udp: server.server_type.is_udp(),
        });
    }
    targets
}
fn interface_for_address(snapshot: &serde_json::Value, ip: IpAddr) -> Result<Option<String>> {
    let interfaces = snapshot
        .as_array()
        .context("Linux address inventory must be an array")?;
    ensure!(
        interfaces.len() <= 4096,
        "Linux interface inventory exceeds its limit"
    );
    let mut owners = BTreeSet::new();
    for interface in interfaces {
        let Some(name) = interface["ifname"].as_str() else {
            continue;
        };
        ensure!(
            !name.is_empty()
                && name.len() <= 15
                && !name.contains('/')
                && !name.chars().any(char::is_control)
                && ![".", ".."].contains(&name),
            "invalid Linux interface name"
        );
        for address in interface["addr_info"].as_array().into_iter().flatten() {
            if address["local"]
                .as_str()
                .is_some_and(|local| local.parse::<IpAddr>().is_ok_and(|address| address == ip))
            {
                owners.insert(name.to_owned());
            }
        }
    }
    ensure!(
        owners.len() <= 1,
        "address {ip} is assigned to multiple Linux interfaces; configure a specific VLAN binding"
    );
    Ok(owners.into_iter().next())
}

async fn run(program: &Path, args: &[String]) -> Result<Output> {
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new(program)
            .args(args)
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("firewall command exceeded five seconds")?
    .with_context(|| format!("run {}", program.display()))
}
async fn query(args: &[String]) -> Result<String> {
    let output = run(Path::new(PROGRAM), args).await?;
    ensure!(
        output.status.success(),
        "firewalld query failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8(output.stdout)?.trim().to_owned())
}
fn same_namespace(current: &Path, host: &Path) -> std::io::Result<bool> {
    use std::os::unix::fs::MetadataExt;
    let current = std::fs::metadata(current)?;
    let host = std::fs::metadata(host)?;
    Ok((current.dev(), current.ino()) == (host.dev(), host.ino()))
}
fn namespace_fd(
    process: u32,
    pid: Option<&str>,
    count: Option<&str>,
    names: Option<&str>,
) -> Result<Option<i32>> {
    // Ignore activation metadata inherited by subprocesses or a console shell.
    if pid.and_then(|pid| pid.parse::<u32>().ok()) != Some(process) {
        return Ok(None);
    }
    let count = count
        .context("missing systemd descriptor count")?
        .parse::<usize>()?;
    ensure!(count <= 64, "too many systemd descriptors");
    let names: Vec<_> = names
        .context("missing systemd descriptor names")?
        .split(':')
        .collect();
    ensure!(
        names.len() == count,
        "inconsistent systemd descriptor names"
    );
    let mut matches = names
        .iter()
        .enumerate()
        .filter(|(_, name)| **name == HOST_NETNS_NAME);
    let fd = matches.next().map(|(index, _)| 3 + index as i32);
    ensure!(
        matches.next().is_none(),
        "duplicate host network namespace descriptor"
    );
    Ok(fd)
}
fn host_network_namespace() -> Result<bool> {
    let pid = std::env::var("LISTEN_PID").ok();
    let count = std::env::var("LISTEN_FDS").ok();
    let names = std::env::var("LISTEN_FDNAMES").ok();
    let host = match namespace_fd(
        std::process::id(),
        pid.as_deref(),
        count.as_deref(),
        names.as_deref(),
    )? {
        Some(fd) => {
            // systemd opens this read-only before dropping capabilities. Keep
            // the namespace reference for later recovery checks, but do not
            // pass it to firewall-cmd, ip, pcs, or other exec'd children.
            let flags = unsafe { libc::fcntl(fd, libc::F_GETFD) };
            ensure!(flags >= 0, "invalid host network namespace descriptor");
            let result = unsafe { libc::fcntl(fd, libc::F_SETFD, flags | libc::FD_CLOEXEC) };
            ensure!(
                result >= 0,
                "cannot protect host network namespace descriptor"
            );
            std::path::PathBuf::from(format!("/proc/self/fd/{fd}"))
        }
        None => std::path::PathBuf::from("/proc/1/ns/net"),
    };
    Ok(same_namespace(Path::new("/proc/self/ns/net"), &host)?)
}
pub async fn active(managed: bool) -> Result<bool> {
    if !managed || !Path::new(PROGRAM).exists() {
        return Ok(false);
    }
    // firewalld's system D-Bus service controls PID 1's namespace. Never let a
    // disposable namespace's root/CAP_NET_ADMIN modify the host's firewall.
    match host_network_namespace() {
        Ok(true) => {}
        Ok(false) => return Ok(false),
        Err(error) => {
            tracing::warn!(%error, "automatic firewall provisioning disabled: cannot verify host network namespace; use the packaged systemd service");
            return Ok(false);
        }
    }
    let output = run(Path::new(PROGRAM), &["--get-default-zone".into()]).await?;
    if output.status.success() {
        return Ok(true);
    }
    ensure!(
        output.status.code() == Some(252)
            || String::from_utf8_lossy(&output.stderr).contains("not running"),
        "cannot determine firewalld state: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(false)
}
#[cfg(test)]
pub fn text(ip: std::net::IpAddr, port: u16) -> String {
    protocol_text(ip, port, false)
}
fn protocol_text(ip: std::net::IpAddr, port: u16, udp: bool) -> String {
    let protocol = if udp { "udp" } else { "tcp" };
    format!(
        "rule family=\"{}\" priority=\"18600\" destination address=\"{ip}\" port port=\"{port}\" protocol=\"{protocol}\" accept",
        if ip.is_ipv4() { "ipv4" } else { "ipv6" }
    )
}
fn interface_zone(output: Output, default: &str) -> Result<String> {
    let value = String::from_utf8(output.stdout)?.trim().to_owned();
    let error = String::from_utf8_lossy(&output.stderr);
    // firewalld versions report an unassigned interface on either stream.
    let unassigned = output.status.code() == Some(2)
        && ((value == "no zone" && error.trim().is_empty())
            || (value.is_empty() && error.trim() == "no zone"));
    ensure!(
        output.status.success() || unassigned,
        "firewalld interface zone query failed: {}",
        error.trim()
    );
    Ok(if unassigned || value.is_empty() || value == "no zone" {
        default.to_owned()
    } else {
        value
    })
}
pub async fn desired(config: &Config, enabled: bool) -> Result<Rules> {
    if !enabled {
        return Ok(Rules::new());
    }
    let network = crate::network::provisioned(config)?;
    let targets = targets(config, &network);
    if targets.is_empty() {
        return Ok(Rules::new());
    }
    let inventory = if targets.iter().any(|target| target.device.is_none()) {
        let output = run(
            Path::new("/usr/sbin/ip"),
            &["-j".into(), "address".into(), "show".into()],
        )
        .await?;
        ensure!(
            output.status.success(),
            "Linux management interface query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        ensure!(
            output.stdout.len() <= 2 * 1024 * 1024,
            "Linux address inventory exceeds 2 MiB"
        );
        serde_json::from_slice(&output.stdout)?
    } else {
        serde_json::json!([])
    };
    let default = query(&["--get-default-zone".into()]).await?;
    let mut rules = Rules::new();
    let mut zones = BTreeMap::<String, String>::new();
    for target in targets {
        let ip = target.address.ip();
        let device = match target.device {
            Some(device) => Some(device),
            None => interface_for_address(&inventory, ip)?,
        };
        ensure!(
            !target.management || device.is_some(),
            "management address {ip} is not assigned to a Linux interface"
        );
        let zone = if let Some(device) = device {
            let device = device.as_str();
            let value = if let Some(zone) = zones.get(device) {
                zone.clone()
            } else if Path::new("/sys/class/net").join(device).exists() {
                let output = run(
                    Path::new(PROGRAM),
                    &[format!("--get-zone-of-interface={device}")],
                )
                .await?;
                let zone = interface_zone(output, &default)?;
                zones.insert(device.to_owned(), zone.clone());
                zone
            } else {
                String::new()
            };
            if value.is_empty() || value == "no zone" {
                default.clone()
            } else {
                value
            }
        } else {
            default.clone()
        };
        rules.insert(Rule {
            zone,
            text: protocol_text(ip, target.address.port(), target.udp),
        });
    }
    Ok(rules)
}
fn command(rule: &Rule, add: bool, permanent: bool) -> Vec<String> {
    let mut args = vec!["firewall-cmd".into(), format!("--zone={}", rule.zone)];
    if permanent {
        args.push("--permanent".into());
    }
    args.push(format!(
        "--{}-rich-rule={}",
        if add { "add" } else { "remove" },
        rule.text
    ));
    args
}
pub fn plan(old: &Rules, new: &Rules) -> Vec<Step> {
    let mut steps = Vec::new();
    // Never remove broad service/port openings or administrator-authored rules.
    for rule in old.difference(new) {
        for permanent in [false, true] {
            steps.push(Step {
                command: command(rule, false, permanent),
                undo: vec![command(rule, true, permanent)],
            });
        }
    }
    for rule in new.difference(old) {
        for permanent in [true, false] {
            steps.push(Step {
                command: command(rule, true, permanent),
                undo: vec![command(rule, false, permanent)],
            });
        }
    }
    steps
}
pub async fn execute(args: &[String]) -> Result<bool> {
    execute_at(Path::new(PROGRAM), args).await
}
async fn execute_at(program: &Path, args: &[String]) -> Result<bool> {
    let action = args
        .iter()
        .find(|a| a.starts_with("--add-rich-rule=") || a.starts_with("--remove-rich-rule="))
        .ok_or_else(|| anyhow::anyhow!("invalid managed firewall action"))?;
    let add = action.starts_with("--add");
    let (_, text) = action.split_once('=').unwrap();
    let mut probe = args
        .iter()
        .filter(|a| *a != action)
        .cloned()
        .collect::<Vec<_>>();
    probe.push(format!("--query-rich-rule={text}"));
    let existing = run(program, &probe).await?;
    ensure!(
        matches!(existing.status.code(), Some(0 | 1)),
        "firewalld denied rule inspection: {}. Start RiverLB with root/firewalld authorization",
        String::from_utf8_lossy(&existing.stderr).trim()
    );
    // Exact rich-rule queries include zone, destination, TCP port, family,
    // priority and runtime/permanent scope. Reuse matches without recording
    // an inverse operation that could remove them during startup rollback.
    if (add && existing.status.code() == Some(0)) || (!add && existing.status.code() == Some(1)) {
        return Ok(false);
    }
    let output = run(program, args).await?;
    ensure!(
        output.status.success(),
        "firewalld {} failed: {}. Start RiverLB with root/firewalld authorization",
        if add { "allow" } else { "cleanup" },
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(true)
}
#[cfg(test)]
mod tests {
    #[test]
    fn pinned_namespace_works_without_pid_one_access() {
        let directory = tempfile::tempdir().unwrap();
        let unavailable = directory.path().join("unavailable");
        let current = Path::new("/proc/self/ns/net");
        let reference = std::fs::File::open(current).unwrap();
        use std::os::fd::AsRawFd;
        let pinned = std::path::PathBuf::from(format!("/proc/self/fd/{}", reference.as_raw_fd()));
        assert!(same_namespace(current, &pinned).unwrap());
        assert!(same_namespace(current, &unavailable).is_err());
        let mount_namespace = Path::new("/proc/self/ns/mnt");
        assert!(!same_namespace(current, mount_namespace).unwrap());
    }

    #[test]
    fn systemd_namespace_descriptor_requires_matching_process_and_unique_name() {
        assert_eq!(
            namespace_fd(7, Some("7"), Some("1"), Some(HOST_NETNS_NAME)).unwrap(),
            Some(3)
        );
        assert_eq!(
            namespace_fd(7, Some("7"), Some("2"), Some("other:riverlb-host-netns")).unwrap(),
            Some(4)
        );
        assert_eq!(
            namespace_fd(7, Some("8"), Some("1"), Some(HOST_NETNS_NAME)).unwrap(),
            None
        );
        assert_eq!(namespace_fd(7, None, None, None).unwrap(), None);
        assert_eq!(
            namespace_fd(7, Some("7"), Some("1"), Some("other")).unwrap(),
            None
        );
        for (count, names) in [
            ("2", HOST_NETNS_NAME),
            ("65", HOST_NETNS_NAME),
            ("2", "riverlb-host-netns:riverlb-host-netns"),
        ] {
            assert!(namespace_fd(7, Some("7"), Some(count), Some(names)).is_err());
        }
    }

    #[test]
    fn udp_permissions_are_distinct_from_tcp_and_management() {
        let ip = "192.0.2.10".parse().unwrap();
        assert!(protocol_text(ip, 53, true).contains("protocol=\"udp\""));
        assert!(protocol_text(ip, 53, false).contains("protocol=\"tcp\""));
        let mut config = Config::load(Path::new("examples/riverlb.toml")).unwrap();
        config.management = "192.0.2.10:18090".parse().unwrap();
        config.virtual_servers[0].listen = "192.0.2.10:53".parse().unwrap();
        config.virtual_servers[0].server_type = crate::config::VirtualServerType::Udp;
        let selected = targets(&config, &config.network);
        assert!(!selected[0].udp);
        assert!(selected[1].udp);
    }

    use super::*;
    #[test]
    fn management_listener_and_only_enabled_explicit_traffic_are_targets() {
        let mut config = Config::load(Path::new("examples/riverlb.toml")).unwrap();
        config.management = "192.0.2.10:18443".parse().unwrap();
        config.virtual_servers[0].enabled = false;
        let selected = targets(&config, &config.network);
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].address, config.management);
        assert!(selected[0].management);
        assert!(
            text(selected[0].address.ip(), selected[0].address.port()).contains("port=\"18443\"")
        );
        config.virtual_servers[0].enabled = true;
        config.virtual_servers[0].listen = "192.0.2.20:443".parse().unwrap();
        assert_eq!(targets(&config, &config.network).len(), 2);
        config.virtual_servers[0].listen = "0.0.0.0:443".parse().unwrap();
        assert_eq!(targets(&config, &config.network).len(), 1);
        config.management = "127.0.0.1:18090".parse().unwrap();
        assert!(targets(&config, &config.network).is_empty());
    }
    #[test]
    fn configured_management_self_ip_uses_its_vlan_device() {
        let mut config = Config::load(Path::new("examples/riverlb.toml")).unwrap();
        config.management = "192.0.2.10:18443".parse().unwrap();
        config.virtual_servers[0].enabled = false;
        config.network = crate::network::Network {
            vlans: vec![crate::network::Vlan {
                name: "management".into(),
                interface: "eth1".into(),
                tag: None,
                role: Default::default(),
                ipv4_gateway: None,
                ipv6_gateway: None,
            }],
            self_ips: vec![crate::network::SelfIp {
                name: "device".into(),
                address: "192.0.2.10/24".into(),
                vlan: "management".into(),
            }],
            routes: Vec::new(),
        };
        assert_eq!(
            targets(&config, &config.network)[0].device.as_deref(),
            Some("eth1")
        );
        config.network.vlans[0].tag = Some(11);
        assert_eq!(
            targets(&config, &config.network)[0].device.as_deref(),
            Some("management")
        );
    }
    #[test]
    fn linux_interface_inventory_matches_exact_ipv4_ipv6_and_rejects_ambiguity() {
        let inventory = serde_json::json!([
            {"ifname":"lo","addr_info":[{"local":"127.0.0.1","prefixlen":8}]},
            {"ifname":"eth0","addr_info":[{"family":"inet","local":"192.0.2.10","prefixlen":24,"dynamic":true},{"family":"inet6","local":"2001:db8::10","prefixlen":64}]},
            {"ifname":"eth1","addr_info":[{"local":"192.0.2.11","prefixlen":24}]}
        ]);
        assert_eq!(
            interface_for_address(&inventory, "192.0.2.10".parse().unwrap())
                .unwrap()
                .as_deref(),
            Some("eth0")
        );
        assert_eq!(
            interface_for_address(&inventory, "2001:db8::10".parse().unwrap())
                .unwrap()
                .as_deref(),
            Some("eth0")
        );
        assert_eq!(
            interface_for_address(&inventory, "192.0.2.99".parse().unwrap()).unwrap(),
            None
        );
        let duplicate = serde_json::json!([{"ifname":"eth0","addr_info":[{"local":"192.0.2.10"}]},{"ifname":"eth1","addr_info":[{"local":"192.0.2.10"}]}]);
        assert!(interface_for_address(&duplicate, "192.0.2.10".parse().unwrap()).is_err());
        assert!(
            interface_for_address(&serde_json::json!({}), "192.0.2.10".parse().unwrap()).is_err()
        );
        assert!(
            interface_for_address(
                &serde_json::json!([{"ifname":"../bad"}]),
                "192.0.2.10".parse().unwrap()
            )
            .is_err()
        );
    }
    #[test]
    fn firewall_delta_is_scoped_owned_and_reversible() {
        let old = Rules::from([Rule {
            zone: "public".into(),
            text: text("192.0.2.10".parse().unwrap(), 8080),
        }]);
        let new = Rules::from([Rule {
            zone: "public".into(),
            text: text("2001:db8::10".parse().unwrap(), 443),
        }]);
        let steps = plan(&old, &new);
        assert_eq!(steps.len(), 4);
        assert!(
            steps[0]
                .command
                .last()
                .unwrap()
                .starts_with("--remove-rich-rule=")
        );
        assert!(steps[2].command.contains(&"--permanent".into()));
        assert!(steps[2].command.last().unwrap().contains("family=\"ipv6\""));
        assert!(
            steps
                .iter()
                .all(|s| s.command.last().unwrap().contains("priority=\"18600\""))
        );
        assert!(plan(&old, &old).is_empty());
        assert_eq!(
            plan(&new, &old)
                .iter()
                .map(|s| s.command.clone())
                .collect::<BTreeSet<_>>(),
            steps.iter().flat_map(|s| s.undo.clone()).collect()
        );
    }
    #[test]
    fn unassigned_interface_uses_default_zone_on_either_output_stream() {
        use std::os::unix::process::ExitStatusExt;
        let output = |code, stdout: &str, stderr: &str| Output {
            status: std::process::ExitStatus::from_raw(code << 8),
            stdout: stdout.as_bytes().to_vec(),
            stderr: stderr.as_bytes().to_vec(),
        };
        assert_eq!(
            interface_zone(output(2, "", "no zone\n"), "public").unwrap(),
            "public"
        );
        assert_eq!(
            interface_zone(output(2, "no zone\n", ""), "public").unwrap(),
            "public"
        );
        assert_eq!(
            interface_zone(output(0, "internal\n", ""), "public").unwrap(),
            "internal"
        );
        assert!(interface_zone(output(2, "", "Authorization failed"), "public").is_err());
        assert!(interface_zone(output(104, "", "INVALID_INTERFACE"), "public").is_err());
    }
    #[tokio::test]
    async fn existing_rules_are_reused_and_missing_cleanup_is_safe() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("firewall-cmd");
        std::fs::write(&helper,"#!/bin/sh\nfor arg do\ncase \"$arg\" in --query-rich-rule=*) exit 0;; esac\ndone\nexit 99\n").unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
        let rule = Rule {
            zone: "public".into(),
            text: text("192.0.2.10".parse().unwrap(), 80),
        };
        for permanent in [false, true] {
            assert!(
                !execute_at(&helper, &command(&rule, true, permanent)[1..])
                    .await
                    .unwrap()
            );
        }
        std::fs::write(&helper,"#!/bin/sh\nfor arg do\ncase \"$arg\" in --query-rich-rule=*) exit 1;; esac\ndone\nexit 99\n").unwrap();
        execute_at(&helper, &command(&rule, false, false)[1..])
            .await
            .unwrap();
        assert!(
            execute_at(&helper, &command(&rule, true, false)[1..])
                .await
                .unwrap_err()
                .to_string()
                .contains("allow failed")
        );
    }
    #[tokio::test]
    async fn rule_lifecycle_and_partial_failure_preserve_manual_rules() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let helper = dir.path().join("firewall-cmd");
        let state = dir.path().join("state.json");
        let fail = dir.path().join("fail");
        std::fs::write(
            &state,
            r#"{"runtime":["manual-rule"],"permanent":["manual-rule"]}"#,
        )
        .unwrap();
        std::fs::write(
            &helper,
            format!(
                r#"#!/usr/bin/python3
import json, pathlib, sys
state = pathlib.Path({state:?})
fail = pathlib.Path({fail:?})
data = json.loads(state.read_text())
key = 'permanent' if '--permanent' in sys.argv else 'runtime'
action = next(a for a in sys.argv if '-rich-rule=' in a)
op, rule = action.split('=', 1)
if op == '--query-rich-rule': sys.exit(0 if rule in data[key] else 1)
if op == '--add-rich-rule':
    if key == 'runtime' and fail.exists(): sys.exit(13)
    data[key].append(rule)
else: data[key].remove(rule)
state.write_text(json.dumps(data))
"#,
                state = state.to_str().unwrap(),
                fail = fail.to_str().unwrap()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&helper, std::fs::Permissions::from_mode(0o700)).unwrap();
        let desired = Rules::from([Rule {
            zone: "public".into(),
            text: text("192.0.2.10".parse().unwrap(), 8080),
        }]);
        let steps = plan(&Rules::new(), &desired);
        std::fs::write(&fail, "fail runtime addition").unwrap();
        execute_at(&helper, &steps[0].command[1..]).await.unwrap();
        assert!(execute_at(&helper, &steps[1].command[1..]).await.is_err());
        execute_at(&helper, &steps[0].undo[0][1..]).await.unwrap();
        let restored: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
        assert_eq!(
            restored,
            serde_json::json!({"runtime":["manual-rule"],"permanent":["manual-rule"]})
        );
        std::fs::remove_file(&fail).unwrap();
        for step in &steps {
            execute_at(&helper, &step.command[1..]).await.unwrap();
        }
        let installed: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
        assert_eq!(installed["runtime"].as_array().unwrap().len(), 2);
        assert_eq!(installed["permanent"].as_array().unwrap().len(), 2);
        // Repeated startup must leave both scopes unchanged and provide no
        // mutations to roll back if a later startup operation fails.
        for step in &steps {
            assert!(!execute_at(&helper, &step.command[1..]).await.unwrap());
        }
        assert_eq!(
            serde_json::from_slice::<serde_json::Value>(&std::fs::read(&state).unwrap()).unwrap(),
            installed
        );
        // With only permanent state left, repair runtime state. A subsequent
        // rollback removes only the repaired runtime rule.
        execute_at(&helper, &steps[1].undo[0][1..]).await.unwrap();
        let mut applied = Vec::new();
        for step in &steps {
            if execute_at(&helper, &step.command[1..]).await.unwrap() {
                applied.push(step);
            }
        }
        assert_eq!(applied.len(), 1);
        for step in applied.iter().rev() {
            execute_at(&helper, &step.undo[0][1..]).await.unwrap();
        }
        let partial: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
        assert_eq!(partial["runtime"], restored["runtime"]);
        assert_eq!(partial["permanent"], installed["permanent"]);
        for step in plan(&desired, &Rules::new()) {
            execute_at(&helper, &step.command[1..]).await.unwrap();
        }
        let cleaned: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&state).unwrap()).unwrap();
        assert_eq!(cleaned, restored);
    }
}
