//! Linux network objects, deterministic change plans and compensating rollback.
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr};

#[derive(Clone, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Network {
    #[serde(default)]
    pub vlans: Vec<Vlan>,
    #[serde(default)]
    pub self_ips: Vec<SelfIp>,
    #[serde(default)]
    pub routes: Vec<Route>,
}

pub async fn interface_addresses() -> Result<Vec<serde_json::Value>> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new("/usr/sbin/ip")
            .args(["-j", "address", "show"])
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    ensure!(
        output.status.success(),
        "Cannot inspect interface addresses"
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Vlan {
    pub name: String,
    pub interface: String,
    pub tag: Option<u16>,
    #[serde(default, skip_serializing_if = "Role::is_unspecified")]
    pub role: Role,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv4_gateway: Option<IpAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ipv6_gateway: Option<IpAddr>,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    #[default]
    Unspecified,
    External,
    Internal,
}
impl Role {
    fn is_unspecified(&self) -> bool {
        *self == Self::Unspecified
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SelfIp {
    pub name: String,
    pub address: String,
    pub vlan: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Route {
    pub name: String,
    pub destination: String,
    pub gateway: IpAddr,
    pub vlan: String,
    pub metric: u32,
}

pub fn cidr(text: &str) -> Result<(IpAddr, u8)> {
    let (ip, prefix) = text
        .split_once('/')
        .ok_or_else(|| anyhow::anyhow!("address requires CIDR prefix"))?;
    let ip: IpAddr = ip.parse()?;
    let prefix: u8 = prefix.parse()?;
    ensure!(
        prefix <= if ip.is_ipv4() { 32 } else { 128 },
        "invalid CIDR prefix"
    );
    ensure!(
        text == format!("{ip}/{prefix}"),
        "use canonical CIDR notation: {ip}/{prefix}"
    );
    Ok((ip, prefix))
}
fn interface(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 15
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
        && !value.starts_with('-')
        && value != "."
        && value != ".."
}
impl Network {
    pub fn is_empty(&self) -> bool {
        self.vlans.is_empty() && self.self_ips.is_empty() && self.routes.is_empty()
    }
    pub fn device(&self, vlan: &str) -> &str {
        let vlan = self
            .vlans
            .iter()
            .find(|v| v.name == vlan)
            .expect("validated VLAN reference");
        if vlan.tag.is_some() {
            &vlan.name
        } else {
            &vlan.interface
        }
    }
    pub fn validate(&self) -> Result<()> {
        let mut names = HashSet::new();
        let mut devices = HashSet::new();
        let mut tags = HashSet::new();
        let mut tables = HashSet::new();
        for vlan in &self.vlans {
            ensure!(
                tables.insert(policy_table(&vlan.name)),
                "VLAN routing table identifier collision; rename one VLAN"
            );
            for (gateway, ipv4) in [(vlan.ipv4_gateway, true), (vlan.ipv6_gateway, false)] {
                if let Some(gateway) = gateway {
                    ensure!(
                        gateway.is_ipv4() == ipv4
                            && !gateway.is_unspecified()
                            && !gateway.is_multicast()
                            && !gateway.is_loopback(),
                        "VLAN return gateway must be a unicast address in its IP family"
                    );
                }
            }
            ensure!(
                interface(&vlan.name) && interface(&vlan.interface),
                "VLAN name/interface must use 1–15 safe interface characters"
            );
            ensure!(names.insert(&vlan.name), "duplicate VLAN name");
            if let Some(tag) = vlan.tag {
                ensure!((1..=4094).contains(&tag), "VLAN tag must be 1–4094");
                ensure!(
                    vlan.name != vlan.interface && vlan.name != "lo",
                    "tagged VLAN needs a distinct device name"
                );
                ensure!(
                    tags.insert((&vlan.interface, tag)),
                    "duplicate VLAN tag on parent interface"
                );
            }
            ensure!(
                devices.insert(self.device(&vlan.name)),
                "VLANs cannot share a Linux device"
            );
        }
        for vlan in &self.vlans {
            ensure!(
                !self
                    .vlans
                    .iter()
                    .any(|v| v.tag.is_some() && v.name == vlan.interface),
                "nested VLAN parents are not supported"
            );
        }
        let mut ips = HashSet::new();
        names.clear();
        for ip in &self.self_ips {
            ensure!(
                !ip.name.trim().is_empty() && names.insert(&ip.name),
                "self IP names must be nonempty and unique"
            );
            ensure!(
                self.vlans.iter().any(|v| v.name == ip.vlan),
                "unknown VLAN for self IP {}",
                ip.name
            );
            let (address, _) = cidr(&ip.address)?;
            ensure!(
                !self
                    .vlans
                    .iter()
                    .any(|v| v.ipv4_gateway == Some(address) || v.ipv6_gateway == Some(address)),
                "return gateway cannot be a local self IP or VIP"
            );
            ensure!(
                !address.is_unspecified() && !address.is_multicast() && !address.is_loopback(),
                "self IP must be a unicast data-plane address"
            );
            ensure!(ips.insert(address), "duplicate self IP address");
        }
        names.clear();
        let mut routes = HashSet::new();
        for route in &self.routes {
            ensure!(
                !route.name.trim().is_empty() && names.insert(&route.name),
                "route names must be nonempty and unique"
            );
            ensure!(
                self.vlans.iter().any(|v| v.name == route.vlan),
                "unknown VLAN for route {}",
                route.name
            );
            let (destination, prefix) = cidr(&route.destination)?;
            ensure!(
                destination.is_ipv4() == route.gateway.is_ipv4()
                    && !route.gateway.is_unspecified()
                    && !route.gateway.is_multicast(),
                "route gateway must be a unicast address in the destination family"
            );
            let host_bits = if destination.is_ipv4() { 32 } else { 128 } - u32::from(prefix);
            let number = match destination {
                IpAddr::V4(ip) => u128::from(u32::from(ip)),
                IpAddr::V6(ip) => u128::from(ip),
            };
            let mask = if host_bits == 128 {
                u128::MAX
            } else {
                (1u128 << host_bits) - 1
            };
            ensure!(
                number & mask == 0,
                "route destination must be a network address"
            );
            ensure!(
                routes.insert((&route.destination, route.metric)),
                "duplicate destination/metric route"
            );
        }
        Ok(())
    }
}

/// Linux addresses required by configured objects, including enabled virtual IPs.
/// VIPs use host prefixes so they do not introduce a second connected subnet route.
pub fn provisioned(config: &crate::config::Config) -> Result<Network> {
    let mut network = config.network.clone();
    for server in config.virtual_servers.iter().filter(|v| v.enabled) {
        let ip = server.listen.ip();
        if ip.is_unspecified() || ip.is_loopback() || ip.is_multicast() {
            continue;
        }
        let existing = config
            .network
            .self_ips
            .iter()
            .find(|s| cidr(&s.address).is_ok_and(|(address, _)| address == ip));
        if let Some(existing) = existing {
            ensure!(
                server
                    .ingress_vlan
                    .as_ref()
                    .is_none_or(|v| v == &existing.vlan),
                "VIP {ip} is a self IP on VLAN {}; select that ingress VLAN",
                existing.vlan
            );
            continue;
        }
        let vlan = if let Some(vlan) = &server.ingress_vlan {
            Some(vlan.clone())
        } else {
            let mut candidates = HashSet::new();
            for self_ip in &config.network.self_ips {
                let (address, prefix) = cidr(&self_ip.address)?;
                if same_subnet(ip, address, prefix) {
                    candidates.insert(self_ip.vlan.clone());
                }
            }
            ensure!(
                candidates.len() <= 1,
                "VIP {ip} matches multiple VLANs; select an ingress VLAN on virtual server {}",
                server.name
            );
            candidates.into_iter().next()
        };
        let Some(vlan) = vlan else { continue };
        if let Some(previous) = network
            .self_ips
            .iter()
            .find(|s| cidr(&s.address).is_ok_and(|(address, _)| address == ip))
        {
            ensure!(
                previous.vlan == vlan,
                "VIP {ip} cannot belong to multiple ingress VLANs"
            );
            continue;
        }
        let base = format!("RiverLB VIP {ip}");
        let mut name = base.clone();
        let mut suffix = 2;
        while network.self_ips.iter().any(|s| s.name == name) {
            name = format!("{base} ({suffix})");
            suffix += 1;
        }
        network.self_ips.push(SelfIp {
            name,
            address: format!("{ip}/{}", if ip.is_ipv4() { 32 } else { 128 }),
            vlan,
        });
    }
    network.validate()?;
    Ok(network)
}
fn same_subnet(a: IpAddr, b: IpAddr, prefix: u8) -> bool {
    match (a, b) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            prefix == 0 || u32::from(a) >> (32 - prefix) == u32::from(b) >> (32 - prefix)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            prefix == 0 || u128::from(a) >> (128 - prefix) == u128::from(b) >> (128 - prefix)
        }
        _ => false,
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Step {
    pub command: Vec<String>,
    pub undo: Vec<Vec<String>>,
}
fn args(parts: &[&str]) -> Vec<String> {
    parts.iter().map(|v| v.to_string()).collect()
}
fn vlan_add(v: &Vlan) -> Vec<String> {
    args(&[
        "link",
        "add",
        "link",
        &v.interface,
        "name",
        &v.name,
        "type",
        "vlan",
        "id",
        &v.tag.unwrap().to_string(),
    ])
}
fn address(n: &Network, ip: &SelfIp, action: &str) -> Vec<String> {
    args(&["address", action, &ip.address, "dev", n.device(&ip.vlan)])
}
fn route(n: &Network, r: &Route, action: &str) -> Vec<String> {
    args(&[
        if r.gateway.is_ipv4() { "-4" } else { "-6" },
        "route",
        action,
        &r.destination,
        "via",
        &r.gateway.to_string(),
        "dev",
        n.device(&r.vlan),
        "metric",
        &r.metric.to_string(),
        "proto",
        "186",
    ])
}
fn changed_vlan(old: &Network, new: &Network, name: &str) -> bool {
    let link = |n: &Network| {
        n.vlans
            .iter()
            .find(|v| v.name == name)
            .map(|v| (v.interface.clone(), v.tag))
    };
    link(old) != link(new)
}
/// Bind the socket in the kernel so ingress and egress cannot cross devices.
pub fn bind_device(socket: &impl std::os::fd::AsRawFd, device: &str) -> std::io::Result<()> {
    let name = std::ffi::CString::new(device).map_err(|_| {
        std::io::Error::new(std::io::ErrorKind::InvalidInput, "invalid device name")
    })?;
    // SAFETY: the live socket owns the fd; name is NUL-terminated and remains
    // alive throughout setsockopt. The length includes the terminating NUL.
    let result = unsafe {
        libc::setsockopt(
            socket.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_BINDTODEVICE,
            name.as_ptr().cast(),
            name.as_bytes_with_nul().len() as libc::socklen_t,
        )
    };
    if result != 0 {
        return Err(std::io::Error::new(
            std::io::Error::last_os_error().kind(),
            format!(
                "bind socket to device {device}: {}",
                std::io::Error::last_os_error()
            ),
        ));
    }
    Ok(())
}
pub async fn listener(
    network: &Network,
    server: &crate::config::VirtualServer,
) -> std::io::Result<tokio::net::TcpListener> {
    let Some(vlan) = &server.ingress_vlan else {
        return tokio::net::TcpListener::bind(server.listen)
            .await
            .map_err(|e| listener_error(e, server));
    };
    let socket = if server.listen.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.set_reuseaddr(true)?;
    bind_device(&socket, network.device(vlan))?;
    socket
        .bind(server.listen)
        .map_err(|e| listener_error(e, server))?;
    socket.listen(1024)
}
/// UDP VIPs bind a specific address so every reply retains the requested VIP.
pub async fn udp_listener(
    network: &Network,
    server: &crate::config::VirtualServer,
) -> std::io::Result<tokio::net::UdpSocket> {
    let socket = std::net::UdpSocket::bind(server.listen).map_err(|e| listener_error(e, server))?;
    socket.set_nonblocking(true)?;
    if let Some(vlan) = &server.ingress_vlan {
        bind_device(&socket, network.device(vlan))?;
    }
    tokio::net::UdpSocket::from_std(socket)
}
/// Check device existence and socket binding permissions before activating a generation.
fn listener_error(error: std::io::Error, server: &crate::config::VirtualServer) -> std::io::Error {
    if error.raw_os_error() == Some(libc::EADDRNOTAVAIL) {
        std::io::Error::new(
            error.kind(),
            format!(
                "VIP {} is not assigned to Linux: {error}. Select its ingress VLAN and run in managed network mode to provision it automatically; with --external-network, assign it externally before applying",
                server.listen.ip()
            ),
        )
    } else {
        error
    }
}
pub fn validate_runtime_devices(config: &crate::config::Config) -> std::io::Result<()> {
    let mut seen = HashSet::new();
    for server in config.virtual_servers.iter().filter(|v| v.enabled) {
        for vlan in [&server.ingress_vlan, &server.backend_vlan]
            .into_iter()
            .flatten()
        {
            let device = config.network.device(vlan);
            if seen.insert(device) {
                let socket = tokio::net::TcpSocket::new_v4()?;
                bind_device(&socket, device)?;
            }
        }
    }
    Ok(())
}
// Stable private table IDs leave the host's main/default/local tables untouched.
// Collisions within a configuration are rejected before any mutation.
fn policy_table(name: &str) -> u32 {
    let hash = name.bytes().fold(2_166_136_261u32, |h, b| {
        (h ^ u32::from(b)).wrapping_mul(16_777_619)
    });
    1_000_000 + (hash & 0x00ff_ffff)
}
fn subnet(address: IpAddr, prefix: u8) -> String {
    let address = match address {
        IpAddr::V4(ip) => IpAddr::V4(
            (u32::from(ip)
                & if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                })
            .into(),
        ),
        IpAddr::V6(ip) => IpAddr::V6(
            (u128::from(ip)
                & if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                })
            .into(),
        ),
    };
    format!("{address}/{prefix}")
}
#[derive(Default)]
struct Policies {
    routes: std::collections::BTreeSet<Vec<String>>,
    rules: std::collections::BTreeSet<Vec<String>>,
}
fn policies(network: &Network) -> Result<Policies> {
    let mut result = Policies::default();
    for vlan in &network.vlans {
        let table = policy_table(&vlan.name).to_string();
        let device = network.device(&vlan.name);
        for ipv4 in [true, false] {
            let family = if ipv4 { "-4" } else { "-6" };
            let addresses = network
                .self_ips
                .iter()
                .filter(|s| s.vlan == vlan.name)
                .map(|s| cidr(&s.address))
                .collect::<Result<Vec<_>>>()?
                .into_iter()
                .filter(|(ip, _)| ip.is_ipv4() == ipv4)
                .collect::<Vec<_>>();
            if addresses.is_empty() {
                continue;
            }
            for (ip, prefix) in &addresses {
                let destination = subnet(*ip, *prefix);
                result.routes.insert(args(&[
                    family,
                    "route",
                    "add",
                    "table",
                    &table,
                    &destination,
                    "dev",
                    device,
                    "scope",
                    "link",
                    "proto",
                    "186",
                ]));
                let source = format!("{ip}/{}", if ipv4 { 32 } else { 128 });
                result.rules.insert(args(&[
                    family, "rule", "add", "from", &source, "lookup", &table, "priority", "18600",
                    "protocol", "186",
                ]));
            }
            let gateway = if ipv4 {
                vlan.ipv4_gateway
            } else {
                vlan.ipv6_gateway
            };
            for route in network
                .routes
                .iter()
                .filter(|r| r.vlan == vlan.name && r.gateway.is_ipv4() == ipv4)
            {
                let (_, prefix) = cidr(&route.destination)?;
                if prefix == 0 && gateway.is_some() {
                    continue;
                }
                ensure!(
                    prefix != 0 || route.metric < u32::MAX,
                    "default route metric 4294967295 is reserved for the return-routing guard"
                );
                let mut command = self::route(network, route, "add");
                command.extend(args(&["table", &table, "onlink"]));
                result.routes.insert(command);
            }
            if let Some(gateway) = gateway {
                result.routes.insert(args(&[
                    family,
                    "route",
                    "add",
                    "table",
                    &table,
                    "default",
                    "via",
                    &gateway.to_string(),
                    "dev",
                    device,
                    "onlink",
                    "metric",
                    "0",
                    "proto",
                    "186",
                ]));
            }
            // A missing route must fail here rather than fall through to another
            // interface's connected route or to the host's default gateway.
            result.routes.insert(args(&[
                family,
                "route",
                "add",
                "table",
                &table,
                "unreachable",
                "default",
                "metric",
                "4294967295",
                "proto",
                "186",
            ]));
        }
    }
    Ok(result)
}
fn policy_step(command: &[String], add: bool) -> Step {
    let mut command = command.to_vec();
    command[2] = if add { "add" } else { "del" }.into();
    let mut undo = command.clone();
    undo[2] = if add { "del" } else { "add" }.into();
    Step {
        command,
        undo: vec![undo],
    }
}
fn policy_device_changed(command: &[String], old: &Network, new: &Network) -> bool {
    old.vlans.iter().chain(&new.vlans).any(|v| {
        (changed_vlan(old, new, &v.name)
            || old
                .self_ips
                .iter()
                .any(|ip| ip.vlan == v.name && !new.self_ips.contains(ip)))
            && command.windows(2).any(|pair| {
                matches!(pair[0].as_str(), "table" | "lookup")
                    && pair[1] == policy_table(&v.name).to_string()
            })
    })
}
pub fn plan(old: &Network, new: &Network) -> Result<Vec<Step>> {
    old.validate()?;
    new.validate()?;
    let before = policies(old)?;
    let after = policies(new)?;
    let mut steps = Vec::new();
    for rule in before
        .rules
        .iter()
        .filter(|r| !after.rules.contains(*r) || policy_device_changed(r, old, new))
    {
        steps.push(policy_step(rule, false));
    }
    for route in before
        .routes
        .iter()
        .filter(|r| !after.routes.contains(*r) || policy_device_changed(r, old, new))
    {
        steps.push(policy_step(route, false));
    }
    for r in &old.routes {
        if !new.routes.contains(r) || changed_vlan(old, new, &r.vlan) {
            steps.push(Step {
                command: route(old, r, "del"),
                undo: vec![route(old, r, "add")],
            });
        }
    }
    for ip in &old.self_ips {
        if !new.self_ips.contains(ip) || changed_vlan(old, new, &ip.vlan) {
            steps.push(Step {
                command: address(old, ip, "del"),
                undo: vec![address(old, ip, "add")],
            });
        }
    }
    for v in &old.vlans {
        if v.tag.is_some() && changed_vlan(old, new, &v.name) {
            steps.push(Step {
                command: args(&["link", "del", "dev", &v.name]),
                undo: vec![vlan_add(v), args(&["link", "set", "dev", &v.name, "up"])],
            });
        }
    }
    for v in &new.vlans {
        if v.tag.is_some() && changed_vlan(old, new, &v.name) {
            steps.push(Step {
                command: vlan_add(v),
                undo: vec![args(&["link", "del", "dev", &v.name])],
            });
            steps.push(Step {
                command: args(&["link", "set", "dev", &v.name, "up"]),
                undo: vec![],
            });
        }
    }
    for ip in &new.self_ips {
        if !old.self_ips.contains(ip) || changed_vlan(old, new, &ip.vlan) {
            steps.push(Step {
                command: address(new, ip, "add"),
                undo: vec![address(new, ip, "del")],
            });
        }
    }
    for r in &new.routes {
        if !old.routes.contains(r) || changed_vlan(old, new, &r.vlan) {
            steps.push(Step {
                command: route(new, r, "add"),
                undo: vec![route(new, r, "del")],
            });
        }
    }
    for route in after
        .routes
        .iter()
        .filter(|r| !before.routes.contains(*r) || policy_device_changed(r, old, new))
    {
        steps.push(policy_step(route, true));
    }
    for rule in after
        .rules
        .iter()
        .filter(|r| !before.rules.contains(*r) || policy_device_changed(r, old, new))
    {
        steps.push(policy_step(rule, true));
    }
    Ok(steps)
}
/// Withdraw obsolete address and routing ownership before provisioning a target
/// whose Linux interfaces may not exist yet. Keep links and never compensate
/// these removals by restoring ownership if a later startup step fails.
pub fn withdrawal_plan(old: &Network, new: &Network) -> Result<Vec<Step>> {
    Ok(plan(old, new)?
        .into_iter()
        .filter(|step| match step.command.as_slice() {
            [object, operation, ..] if object == "address" => operation == "del",
            [family, object, operation, ..]
                if matches!(family.as_str(), "-4" | "-6")
                    && matches!(object.as_str(), "route" | "rule") =>
            {
                operation == "del"
            }
            _ => false,
        })
        .map(|mut step| {
            step.undo.clear();
            step
        })
        .collect())
}
// Restart after an unclean exit can leave provisioned objects in the kernel.
// Only reuse exact matches; skipped additions must not enter the rollback log.
async fn already_present(command: &[String]) -> Result<bool> {
    let value = |key: &str| {
        command
            .iter()
            .position(|s| s == key)
            .and_then(|i| command.get(i + 1))
            .map(String::as_str)
    };
    let mut query: Vec<String> = vec!["-j".into(), "-d".into()];
    if command.starts_with(&args(&["link", "add"])) {
        query.extend(args(&["link", "show"]));
        let links = inspect(&query).await?;
        let Some(link) = links.iter().find(|l| l["ifname"].as_str() == value("name")) else {
            return Ok(false);
        };
        let parent = command.get(3).map(String::as_str);
        let parent_index = links
            .iter()
            .find(|l| l["ifname"].as_str() == parent)
            .and_then(|l| l["ifindex"].as_u64());
        ensure!(
            link["linkinfo"]["info_kind"] == "vlan"
                && link["linkinfo"]["info_data"]["protocol"] == "802.1Q"
                && link["linkinfo"]["info_data"]["id"].as_u64()
                    == value("id").and_then(|s| s.parse().ok())
                && (link["link"].as_str() == parent
                    || (parent_index.is_some() && link["link_index"].as_u64() == parent_index)),
            "existing interface {} does not match requested VLAN tag {} on {}; refusing to replace it",
            value("name").unwrap_or(""),
            value("id").unwrap_or(""),
            parent.unwrap_or("")
        );
        return Ok(true);
    }
    if command.starts_with(&args(&["address", "add"])) {
        let (ip, prefix) = cidr(&command[2])?;
        query.extend(args(&["address", "show", "dev", &command[4]]));
        return Ok(inspect(&query)
            .await?
            .iter()
            .flat_map(|l| l["addr_info"].as_array().into_iter().flatten())
            .any(|a| {
                a["local"].as_str().and_then(|s| s.parse::<IpAddr>().ok()) == Some(ip)
                    && a["prefixlen"].as_u64() == Some(u64::from(prefix))
            }));
    }
    if command.len() < 4 || !matches!(command[0].as_str(), "-4" | "-6") || command[2] != "add" {
        return Ok(false);
    }
    query.push("-N".into());
    query.push(command[0].clone());
    if command[1] == "rule" {
        query.extend(args(&["rule", "show"]));
        let source = value("from").unwrap_or("");
        return Ok(inspect(&query).await?.iter().any(|r| {
            let src = r["src"].as_str().unwrap_or("");
            (src == source
                || format!("{src}/{}", if command[0] == "-4" { 32 } else { 128 }) == source)
                && json_number(&r["table"]) == value("lookup").and_then(|s| s.parse().ok())
                && json_number(&r["priority"]) == value("priority").and_then(|s| s.parse().ok())
                && json_number(&r["protocol"]) == Some(186)
        }));
    }
    if command[1] != "route" {
        return Ok(false);
    }
    query.extend(args(&[
        "route",
        "show",
        "table",
        value("table").unwrap_or("main"),
    ]));
    let mut index = 3;
    if command[index] == "table" {
        index += 2;
    }
    let unreachable = command[index] == "unreachable";
    if unreachable {
        index += 1;
    }
    let destination = &command[index];
    Ok(inspect(&query).await?.iter().any(|r| {
        let dst = r["dst"].as_str().unwrap_or("");
        (dst == destination
            || format!("{dst}/{}", if command[0] == "-4" { 32 } else { 128 }) == *destination
            || (dst == "default" && matches!(destination.as_str(), "0.0.0.0/0" | "::/0")))
            && r["gateway"].as_str() == value("via")
            && r["dev"].as_str()
                == if unreachable && command[0] == "-6" {
                    Some("lo")
                } else {
                    value("dev")
                }
            && json_number(&r["metric"]).unwrap_or(0) == {
                let metric = value("metric").and_then(|s| s.parse().ok()).unwrap_or(0);
                if command[0] == "-6" && metric == 0 {
                    1024
                } else {
                    metric
                }
            }
            && json_number(&r["protocol"]) == Some(186)
            && json_number(&r["type"]) == Some(if unreachable { 7 } else { 1 })
            && (command[0] == "-6"
                || value("scope") != Some("link")
                || json_number(&r["scope"]) == Some(253))
            && (!command.iter().any(|s| s == "onlink")
                || r["flags"]
                    .as_array()
                    .is_some_and(|f| f.iter().any(|v| v == "onlink")))
    }))
}
fn json_number(value: &serde_json::Value) -> Option<u64> {
    value
        .as_u64()
        .or_else(|| value.as_str().and_then(|s| s.parse().ok()))
}
fn matches_vlan(link: &serde_json::Value, vlan: &Vlan, links: &[serde_json::Value]) -> bool {
    let parent_index = links
        .iter()
        .find(|parent| parent["ifname"].as_str() == Some(vlan.interface.as_str()))
        .and_then(|parent| parent["ifindex"].as_u64());
    vlan.tag.is_some()
        && link["linkinfo"]["info_kind"] == "vlan"
        && link["linkinfo"]["info_data"]["protocol"] == "802.1Q"
        && link["linkinfo"]["info_data"]["id"].as_u64() == vlan.tag.map(u64::from)
        && (link["link"].as_str() == Some(vlan.interface.as_str())
            || (parent_index.is_some() && link["link_index"].as_u64() == parent_index))
}
/// Reconcile a possibly partial trial without deleting a restored or foreign
/// same-name VLAN. The caller retains its durable journal until this succeeds.
pub async fn recovery_plan(
    previous: &Network,
    trial: &Network,
    restored: &Network,
) -> Result<Vec<Step>> {
    let links = inspect(&args(&["-j", "-d", "link", "show"])).await?;
    for vlan in previous
        .vlans
        .iter()
        .chain(&trial.vlans)
        .filter(|v| v.tag.is_some())
    {
        if let Some(link) = links
            .iter()
            .find(|link| link["ifname"].as_str() == Some(vlan.name.as_str()))
        {
            ensure!(
                previous
                    .vlans
                    .iter()
                    .chain(&trial.vlans)
                    .filter(|v| v.name == vlan.name)
                    .any(|v| matches_vlan(link, v, &links)),
                "confirmation recovery refused foreign interface {}; expected the previous or trial VLAN identity",
                vlan.name
            );
        }
    }
    let mut steps = plan(trial, restored)?;
    // A failed apply/previous recovery may already have restored the old link.
    // Inverse-plan deletion must not remove that link and its restored addresses.
    steps.retain(|step| {
        if !step.command.starts_with(&args(&["link", "del", "dev"])) {
            return true;
        }
        !links
            .iter()
            .find(|link| link["ifname"].as_str() == Some(step.command[3].as_str()))
            .is_some_and(|link| {
                restored
                    .vlans
                    .iter()
                    .filter(|v| v.name == step.command[3])
                    .any(|v| matches_vlan(link, v, &links))
            })
    });
    // Also withdraw old floating ownership when a cluster restarts as standby.
    steps.extend(plan(previous, restored)?);
    // Unchanged objects can have disappeared with a replaced link before a
    // crash, so restore the complete target using exact-match idempotent adds.
    steps.extend(plan(&Network::default(), restored)?);
    Ok(steps)
}
async fn inspect(command: &[String]) -> Result<Vec<serde_json::Value>> {
    let output = tokio::process::Command::new("/usr/sbin/ip")
        .args(command)
        .output()
        .await?;
    if !output.status.success()
        && String::from_utf8_lossy(&output.stderr).contains("does not exist")
        && command.iter().any(|s| s == "dev")
    {
        return Ok(vec![]);
    }
    // A private policy table has no kernel entry until its first route.
    if !output.status.success()
        && command.iter().any(|s| s == "route")
        && String::from_utf8_lossy(&output.stderr).contains("FIB table does not exist")
    {
        return Ok(vec![]);
    }
    ensure!(
        output.status.success(),
        "inspect existing networking: ip {}: {}",
        command.join(" "),
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(serde_json::from_slice(&output.stdout)?)
}
async fn already_absent(command: &[String]) -> Result<bool> {
    if command.starts_with(&args(&["link", "del", "dev"])) {
        return Ok(!inspect(&args(&["-j", "link", "show"]))
            .await?
            .iter()
            .any(|l| l["ifname"].as_str() == Some(command[3].as_str())));
    }
    let position = if command.starts_with(&args(&["address", "del"])) {
        Some(1)
    } else if command.len() > 2
        && matches!(command[0].as_str(), "-4" | "-6")
        && matches!(command[1].as_str(), "route" | "rule")
        && command[2] == "del"
    {
        Some(2)
    } else {
        None
    };
    let Some(position) = position else {
        return Ok(false);
    };
    let mut addition = command.to_vec();
    addition[position] = "add".into();
    Ok(!already_present(&addition).await?)
}
async fn execute(command: &[String]) -> Result<bool> {
    if command.first().is_some_and(|p| p == "firewall-cmd") {
        return crate::firewall::execute(&command[1..]).await;
    }
    let output = tokio::process::Command::new("/usr/sbin/ip")
        .args(command)
        .output()
        .await
        .map_err(|error| {
            anyhow::anyhow!("run /usr/sbin/ip (install the iproute package): {error}")
        })?;
    let detail = String::from_utf8_lossy(&output.stderr);
    if !output.status.success()
        && (detail.contains("Operation not permitted") || detail.contains("Permission denied"))
    {
        bail!(
            "Linux denied network provisioning: ip {}: {}. RiverLB requires CAP_NET_ADMIN; start the deployed binary with sudo or a service granting this capability. The configuration was not applied",
            command.join(" "),
            detail.trim()
        );
    }
    ensure!(
        output.status.success(),
        "ip {}: {}",
        command.join(" "),
        detail.trim()
    );
    Ok(true)
}
// IPv6 addresses on Ethernet remain tentative while duplicate-address detection
// runs. Do not bind listeners or use an address as a source until it is ready.
async fn wait_address_ready(command: &[String]) -> Result<()> {
    if command.len() != 5 || command[0] != "address" || command[1] != "add" {
        return Ok(());
    }
    let (ip, prefix) = cidr(&command[2])?;
    if ip.is_ipv4() {
        return Ok(());
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        loop {
            let output = tokio::process::Command::new("/usr/sbin/ip")
                .kill_on_drop(true)
                .args(["-6", "-j", "address", "show", "dev", &command[4]])
                .output()
                .await?;
            ensure!(
                output.status.success(),
                "cannot inspect IPv6 address on {}",
                command[4]
            );
            let devices: Vec<serde_json::Value> = serde_json::from_slice(&output.stdout)?;
            let address = devices
                .iter()
                .flat_map(|d| d["addr_info"].as_array().into_iter().flatten())
                .find(|a| {
                    a["local"].as_str().and_then(|s| s.parse::<IpAddr>().ok()) == Some(ip)
                        && a["prefixlen"].as_u64() == Some(u64::from(prefix))
                })
                .ok_or_else(|| anyhow::anyhow!("IPv6 address {ip} disappeared during setup"))?;
            ensure!(
                address["dadfailed"].as_bool() != Some(true),
                "IPv6 duplicate address detected: {ip}"
            );
            if address["tentative"].as_bool() != Some(true) {
                return Ok(());
            }
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    })
    .await
    .map_err(|_| anyhow::anyhow!("IPv6 address {ip} did not become ready within five seconds"))?
}
pub struct Transaction {
    applied: Vec<Step>,
}
#[derive(Debug)]
pub struct RollbackFailure(String);
impl std::fmt::Display for RollbackFailure {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "network rollback needs operator recovery: {}", self.0)
    }
}
impl std::error::Error for RollbackFailure {}
impl Transaction {
    pub async fn reconcile(steps: Vec<Step>) -> Result<()> {
        // Recovery progresses toward the safe target and remains retryable.
        // Compensating back to an unconfirmed (possibly active HA) trial would
        // resurrect precisely the ownership this operation must withdraw.
        Self { applied: vec![] }.apply_steps(steps).await
    }
    pub async fn prepare(old: &Network, new: &Network, managed: bool) -> Result<Self> {
        Self::prepare_plan(if managed { plan(old, new)? } else { vec![] }).await
    }
    pub async fn prepare_plan(steps: Vec<Step>) -> Result<Self> {
        let mut tx = Self { applied: vec![] };
        if let Err(error) = tx.apply_steps(steps).await {
            if let Err(rollback) = tx.rollback().await {
                return Err(rollback.context(format!("network/firewall change failed: {error:#}")));
            }
            bail!("network change failed: {error:#}; previous network configuration restored");
        }
        Ok(tx)
    }
    pub async fn apply_steps(&mut self, steps: Vec<Step>) -> Result<()> {
        for step in steps {
            if already_absent(&step.command).await? {
                continue;
            }
            if already_present(&step.command).await? {
                wait_address_ready(&step.command).await?;
                continue;
            }
            if !execute(&step.command).await? {
                continue;
            }
            self.applied.push(step);
            wait_address_ready(&self.applied.last().unwrap().command).await?;
        }
        Ok(())
    }
    pub async fn rollback(&mut self) -> Result<()> {
        let mut failures = Vec::new();
        for step in self.applied.iter().rev() {
            for command in &step.undo {
                let result = async {
                    execute(command).await?;
                    wait_address_ready(command).await
                }
                .await;
                if let Err(e) = result {
                    failures.push(e.to_string());
                }
            }
        }
        self.applied.clear();
        if !failures.is_empty() {
            return Err(RollbackFailure(failures.join("; ")).into());
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn fixture() -> Network {
        Network {
            vlans: vec![Vlan {
                name: "rlb100".into(),
                interface: "eth0".into(),
                tag: Some(100),
                role: Role::Unspecified,
                ipv4_gateway: None,
                ipv6_gateway: None,
            }],
            self_ips: vec![SelfIp {
                name: "inside".into(),
                address: "192.0.2.2/24".into(),
                vlan: "rlb100".into(),
            }],
            routes: vec![Route {
                name: "default".into(),
                destination: "0.0.0.0/0".into(),
                gateway: "192.0.2.1".parse().unwrap(),
                vlan: "rlb100".into(),
                metric: 100,
            }],
        }
    }
    #[test]
    fn virtual_addresses_are_shared_inferred_and_removed_when_unused() {
        let mut config: crate::config::Config =
            toml::from_str(include_str!("../examples/riverlb.toml")).unwrap();
        config.network = fixture();
        config.virtual_servers.truncate(1);
        config.virtual_servers[0].listen = "192.0.2.99:8080".parse().unwrap();
        config.virtual_servers[0].ingress_vlan = None;
        let mut second = config.virtual_servers[0].clone();
        second.name = "second".into();
        second.listen.set_port(8081);
        config.virtual_servers.push(second);
        let assigned = provisioned(&config).unwrap();
        assert_eq!(assigned.self_ips.len(), 2);
        assert_eq!(assigned.self_ips[1].address, "192.0.2.99/32");
        assert_eq!(assigned.self_ips[1].vlan, "rlb100");
        config.virtual_servers[0].enabled = false;
        assert_eq!(provisioned(&config).unwrap(), assigned);
        config.virtual_servers[1].enabled = false;
        assert_eq!(provisioned(&config).unwrap(), config.network);
        assert!(
            plan(&assigned, &config.network)
                .unwrap()
                .iter()
                .any(|s| s.command == args(&["address", "del", "192.0.2.99/32", "dev", "rlb100"]))
        );
    }
    #[test]
    fn virtual_addresses_require_unambiguous_vlan_and_support_ipv6() {
        let mut config: crate::config::Config =
            toml::from_str(include_str!("../examples/riverlb.toml")).unwrap();
        config.network = fixture();
        config.network.vlans.push(Vlan {
            name: "other".into(),
            interface: "eth1".into(),
            tag: None,
            role: Role::External,
            ipv4_gateway: None,
            ipv6_gateway: None,
        });
        config.network.self_ips.push(SelfIp {
            name: "other-self".into(),
            address: "192.0.2.3/24".into(),
            vlan: "other".into(),
        });
        config.virtual_servers.truncate(1);
        config.virtual_servers[0].listen = "192.0.2.99:8080".parse().unwrap();
        assert!(
            provisioned(&config)
                .unwrap_err()
                .to_string()
                .contains("multiple VLANs")
        );
        config.virtual_servers[0].ingress_vlan = Some("rlb100".into());
        assert_eq!(
            provisioned(&config).unwrap().self_ips.last().unwrap().vlan,
            "rlb100"
        );
        config.virtual_servers[0].listen = "[2001:db8::99]:8080".parse().unwrap();
        assert_eq!(
            provisioned(&config)
                .unwrap()
                .self_ips
                .last()
                .unwrap()
                .address,
            "2001:db8::99/128"
        );
        config.virtual_servers[0].listen = "192.0.2.3:8080".parse().unwrap();
        assert!(
            provisioned(&config)
                .unwrap_err()
                .to_string()
                .contains("self IP on VLAN other")
        );
    }
    #[test]
    fn dependency_order_and_noop() {
        let n = fixture();
        let p = plan(&Network::default(), &n).unwrap();
        assert_eq!(p.len(), 8);
        assert_eq!(p[0].command[1], "add");
        assert_eq!(p[2].command[0], "address");
        assert_eq!(p[3].command[1], "route");
        assert!(plan(&n, &n).unwrap().is_empty());
        let removal = plan(&n, &Network::default()).unwrap();
        assert_eq!(removal[0].command[1], "rule");
        assert_eq!(removal.last().unwrap().command[0], "link");
    }
    #[test]
    fn address_updates_rebuild_policy_routes_before_enabling_rules() {
        let old = fixture();
        let mut new = old.clone();
        new.self_ips[0].address = "192.0.2.3/24".into();
        new.vlans[0].ipv4_gateway = Some("192.0.2.1".parse().unwrap());
        let steps = plan(&old, &new).unwrap();
        let address_add = steps
            .iter()
            .position(|s| s.command == args(&["address", "add", "192.0.2.3/24", "dev", "rlb100"]))
            .unwrap();
        assert!(steps.iter().take(address_add).any(|s| {
            s.command.get(1).is_some_and(|c| c == "route")
                && s.command.get(2).is_some_and(|c| c == "del")
                && s.command.contains(&"table".into())
        }));
        let last_route = steps
            .iter()
            .rposition(|s| {
                s.command.get(1).is_some_and(|c| c == "route")
                    && s.command.get(2).is_some_and(|c| c == "add")
                    && s.command.contains(&"table".into())
            })
            .unwrap();
        let rule_add = steps
            .iter()
            .position(|s| {
                s.command.get(1).is_some_and(|c| c == "rule")
                    && s.command.get(2).is_some_and(|c| c == "add")
            })
            .unwrap();
        assert!(address_add < last_route && last_route < rule_add);
        new.vlans[0].ipv4_gateway = Some("2001:db8::1".parse().unwrap());
        assert!(new.validate().is_err());
    }
    #[test]
    fn startup_withdrawal_precedes_missing_vlan_provisioning_without_restoring_ownership() {
        let standby = fixture();
        let mut full = standby.clone();
        for (name, address) in [
            ("floating", "192.0.2.100/24"),
            ("vip", "192.0.2.101/32"),
            ("floating-v6", "2001:db8::100/64"),
            ("vip-v6", "2001:db8::101/128"),
        ] {
            full.self_ips.push(SelfIp {
                name: name.into(),
                address: address.into(),
                vlan: "rlb100".into(),
            });
        }
        // Removing a floating address makes the normal plan rebuild even
        // retained local policies. Those adds require a link that may be absent.
        assert!(
            plan(&full, &standby)
                .unwrap()
                .iter()
                .any(|step| { step.command.starts_with(&args(&["-4", "route", "add"])) })
        );
        let withdrawal = withdrawal_plan(&full, &standby).unwrap();
        for ip in full.self_ips.iter().skip(standby.self_ips.len()) {
            assert!(
                withdrawal
                    .iter()
                    .any(|step| { step.command == address(&full, ip, "del") })
            );
        }
        assert!(
            !withdrawal
                .iter()
                .any(|step| { step.command == address(&standby, &standby.self_ips[0], "del") })
        );
        assert!(withdrawal.iter().all(|step| {
            step.command.iter().any(|part| part == "del")
                && step.command[0] != "link"
                && step.undo.is_empty()
        }));
        // Model a boot with only the physical uplink. All provisioning commands
        // referencing a device must follow its creation; withdrawal needs none.
        let mut devices = HashSet::from(["eth0".to_owned()]);
        for step in withdrawal
            .into_iter()
            .chain(plan(&Network::default(), &standby).unwrap())
        {
            if step.command.starts_with(&args(&["link", "add"])) {
                assert!(devices.contains(&step.command[3]));
                devices.insert(step.command[5].clone());
            } else if !step.command.iter().any(|part| part == "del")
                && let Some(device) = step.command.windows(2).find(|pair| pair[0] == "dev")
            {
                assert!(
                    devices.contains(&device[1]),
                    "device missing before ip {}",
                    step.command.join(" ")
                );
            }
        }
    }
    #[test]
    fn changing_network_role_does_not_recreate_kernel_objects() {
        let old = fixture();
        let mut new = old.clone();
        new.vlans[0].role = Role::External;
        assert!(plan(&old, &new).unwrap().is_empty());
        new.vlans[0].role = Role::Internal;
        assert!(plan(&old, &new).unwrap().is_empty());
        new.vlans[0].interface = "eth1".into();
        assert!(!plan(&old, &new).unwrap().is_empty());
    }
    #[test]
    fn rejects_bad_references_prefixes_tags_and_interface_arguments() {
        let mut n = fixture();
        n.self_ips[0].vlan = "unknown".into();
        assert!(n.validate().is_err());
        let mut n = fixture();
        n.vlans[0].tag = Some(4095);
        assert!(n.validate().is_err());
        let mut n = fixture();
        n.vlans[0].interface = "--help".into();
        assert!(n.validate().is_err());
        let mut n = fixture();
        n.routes[0].destination = "192.0.2.1/24".into();
        assert!(n.validate().is_err());
        assert!(cidr("192.0.2.1/33").is_err());
        assert!(cidr("2001:db8::1/129").is_err());
    }
}
