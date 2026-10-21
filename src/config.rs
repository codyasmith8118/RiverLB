//! Strict configuration parsing. Invalid configurations never open listeners.
use crate::network::Network;
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashSet},
    net::SocketAddr,
    path::Path,
};
fn default_enabled() -> bool {
    true
}
fn is_enabled(value: &bool) -> bool {
    *value
}
fn is_zero(value: &usize) -> bool {
    *value == 0
}
fn one() -> u32 {
    1
}
fn is_one(value: &u32) -> bool {
    *value == 1
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum ManagementProtocol {
    Http,
    Https,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub management: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_protocol: Option<ManagementProtocol>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_tls: Option<crate::tls::Tls>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub management_certificate: Option<String>,
    pub connect_timeout_ms: u64,
    pub session_timeout_secs: u64,
    pub health_interval_secs: u64,
    pub max_connections: usize,
    pub virtual_servers: Vec<VirtualServer>,
    #[serde(default, skip_serializing_if = "Network::is_empty")]
    pub network: Network,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub pools: Vec<PoolConfig>,
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub health_rise: u32,
    #[serde(default = "one", skip_serializing_if = "is_one")]
    pub health_fall: u32,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub health_monitors: Vec<crate::monitor::Monitor>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub persistence_profiles: Vec<PersistenceProfile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub server_tls_profiles: Vec<crate::server_tls::Profile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub river_rules: Vec<crate::http_proxy::RuleSet>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub cookie_profiles: Vec<crate::http_proxy::CookieProfile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub http_profiles: Vec<crate::http_proxy::HttpProfile>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub nodes: Vec<Node>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub domain_routes: Vec<DomainRoute>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Node {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor: Option<String>,
    pub name: String,
    pub address: SocketAddr,
    #[serde(default)]
    pub description: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DomainRoute {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub https_port: Option<u16>,
    pub name: String,
    pub virtual_server: String,
    pub hostname: String,
    pub node: String,
    #[serde(default = "default_enabled")]
    pub enabled: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PoolConfig {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_members: Vec<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub member_priorities: BTreeMap<SocketAddr, u16>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub member_connection_limits: BTreeMap<SocketAddr, usize>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub priority_group_min_active: usize,

    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor: Option<String>,
    pub name: String,
    pub algorithm: Algorithm,
    pub members: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub draining_members: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub member_weights: BTreeMap<SocketAddr, u32>,
}
/// Per-virtual-server source-IP affinity. Zero timeout disables persistence.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Persistence {
    #[serde(default, skip_serializing_if = "PersistenceKind::is_default")]
    pub kind: PersistenceKind,
    #[serde(default = "prefix4", skip_serializing_if = "is_prefix4")]
    pub ipv4_prefix: u8,
    #[serde(default = "prefix6", skip_serializing_if = "is_prefix6")]
    pub ipv6_prefix: u8,
    #[serde(default = "default_enabled", skip_serializing_if = "is_enabled")]
    pub refresh_on_use: bool,
    pub timeout_secs: u32,
    pub max_entries: usize,
}
fn prefix4() -> u8 {
    32
}
fn prefix6() -> u8 {
    128
}
fn is_prefix4(v: &u8) -> bool {
    *v == 32
}
fn is_prefix6(v: &u8) -> bool {
    *v == 128
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PersistenceKind {
    #[default]
    SourceAddress,
    SourceHash,
}
impl PersistenceKind {
    fn is_default(&self) -> bool {
        *self == Self::SourceAddress
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PersistenceProfile {
    pub name: String,
    pub settings: Persistence,
}
impl Default for Persistence {
    fn default() -> Self {
        Self {
            kind: PersistenceKind::SourceAddress,
            ipv4_prefix: 32,
            ipv6_prefix: 128,
            refresh_on_use: true,
            timeout_secs: 0,
            max_entries: 0,
        }
    }
}
impl Persistence {
    pub fn validate(&self) -> Result<()> {
        if self.ipv4_prefix > 32
            || self.ipv6_prefix > 128
            || self.timeout_secs > 86400
            || self.max_entries > 1_000_000
            || (self.timeout_secs > 0 && self.max_entries == 0)
        {
            bail!(
                "persistence requires valid prefixes, timeout <=86400 and capacity 1..1000000 when enabled"
            );
        }
        if self.kind == PersistenceKind::SourceHash
            && (self.timeout_secs != 0 || self.max_entries != 0)
        {
            bail!("stateless source hash uses zero timeout and capacity");
        }
        Ok(())
    }
    pub fn key(&self, source: std::net::IpAddr) -> std::net::IpAddr {
        use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
        match source {
            IpAddr::V4(ip) => IpAddr::V4(Ipv4Addr::from(
                u32::from(ip)
                    & u32::MAX
                        .checked_shl(u32::from(32 - self.ipv4_prefix))
                        .unwrap_or(0),
            )),
            IpAddr::V6(ip) => IpAddr::V6(Ipv6Addr::from(
                u128::from(ip)
                    & u128::MAX
                        .checked_shl(u32::from(128 - self.ipv6_prefix))
                        .unwrap_or(0),
            )),
        }
    }
    fn is_default(&self) -> bool {
        self.timeout_secs == 0
            && self.max_entries == 0
            && self.kind == PersistenceKind::SourceAddress
            && self.ipv4_prefix == 32
            && self.ipv6_prefix == 128
            && self.refresh_on_use
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct VirtualServer {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub domain_tls_parent: Option<String>,
    #[serde(default, skip_serializing_if = "VirtualServerType::is_standard")]
    pub server_type: VirtualServerType,
    #[serde(
        default = "udp_idle_timeout",
        skip_serializing_if = "is_udp_idle_default"
    )]
    pub udp_idle_timeout_secs: u64,
    #[serde(
        default = "default_hostname_miss_body",
        skip_serializing_if = "is_default_hostname_miss_body"
    )]
    pub hostname_miss_body: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub node_members: Vec<String>,
    #[serde(skip)]
    pub resolved_domains: BTreeMap<String, SocketAddr>,
    #[serde(skip)]
    pub default_members: Option<Vec<SocketAddr>>,
    #[serde(skip)]
    pub has_domain_routes: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub http: Option<crate::http_proxy::Profile>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub member_priorities: BTreeMap<SocketAddr, u16>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub member_connection_limits: BTreeMap<SocketAddr, usize>,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub priority_group_min_active: usize,
    #[serde(default, skip_serializing_if = "is_zero")]
    pub connection_limit: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub server_tls_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub certificate: Option<String>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub sni_certificates: BTreeMap<String, String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub persistence_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub monitor: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub app_url: String,
    pub name: String,
    pub listen: SocketAddr,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tls: Option<crate::tls::Tls>,
    #[serde(default)]
    pub algorithm: Algorithm,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub members: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub draining_members: Vec<SocketAddr>,
    #[serde(default, skip_serializing_if = "BTreeMap::is_empty")]
    pub member_weights: BTreeMap<SocketAddr, u32>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_pool: Option<String>,
    #[serde(default = "default_enabled", skip_serializing_if = "is_enabled")]
    pub enabled: bool,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_self_ip: Option<String>,
    /// Limit incoming connections to this VLAN's Linux device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ingress_vlan: Option<String>,
    /// Pin backend connections and health probes to this VLAN's Linux device.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub backend_vlan: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_nat: Option<crate::nat::SourceNat>,
    #[serde(default, skip_serializing_if = "Persistence::is_default")]
    pub persistence: Persistence,
}
fn default_hostname_miss_body() -> String {
    "No domain route for this hostname".into()
}
fn is_default_hostname_miss_body(body: &str) -> bool {
    body == "No domain route for this hostname"
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum VirtualServerType {
    #[default]
    Standard,
    Tcp,
    Udp,
    Http,
    DomainRouting,
}
fn udp_idle_timeout() -> u64 {
    30
}
fn is_udp_idle_default(value: &u64) -> bool {
    *value == 30
}
impl VirtualServerType {
    pub fn is_udp(&self) -> bool {
        *self == Self::Udp
    }
    fn is_standard(&self) -> bool {
        *self == Self::Standard
    }
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Algorithm {
    #[default]
    RoundRobin,
    WeightedRoundRobin,
    WeightedLeastConnections,
    LeastConnections,
    SourceHash,
}

fn validate_draining(members: &[SocketAddr], draining: &[SocketAddr]) -> Result<()> {
    let mut seen = HashSet::new();
    for address in draining {
        if !members.contains(address) || !seen.insert(address) {
            bail!("draining members must be unique addresses present in the pool");
        }
    }
    Ok(())
}

fn validate_weights(members: &[SocketAddr], weights: &BTreeMap<SocketAddr, u32>) -> Result<()> {
    for (address, weight) in weights {
        if !members.contains(address) || !(1..=1000).contains(weight) {
            bail!("member weights must reference existing members and be integers 1..1000");
        }
    }
    Ok(())
}

fn validate_capacity(
    members: &[SocketAddr],
    priorities: &BTreeMap<SocketAddr, u16>,
    limits: &BTreeMap<SocketAddr, usize>,
    minimum: usize,
) -> Result<()> {
    if minimum > members.len() {
        bail!("priority group minimum must be 0..member count");
    }
    if priorities.keys().any(|address| !members.contains(address)) {
        bail!("priority groups must reference existing members");
    }
    if limits
        .iter()
        .any(|(address, limit)| !members.contains(address) || *limit == 0 || *limit > 1_000_000)
    {
        bail!(
            "member connection limits must reference members and be 1..1000000; omit for unlimited"
        );
    }
    Ok(())
}
impl Config {
    pub fn resolve(&self, vs: &VirtualServer) -> Result<VirtualServer> {
        let mut effective = vs.clone();
        if let Some(name) = &vs.persistence_profile {
            if !vs.persistence.is_default() {
                bail!("choose a persistence profile or inline settings, not both");
            }
            effective.persistence = self
                .persistence_profiles
                .iter()
                .find(|p| &p.name == name)
                .map(|p| p.settings.clone())
                .or_else(|| match name.as_str() {
                    "source_addr" => Some(Persistence {
                        timeout_secs: 180,
                        max_entries: 10000,
                        ..Default::default()
                    }),
                    "source_hash" => Some(Persistence {
                        kind: PersistenceKind::SourceHash,
                        ..Default::default()
                    }),
                    _ => None,
                })
                .context("unknown persistence profile")?;
        }
        if let Some(name) = &vs.default_pool {
            if !vs.members.is_empty()
                || !vs.draining_members.is_empty()
                || !vs.member_weights.is_empty()
                || !vs.member_priorities.is_empty()
                || !vs.member_connection_limits.is_empty()
                || vs.priority_group_min_active != 0
                || !vs.node_members.is_empty()
            {
                bail!("{} must use either a named pool or inline members", vs.name);
            }
            let pool =
                self.pools.iter().find(|p| &p.name == name).ok_or_else(|| {
                    anyhow::anyhow!("unknown default pool {name} for {}", vs.name)
                })?;
            if vs.monitor.is_some() {
                bail!("named pool owns its health monitor; configure the monitor on the pool");
            }
            effective.monitor = pool.monitor.clone();
            effective.algorithm = pool.algorithm;
            effective.members = pool.members.clone();
            for name in &pool.node_members {
                effective.members.push(
                    self.nodes
                        .iter()
                        .find(|n| &n.name == name)
                        .context("unknown pool node")?
                        .address,
                );
            }
            effective.draining_members = pool.draining_members.clone();
            effective.member_weights = pool.member_weights.clone();
            effective.member_priorities = pool.member_priorities.clone();
            effective.member_connection_limits = pool.member_connection_limits.clone();
            effective.priority_group_min_active = pool.priority_group_min_active;
        }
        if let Some(http) = &mut effective.http {
            if let Some(name) = &http.profile {
                let default = crate::http_proxy::HttpSettings::default();
                if http.max_body_bytes != default.max_body_bytes
                    || http.max_header_bytes != default.max_header_bytes
                    || http.keep_alive != default.keep_alive
                    || http.streaming != default.streaming
                    || http.websockets != default.websockets
                {
                    bail!("choose an HTTP profile or inline HTTP limits");
                }
                let settings = if name == "http" {
                    default
                } else {
                    self.http_profiles
                        .iter()
                        .find(|p| &p.name == name)
                        .context("unknown HTTP profile")?
                        .settings
                        .clone()
                };
                http.max_body_bytes = settings.max_body_bytes;
                http.max_header_bytes = settings.max_header_bytes;
                http.keep_alive = settings.keep_alive;
                http.streaming = settings.streaming;
                http.websockets = settings.websockets;
            }
            if http.cookie_profile.is_some() && http.cookie.is_some() {
                bail!("choose a cookie profile or inline cookie settings");
            }
            if let Some(name) = &http.cookie_profile {
                http.cookie = Some(if name == "cookie" {
                    crate::http_proxy::Cookie::default()
                } else {
                    self.cookie_profiles
                        .iter()
                        .find(|p| &p.name == name)
                        .context("unknown cookie profile")?
                        .settings
                        .clone()
                });
            }
            if !http.rule_sets.is_empty() && !http.rules.is_empty() {
                bail!("choose named RiverRules or inline rules");
            }
            let mut seen = HashSet::new();
            for name in &http.rule_sets {
                if !seen.insert(name) {
                    bail!("duplicate RiverRules assignment");
                }
                let rules = if let Some(builtin) = crate::http_proxy::builtin_rule_set(name) {
                    builtin.rules
                } else {
                    self.river_rules
                        .iter()
                        .find(|r| &r.name == name)
                        .context("unknown RiverRules object")?
                        .rules
                        .clone()
                };
                http.rules.extend(rules);
            }
        }
        if vs.default_pool.is_none() {
            for name in &vs.node_members {
                effective.members.push(
                    self.nodes
                        .iter()
                        .find(|n| &n.name == name)
                        .context("unknown virtual server node")?
                        .address,
                );
            }
        }
        effective.default_members = Some(if vs.server_type == VirtualServerType::DomainRouting {
            Vec::new()
        } else {
            effective.members.clone()
        });
        effective.has_domain_routes = vs.server_type == VirtualServerType::DomainRouting;
        for route in self.domain_routes.iter().filter(|r| {
            r.virtual_server == vs.name
                || (vs.domain_tls_parent.as_deref() == Some(r.virtual_server.as_str())
                    && r.certificate.is_some()
                    && r.https_port.unwrap_or(443) == vs.listen.port())
        }) {
            let node = self
                .nodes
                .iter()
                .find(|n| n.name == route.node)
                .context("unknown domain route node")?;
            effective.has_domain_routes = true;
            if route.enabled {
                effective
                    .resolved_domains
                    .insert(route.hostname.clone(), node.address);
            }
            if !effective.members.contains(&node.address) {
                effective.members.push(node.address);
            }
        }
        for node in self.nodes.iter().filter(|n| !n.enabled) {
            if effective.members.contains(&node.address)
                && !effective.draining_members.contains(&node.address)
            {
                effective.draining_members.push(node.address);
            }
        }
        Ok(effective)
    }
    pub fn expand_domain_tls(&self) -> Result<Self> {
        let mut config = self.clone();
        config
            .virtual_servers
            .retain(|v| v.domain_tls_parent.is_none());
        let mut groups: BTreeMap<(String, u16), Vec<&DomainRoute>> = BTreeMap::new();
        for route in &self.domain_routes {
            if let Some(certificate) = &route.certificate {
                crate::certificates::validate_name(certificate)?;
                let port = route.https_port.unwrap_or(443);
                if port == 0 {
                    bail!("HTTPS route port must not be zero");
                }
                if route.enabled {
                    groups
                        .entry((route.virtual_server.clone(), port))
                        .or_default()
                        .push(route);
                }
            } else if route.https_port.is_some() {
                bail!("HTTPS route port requires a certificate");
            }
        }
        for ((parent, port), routes) in groups {
            let source = config
                .virtual_servers
                .iter()
                .find(|v| v.name == parent)
                .context("unknown HTTPS route parent virtual server")?;
            if source.http.is_none() || source.tls.is_some() || source.certificate.is_some() {
                bail!(
                    "route HTTPS requires a plaintext HTTP parent; use the virtual server's TLS/SNI settings for an existing HTTPS listener"
                );
            }
            let mut server = source.clone();
            server.listen.set_port(port);
            if config
                .virtual_servers
                .iter()
                .any(|v| !v.server_type.is_udp() && v.listen == server.listen)
            {
                bail!(
                    "HTTPS address {} already has a virtual server; use its TLS/SNI settings or choose another HTTPS port",
                    server.listen
                );
            }
            let mut prefix = parent.clone();
            while prefix.len() > 105 {
                prefix.pop();
            }
            server.name = format!("{prefix}-https-{port}");
            if config.virtual_servers.iter().any(|v| v.name == server.name) {
                bail!(
                    "generated HTTPS virtual server name {} conflicts with an existing object",
                    server.name
                );
            }
            server.domain_tls_parent = Some(parent);
            server.server_type = VirtualServerType::DomainRouting;
            server.default_pool = None;
            server.members.clear();
            server.node_members.clear();
            server.member_weights.clear();
            server.member_priorities.clear();
            server.member_connection_limits.clear();
            server.draining_members.clear();
            server.priority_group_min_active = 0;
            server.persistence = Persistence::default();
            server.persistence_profile = None;
            if let Some(http) = &mut server.http {
                http.cookie = None;
                http.cookie_profile = None;
                // Keep request processing on HTTPS, excluding the plaintext redirect.
                for rule in &mut http.rules {
                    rule.actions.retain(|action| {
                        !matches!(action, crate::http_proxy::Action::RedirectHttps { .. })
                    });
                }
                http.rules.retain(|rule| !rule.actions.is_empty());
                http.rule_sets
                    .retain(|name| name != "builtin-http-to-https");
            }
            server.certificate = routes[0].certificate.clone();
            server.sni_certificates.clear();
            for route in routes {
                server
                    .sni_certificates
                    .insert(route.hostname.clone(), route.certificate.clone().unwrap());
            }
            config.virtual_servers.push(server);
        }
        Ok(config)
    }
    pub fn load(path: &Path) -> Result<Self> {
        let config: Self =
            toml::from_str(&std::fs::read_to_string(path).context("read configuration")?)?;
        config.validate()?;
        config.expand_domain_tls()
    }
    pub fn validate(&self) -> Result<()> {
        self.expand_domain_tls()?.validate_inner()
    }
    fn validate_inner(&self) -> Result<()> {
        let mut node_names = HashSet::new();
        let mut addresses = HashSet::new();
        if self.nodes.len() > 10000 || self.domain_routes.len() > 10000 {
            bail!("node/domain route inventory limit is 10000");
        }
        for node in &self.nodes {
            crate::certificates::validate_name(&node.name)?;
            if !node_names.insert(&node.name)
                || !addresses.insert(node.address)
                || node.address.port() == 0
                || node.address.ip().is_unspecified()
                || node.address.ip().is_multicast()
                || node.description.len() > 4096
            {
                bail!("nodes require unique names/addresses and a valid unicast IP/service port");
            }
        }
        let mut route_names = HashSet::new();
        let mut hostnames = HashSet::new();
        for route in &self.domain_routes {
            crate::certificates::validate_name(&route.name)?;
            if !route_names.insert(&route.name)
                || !hostnames.insert((&route.virtual_server, &route.hostname))
                || !crate::certificates::dns_name(&route.hostname)
                || !node_names.contains(&route.node)
            {
                bail!("domain routes require unique names/hostnames and an existing node");
            }
            let vs = self
                .virtual_servers
                .iter()
                .find(|v| v.name == route.virtual_server)
                .context("unknown domain routing virtual server")?;
            if vs.http.is_none() {
                bail!(
                    "domain routing requires an HTTP virtual server (terminate HTTPS to inspect Host)"
                );
            }
        }
        self.network.validate()?;
        if self.http_profiles.len() > 1000 {
            bail!("at most 1000 HTTP profiles");
        }
        let mut http_names = HashSet::new();
        for p in &self.http_profiles {
            if p.name == "http"
                || p.name.trim().is_empty()
                || p.name.len() > 128
                || !http_names.insert(&p.name)
                || p.description.len() > 4096
            {
                bail!(
                    "HTTP profiles need unique names (http is reserved), names <=128 and descriptions <=4096 bytes"
                );
            }
            p.settings.validate()?;
        }
        if self.cookie_profiles.len() > 1000 || self.river_rules.len() > 1000 {
            bail!("at most 1000 cookie profiles and RiverRules objects");
        }
        let mut cookie_names = HashSet::new();
        for p in &self.cookie_profiles {
            if p.name == "cookie"
                || p.name.trim().is_empty()
                || p.name.len() > 128
                || !cookie_names.insert(&p.name)
                || p.description.len() > 4096
            {
                bail!(
                    "cookie profiles need unique names (cookie is reserved), at most 128 bytes and descriptions <=4096 bytes"
                );
            }
            p.settings.validate()?;
        }
        let mut rule_names = HashSet::new();
        for r in &self.river_rules {
            if r.name.trim().is_empty()
                || r.name.len() > 128
                || crate::http_proxy::builtin_rule_set(&r.name).is_some()
                || !rule_names.insert(&r.name)
                || r.description.len() > 4096
            {
                bail!(
                    "RiverRules objects need unique non-reserved names of at most 128 bytes and descriptions <=4096 bytes"
                );
            }
            let http = crate::http_proxy::Profile {
                profile: None,
                max_header_bytes: 32768,
                keep_alive: true,
                streaming: false,
                websockets: true,
                max_body_bytes: 8388608,
                cookie: None,
                rules: r.rules.clone(),
                cookie_profile: None,
                rule_sets: Vec::new(),
            };
            let members = r
                .rules
                .iter()
                .flat_map(|r| &r.actions)
                .filter_map(|a| {
                    if let crate::http_proxy::Action::SelectMember { address } = a {
                        Some(*address)
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            http.validate(&members)?;
        }
        let mut server_tls_names = HashSet::new();
        for profile in &self.server_tls_profiles {
            if profile.name == "server_tls" {
                bail!("server_tls is a reserved default profile name");
            }
            profile.connector()?;
            if !server_tls_names.insert(&profile.name) {
                bail!("duplicate server TLS profile name");
            }
        }
        for vs in &self.virtual_servers {
            if vs.hostname_miss_body.len() > 65536 {
                bail!("hostname miss response must be at most 65536 bytes");
            }
            match vs.server_type {
                VirtualServerType::Tcp | VirtualServerType::Udp if vs.http.is_some() => {
                    bail!("TCP and UDP virtual servers cannot use HTTP processing")
                }
                VirtualServerType::Http | VirtualServerType::DomainRouting if vs.http.is_none() => {
                    bail!("HTTP and domain-routing virtual servers require HTTP processing")
                }
                _ => {}
            }
            if vs.server_type == VirtualServerType::DomainRouting
                && (vs.default_pool.is_some()
                    || !vs.members.is_empty()
                    || !vs.node_members.is_empty())
            {
                bail!(
                    "domain-routing virtual servers use only the domain route table; remove default pool and members"
                );
            }
            if let Some(name) = &vs.server_tls_profile
                && name != "server_tls"
                && !server_tls_names.contains(name)
            {
                bail!("unknown server TLS profile {name}");
            }
            if vs.server_tls_profile.as_deref() == Some("server_tls") {
                crate::server_tls::Profile::default().connector()?;
            }
        }
        let mut profile_names = HashSet::new();
        for profile in &self.persistence_profiles {
            if profile.name.trim().is_empty()
                || profile.name.len() > 128
                || !profile_names.insert(&profile.name)
            {
                bail!("persistence profile names must be nonempty and unique, at most 128 bytes");
            }
            profile.settings.validate()?;
        }
        let has_management_tls =
            self.management_tls.is_some() || self.management_certificate.is_some();
        match self.management_protocol {
            Some(ManagementProtocol::Http) if has_management_tls => {
                bail!("HTTP management must not have a TLS certificate assignment")
            }
            Some(ManagementProtocol::Https) if !has_management_tls => {
                bail!("HTTPS management requires a device certificate or certificate/key PEM files")
            }
            _ => {}
        }
        if self.management_tls.is_some() && self.management_certificate.is_some() {
            bail!("choose a managed management certificate or PEM paths");
        }
        for name in self.management_certificate.iter().chain(
            self.virtual_servers
                .iter()
                .flat_map(|v| v.certificate.iter().chain(v.sni_certificates.values())),
        ) {
            crate::certificates::validate_name(name)?;
        }
        for vs in &self.virtual_servers {
            if !vs.sni_certificates.is_empty() {
                if vs.certificate.is_none() || vs.sni_certificates.len() > 100 {
                    bail!(
                        "SNI requires a managed default certificate and at most 100 hostname assignments"
                    );
                }
                if vs
                    .sni_certificates
                    .keys()
                    .any(|host| !crate::certificates::dns_name(host))
                {
                    bail!("SNI names must be lowercase DNS hostnames without wildcards or ports");
                }
            }
            if vs.tls.is_some() && vs.certificate.is_some() {
                bail!("choose a managed virtual-server certificate or PEM paths");
            }
        }
        let mut monitor_names = HashSet::new();
        for monitor in &self.health_monitors {
            monitor.validate()?;
            if !monitor_names.insert(&monitor.name) {
                bail!("duplicate health monitor name");
            }
        }
        for name in self
            .nodes
            .iter()
            .filter_map(|n| n.monitor.as_ref())
            .chain(self.pools.iter().filter_map(|p| p.monitor.as_ref()))
            .chain(
                self.virtual_servers
                    .iter()
                    .filter_map(|v| v.monitor.as_ref()),
            )
        {
            if !monitor_names.contains(name) {
                bail!("unknown health monitor {name}");
            }
        }
        for vs in &self.virtual_servers {
            if !vs.app_url.is_empty() {
                let uri: axum::http::Uri = vs.app_url.parse().context("invalid app URL")?;
                if !matches!(uri.scheme_str(), Some("http" | "https"))
                    || uri.host().is_none()
                    || uri.authority().is_some_and(|a| a.as_str().contains('@'))
                    || vs.app_url.contains('\\')
                {
                    bail!("app URL must be an absolute HTTP/HTTPS URL without credentials");
                }
            }
        }
        if let Some(tls) = &self.management_tls {
            tls.server_config()?;
        }
        if self.health_rise == 0
            || self.health_fall == 0
            || self.health_rise > 1000
            || self.health_fall > 1000
        {
            bail!("health rise/fall must be 1–1000 consecutive probes");
        }
        let mut pool_names = HashSet::new();
        for pool in &self.pools {
            let mut pool = pool.clone();
            for name in &pool.node_members {
                pool.members.push(
                    self.nodes
                        .iter()
                        .find(|n| &n.name == name)
                        .context("unknown pool node")?
                        .address,
                );
            }
            if pool.name.trim().is_empty()
                || !pool_names.insert(pool.name.clone())
                || pool.members.is_empty()
            {
                bail!("pool names must be nonempty and unique, with at least one member");
            }
            validate_draining(&pool.members, &pool.draining_members)?;
            validate_weights(&pool.members, &pool.member_weights)?;
            validate_capacity(
                &pool.members,
                &pool.member_priorities,
                &pool.member_connection_limits,
                pool.priority_group_min_active,
            )?;
            let mut members = HashSet::new();
            for member in &pool.members {
                if member.port() == 0 || member.ip().is_unspecified() || !members.insert(member) {
                    bail!("invalid or duplicate member in pool {}", pool.name);
                }
            }
        }
        if self.management.ip().is_unspecified() || self.management.ip().is_multicast() {
            bail!("management must bind a specific unicast address");
        }
        if self.management.port() == 0
            || self.max_connections == 0
            || self.max_connections > 1_000_000
            || self.connect_timeout_ms == 0
            || self.session_timeout_secs == 0
            || self.health_interval_secs == 0
        {
            bail!("ports, timeouts and limits must be positive; max_connections <= 1000000");
        }
        let mut names = HashSet::new();
        let mut listeners = HashSet::from([(self.management, false)]);
        for vs in &self.virtual_servers {
            let vs = &self.resolve(vs)?;
            if let Some(tls) = &vs.tls {
                tls.server_config()?;
            }
            vs.persistence.validate()?;
            if vs.server_type.is_udp() {
                if vs.listen.ip().is_unspecified() || vs.listen.ip().is_multicast() {
                    bail!("UDP virtual servers require a specific unicast VIP");
                }
                if !(1..=3600).contains(&vs.udp_idle_timeout_secs) {
                    bail!("UDP idle timeout must be 1..3600 seconds");
                }
                if vs.tls.is_some()
                    || vs.certificate.is_some()
                    || !vs.sni_certificates.is_empty()
                    || vs.server_tls_profile.is_some()
                    || vs.http.is_some()
                {
                    bail!("UDP virtual servers cannot use HTTP or TCP TLS termination profiles");
                }
                let monitor = vs
                    .monitor
                    .as_ref()
                    .and_then(|name| self.health_monitors.iter().find(|m| &m.name == name));
                if monitor.is_none_or(|m| !m.is_datagram()) {
                    bail!(
                        "UDP virtual servers require an explicit UDP, DNS or ICMP health monitor on the virtual server or its pool"
                    );
                }
                for node in self
                    .nodes
                    .iter()
                    .filter(|n| vs.members.contains(&n.address))
                {
                    if let Some(name) = &node.monitor
                        && self
                            .health_monitors
                            .iter()
                            .find(|m| &m.name == name)
                            .is_none_or(|m| !m.is_datagram())
                    {
                        bail!("UDP node monitor must use UDP, DNS or ICMP");
                    }
                }
            }

            if let Some(http) = &vs.http {
                http.validate(&vs.members)?;
                if http.cookie.as_ref().is_some_and(|c| {
                    matches!(
                        c.method,
                        crate::http_proxy::CookieMethod::Insert
                            | crate::http_proxy::CookieMethod::Rewrite
                    ) && c.same_site == crate::http_proxy::SameSite::None
                        && c.secure == crate::http_proxy::Secure::Auto
                }) && vs.tls.is_none()
                    && vs.certificate.is_none()
                {
                    bail!("SameSite=None with Secure=auto requires client TLS");
                }
                if http.cookie.is_some()
                    && (vs.persistence.timeout_secs > 0
                        || vs.persistence.kind == PersistenceKind::SourceHash)
                {
                    bail!("cookie persistence cannot be combined with source persistence");
                }
            }
            if vs.connection_limit > 1_000_000 {
                bail!("virtual server connection limit must be 0..1000000");
            }
            for vlan in [&vs.ingress_vlan, &vs.backend_vlan].into_iter().flatten() {
                if !self.network.vlans.iter().any(|v| &v.name == vlan) {
                    bail!("unknown traffic VLAN {vlan} for {}", vs.name);
                }
            }
            if let Some(vlan) = &vs.backend_vlan {
                let sources = self
                    .network
                    .self_ips
                    .iter()
                    .filter(|ip| &ip.vlan == vlan)
                    .map(|ip| crate::network::cidr(&ip.address).expect("validated CIDR").0)
                    .collect::<Vec<_>>();
                for member in &vs.members {
                    if !sources.iter().any(|ip| ip.is_ipv4() == member.is_ipv4()) {
                        bail!(
                            "backend VLAN {vlan} needs a self IP for every backend address family"
                        );
                    }
                    if let Some(crate::nat::SourceNat::Snat { addresses }) = &vs.source_nat
                        && addresses
                            .iter()
                            .any(|ip| ip.is_ipv4() == member.is_ipv4() && !sources.contains(ip))
                    {
                        bail!("SNAT addresses must belong to the selected backend VLAN {vlan}");
                    }
                }
            }
            validate_capacity(
                &vs.members,
                &vs.member_priorities,
                &vs.member_connection_limits,
                vs.priority_group_min_active,
            )?;
            if let Some(nat) = &vs.source_nat {
                if vs.source_self_ip.is_some() {
                    bail!("choose source NAT or legacy source self IP, not both");
                }
                nat.validate(self, &vs.members)?;
            }
            if let Some(name) = &vs.source_self_ip {
                let source_ip = self
                    .network
                    .self_ips
                    .iter()
                    .find(|ip| &ip.name == name)
                    .ok_or_else(|| anyhow::anyhow!("unknown source self IP for {}", vs.name))?;
                let (source, _) = crate::network::cidr(&source_ip.address)?;
                if vs.members.iter().any(|m| m.is_ipv4() != source.is_ipv4()) {
                    bail!("backend/source self IP families must match in {}", vs.name);
                }
                if let Some(vlan) = &vs.backend_vlan
                    && &source_ip.vlan != vlan
                {
                    bail!("source self IP must belong to backend VLAN {vlan}");
                }
            }
            if vs.name.trim().is_empty() || !names.insert(vs.name.clone()) {
                bail!("virtual server names must be nonempty and unique");
            }
            if vs.listen.port() == 0 || !listeners.insert((vs.listen, vs.server_type.is_udp())) {
                bail!("listeners must use unique nonzero addresses");
            }
            validate_draining(&vs.members, &vs.draining_members)?;
            validate_weights(&vs.members, &vs.member_weights)?;
            if vs.members.is_empty() && vs.server_type != VirtualServerType::DomainRouting {
                bail!("{} has no members", vs.name);
            }
            let mut members = HashSet::new();
            for member in &vs.members {
                if member.port() == 0 || member.ip().is_unspecified() || !members.insert(member) {
                    bail!("invalid or duplicate member in {}", vs.name);
                }
            }
        }
        // Reject direct loops and wildcard listener overlaps.
        for (a, udp) in &listeners {
            for (b, other_udp) in &listeners {
                if udp == other_udp
                    && a != b
                    && a.port() == b.port()
                    && a.is_ipv4() == b.is_ipv4()
                    && (a.ip().is_unspecified() || b.ip().is_unspecified())
                {
                    bail!("overlapping listeners");
                }
            }
            for vs in &self.virtual_servers {
                for member in &self.resolve(vs)?.members {
                    if *udp == vs.server_type.is_udp()
                        && a.port() == member.port()
                        && (a.ip() == member.ip()
                            || (a.ip().is_unspecified() && a.is_ipv4() == member.is_ipv4()))
                    {
                        bail!("member points at a local listener");
                    }
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn udp_requires_datagram_health_and_allows_tcp_on_same_endpoint() {
        let mut config =
            super::Config::load(std::path::Path::new("examples/riverlb.toml")).unwrap();
        config.virtual_servers[0].server_type = super::VirtualServerType::Udp;
        assert!(config.validate().is_err());
        config.health_monitors.push(
            serde_json::from_value(serde_json::json!({
                "name":"udp-ready", "kind":"udp", "send":"probe", "receive":"alive",
                "interval_secs":1,"timeout_ms":100,"rise":1,"fall":1
            }))
            .unwrap(),
        );
        config.virtual_servers[0].monitor = Some("udp-ready".into());
        config.validate().unwrap();
        let mut tcp = config.virtual_servers[0].clone();
        tcp.name = "same-port-tcp".into();
        tcp.server_type = super::VirtualServerType::Tcp;
        config.virtual_servers.push(tcp);
        config.validate().unwrap();
        config.virtual_servers[0].udp_idle_timeout_secs = 0;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("UDP idle timeout")
        );
        config.virtual_servers[0].udp_idle_timeout_secs = 30;
        let duplicate = config.virtual_servers[0].clone();
        config.virtual_servers.push(duplicate);
        assert!(config.validate().is_err());
    }

    #[test]
    fn builtin_river_rules_resolve_without_saved_custom_objects() {
        let mut config = Config::load(Path::new("examples/riverlb.toml")).unwrap();
        config.virtual_servers[0].http = Some(serde_json::from_value(serde_json::json!({"rule_sets":["builtin-http-to-https","builtin-x-forwarded-for"]})).unwrap());
        config.validate().unwrap();
        let resolved = config.resolve(&config.virtual_servers[0]).unwrap();
        let rules = resolved.http.unwrap().rules;
        assert_eq!(rules.len(), 2);
        assert!(matches!(
            rules[0].actions[0],
            crate::http_proxy::Action::RedirectHttps { .. }
        ));
        assert!(matches!(
            rules[1].actions[0],
            crate::http_proxy::Action::SetForwardedFor
        ));
        config
            .river_rules
            .push(crate::http_proxy::builtin_rule_set("builtin-http-to-https").unwrap());
        assert!(config.validate().is_err());
        config.river_rules.clear();
        for entry in crate::http_proxy::builtin_rule_sets() {
            config.virtual_servers[0].http = Some(
                serde_json::from_value(serde_json::json!({
                    "rule_sets":[entry.name]
                }))
                .unwrap(),
            );
            config
                .validate()
                .unwrap_or_else(|error| panic!("{}: {error}", entry.name));
            assert_eq!(
                config
                    .resolve(&config.virtual_servers[0])
                    .unwrap()
                    .http
                    .unwrap()
                    .rules
                    .len(),
                entry.rules.len()
            );
        }
    }
    #[test]
    fn traffic_vlan_references_and_sources_are_validated() {
        let mut config =
            super::Config::load(std::path::Path::new("examples/networking.toml")).unwrap();
        config.virtual_servers[0].ingress_vlan = Some("missing".into());
        assert!(config.validate().is_err());
        config.virtual_servers[0].ingress_vlan = Some("rlb100".into());
        config.virtual_servers[0].backend_vlan = Some("rlb100".into());
        config.validate().unwrap();
        let mut invalid = config.clone();
        invalid.network.self_ips.clear();
        invalid.virtual_servers[0].source_self_ip = None;
        assert!(invalid.validate().is_err());
        let mut invalid = config.clone();
        invalid.virtual_servers[0].source_self_ip = None;
        invalid.virtual_servers[0].source_nat = Some(crate::nat::SourceNat::Snat {
            addresses: vec!["192.0.2.99".parse().unwrap()],
        });
        assert!(invalid.validate().is_err());
        invalid.virtual_servers[0].source_nat = Some(crate::nat::SourceNat::Snat {
            addresses: vec!["192.0.2.10".parse().unwrap()],
        });
        invalid.validate().unwrap();
        let mut invalid = config.clone();
        invalid.virtual_servers[0].members = vec!["[2001:db8::20]:8001".parse().unwrap()];
        invalid.virtual_servers[0].source_self_ip = None;
        assert!(invalid.validate().is_err());
        let mut internal = config.network.vlans[0].clone();
        internal.name = "internal".into();
        internal.interface = "eth1".into();
        internal.tag = None;
        config.network.vlans.push(internal);
        let mut ip = config.network.self_ips[0].clone();
        ip.name = "internal-self".into();
        ip.address = "198.51.100.10/24".into();
        ip.vlan = "internal".into();
        config.network.self_ips.push(ip);
        config.virtual_servers[0].backend_vlan = Some("internal".into());
        assert!(config.validate().is_err());
        config.virtual_servers[0].source_self_ip = Some("internal-self".into());
        config.validate().unwrap();
    }
    #[test]
    fn priority_capacity_validation_rejects_dangling_maps_and_invalid_limits() {
        let mut config =
            super::Config::load(std::path::Path::new("examples/riverlb.toml")).unwrap();
        let address = config.virtual_servers[0].members[0];
        config.virtual_servers[0]
            .member_priorities
            .insert(address, 100);
        config.virtual_servers[0].priority_group_min_active = 1;
        config.virtual_servers[0]
            .member_connection_limits
            .insert(address, 1);
        config.virtual_servers[0].connection_limit = 2;
        config.validate().unwrap();
        config.virtual_servers[0]
            .member_connection_limits
            .insert(address, 0);
        assert!(config.validate().is_err());
        config.virtual_servers[0].member_connection_limits.clear();
        config.virtual_servers[0]
            .member_priorities
            .insert("192.0.2.1:80".parse().unwrap(), 1);
        assert!(config.validate().is_err());
        config.virtual_servers[0].member_priorities.clear();
        config.virtual_servers[0].priority_group_min_active = 1000000;
        assert!(config.validate().is_err());
        config.virtual_servers[0].priority_group_min_active = 0;
        config.virtual_servers[0].connection_limit = 1000001;
        assert!(config.validate().is_err());
    }
    #[test]
    fn profiles_resolve_and_reject_bad_masks_ambiguity_and_references() {
        let mut config =
            super::Config::load(std::path::Path::new("examples/riverlb.toml")).unwrap();
        config.persistence_profiles.push(super::PersistenceProfile {
            name: "home".into(),
            settings: super::Persistence {
                timeout_secs: 180,
                max_entries: 100,
                ipv4_prefix: 24,
                ipv6_prefix: 64,
                ..Default::default()
            },
        });
        config.virtual_servers[0].persistence_profile = Some("home".into());
        config.validate().unwrap();
        assert_eq!(
            config
                .resolve(&config.virtual_servers[0])
                .unwrap()
                .persistence
                .ipv4_prefix,
            24
        );
        config.virtual_servers[0].persistence.timeout_secs = 10;
        assert!(config.validate().is_err());
        config.virtual_servers[0].persistence = Default::default();
        config.persistence_profiles[0].settings.ipv6_prefix = 129;
        assert!(config.validate().is_err());
        config.persistence_profiles[0].settings.ipv6_prefix = 64;
        config.virtual_servers[0].persistence_profile = Some("missing".into());
        assert!(config.validate().is_err());
        config.virtual_servers[0].persistence_profile = None;
        config
            .persistence_profiles
            .push(config.persistence_profiles[0].clone());
        assert!(config.validate().is_err());
    }
    use super::*;
    #[test]
    fn resolves_named_http_and_builtin_source_profiles() {
        let mut config = Config::load(Path::new("examples/riverlb.toml")).unwrap();
        config.http_profiles.push(crate::http_proxy::HttpProfile {
            name: "small".into(),
            description: String::new(),
            settings: crate::http_proxy::HttpSettings {
                max_body_bytes: 4096,
                max_header_bytes: 8192,
                keep_alive: false,
                streaming: false,
                websockets: true,
            },
        });
        config.virtual_servers[0].http =
            Some(serde_json::from_value(serde_json::json!({"profile":"small"})).unwrap());
        config.virtual_servers[0].persistence_profile = Some("source_addr".into());
        config.validate().unwrap();
        let resolved = config.resolve(&config.virtual_servers[0]).unwrap();
        assert_eq!(resolved.http.unwrap().max_body_bytes, 4096);
        assert_eq!(resolved.persistence.timeout_secs, 180);
        config.virtual_servers[0].http.as_mut().unwrap().profile = Some("missing".into());
        assert!(config.validate().is_err());
        config.virtual_servers[0].http.as_mut().unwrap().profile = Some("http".into());
        config.validate().unwrap();
        assert_eq!(
            config
                .resolve(&config.virtual_servers[0])
                .unwrap()
                .http
                .unwrap()
                .max_body_bytes,
            8388608
        );
        config.virtual_servers[0]
            .http
            .as_mut()
            .unwrap()
            .max_body_bytes = 1024;
        assert!(config.validate().is_err());
        config.virtual_servers[0]
            .http
            .as_mut()
            .unwrap()
            .max_body_bytes = 8388608;
        config.http_profiles[0].name = "http".into();
        assert!(config.validate().is_err());
    }
    #[test]
    fn validates_member_weights() {
        let mut config = Config::load(Path::new("examples/riverlb.toml")).unwrap();
        let address = config.virtual_servers[0].members[0];
        config.virtual_servers[0].member_weights.insert(address, 3);
        config.validate().unwrap();
        for invalid in [0, 1001] {
            config.virtual_servers[0]
                .member_weights
                .insert(address, invalid);
            assert!(config.validate().is_err());
        }
        config.virtual_servers[0].member_weights.clear();
        config.virtual_servers[0]
            .member_weights
            .insert("192.0.2.100:80".parse().unwrap(), 1);
        assert!(config.validate().is_err());
    }
    #[test]
    fn validates_member_drain_references() {
        let mut config = Config::load(Path::new("examples/riverlb.toml")).unwrap();
        let vs = &mut config.virtual_servers[0];
        vs.draining_members = vec![vs.members[0]];
        config.validate().unwrap();
        let address = config.virtual_servers[0].members[0];
        config.virtual_servers[0].draining_members.push(address);
        assert!(config.validate().is_err());
        config.virtual_servers[0].draining_members = vec!["192.0.2.100:80".parse().unwrap()];
        assert!(config.validate().is_err());
    }
    #[test]
    fn rejects_unbounded_or_invalid_persistence() {
        let mut config = Config::load(Path::new("examples/riverlb.toml")).unwrap();
        config.virtual_servers[0].persistence.timeout_secs = 120;
        assert!(config.validate().is_err());
        config.virtual_servers[0].persistence.max_entries = 100;
        config.validate().unwrap();
        config.virtual_servers[0].persistence.timeout_secs = 86401;
        assert!(config.validate().is_err());
        config.virtual_servers[0].persistence.timeout_secs = 0;
        config.virtual_servers[0].persistence.max_entries = 1000001;
        assert!(config.validate().is_err());
    }
    #[test]
    fn validates_specific_management_addresses_and_rejects_unknown_fields() {
        let text = include_str!("../examples/riverlb.toml");
        let mut config: Config = toml::from_str(text).unwrap();
        config.validate().unwrap();
        config.management = "0.0.0.0:9090".parse().unwrap();
        assert!(config.validate().is_err());
        config.management = "192.168.58.144:18090".parse().unwrap();
        config.validate().unwrap();
        config.management = "[fd00::1]:18090".parse().unwrap();
        config.validate().unwrap();
        for address in ["[::]:18090", "224.0.0.1:18090", "[ff02::1]:18090"] {
            config.management = address.parse().unwrap();
            assert!(config.validate().is_err());
        }
        assert!(toml::from_str::<Config>(&text.replace("management =", "typo =")).is_err());
    }
    #[test]
    fn rejects_proxy_loop_and_duplicate_members() {
        let mut config: Config = toml::from_str(include_str!("../examples/riverlb.toml")).unwrap();
        let duplicate = config.virtual_servers[0].members[0];
        config.virtual_servers[0].members.push(duplicate);
        assert!(config.validate().is_err());
        config.virtual_servers[0].members = vec![config.virtual_servers[0].listen];
        assert!(config.validate().is_err());
    }
    #[test]
    fn resolves_named_pools_and_rejects_ambiguous_or_dangling_references() {
        let mut config: Config = toml::from_str(include_str!("../examples/riverlb.toml")).unwrap();
        config.pools.push(PoolConfig {
            node_members: vec![],
            member_priorities: Default::default(),
            member_connection_limits: Default::default(),
            priority_group_min_active: 0,
            monitor: None,
            name: "shared".into(),
            algorithm: Algorithm::LeastConnections,
            members: config.virtual_servers[0].members.clone(),
            draining_members: vec![],
            member_weights: BTreeMap::new(),
        });
        config.virtual_servers[0].default_pool = Some("shared".into());
        assert!(config.validate().is_err());
        config.virtual_servers[0].members.clear();
        config.validate().unwrap();
        assert!(matches!(
            config
                .resolve(&config.virtual_servers[0])
                .unwrap()
                .algorithm,
            Algorithm::LeastConnections
        ));
        config.pools.clear();
        assert!(config.validate().is_err());
    }
    #[test]
    fn management_protocol_requires_consistent_tls_assignments_and_keeps_legacy_inference() {
        let mut config = Config::load(Path::new("examples/riverlb.toml")).unwrap();
        config.management_protocol = Some(ManagementProtocol::Https);
        assert!(config.validate().is_err());
        config.management_certificate = Some("device-portal".into());
        config.validate().unwrap();
        config.management_protocol = Some(ManagementProtocol::Http);
        assert!(config.validate().is_err());
        config.management_protocol = None;
        config.validate().unwrap();
        config.management_certificate = None;
        config.management_protocol = Some(ManagementProtocol::Http);
        config.validate().unwrap();
    }
}
