//! TCP and UDP data planes. Pool selection is serialized to reserve least-connection slots.
use crate::config::{Algorithm, Config, VirtualServer};
use anyhow::{Context, Result};
use serde::Serialize;
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpListener, TcpSocket, TcpStream},
    time::timeout,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};
mod udp;
#[derive(Clone)]
pub(crate) enum Listener {
    Tcp(Arc<TcpListener>),
    Udp(Arc<tokio::net::UdpSocket>),
}
pub(crate) async fn bind_listener(
    config: &Config,
    server: &VirtualServer,
) -> std::io::Result<Listener> {
    if server.server_type.is_udp() {
        Ok(Listener::Udp(Arc::new(
            crate::network::udp_listener(&config.network, server).await?,
        )))
    } else {
        Ok(Listener::Tcp(Arc::new(
            crate::network::listener(&config.network, server).await?,
        )))
    }
}
pub(crate) trait HttpStream:
    tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send
{
}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> HttpStream for T {}

#[derive(Clone, Serialize)]
pub struct Member {
    #[serde(serialize_with = "crate::traffic::serialize")]
    pub traffic: Arc<crate::traffic::Traffic>,
    pub address: SocketAddr,
    pub healthy: bool,
    pub last_probe: Option<i64>,
    #[serde(skip)]
    last_checked: Option<Instant>,
    pub probe_latency_ms: Option<u64>,
    pub probe_error: Option<String>,
    pub draining: bool,
    pub weight: u32,
    pub priority: u16,
    pub connection_limit: usize,
    #[serde(serialize_with = "crate::admission::serialize")]
    pub admission_active: Arc<AtomicUsize>,
    #[serde(skip)]
    current_weight: i64,
    pub active: usize,
    pub total_connections: u64,
    pub peak_connections: usize,
    pub completed: u64,
    pub failures: u64,
    pub bytes_to_backend: u64,
    pub bytes_to_client: u64,
    #[serde(skip)]
    successes: u32,
    #[serde(skip)]
    misses: u32,
}
pub struct Pool {
    pub acme_challenges: crate::acme::Challenges,
    pub config: VirtualServer,
    pub members: Mutex<Vec<Member>>,
    cursor: Mutex<usize>,
    affinity: Mutex<HashMap<IpAddr, (usize, Instant)>>,
    cookies: Mutex<HashMap<String, (SocketAddr, Instant)>>,
    tls: Option<tokio_rustls::TlsAcceptor>,
    pub traffic: Arc<crate::traffic::Traffic>,
    pub admission: Arc<AtomicUsize>,
    monitor_tls: Option<tokio_rustls::TlsConnector>,
    server_tls: Option<(
        tokio_rustls::TlsConnector,
        Option<tokio_rustls::rustls::pki_types::ServerName<'static>>,
    )>,
    source_v4_cursor: AtomicUsize,
    source_v6_cursor: AtomicUsize,
}
#[derive(Clone, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistenceReplica {
    pub virtual_server: String,
    pub source: Vec<(IpAddr, SocketAddr, i64)>,
    pub cookies: Vec<(String, SocketAddr, i64)>,
}
impl Pool {
    pub(crate) fn client_tls(&self) -> bool {
        self.tls.is_some()
    }
    pub fn export_persistence(&self) -> Result<PersistenceReplica> {
        let now = Instant::now();
        let wall = crate::storage::now() * 1000;
        let affinity = self.affinity.lock().unwrap();
        let cookies = self.cookies.lock().unwrap();
        anyhow::ensure!(
            affinity.len() + cookies.len() <= 100000,
            "HA persistence snapshot exceeds 100000 records per virtual server"
        );
        Ok(PersistenceReplica {
            virtual_server: self.config.name.clone(),
            source: affinity
                .iter()
                .filter(|(_, (_, expires))| *expires > now)
                .map(|(source, (index, expires))| {
                    (
                        *source,
                        self.config.members[*index],
                        wall + expires.saturating_duration_since(now).as_millis() as i64,
                    )
                })
                .collect(),
            cookies: cookies
                .iter()
                .filter(|(_, (_, expires))| *expires > now)
                .map(|(token, (address, expires))| {
                    (
                        token.clone(),
                        *address,
                        wall + expires.saturating_duration_since(now).as_millis() as i64,
                    )
                })
                .collect(),
        })
    }
    pub fn import_persistence(&self, replica: &PersistenceReplica) -> Result<()> {
        anyhow::ensure!(
            replica.virtual_server == self.config.name,
            "persistence object mismatch"
        );
        anyhow::ensure!(
            replica.source.len() <= self.config.persistence.max_entries,
            "source persistence replica exceeds configured capacity"
        );
        let cookie_settings = self.config.http.as_ref().and_then(|h| h.cookie.as_ref());
        anyhow::ensure!(
            replica.cookies.len() <= cookie_settings.map_or(0, |s| s.max_entries),
            "cookie persistence replica exceeds configured capacity"
        );
        let now = Instant::now();
        let wall = crate::storage::now() * 1000;
        let mut sources = HashMap::new();
        let mut cookies = HashMap::new();
        for (source, address, expires) in &replica.source {
            let index = self
                .config
                .members
                .iter()
                .position(|a| a == address)
                .context("replicated source member not configured")?;
            anyhow::ensure!(
                self.config.persistence.timeout_secs > 0
                    && self.config.persistence.key(*source) == *source,
                "invalid replicated source persistence key"
            );
            let ttl = expires.saturating_sub(wall);
            if ttl <= 0 {
                continue;
            }
            anyhow::ensure!(
                ttl <= i64::from(self.config.persistence.timeout_secs) * 1000 + 5000,
                "replicated source expiry exceeds policy"
            );
            anyhow::ensure!(
                sources
                    .insert(*source, (index, now + Duration::from_millis(ttl as u64)))
                    .is_none(),
                "duplicate source persistence record"
            );
        }
        for (token, address, expires) in &replica.cookies {
            anyhow::ensure!(
                token.len() == 64
                    && token.bytes().all(|c| c.is_ascii_hexdigit())
                    && self.config.members.contains(address),
                "invalid replicated cookie record"
            );
            let ttl = expires.saturating_sub(wall);
            if ttl <= 0 {
                continue;
            }
            anyhow::ensure!(
                ttl <= i64::from(cookie_settings.context("cookie profile missing")?.ttl_secs)
                    * 1000
                    + 5000,
                "replicated cookie expiry exceeds policy"
            );
            anyhow::ensure!(
                cookies
                    .insert(
                        token.clone(),
                        (*address, now + Duration::from_millis(ttl as u64))
                    )
                    .is_none(),
                "duplicate cookie persistence record"
            );
        }
        *self.affinity.lock().unwrap() = sources;
        *self.cookies.lock().unwrap() = cookies;
        Ok(())
    }
}
impl Pool {
    pub(crate) fn hash_cookie_member(&self, value: &str) -> Option<SocketAddr> {
        use sha2::Digest;
        let settings = self.config.http.as_ref()?.cookie.as_ref()?;
        let bytes = value.as_bytes().get(settings.hash_offset..)?;
        let bytes = if settings.hash_length == 0 {
            bytes
        } else {
            &bytes[..settings.hash_length.min(bytes.len())]
        };
        if bytes.is_empty() {
            return None;
        }
        let members = self.members.lock().unwrap();
        let mut eligible = members
            .iter()
            .filter(|m| {
                m.healthy
                    && self
                        .config
                        .default_members
                        .as_ref()
                        .is_none_or(|list| list.contains(&m.address))
                    && !m.draining
                    && (settings.override_connection_limit || Self::available(m))
            })
            .collect::<Vec<_>>();
        if self.config.priority_group_min_active > 0 {
            eligible.sort_by_key(|m| std::cmp::Reverse(m.priority));
            if let Some(cutoff) = eligible
                .get(self.config.priority_group_min_active - 1)
                .map(|m| m.priority)
            {
                eligible.retain(|m| m.priority >= cutoff);
            }
            eligible.sort_by_key(|m| m.address);
        }
        if eligible.is_empty() {
            return None;
        }
        let digest = sha2::Sha256::digest(bytes);
        let hash = u64::from_be_bytes(digest[..8].try_into().unwrap());
        Some(eligible[(hash % eligible.len() as u64) as usize].address)
    }
    pub(crate) fn learn_cookie(&self, key: &str, address: SocketAddr) {
        let settings = self.config.http.as_ref().unwrap().cookie.as_ref().unwrap();
        let now = Instant::now();
        let mut cookies = self.cookies.lock().unwrap();
        if cookies.len() >= settings.max_entries {
            cookies.retain(|_, (_, expires)| *expires > now);
        }
        if cookies.contains_key(key) || cookies.len() < settings.max_entries {
            if !settings.refresh_on_use
                && cookies
                    .get(key)
                    .is_some_and(|(member, expires)| *member == address && *expires > now)
            {
                return;
            }
            cookies.insert(
                key.to_owned(),
                (
                    address,
                    now + Duration::from_secs(u64::from(settings.ttl_secs)),
                ),
            );
        }
    }
    pub(crate) fn cookie_member(&self, token: &str) -> Option<SocketAddr> {
        if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        let mut cookies = self.cookies.lock().unwrap();
        let now = Instant::now();
        if let Some(&(address, expires)) = cookies.get(token) {
            if expires > now {
                if let Some(settings) = self.config.http.as_ref().and_then(|h| h.cookie.as_ref())
                    && settings.refresh_on_use
                    && settings.method == crate::http_proxy::CookieMethod::Passive
                {
                    cookies.insert(
                        token.to_owned(),
                        (
                            address,
                            now + Duration::from_secs(u64::from(settings.ttl_secs)),
                        ),
                    );
                }
                return Some(address);
            }
            cookies.remove(token);
        }
        None
    }
    pub(crate) fn issue_cookie(
        &self,
        existing: Option<&str>,
        address: SocketAddr,
    ) -> Option<String> {
        let settings = self.config.http.as_ref()?.cookie.as_ref()?;
        let now = Instant::now();
        let mut cookies = self.cookies.lock().unwrap();
        // Replace a presented mapping after failover even when the table is full.
        if let Some(token) = existing
            && cookies
                .get(token)
                .is_some_and(|(member, _)| *member != address)
        {
            cookies.remove(token);
        }
        if cookies.len() >= settings.max_entries {
            cookies.retain(|_, (_, expires)| *expires > now);
        }
        let reusable = existing.filter(|token| {
            cookies
                .get(*token)
                .is_some_and(|(member, expires)| *member == address && *expires > now)
        });
        if reusable.is_none() && cookies.len() >= settings.max_entries {
            return None;
        }
        if let Some(token) = reusable
            && !settings.refresh_on_use
        {
            return Some(token.to_owned());
        }
        let token = reusable.map(str::to_owned).unwrap_or_else(|| {
            rand::random::<[u8; 32]>()
                .iter()
                .map(|b| format!("{b:02x}"))
                .collect()
        });
        cookies.insert(
            token.clone(),
            (
                address,
                now + Duration::from_secs(u64::from(settings.ttl_secs)),
            ),
        );
        Some(token)
    }
    pub fn persistence_records(&self) -> serde_json::Value {
        let now = Instant::now();
        let mut affinity = self.affinity.lock().unwrap();
        affinity.retain(|_, (_, expires)| *expires > now);
        let mut cookies = self.cookies.lock().unwrap();
        cookies.retain(|_, (_, expires)| *expires > now);
        let total = affinity.len() + cookies.len();
        let mut records = affinity.iter().take(1000).map(|(source,(index,expires))| serde_json::json!({"source":source,"member":self.config.members[*index],"expires_in_secs":expires.saturating_duration_since(now).as_secs()})).collect::<Vec<_>>();
        records.sort_by_key(|r| r["source"].as_str().unwrap_or("").to_owned());
        for (_, (address, expires)) in cookies.iter().take(1000 - records.len()) {
            records.push(serde_json::json!({"source":"Cookie (token redacted)","member":address,"expires_in_secs":expires.saturating_duration_since(now).as_secs()}));
        }
        serde_json::json!({"virtual_server":self.config.name,"profile":self.config.http.as_ref().and_then(|h| h.cookie_profile.as_ref()).or(self.config.persistence_profile.as_ref()),"settings":self.config.persistence,"cookie_settings":self.config.http.as_ref().and_then(|h| h.cookie.as_ref()),"total_records":total,"records":records})
    }
    pub fn clear_persistence(&self) -> usize {
        let mut records = self.affinity.lock().unwrap();
        let count = records.len();
        records.clear();
        let mut cookies = self.cookies.lock().unwrap();
        let count = count + cookies.len();
        cookies.clear();
        count
    }
    fn new(config: VirtualServer) -> Result<Self> {
        let members = config
            .members
            .iter()
            .map(|&address| Member {
                traffic: Arc::new(crate::traffic::Traffic::default()),
                address,
                healthy: false,
                last_probe: None,
                last_checked: None,
                probe_latency_ms: None,
                probe_error: None,
                draining: config.draining_members.contains(&address),
                weight: config.member_weights.get(&address).copied().unwrap_or(1),
                priority: config.member_priorities.get(&address).copied().unwrap_or(0),
                connection_limit: config
                    .member_connection_limits
                    .get(&address)
                    .copied()
                    .unwrap_or(0),
                admission_active: Arc::new(AtomicUsize::new(0)),
                current_weight: 0,
                active: 0,
                total_connections: 0,
                peak_connections: 0,
                completed: 0,
                failures: 0,
                bytes_to_backend: 0,
                bytes_to_client: 0,
                successes: 0,
                misses: 0,
            })
            .collect();
        let tls = config.tls.as_ref().map(|tls| tls.acceptor()).transpose()?;
        Ok(Self {
            acme_challenges: Default::default(),
            tls,
            monitor_tls: None,
            server_tls: None,
            traffic: Arc::new(crate::traffic::Traffic::default()),
            admission: Arc::new(AtomicUsize::new(0)),
            source_v4_cursor: AtomicUsize::new(0),
            source_v6_cursor: AtomicUsize::new(0),
            config,
            members: Mutex::new(members),
            cursor: Mutex::new(0),
            affinity: Mutex::new(HashMap::new()),
            cookies: Mutex::new(HashMap::new()),
        })
    }
    fn attach_admission(&mut self, registry: &crate::admission::Registry) {
        self.admission = crate::admission::counter(registry, &self.config.name, None);
        for member in self.members.get_mut().unwrap() {
            member.admission_active =
                crate::admission::counter(registry, &self.config.name, Some(member.address));
        }
    }
    fn available(member: &Member) -> bool {
        member.healthy
            && !member.draining
            && (member.connection_limit == 0
                || member.admission_active.load(Ordering::SeqCst) < member.connection_limit)
    }
    fn reserve(self: &Arc<Self>, source: IpAddr) -> Option<Reservation> {
        self.reserve_at(source, Instant::now())
    }
    // Injecting monotonic time makes expiry tests deterministic.
    fn reserve_at(self: &Arc<Self>, source: IpAddr, now: Instant) -> Option<Reservation> {
        self.reserve_choice(source, now, None, false, (false, false))
    }
    pub(crate) fn reserve_http(
        self: &Arc<Self>,
        source: IpAddr,
        preferred: Option<SocketAddr>,
        strict: bool,
        bypass: bool,
    ) -> Option<Reservation> {
        self.reserve_choice(source, Instant::now(), preferred, strict, (true, bypass))
    }
    fn reserve_choice(
        self: &Arc<Self>,
        source: IpAddr,
        now: Instant,
        preferred: Option<SocketAddr>,
        strict: bool,
        (http, bypass): (bool, bool),
    ) -> Option<Reservation> {
        let virtual_permit = if http {
            None
        } else {
            Some(crate::admission::Permit::take(
                &self.admission,
                self.config.connection_limit,
            )?)
        };
        let source = self.config.persistence.key(source);
        let mut members = self.members.lock().unwrap();
        let is_default = |address: SocketAddr| {
            self.config
                .default_members
                .as_ref()
                .is_none_or(|list| list.contains(&address))
        };
        if let Some(address) = preferred {
            if let Some(index) = members.iter().position(|m| {
                m.address == address
                    && (strict || is_default(address))
                    && m.healthy
                    && !m.draining
                    && (bypass || Self::available(m))
            }) {
                let member_permit = crate::admission::Permit::take(
                    &members[index].admission_active,
                    if bypass {
                        0
                    } else {
                        members[index].connection_limit
                    },
                )?;
                members[index].active += 1;
                members[index].total_connections += 1;
                members[index].traffic.member_enter();
                members[index].peak_connections =
                    members[index].peak_connections.max(members[index].active);
                return Some(Reservation {
                    pool: self.clone(),
                    index,
                    _virtual_permit: virtual_permit,
                    _member_permit: member_permit,
                });
            }
            if strict {
                return None;
            }
        }
        let mut affinity = self.affinity.lock().unwrap();
        if let Some(&(index, expires)) = affinity.get(&source) {
            if expires > now
                && Self::available(&members[index])
                && is_default(members[index].address)
            {
                let member_permit = crate::admission::Permit::take(
                    &members[index].admission_active,
                    members[index].connection_limit,
                )?;
                members[index].active += 1;
                members[index].total_connections += 1;
                members[index].traffic.member_enter();
                members[index].peak_connections =
                    members[index].peak_connections.max(members[index].active);
                if self.config.persistence.refresh_on_use {
                    affinity.insert(
                        source,
                        (
                            index,
                            now + Duration::from_secs(u64::from(
                                self.config.persistence.timeout_secs,
                            )),
                        ),
                    );
                }
                return Some(Reservation {
                    pool: self.clone(),
                    index,
                    _virtual_permit: virtual_permit,
                    _member_permit: member_permit,
                });
            }
            affinity.remove(&source);
        }
        let mut eligible: Vec<usize> = members
            .iter()
            .enumerate()
            .filter(|(_, m)| Self::available(m) && is_default(m.address))
            .map(|(i, _)| i)
            .collect();
        if eligible.is_empty() {
            return None;
        }
        if self.config.priority_group_min_active > 0 {
            let mut groups = eligible
                .iter()
                .map(|&i| members[i].priority)
                .collect::<Vec<_>>();
            groups.sort_unstable_by(|a, b| b.cmp(a));
            groups.dedup();
            let mut cutoff = 0;
            for priority in groups {
                cutoff = priority;
                if eligible
                    .iter()
                    .filter(|&&i| members[i].priority >= cutoff)
                    .count()
                    >= self.config.priority_group_min_active
                {
                    break;
                }
            }
            eligible.retain(|&i| members[i].priority >= cutoff);
        }
        let mut cursor = self.cursor.lock().unwrap();
        let algorithm =
            if self.config.persistence.kind == crate::config::PersistenceKind::SourceHash {
                Algorithm::SourceHash
            } else {
                self.config.algorithm
            };
        let index = match algorithm {
            Algorithm::RoundRobin => eligible[*cursor % eligible.len()],
            Algorithm::WeightedRoundRobin => {
                // Smooth weighted round robin, serialized with reservations.
                // Reset excluded members so recovery cannot accumulate credit.
                for member in members.iter_mut().filter(|m| !m.healthy || m.draining) {
                    member.current_weight = 0;
                }
                let mut total = 0i64;
                let mut selected = eligible[0];
                for &i in &eligible {
                    let weight = i64::from(members[i].weight);
                    total += weight;
                    members[i].current_weight += weight;
                    if members[i].current_weight > members[selected].current_weight {
                        selected = i;
                    }
                }
                members[selected].current_weight -= total;
                selected
            }
            Algorithm::WeightedLeastConnections => {
                // Compare active/weight with integer cross products. Rotate ties.
                let mut candidates = eligible.clone();
                let count = candidates.len();
                candidates.rotate_left(*cursor % count);
                *candidates
                    .iter()
                    .min_by(|&&a, &&b| {
                        ((members[a].active as u128) * u128::from(members[b].weight))
                            .cmp(&((members[b].active as u128) * u128::from(members[a].weight)))
                    })
                    .unwrap()
            }
            Algorithm::LeastConnections => {
                *eligible.iter().min_by_key(|&&i| members[i].active).unwrap()
            }
            Algorithm::SourceHash => {
                // Defined FNV-1a hash; stable across processes (no RandomState seed).
                let bytes: Vec<u8> = match source {
                    IpAddr::V4(a) => a.octets().to_vec(),
                    IpAddr::V6(a) => a.octets().to_vec(),
                };
                let hash = bytes.iter().fold(14695981039346656037u64, |h, b| {
                    (h ^ u64::from(*b)).wrapping_mul(1099511628211)
                });
                eligible[(hash % eligible.len() as u64) as usize]
            }
        };
        let member_permit = crate::admission::Permit::take(
            &members[index].admission_active,
            members[index].connection_limit,
        )?;
        *cursor = cursor.wrapping_add(1);
        members[index].active += 1;
        members[index].total_connections += 1;
        members[index].traffic.member_enter();
        members[index].peak_connections =
            members[index].peak_connections.max(members[index].active);
        if self.config.persistence.timeout_secs > 0 {
            // At capacity remove expired records; if still full, serve without
            // caching the new source. Existing affinity is never evicted by churn.
            if affinity.len() >= self.config.persistence.max_entries {
                affinity.retain(|_, (_, expires)| *expires > now);
            }
            if affinity.len() < self.config.persistence.max_entries {
                affinity.insert(
                    source,
                    (
                        index,
                        now + Duration::from_secs(u64::from(self.config.persistence.timeout_secs)),
                    ),
                );
            }
        }
        Some(Reservation {
            pool: self.clone(),
            index,
            _virtual_permit: virtual_permit,
            _member_permit: member_permit,
        })
    }
}
pub(crate) struct Reservation {
    _virtual_permit: Option<crate::admission::Permit>,
    _member_permit: crate::admission::Permit,
    pool: Arc<Pool>,
    pub(crate) index: usize,
}
struct Admission(Arc<AtomicUsize>);
impl Drop for Admission {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
impl Drop for Reservation {
    fn drop(&mut self) {
        let mut members = self.pool.members.lock().unwrap();
        members[self.index].active -= 1;
        members[self.index]
            .traffic
            .current
            .fetch_sub(1, Ordering::Relaxed);
    }
}
pub struct Runtime {
    pub inspection: Arc<crate::inspection::Registry>,
    pub inspection_generation: u64,
    pub acme_challenges: crate::acme::Challenges,
    pub stats_registry: crate::traffic::Registry,
    pub admission_registry: crate::admission::Registry,
    pub epoch: Mutex<String>,
    pub config: Config,
    pub pools: Vec<Arc<Pool>>,
    pub node_pools: Vec<Arc<Pool>>,
    probe_budget: Arc<tokio::sync::Semaphore>,
    node_monitor_tls: HashMap<SocketAddr, Option<tokio_rustls::TlsConnector>>,
    pub management_tls: Option<Arc<tokio_rustls::rustls::ServerConfig>>,
}
impl Runtime {
    pub(crate) async fn http_backend(
        config: &Config,
        pool: &Pool,
        address: SocketAddr,
    ) -> std::io::Result<Box<dyn HttpStream>> {
        let raw = Self::connect_backend(config, pool, false, address).await?;
        if let Some((tls, name)) = &pool.server_tls {
            Ok(Box::new(
                tls.connect(name.clone().unwrap_or_else(|| address.ip().into()), raw)
                    .await?,
            ))
        } else {
            Ok(Box::new(raw))
        }
    }
    async fn connect_backend(
        config: &Config,
        pool: &Pool,
        probe: bool,
        address: SocketAddr,
    ) -> std::io::Result<TcpStream> {
        let source = Self::backend_source(config, pool, probe, address).await?;
        if source.is_some() || pool.config.backend_vlan.is_some() {
            let socket = if address.is_ipv4() {
                TcpSocket::new_v4()?
            } else {
                TcpSocket::new_v6()?
            };
            if let Some(vlan) = &pool.config.backend_vlan {
                crate::network::bind_device(&socket, config.network.device(vlan))?;
            }
            if let Some(ip) = source {
                socket.bind(SocketAddr::new(ip, 0))?;
            }
            socket.connect(address).await
        } else {
            TcpStream::connect(address).await
        }
    }
    async fn backend_source(
        config: &Config,
        pool: &Pool,
        probe: bool,
        address: SocketAddr,
    ) -> std::io::Result<Option<IpAddr>> {
        let source = match &pool.config.source_nat {
            Some(crate::nat::SourceNat::Automap) => Some(
                crate::nat::automap_on(config, address.ip(), pool.config.backend_vlan.as_deref())
                    .await?,
            ),
            Some(crate::nat::SourceNat::Snat { addresses }) => {
                let eligible = addresses
                    .iter()
                    .copied()
                    .filter(|ip| ip.is_ipv4() == address.is_ipv4())
                    .collect::<Vec<_>>();
                let cursor = if probe {
                    0
                } else {
                    if address.is_ipv4() {
                        &pool.source_v4_cursor
                    } else {
                        &pool.source_v6_cursor
                    }
                    .fetch_add(1, Ordering::Relaxed)
                };
                Some(eligible[cursor % eligible.len()])
            }
            None => pool
                .config
                .source_self_ip
                .as_ref()
                .map(|name| {
                    let ip = config
                        .network
                        .self_ips
                        .iter()
                        .find(|ip| &ip.name == name)
                        .expect("validated source self IP");
                    crate::network::cidr(&ip.address).expect("validated CIDR").0
                })
                .or_else(|| {
                    pool.config.backend_vlan.as_ref().and_then(|vlan| {
                        config
                            .network
                            .self_ips
                            .iter()
                            .filter(|ip| &ip.vlan == vlan)
                            .map(|ip| crate::network::cidr(&ip.address).expect("validated CIDR").0)
                            .find(|ip| ip.is_ipv4() == address.is_ipv4())
                    })
                }),
        };
        Ok(source)
    }
    #[cfg(test)]
    pub fn new(config: Config) -> Result<Arc<Self>> {
        Self::with_certificates(
            config,
            &Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        )
    }
    pub fn with_certificates(
        config: Config,
        certificates: &crate::certificates::Resolved,
        admission_registry: crate::admission::Registry,
        stats_registry: crate::traffic::Registry,
        acme_challenges: crate::acme::Challenges,
        inspection: Arc<crate::inspection::Registry>,
    ) -> Result<Arc<Self>> {
        let config = config.expand_domain_tls()?;
        crate::admission::prune(&admission_registry);
        crate::traffic::prune(&stats_registry);
        let mut management_tls = config
            .management_tls
            .as_ref()
            .map(|tls| tls.server_config())
            .transpose()?;
        if let Some(name) = &config.management_certificate {
            management_tls = Some(
                certificates
                    .get(&crate::certificates::StoreKind::Device.key(name))
                    .context("unknown device certificate for management")?
                    .clone(),
            );
        }
        let mut monitor_connectors = HashMap::new();
        let mut server_tls_connectors = HashMap::new();
        let pools = config
            .virtual_servers
            .iter()
            .map(|vs| {
                let mut pool = Pool::new(config.resolve(vs)?)?;
                pool.acme_challenges = acme_challenges.clone();
                pool.attach_admission(&admission_registry);
                pool.traffic = crate::traffic::counter(&stats_registry, &pool.config.name, None);
                for member in pool.members.get_mut().unwrap() {
                    member.traffic = crate::traffic::counter(
                        &stats_registry,
                        &pool.config.name,
                        Some(member.address),
                    );
                }
                if let Some(name) = &vs.server_tls_profile {
                    let default = crate::server_tls::Profile::default();
                    let profile = config
                        .server_tls_profiles
                        .iter()
                        .find(|p| &p.name == name)
                        .or_else(|| (name == "server_tls").then_some(&default))
                        .context("unknown server TLS profile")?;
                    if !server_tls_connectors.contains_key(name) {
                        server_tls_connectors
                            .insert(name.clone(), (profile.connector()?, profile.server_name()?));
                    }
                    pool.server_tls = server_tls_connectors.get(name).cloned();
                }
                if let Some(name) = &vs.certificate {
                    pool.tls = Some(tokio_rustls::TlsAcceptor::from(
                        crate::certificates::sni_config(
                            certificates
                                .get(name)
                                .context("unknown virtual-server certificate")?
                                .clone(),
                            &vs.sni_certificates,
                            certificates,
                        )?,
                    ));
                }
                if let Some(name) = &pool.config.monitor {
                    if !monitor_connectors.contains_key(name) {
                        let connector = config
                            .health_monitors
                            .iter()
                            .find(|m| &m.name == name)
                            .context("unknown health monitor")?
                            .connector()?;
                        monitor_connectors.insert(name.clone(), connector);
                    }
                    pool.monitor_tls = monitor_connectors.get(name).cloned().flatten();
                }
                Ok(Arc::new(pool))
            })
            .collect::<Result<Vec<_>>>()?;
        // Nodes without a traffic listener still receive their explicitly assigned checks.
        let mut node_pools = Vec::new();
        let mut node_monitor_tls = HashMap::new();
        for node in &config.nodes {
            let Some(name) = &node.monitor else { continue };
            let monitor = config
                .health_monitors
                .iter()
                .find(|m| &m.name == name)
                .context("unknown node health monitor")?;
            if !monitor_connectors.contains_key(name) {
                monitor_connectors.insert(name.clone(), monitor.connector()?);
            }
            node_monitor_tls.insert(
                node.address,
                monitor_connectors.get(name).cloned().flatten(),
            );
            if node.enabled
                && !pools
                    .iter()
                    .any(|p| p.config.enabled && p.config.members.contains(&node.address))
            {
                let vs: VirtualServer = serde_json::from_value(serde_json::json!({
                    "name":format!("node:{}",node.name), "listen":"127.0.0.1:0",
                    "members":[node.address], "monitor":name
                }))?;
                let mut pool = Pool::new(vs)?;
                pool.traffic = crate::traffic::counter(&stats_registry, &pool.config.name, None);
                for member in pool.members.get_mut().unwrap() {
                    member.traffic = crate::traffic::counter(
                        &stats_registry,
                        &pool.config.name,
                        Some(member.address),
                    );
                }
                node_pools.push(Arc::new(pool));
            }
        }
        let inspection_generation = inspection.generation();
        Ok(Arc::new(Self {
            inspection,
            inspection_generation,
            acme_challenges,
            stats_registry,
            admission_registry,
            epoch: Mutex::new(format!("{:016x}", rand::random::<u64>())),
            pools,
            node_pools,
            probe_budget: Arc::new(tokio::sync::Semaphore::new(16)),
            node_monitor_tls,
            config,
            management_tls,
        }))
    }
    pub async fn bind(&self) -> Result<Vec<Option<Listener>>> {
        crate::network::validate_runtime_devices(&self.config)?;
        let mut listeners = vec![];
        for pool in &self.pools {
            listeners.push(if pool.config.enabled {
                Some(bind_listener(&self.config, &pool.config).await?)
            } else {
                None
            });
        }
        Ok(listeners)
    }
    /// Retain verified health only when backend and monitoring inputs are unchanged.
    pub fn inherit_health(&self, previous: &Runtime) {
        if std::ptr::eq(self, previous) {
            return;
        }
        let context = |config: &Config| {
            serde_json::json!({
                "network":config.network, "monitors":config.health_monitors,
                "nodes":config.nodes.iter().map(|node| (&node.address,&node.monitor)).collect::<Vec<_>>(),
                "server_tls":config.server_tls_profiles,
                "timeout":config.connect_timeout_ms, "interval":config.health_interval_secs,
                "rise":config.health_rise, "fall":config.health_fall
            })
        };
        if context(&self.config) != context(&previous.config) {
            return;
        }
        let backend = |pool: &Pool| {
            serde_json::json!({
                "monitor":pool.config.monitor, "server_tls":pool.config.server_tls_profile,
                "source_nat":pool.config.source_nat, "self_ip":pool.config.source_self_ip,
                "backend_vlan":pool.config.backend_vlan
            })
        };
        for pool in self.pools.iter().chain(&self.node_pools) {
            let Some(old) = previous
                .pools
                .iter()
                .chain(&previous.node_pools)
                .find(|old| {
                    old.config.enabled
                        && old.config.name == pool.config.name
                        && backend(old) == backend(pool)
                })
            else {
                continue;
            };
            let old_members = old.members.lock().unwrap();
            let by_address = old_members
                .iter()
                .map(|member| (member.address, member))
                .collect::<HashMap<_, _>>();
            for member in pool.members.lock().unwrap().iter_mut() {
                if let Some(old) = by_address.get(&member.address) {
                    member.healthy = old.healthy;
                    member.last_probe = old.last_probe;
                    member.last_checked = old.last_checked;
                    member.probe_latency_ms = old.probe_latency_ms;
                    member.probe_error = old.probe_error.clone();
                    member.successes = old.successes;
                    member.misses = old.misses;
                }
            }
        }
    }
    pub async fn probe(self: &Arc<Self>) {
        let mut checks = tokio::task::JoinSet::new();
        for pool in self.pools.iter().chain(&self.node_pools) {
            let runtime = self.clone();
            let pool = pool.clone();
            checks.spawn(async move {
                runtime.probe_pool(&pool, None).await;
            });
            if checks.len() >= 16 {
                let _ = checks.join_next().await;
            }
        }
        while checks.join_next().await.is_some() {}
    }
    async fn probe_pool(self: &Arc<Self>, pool: &Arc<Pool>, scheduled_interval: Option<u64>) {
        if !pool.config.enabled {
            return;
        }
        let mut checks = tokio::task::JoinSet::new();
        for i in 0..pool.config.members.len() {
            let runtime = self.clone();
            let pool = pool.clone();
            checks.spawn(async move {
                let _permit = runtime
                    .probe_budget
                    .acquire()
                    .await
                    .expect("probe budget open");
                runtime.probe_member(&pool, i, scheduled_interval).await;
            });
            if checks.len() >= 16 {
                let _ = checks.join_next().await;
            }
        }
        while checks.join_next().await.is_some() {}
    }
    async fn probe_member(&self, pool: &Pool, i: usize, scheduled_interval: Option<u64>) {
        let address = &pool.config.members[i];
        let node_monitor = self
            .config
            .nodes
            .iter()
            .find(|n| n.address == *address)
            .and_then(|n| n.monitor.as_ref());
        let monitor = node_monitor
            .or(pool.config.monitor.as_ref())
            .and_then(|name| self.config.health_monitors.iter().find(|m| &m.name == name));
        let interval = monitor.map_or(self.config.health_interval_secs, |m| m.interval_secs);
        if scheduled_interval.is_some_and(|tick| interval > tick)
            && pool.members.lock().unwrap()[i]
                .last_checked
                .is_some_and(|last| last.elapsed() < Duration::from_secs(interval))
        {
            return;
        }
        let timeout_ms = monitor.map_or(self.config.connect_timeout_ms, |m| m.timeout_ms);
        let rise = monitor.map_or(self.config.health_rise, |m| m.rise);
        let fall = monitor.map_or(self.config.health_fall, |m| m.fall);
        let monitor_tls = if node_monitor.is_some() {
            self.node_monitor_tls
                .get(address)
                .and_then(|tls| tls.as_ref())
        } else {
            pool.monitor_tls.as_ref()
        };
        let began = Instant::now();
        let result = timeout(Duration::from_millis(timeout_ms), async {
            if let Some(monitor) = monitor
                && monitor.is_datagram()
            {
                let source = Self::backend_source(&self.config, pool, true, *address).await?;
                let device = pool
                    .config
                    .backend_vlan
                    .as_ref()
                    .map(|v| self.config.network.device(v));
                return monitor.probe_datagram(*address, source, device).await;
            }
            let stream = Self::connect_backend(&self.config, pool, true, *address)
                .await
                .context("monitor connection failed")?;
            if monitor.is_none_or(|m| matches!(m.check, crate::monitor::Check::Tcp {})) {
                if let Some((tls, name)) = &pool.server_tls {
                    let mut checked = tls
                        .connect(name.clone().unwrap_or_else(|| address.ip().into()), stream)
                        .await
                        .context("server TLS probe verification/handshake failed")?;
                    // Send close_notify rather than resetting a successful probe.
                    checked.shutdown().await.context("close server TLS probe")?;
                }
            } else if let Some(monitor) = monitor {
                monitor.probe(stream, monitor_tls).await?;
            }
            anyhow::Ok(())
        })
        .await;
        let error = match result {
            Ok(Ok(())) => None,
            Ok(Err(e)) => Some(e.to_string()),
            Err(_) => Some("monitor deadline exceeded".into()),
        };
        let mut members = pool.members.lock().unwrap();
        let member = &mut members[i];
        member.last_checked = Some(began);
        member.last_probe = Some(crate::storage::now());
        member.probe_latency_ms = Some(began.elapsed().as_millis() as u64);
        member.traffic.probe_latency.record(began.elapsed());
        pool.traffic.probe_latency.record(began.elapsed());
        member.probe_error = error;
        if member.probe_error.is_none() {
            member.successes = member.successes.saturating_add(1);
            member.misses = 0;
            if member.successes >= rise {
                member.healthy = true;
            }
        } else {
            member.misses = member.misses.saturating_add(1);
            member.successes = 0;
            if member.misses >= fall {
                member.healthy = false;
            }
        }
    }
    pub fn start(
        self: &Arc<Self>,
        listeners: Vec<Option<Listener>>,
        stop: CancellationToken,
        tasks: &TaskTracker,
        sessions: (&TaskTracker, CancellationToken),
        active: Arc<AtomicUsize>,
    ) {
        for pool in self
            .pools
            .iter()
            .chain(&self.node_pools)
            .filter(|p| p.config.enabled)
            .cloned()
        {
            let runtime = self.clone();
            let health_stop = stop.clone();
            // Poll at the shortest effective member interval; slower checks are skipped above.
            let seconds = pool
                .config
                .members
                .iter()
                .map(|address| {
                    self.config
                        .nodes
                        .iter()
                        .find(|n| n.address == *address)
                        .and_then(|n| n.monitor.as_ref())
                        .or(pool.config.monitor.as_ref())
                        .and_then(|name| {
                            self.config.health_monitors.iter().find(|m| &m.name == name)
                        })
                        .map_or(self.config.health_interval_secs, |m| m.interval_secs)
                })
                .min()
                .unwrap_or(self.config.health_interval_secs);
            tasks.spawn(async move {
                let period = Duration::from_secs(seconds);
                let mut interval = tokio::time::interval(period);
                interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
                loop { tokio::select! { _ = health_stop.cancelled() => break, _ = interval.tick() => { tokio::select! { _ = health_stop.cancelled() => break, _ = runtime.probe_pool(&pool, Some(seconds)) => {} } } } }
            });
        }
        for (pool, listener) in self.pools.iter().cloned().zip(listeners) {
            let Some(listener) = listener else {
                continue;
            };
            let listener = match listener {
                Listener::Udp(socket) => {
                    self.start_udp(pool, socket, stop.clone(), tasks, active.clone());
                    continue;
                }
                Listener::Tcp(socket) => socket,
            };
            let stop = stop.clone();
            let tracker = sessions.0.clone();
            let session_stop = sessions.1.clone();
            let active = active.clone();
            let config = self.config.clone();
            let inspection = self.inspection.clone();
            let inspection_generation = self.inspection_generation;
            tasks.spawn(async move {
                loop {
                    let accepted = tokio::select! { _ = stop.cancelled() => break, result = listener.accept() => result };
                    let (client, source) = match accepted { Ok(v) => v, Err(e) => { tracing::error!(%e, "accept failed"); stop.cancel(); break; } };
                    pool.traffic.accepted.fetch_add(1, Ordering::Relaxed);
                    if active.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < config.max_connections).then_some(n + 1)).is_err() { inspection.reject(crate::inspection::Rejection::GlobalLimit); pool.traffic.rejected.fetch_add(1, Ordering::Relaxed); continue; }
                    let permit = Admission(active.clone());
                    if pool.config.http.is_some() {
                        let Some(capacity) = crate::admission::Permit::take(&pool.admission,pool.config.connection_limit) else {inspection.reject(crate::inspection::Rejection::VirtualLimit); pool.traffic.rejected.fetch_add(1,Ordering::Relaxed); continue;};
                        let flow=inspection.observe(&pool.config.name,source,crate::inspection::Protocol::Http,None,inspection_generation);
                        let observation=crate::inspection::Context {entry:flow.as_ref().map(crate::inspection::Guard::entry),registry:inspection.clone()};
                        let pool = pool.clone(); let config = config.clone();
                        let traffic_permit = pool.traffic.enter();
                        tracker.spawn(session_stop.clone().run_until_cancelled_owned(async move {
                            let _permit = permit; let _capacity = capacity; let _traffic_permit = traffic_permit; let _flow=flow;
                            let client: Box<dyn HttpStream> = if let Some(tls) = &pool.tls {
                                match timeout(Duration::from_millis(config.connect_timeout_ms),tls.accept(client)).await {
                                    Ok(Ok(stream)) => Box::new(stream),
                                    _ => {pool.traffic.failures.fetch_add(1,Ordering::Relaxed); pool.traffic.transport_errors.fetch_add(1,Ordering::Relaxed); return;}
                                }
                            } else {Box::new(client)};
                            if let Some(entry)=&observation.entry {entry.http();}
                            let result = timeout(Duration::from_secs(config.session_timeout_secs),crate::http_proxy::serve(client,pool.clone(),config,source.ip(),observation)).await;
                            match result { Ok(Ok(())) => {}, Err(_) => {pool.traffic.failures.fetch_add(1,Ordering::Relaxed); pool.traffic.session_timeouts.fetch_add(1,Ordering::Relaxed);}, Ok(Err(_)) => {pool.traffic.failures.fetch_add(1,Ordering::Relaxed); pool.traffic.transport_errors.fetch_add(1,Ordering::Relaxed);} }
                        }));
                        continue;
                    }
                    let Some(reservation) = pool.reserve(source.ip()) else { inspection.reject(crate::inspection::Rejection::NoEligibleBackend); pool.traffic.rejected.fetch_add(1, Ordering::Relaxed); continue; };
                    let address=reservation.pool.members.lock().unwrap()[reservation.index].address;
                    let flow=inspection.observe(&pool.config.name,source,crate::inspection::Protocol::Tcp,Some(address),inspection_generation);
                    let traffic_permit = pool.traffic.enter();
                    let config = config.clone();
                    tracker.spawn(session_stop.clone().run_until_cancelled_owned(async move {
                        let _permit = permit;
                        let _traffic_permit = traffic_permit;
                        let _flow=flow;
                        trait Stream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
                        impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> Stream for T {}
                        let client: Box<dyn Stream> = if let Some(tls) = &reservation.pool.tls {
                            match timeout(Duration::from_millis(config.connect_timeout_ms), tls.accept(client)).await {
                                Ok(Ok(stream)) => Box::new(stream),
                                _ => { reservation.pool.members.lock().unwrap()[reservation.index].failures += 1; reservation.pool.members.lock().unwrap()[reservation.index].traffic.failures.fetch_add(1, Ordering::Relaxed); reservation.pool.traffic.failures.fetch_add(1, Ordering::Relaxed); reservation.pool.traffic.transport_errors.fetch_add(1, Ordering::Relaxed); return; }
                            }
                        } else { Box::new(client) };
                        let connect_started=Instant::now();
                        let result = timeout(Duration::from_millis(config.connect_timeout_ms), async {
                            let raw = Self::connect_backend(&config, &reservation.pool, false, address).await?;
                            let stream: Box<dyn Stream> = if let Some((tls,name)) = &reservation.pool.server_tls {
                                Box::new(tls.connect(name.clone().unwrap_or_else(|| address.ip().into()),raw).await?)
                            } else {Box::new(raw)};
                            std::io::Result::Ok(stream)
                        }).await;
                        match result {
                            Ok(Ok(backend)) => {
                                if let Some(flow)=&_flow {flow.entry().forwarding();}
                                reservation.pool.traffic.connect_latency.record(connect_started.elapsed());
                                reservation.pool.members.lock().unwrap()[reservation.index].traffic.connect_latency.record(connect_started.elapsed());
                                let mut client = crate::traffic::Counted { stream: client, pool: reservation.pool.clone(), index: reservation.index, backend: false };
                                let mut backend = crate::traffic::Counted { stream: backend, pool: reservation.pool.clone(), index: reservation.index, backend: true };
                                let result = timeout(Duration::from_secs(config.session_timeout_secs), tokio::io::copy_bidirectional(&mut client, &mut backend)).await;
                                let mut members = reservation.pool.members.lock().unwrap();
                                let member = &mut members[reservation.index];
                                match result { Ok(Ok(_)) => { member.completed += 1; member.traffic.completed.fetch_add(1, Ordering::Relaxed); reservation.pool.traffic.completed.fetch_add(1, Ordering::Relaxed); }, _ => { member.failures += 1; member.traffic.failures.fetch_add(1, Ordering::Relaxed); reservation.pool.traffic.failures.fetch_add(1, Ordering::Relaxed); if result.is_err() { reservation.pool.traffic.session_timeouts.fetch_add(1, Ordering::Relaxed); } else { reservation.pool.traffic.transport_errors.fetch_add(1, Ordering::Relaxed); } } }
                            }
                            _ => { let mut members = reservation.pool.members.lock().unwrap(); members[reservation.index].healthy = false; members[reservation.index].successes=0; members[reservation.index].misses=0; members[reservation.index].failures += 1; members[reservation.index].traffic.failures.fetch_add(1, Ordering::Relaxed); reservation.pool.traffic.failures.fetch_add(1, Ordering::Relaxed); reservation.pool.traffic.backend_errors.fetch_add(1, Ordering::Relaxed); }
                        }
                    }));
                }
            });
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn priority_groups_expand_for_capacity_and_preserve_live_slots_across_generations() {
        let mut config = Config::load(std::path::Path::new("examples/riverlb.toml")).unwrap();
        let vs = &mut config.virtual_servers[0];
        vs.members.truncate(2);
        vs.priority_group_min_active = 1;
        vs.connection_limit = 2;
        vs.member_priorities.insert(vs.members[0], 100);
        vs.member_priorities.insert(vs.members[1], 10);
        vs.member_connection_limits.insert(vs.members[0], 1);
        let registry = crate::admission::Registry::default();
        let make = |vs: VirtualServer| {
            let mut pool = Pool::new(vs).unwrap();
            pool.attach_admission(&registry);
            for member in pool.members.get_mut().unwrap().iter_mut() {
                member.healthy = true;
            }
            Arc::new(pool)
        };
        let old = make(vs.clone());
        let primary = old.reserve("192.0.2.1".parse().unwrap()).unwrap();
        assert_eq!(primary.index, 0);
        let current = make(vs.clone());
        let backup = current.reserve("192.0.2.2".parse().unwrap()).unwrap();
        assert_eq!(backup.index, 1);
        assert!(current.reserve("192.0.2.3".parse().unwrap()).is_none());
        assert_eq!(current.admission.load(Ordering::SeqCst), 2);
        assert_eq!(
            current.members.lock().unwrap()[0]
                .admission_active
                .load(Ordering::SeqCst),
            1
        );
        drop(primary);
        let recovered = current.reserve("192.0.2.3".parse().unwrap()).unwrap();
        assert_eq!(recovered.index, 0);
        drop(backup);
        drop(recovered);
        assert_eq!(current.admission.load(Ordering::SeqCst), 0);
        current.members.lock().unwrap()[0].healthy = false;
        assert_eq!(
            current.reserve("192.0.2.4".parse().unwrap()).unwrap().index,
            1
        );
        vs.priority_group_min_active = 2;
        let expanded = make(vs.clone());
        let selected = (0..4)
            .map(|_| {
                expanded
                    .reserve("192.0.2.5".parse().unwrap())
                    .unwrap()
                    .index
            })
            .collect::<Vec<_>>();
        assert!(selected.contains(&0) && selected.contains(&1));
        current.members.lock().unwrap()[0].healthy = true;
        current.members.lock().unwrap()[0].draining = true;
        assert_eq!(
            current.reserve("192.0.2.4".parse().unwrap()).unwrap().index,
            1
        );
    }
    #[test]
    fn weighted_least_connections_compares_load_ratios_and_excludes_draining() {
        let mut config = Config::load(std::path::Path::new("examples/riverlb.toml")).unwrap();
        let vs = &mut config.virtual_servers[0];
        vs.members.truncate(2);
        vs.algorithm = Algorithm::WeightedLeastConnections;
        vs.member_weights.insert(vs.members[0], 3);
        let pool = Arc::new(Pool::new(vs.clone()).unwrap());
        {
            let mut members = pool.members.lock().unwrap();
            for member in members.iter_mut() {
                member.healthy = true;
            }
            members[0].active = 5;
            members[1].active = 2;
        }
        // Five connections at weight 3 have lower normalized load than two at weight 1.
        assert_eq!(pool.reserve("192.0.2.1".parse().unwrap()).unwrap().index, 0);
        pool.members.lock().unwrap()[0].draining = true;
        assert_eq!(pool.reserve("192.0.2.1".parse().unwrap()).unwrap().index, 1);
        pool.members.lock().unwrap()[0].draining = false;
        let reservations = (0..40)
            .map(|_| pool.reserve("192.0.2.1".parse().unwrap()).unwrap())
            .collect::<Vec<_>>();
        let count = reservations.iter().filter(|r| r.index == 0).count();
        assert!(
            (29..=31).contains(&count),
            "unexpected weighted distribution {count}/40"
        );
    }
    #[test]
    fn masked_affinity_fixed_expiry_and_stateless_hash() {
        let mut config = Config::load(std::path::Path::new("examples/riverlb.toml")).unwrap();
        let vs = &mut config.virtual_servers[0];
        vs.persistence = crate::config::Persistence {
            timeout_secs: 10,
            max_entries: 100,
            ipv4_prefix: 24,
            refresh_on_use: false,
            ..Default::default()
        };
        let pool = Arc::new(Pool::new(vs.clone()).unwrap());
        for member in pool.members.lock().unwrap().iter_mut() {
            member.healthy = true;
        }
        let now = Instant::now();
        let first = pool
            .reserve_at("192.0.2.1".parse().unwrap(), now)
            .unwrap()
            .index;
        assert_eq!(
            first,
            pool.reserve_at("192.0.2.254".parse().unwrap(), now + Duration::from_secs(9))
                .unwrap()
                .index
        );
        assert_eq!(pool.affinity.lock().unwrap().len(), 1);
        assert_ne!(
            first,
            pool.reserve_at("192.0.2.2".parse().unwrap(), now + Duration::from_secs(11))
                .unwrap()
                .index
        );
        assert_eq!(pool.clear_persistence(), 1);
        vs.persistence = crate::config::Persistence {
            kind: crate::config::PersistenceKind::SourceHash,
            ipv4_prefix: 24,
            ..Default::default()
        };
        let pool = Arc::new(Pool::new(vs.clone()).unwrap());
        for member in pool.members.lock().unwrap().iter_mut() {
            member.healthy = true;
        }
        let first = pool.reserve("192.0.2.1".parse().unwrap()).unwrap().index;
        for _ in 0..10 {
            assert_eq!(
                first,
                pool.reserve("192.0.2.254".parse().unwrap()).unwrap().index
            );
        }
        assert!(pool.affinity.lock().unwrap().is_empty());
        assert_eq!(
            vs.persistence
                .key("2001:db8::abcd".parse().unwrap())
                .to_string(),
            "2001:db8::abcd"
        );
        vs.persistence.ipv6_prefix = 64;
        assert_eq!(
            vs.persistence
                .key("2001:db8::abcd".parse().unwrap())
                .to_string(),
            "2001:db8::"
        );
        vs.persistence.ipv6_prefix = 0;
        assert_eq!(
            vs.persistence
                .key("2001:db8::abcd".parse().unwrap())
                .to_string(),
            "::"
        );
    }
    #[test]
    fn weighted_selection_ratios_and_health_exclusion() {
        let mut config = Config::load(std::path::Path::new("examples/riverlb.toml")).unwrap();
        let vs = &mut config.virtual_servers[0];
        vs.algorithm = Algorithm::WeightedRoundRobin;
        vs.members.truncate(2);
        vs.member_weights.insert(vs.members[0], 3);
        let pool = Arc::new(Pool::new(vs.clone()).unwrap());
        for m in pool.members.lock().unwrap().iter_mut() {
            m.healthy = true;
        }
        let source = "192.0.2.1".parse().unwrap();
        let mut counts = [0, 0];
        for _ in 0..400 {
            counts[pool.reserve(source).unwrap().index] += 1;
        }
        assert_eq!(counts, [300, 100]);
        pool.members.lock().unwrap()[0].healthy = false;
        for _ in 0..20 {
            assert_eq!(pool.reserve(source).unwrap().index, 1);
        }
        pool.members.lock().unwrap()[0].healthy = true;
        counts = [0, 0];
        for _ in 0..400 {
            counts[pool.reserve(source).unwrap().index] += 1;
        }
        assert_eq!(counts, [300, 100]);
    }
    #[test]
    fn draining_excludes_new_and_persistent_connections_but_keeps_reservations() {
        let mut config = Config::load(std::path::Path::new("examples/riverlb.toml")).unwrap();
        config.virtual_servers[0].persistence = crate::config::Persistence {
            timeout_secs: 120,
            max_entries: 100,
            ..Default::default()
        };
        let pool = Arc::new(Pool::new(config.virtual_servers.remove(0)).unwrap());
        for m in pool.members.lock().unwrap().iter_mut() {
            m.healthy = true;
        }
        let source = "192.0.2.1".parse().unwrap();
        let existing = pool.reserve(source).unwrap();
        pool.members.lock().unwrap()[existing.index].draining = true;
        let next = pool.reserve(source).unwrap();
        assert_ne!(existing.index, next.index);
        assert_eq!(pool.members.lock().unwrap()[existing.index].active, 1);
        for m in pool.members.lock().unwrap().iter_mut() {
            m.draining = true;
        }
        assert!(pool.reserve(source).is_none());
        drop(existing);
        drop(next);
        assert!(pool.members.lock().unwrap().iter().all(|m| m.active == 0));
    }
    #[test]
    fn selection_reserves_and_releases_and_excludes_unhealthy() {
        let mut config = Config::load(std::path::Path::new("examples/riverlb.toml")).unwrap();
        config.virtual_servers[0].algorithm = Algorithm::LeastConnections;
        let pool = Arc::new(Pool::new(config.virtual_servers.remove(0)).unwrap());
        let source = "127.0.0.1".parse().unwrap();
        assert!(pool.reserve(source).is_none());
        for member in pool.members.lock().unwrap().iter_mut() {
            member.healthy = true;
        }
        let a = pool.reserve(source).unwrap();
        let b = pool.reserve(source).unwrap();
        assert_ne!(a.index, b.index);
        drop(a);
        drop(b);
        assert!(pool.members.lock().unwrap().iter().all(|m| m.active == 0));
    }
    #[test]
    fn persistence_reuses_expires_fails_over_and_bounds_records() {
        let mut config = Config::load(std::path::Path::new("examples/riverlb.toml")).unwrap();
        let vs = &mut config.virtual_servers[0];
        vs.persistence = crate::config::Persistence {
            timeout_secs: 10,
            max_entries: 1,
            ..Default::default()
        };
        let pool = Arc::new(Pool::new(vs.clone()).unwrap());
        for m in pool.members.lock().unwrap().iter_mut() {
            m.healthy = true;
        }
        let source = "192.0.2.1".parse().unwrap();
        let now = Instant::now();
        let first = pool.reserve_at(source, now).unwrap().index;
        assert_eq!(
            pool.reserve_at(source, now + Duration::from_secs(9))
                .unwrap()
                .index,
            first
        );
        // Reuse refreshes the idle timeout: the original deadline has passed.
        assert_eq!(
            pool.reserve_at(source, now + Duration::from_secs(11))
                .unwrap()
                .index,
            first
        );
        let other = "192.0.2.2".parse().unwrap();
        drop(pool.reserve_at(other, now + Duration::from_secs(12)));
        assert_eq!(pool.affinity.lock().unwrap().len(), 1);
        pool.members.lock().unwrap()[first].healthy = false;
        let replacement = pool
            .reserve_at(source, now + Duration::from_secs(13))
            .unwrap()
            .index;
        assert_ne!(first, replacement);
        pool.members.lock().unwrap()[first].healthy = true;
        drop(pool.reserve_at(source, now + Duration::from_secs(24)));
        assert_eq!(
            pool.affinity.lock().unwrap()[&source].1,
            now + Duration::from_secs(34)
        );
        assert_eq!(pool.affinity.lock().unwrap().len(), 1);
    }
    #[test]
    fn metadata_edits_keep_health_but_monitor_inputs_reset_it() {
        let config = Config::load(std::path::Path::new("examples/riverlb.toml")).unwrap();
        let mut config = config;
        config.nodes.push(crate::config::Node {
            name: "backend-node".into(),
            address: config.virtual_servers[0].members[0],
            description: String::new(),
            enabled: true,
            monitor: None,
        });
        let previous = Runtime::new(config.clone()).unwrap();
        {
            let mut members = previous.pools[0].members.lock().unwrap();
            members[0].healthy = true;
            members[0].last_probe = Some(123);
            members[0].successes = 2;
            members[0].misses = 1;
        }
        let mut metadata = config.clone();
        metadata.virtual_servers[0].description = "updated description".into();
        metadata.nodes[0].description = "updated node description".into();
        let next = Runtime::new(metadata).unwrap();
        next.inherit_health(&previous);
        let members = next.pools[0].members.lock().unwrap();
        assert!(members[0].healthy);
        assert_eq!(members[0].last_probe, Some(123));
        assert_eq!(members[0].successes, 2);
        assert_eq!(members[0].misses, 1);
        drop(members);
        let mut changed = config;
        changed.connect_timeout_ms += 1;
        let next = Runtime::new(changed).unwrap();
        next.inherit_health(&previous);
        assert!(!next.pools[0].members.lock().unwrap()[0].healthy);
        assert!(
            next.pools[0].members.lock().unwrap()[0]
                .last_probe
                .is_none()
        );
    }
    #[tokio::test]
    async fn probe_thresholds_require_consecutive_results() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut config = Config::load(std::path::Path::new("examples/riverlb.toml")).unwrap();
        config.health_rise = 2;
        config.health_fall = 2;
        config.virtual_servers[0].members = vec![listener.local_addr().unwrap()];
        let runtime = Runtime::new(config).unwrap();
        runtime.probe().await;
        assert!(!runtime.pools[0].members.lock().unwrap()[0].healthy);
        runtime.probe().await;
        assert!(runtime.pools[0].members.lock().unwrap()[0].healthy);
        drop(listener);
        // The reactor can retain the dropped listener until its pending event is retired.
        // Establish that the test backend is closed before checking failure streaks.
        timeout(Duration::from_secs(1), async {
            loop {
                if TcpStream::connect(runtime.pools[0].config.members[0])
                    .await
                    .is_err()
                {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .unwrap();
        runtime.probe().await;
        assert!(runtime.pools[0].members.lock().unwrap()[0].healthy);
        runtime.probe().await;
        assert!(!runtime.pools[0].members.lock().unwrap()[0].healthy);
    }
}
