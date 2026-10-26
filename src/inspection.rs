//! Bounded, nonblocking observation of live traffic. Never owns sockets or payloads.
use axum::{
    Extension, Json,
    extract::{Query, State},
    http::StatusCode,
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU8, AtomicU64, Ordering},
    },
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

pub const CAPACITY: usize = 4096;
const PAGE_MAX: usize = 200;
const TTL: Duration = Duration::from_secs(5);
const PAGES_PER_SECOND: u32 = 20;
#[derive(Clone, Copy, Serialize, Deserialize, clap::ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Http,
    Udp,
}
#[derive(Clone, Copy, Serialize, Deserialize, clap::ValueEnum, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    Connecting,
    Forwarding,
    Http,
}
#[derive(Clone, Copy)]
pub enum Rejection {
    GlobalLimit = 0,
    VirtualLimit = 1,
    NoEligibleBackend = 2,
    UdpQueue = 3,
}
struct Backend {
    address: Option<SocketAddr>,
    updated: Instant,
}
pub struct Entry {
    id: u64,
    name: String,
    source: SocketAddr,
    protocol: Protocol,
    generation: u64,
    began: Instant,
    alive: AtomicBool,
    phase: AtomicU8,
    backend: Mutex<Backend>,
    sample_tick: AtomicU64,
}
#[derive(Clone)]
pub struct Context {
    pub entry: Option<Arc<Entry>>,
    pub registry: Arc<Registry>,
}
pub struct Guard {
    entry: Arc<Entry>,
}
impl Guard {
    pub fn entry(&self) -> Arc<Entry> {
        self.entry.clone()
    }
}
impl Drop for Guard {
    fn drop(&mut self) {
        self.entry.alive.store(false, Ordering::Release);
    }
}
impl Entry {
    pub fn forwarding(&self) {
        self.phase.store(1, Ordering::Release);
    }
    pub fn http(&self) {
        self.phase.store(2, Ordering::Release);
    }
    /// HTTP keepalive can select many backends. Sample only addresses, at most once/second.
    pub fn selected(&self, address: SocketAddr) {
        let tick = (self.began.elapsed().as_millis().min(u64::MAX as u128) as u64).max(1);
        let last = self.sample_tick.load(Ordering::Relaxed);
        if last != 0 && tick.saturating_sub(last) < 1000 {
            return;
        }
        if self
            .sample_tick
            .compare_exchange(last, tick, Ordering::Relaxed, Ordering::Relaxed)
            .is_err()
        {
            return;
        }
        if let Ok(mut backend) = self.backend.try_lock() {
            *backend = Backend {
                address: Some(address),
                updated: Instant::now(),
            };
        }
    }
}
#[derive(Clone, Serialize)]
struct Row {
    id: u64,
    virtual_server: String,
    source: SocketAddr,
    protocol: Protocol,
    generation: u64,
    previous_generation: bool,
    state: Phase,
    age_ms: u64,
    backend: Option<SocketAddr>,
    backend_observation: &'static str,
    backend_observed_age_ms: Option<u64>,
    backend_available: bool,
}
struct Snapshot {
    id: u64,
    began: Instant,
    captured_at_ms: u64,
    revision: u64,
    rows: Vec<Row>,
    counters: Value,
}
struct Cache {
    snapshots: VecDeque<Arc<Snapshot>>,
    window: Instant,
    requests: u32,
}
pub struct Registry {
    epoch: String,
    stopped: AtomicBool,
    live: Mutex<BTreeMap<u64, Arc<Entry>>>,
    next: AtomicU64,
    generations: AtomicU64,
    rejected: [AtomicU64; 4],
    skipped_capacity: AtomicU64,
    skipped_busy: AtomicU64,
    skipped_name: AtomicU64,
    cache: Mutex<Cache>,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            epoch: format!("{:032x}", rand::random::<u128>()),
            stopped: AtomicBool::new(false),
            live: Mutex::new(BTreeMap::new()),
            next: AtomicU64::new(1),
            generations: AtomicU64::new(1),
            rejected: std::array::from_fn(|_| AtomicU64::new(0)),
            skipped_capacity: AtomicU64::new(0),
            skipped_busy: AtomicU64::new(0),
            skipped_name: AtomicU64::new(0),
            cache: Mutex::new(Cache {
                snapshots: VecDeque::with_capacity(6),
                window: Instant::now(),
                requests: 0,
            }),
        }
    }
}
impl Registry {
    pub fn generation(&self) -> u64 {
        self.generations.fetch_add(1, Ordering::Relaxed)
    }
    pub fn reject(&self, reason: Rejection) {
        self.rejected[reason as usize].fetch_add(1, Ordering::Relaxed);
    }
    pub fn observe(
        &self,
        name: &str,
        source: SocketAddr,
        protocol: Protocol,
        backend: Option<SocketAddr>,
        generation: u64,
    ) -> Option<Guard> {
        if self.stopped.load(Ordering::Acquire) {
            return None;
        }
        if name.len() > 128 {
            self.skipped_name.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let Ok(mut live) = self.live.try_lock() else {
            self.skipped_busy.fetch_add(1, Ordering::Relaxed);
            return None;
        };
        if self.stopped.load(Ordering::Acquire) {
            return None;
        }
        if live.len() >= CAPACITY {
            self.skipped_capacity.fetch_add(1, Ordering::Relaxed);
            return None;
        }
        let id = self
            .next
            .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
            .ok()?;
        let now = Instant::now();
        let entry = Arc::new(Entry {
            id,
            name: name.into(),
            source,
            protocol,
            generation,
            began: now,
            alive: AtomicBool::new(true),
            phase: AtomicU8::new(0),
            backend: Mutex::new(Backend {
                address: backend,
                updated: now,
            }),
            sample_tick: AtomicU64::new(0),
        });
        live.insert(id, entry.clone());
        Some(Guard { entry })
    }
    fn counters(&self) -> Value {
        json!({"global_limit":self.rejected[0].load(Ordering::Relaxed),"virtual_limit":self.rejected[1].load(Ordering::Relaxed),
        "no_eligible_backend_or_capacity":self.rejected[2].load(Ordering::Relaxed),"udp_queue_or_memory":self.rejected[3].load(Ordering::Relaxed),
        "observation_skipped_capacity":self.skipped_capacity.load(Ordering::Relaxed),"observation_skipped_contention":self.skipped_busy.load(Ordering::Relaxed),
        "observation_skipped_long_name":self.skipped_name.load(Ordering::Relaxed)})
    }
    fn maintain(&self) {
        self.live
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .retain(|_, entry| entry.alive.load(Ordering::Acquire));
        self.cache
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .snapshots
            .retain(|s| s.began.elapsed() < TTL);
    }
    fn page(
        &self,
        query: Page,
        generation: u64,
        revision: u64,
    ) -> Result<Value, (StatusCode, &'static str)> {
        if self.stopped.load(Ordering::Acquire) {
            return Err((StatusCode::SERVICE_UNAVAILABLE, "Inspection stopping"));
        }
        let bad = (
            StatusCode::BAD_REQUEST,
            "Invalid inspection page, filter or cursor",
        );
        if query.limit == 0
            || query.limit > PAGE_MAX
            || query.virtual_server.as_ref().is_some_and(|s| s.len() > 128)
            || query.cursor.as_ref().is_some_and(|s| s.len() > 128)
        {
            return Err(bad);
        }
        let fingerprint = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&json!([
                    query.virtual_server,
                    query.protocol,
                    query.source,
                    query.backend,
                    query.state
                ]))
                .unwrap()
            )
        );
        let now = Instant::now();
        let mut cache = self.cache.try_lock().map_err(|_| {
            (
                StatusCode::SERVICE_UNAVAILABLE,
                "Inspection busy; retry later",
            )
        })?;
        if now.duration_since(cache.window) >= Duration::from_secs(1) {
            cache.window = now;
            cache.requests = 0;
        }
        if cache.requests >= PAGES_PER_SECOND {
            return Err((
                StatusCode::TOO_MANY_REQUESTS,
                "Inspection rate limit; retry after one second",
            ));
        }
        cache.requests += 1;
        cache
            .snapshots
            .retain(|s| now.duration_since(s.began) < TTL);
        let (snapshot, offset) = if let Some(cursor) = &query.cursor {
            let fields = cursor.split(':').collect::<Vec<_>>();
            if fields.len() != 4 || fields[3] != fingerprint {
                return Err(bad);
            }
            if fields[0] != self.epoch {
                return Err((
                    StatusCode::GONE,
                    "Inspection snapshot belongs to a previous process",
                ));
            }
            let id = fields[1].parse::<u64>().map_err(|_| bad)?;
            let offset = fields[2].parse::<usize>().map_err(|_| bad)?;
            (
                cache
                    .snapshots
                    .iter()
                    .find(|s| s.id == id)
                    .cloned()
                    .ok_or((
                        StatusCode::GONE,
                        "Inspection snapshot expired; restart pagination",
                    ))?,
                offset,
            )
        } else {
            let latest = cache
                .snapshots
                .back()
                .filter(|s| now.duration_since(s.began) < Duration::from_secs(1))
                .cloned();
            let snapshot = if let Some(snapshot) = latest {
                snapshot
            } else {
                let live = self.live.try_lock().map_err(|_| {
                    (
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Inspection busy; retry later",
                    )
                })?;
                let rows = live
                    .values()
                    .filter(|e| e.alive.load(Ordering::Acquire))
                    .map(|e| {
                        let backend = e.backend.try_lock().ok();
                        Row {
                            id: e.id,
                            virtual_server: e.name.clone(),
                            source: e.source,
                            protocol: e.protocol,
                            generation: e.generation,
                            previous_generation: e.generation != generation,
                            state: match e.phase.load(Ordering::Acquire) {
                                1 => Phase::Forwarding,
                                2 => Phase::Http,
                                _ => Phase::Connecting,
                            },
                            age_ms: now
                                .saturating_duration_since(e.began)
                                .as_millis()
                                .min(u64::MAX as u128) as u64,
                            backend: backend.as_ref().and_then(|b| b.address),
                            backend_observation: if e.protocol == Protocol::Http {
                                "sampled_last_http_selection"
                            } else {
                                "selected_backend"
                            },
                            backend_observed_age_ms: backend
                                .as_ref()
                                .filter(|b| b.address.is_some())
                                .map(|b| {
                                    now.saturating_duration_since(b.updated)
                                        .as_millis()
                                        .min(u64::MAX as u128)
                                        as u64
                                }),
                            backend_available: backend.is_some(),
                        }
                    })
                    .collect();
                let id = self
                    .next
                    .fetch_update(Ordering::Relaxed, Ordering::Relaxed, |n| n.checked_add(1))
                    .map_err(|_| {
                        (
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Inspection identity exhausted",
                        )
                    })?;
                let snapshot = Arc::new(Snapshot {
                    id,
                    began: now,
                    captured_at_ms: SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis()
                        .min(u64::MAX as u128) as u64,
                    revision,
                    rows,
                    counters: self.counters(),
                });
                if cache.snapshots.len() >= 6 {
                    cache.snapshots.pop_front();
                }
                cache.snapshots.push_back(snapshot.clone());
                snapshot
            };
            (snapshot, 0)
        };
        let matches = |row: &&Row| {
            query
                .virtual_server
                .as_ref()
                .is_none_or(|v| v == &row.virtual_server)
                && query.protocol.is_none_or(|v| v == row.protocol)
                && query.source.is_none_or(|v| v == row.source.ip())
                && query.backend.is_none_or(|v| Some(v) == row.backend)
                && query.state.is_none_or(|v| v == row.state)
        };
        let total = snapshot.rows.iter().filter(matches).count();
        if offset > total {
            return Err(bad);
        }
        let rows = snapshot
            .rows
            .iter()
            .filter(matches)
            .skip(offset)
            .take(query.limit)
            .collect::<Vec<_>>();
        let next = offset + rows.len();
        Ok(
            json!({"schema":1,"snapshot":format!("{}:{}",self.epoch,snapshot.id),"captured_at_ms":snapshot.captured_at_ms,"configuration_revision":snapshot.revision,"snapshot_ttl_ms":TTL.as_millis(),
            "capacity":CAPACITY,"total":total,"rows":rows,"next_cursor":if next<total {Some(format!("{}:{}:{next}:{fingerprint}",self.epoch,snapshot.id))}else{None},"admission_and_coverage":snapshot.counters,"termination_supported":false}),
        )
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Page {
    #[serde(default = "page_size")]
    limit: usize,
    cursor: Option<String>,
    virtual_server: Option<String>,
    protocol: Option<Protocol>,
    source: Option<IpAddr>,
    backend: Option<SocketAddr>,
    state: Option<Phase>,
}
fn page_size() -> usize {
    100
}
pub async fn endpoint(
    State(control): State<Arc<crate::control::Control>>,
    Query(query): Query<Page>,
    Extension(principal): Extension<crate::auth::Principal>,
) -> Result<Json<Value>, (StatusCode, &'static str)> {
    if !matches!(
        principal.role,
        crate::auth::Role::Administrator | crate::auth::Role::Operator
    ) || !matches!(
        principal.token_scope,
        None | Some(crate::auth::TokenScope::Read) | Some(crate::auth::TokenScope::Configure)
    ) {
        return Err((
            StatusCode::FORBIDDEN,
            "Flow inspection requires an administrator or operator with read/configure scope",
        ));
    }
    let (registry, generation, revision) = {
        let current = control.generation.lock().await;
        (
            current.runtime.inspection.clone(),
            current.runtime.inspection_generation,
            current.revision,
        )
    };
    registry.page(query, generation, revision).map(Json)
}
pub async fn start(control: Arc<crate::control::Control>) {
    let registry = control.generation.lock().await.runtime.inspection.clone();
    let stop = control.stop.clone();
    control.renewals.spawn(async move {
        let mut timer=tokio::time::interval(Duration::from_secs(1));timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {tokio::select!{_ = stop.cancelled()=>{registry.stopped.store(true,Ordering::Release);registry.live.lock().unwrap_or_else(|e|e.into_inner()).clear();registry.cache.lock().unwrap_or_else(|e|e.into_inner()).snapshots.clear();break;},_=timer.tick()=>registry.maintain()}}
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    fn query(limit: usize, cursor: Option<String>) -> Page {
        Page {
            limit,
            cursor,
            virtual_server: None,
            protocol: None,
            source: None,
            backend: None,
            state: None,
        }
    }
    fn observe(registry: &Registry) -> Option<Guard> {
        registry.observe(
            "web",
            "127.0.0.1:50000".parse().unwrap(),
            Protocol::Tcp,
            Some("127.0.0.1:8080".parse().unwrap()),
            1,
        )
    }
    #[test]
    fn capacity_churn_and_closed_retention_are_bounded() {
        let registry = Registry::default();
        let mut guards = (0..CAPACITY)
            .map(|_| observe(&registry).unwrap())
            .collect::<Vec<_>>();
        for _ in 0..10000 {
            assert!(observe(&registry).is_none());
        }
        assert_eq!(registry.live.lock().unwrap().len(), CAPACITY);
        assert_eq!(registry.skipped_capacity.load(Ordering::Relaxed), 10000);
        guards.clear();
        assert_eq!(registry.page(query(200, None), 1, 1).unwrap()["total"], 0);
        registry.maintain();
        assert!(registry.live.lock().unwrap().is_empty());
        assert!(observe(&registry).is_some());
    }
    #[test]
    fn cursors_keep_an_immutable_filtered_view_during_churn() {
        let registry = Registry::default();
        let guards = (0..500)
            .map(|_| observe(&registry).unwrap())
            .collect::<Vec<_>>();
        let first = registry.page(query(200, None), 1, 10).unwrap();
        let cursor = first["next_cursor"].as_str().unwrap().to_owned();
        drop(guards);
        registry.maintain();
        let _new = (0..20)
            .map(|_| observe(&registry).unwrap())
            .collect::<Vec<_>>();
        let second = registry
            .page(query(200, Some(cursor.clone())), 2, 11)
            .unwrap();
        assert_eq!(second["snapshot"], first["snapshot"]);
        assert_eq!(second["configuration_revision"], 10);
        assert_eq!(second["total"], 500);
        assert!(first["rows"].as_array().unwrap().iter().all(|a| {
            second["rows"]
                .as_array()
                .unwrap()
                .iter()
                .all(|b| a["id"] != b["id"])
        }));
        let mut different = query(200, Some(cursor));
        different.protocol = Some(Protocol::Udp);
        assert_eq!(
            registry.page(different, 2, 11).unwrap_err().0,
            StatusCode::BAD_REQUEST
        );
        registry.cache.lock().unwrap().snapshots.clear();
        assert_eq!(
            registry
                .page(
                    query(200, Some(first["next_cursor"].as_str().unwrap().into())),
                    2,
                    11
                )
                .unwrap_err()
                .0,
            StatusCode::GONE
        );
    }
    #[test]
    fn management_contention_never_waits_on_the_data_plane() {
        let registry = Arc::new(Registry::default());
        let held = registry.live.lock().unwrap();
        let copy = registry.clone();
        let (tx, rx) = std::sync::mpsc::channel();
        let worker = std::thread::spawn(move || tx.send(observe(&copy).is_none()).unwrap());
        let result = rx.recv_timeout(Duration::from_secs(2));
        drop(held);
        worker.join().unwrap();
        assert!(result.unwrap());
        assert_eq!(registry.skipped_busy.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn page_rates_sizes_and_labels_have_hard_limits() {
        let registry = Registry::default();
        assert_eq!(
            registry.page(query(201, None), 1, 1).unwrap_err().0,
            StatusCode::BAD_REQUEST
        );
        for _ in 0..PAGES_PER_SECOND {
            registry.page(query(1, None), 1, 1).unwrap();
        }
        assert_eq!(
            registry.page(query(1, None), 1, 1).unwrap_err().0,
            StatusCode::TOO_MANY_REQUESTS
        );
        assert_eq!(registry.cache.lock().unwrap().snapshots.len(), 1);
        assert!(
            registry
                .observe(
                    &"x".repeat(129),
                    "127.0.0.1:1".parse().unwrap(),
                    Protocol::Udp,
                    None,
                    1
                )
                .is_none()
        );
        assert_eq!(registry.skipped_name.load(Ordering::Relaxed), 1);
    }
    #[test]
    fn http_selection_sampling_is_rate_bounded_without_request_data() {
        let registry = Registry::default();
        let flow = registry
            .observe(
                "http",
                "127.0.0.1:1".parse().unwrap(),
                Protocol::Http,
                None,
                1,
            )
            .unwrap();
        let entry = flow.entry();
        entry.http();
        entry.selected("127.0.0.1:80".parse().unwrap());
        for _ in 0..10000 {
            entry.selected("127.0.0.1:81".parse().unwrap());
        }
        let page = registry.page(query(1, None), 2, 1).unwrap();
        assert_eq!(page["rows"][0]["backend"], "127.0.0.1:80");
        assert_eq!(page["rows"][0]["previous_generation"], true);
        assert_eq!(
            page["rows"][0]["backend_observation"],
            "sampled_last_http_selection"
        );
    }
}

#[cfg(test)]
mod restart_tests {
    use super::*;
    #[test]
    fn previous_process_cursors_cannot_match_reused_numeric_ids() {
        let old = Registry::default();
        let _old = (0..2)
            .map(|_| {
                old.observe("x", "127.0.0.1:1".parse().unwrap(), Protocol::Tcp, None, 1)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        let query = || Page {
            limit: 1,
            cursor: None,
            virtual_server: None,
            protocol: None,
            source: None,
            backend: None,
            state: None,
        };
        let first = old.page(query(), 1, 1).unwrap();
        let new = Registry::default();
        let _new = (0..2)
            .map(|_| {
                new.observe("x", "127.0.0.1:1".parse().unwrap(), Protocol::Tcp, None, 1)
                    .unwrap()
            })
            .collect::<Vec<_>>();
        new.page(query(), 1, 1).unwrap();
        let mut stale = query();
        stale.cursor = Some(first["next_cursor"].as_str().unwrap().into());
        assert_eq!(new.page(stale, 1, 1).unwrap_err().0, StatusCode::GONE);
    }
}
