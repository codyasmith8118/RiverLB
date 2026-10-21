//! Live application-byte counters; socket writes are counted without a DB access.
use crate::runtime::Pool;
use serde::{Deserialize, Serialize};
use std::{
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

#[derive(Default)]
pub struct Traffic {
    pub accepted: AtomicU64,
    pub rejected: AtomicU64,
    pub current: AtomicU64,
    pub peak: AtomicU64,
    pub completed: AtomicU64,
    pub failures: AtomicU64,
    pub session_timeouts: AtomicU64,
    pub transport_errors: AtomicU64,
    pub backend_errors: AtomicU64,
    pub connect_latency: Latency,
    pub response_latency: Latency,
    pub probe_latency: Latency,
    pub up: AtomicU64,
    pub down: AtomicU64,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct Snapshot {
    pub accepted: u64,
    pub rejected: u64,
    pub current: u64,
    pub peak: u64,
    pub completed: u64,
    pub failures: u64,
    pub session_timeouts: u64,
    pub transport_errors: u64,
    pub backend_errors: u64,
    pub connect_latency: LatencySnapshot,
    pub response_latency: LatencySnapshot,
    pub probe_latency: LatencySnapshot,
    pub bytes_in: u64,
    pub bytes_out: u64,
}
#[derive(Clone, Default, Deserialize, Serialize)]
#[serde(default)]
pub struct LatencySnapshot {
    pub samples: u64,
    pub total_us: u64,
    pub min_us: u64,
    pub max_us: u64,
    pub last_us: u64,
    pub average_ms: Option<f64>,
    pub minimum_ms: Option<f64>,
    pub maximum_ms: Option<f64>,
    pub last_ms: Option<f64>,
}
impl LatencySnapshot {
    fn calculate(&mut self) {
        if self.samples > 0 {
            self.average_ms = Some(self.total_us as f64 / self.samples as f64 / 1000.0);
            self.minimum_ms = Some(self.min_us as f64 / 1000.0);
            self.maximum_ms = Some(self.max_us as f64 / 1000.0);
            self.last_ms = Some(self.last_us as f64 / 1000.0);
        }
    }
    pub fn merge(&mut self, other: &Self) {
        if other.samples == 0 {
            return;
        }
        self.min_us = if self.samples == 0 {
            other.min_us
        } else {
            self.min_us.min(other.min_us)
        };
        self.max_us = self.max_us.max(other.max_us);
        self.samples += other.samples;
        self.total_us += other.total_us;
        self.last_us = other.last_us;
        self.calculate();
    }
}
#[derive(Default)]
pub struct Latency(std::sync::Mutex<LatencySnapshot>);
impl Latency {
    pub fn record(&self, elapsed: std::time::Duration) {
        let us = elapsed.as_micros().min(u64::MAX as u128) as u64;
        let mut s = self.0.lock().unwrap();
        s.min_us = if s.samples == 0 { us } else { s.min_us.min(us) };
        s.max_us = s.max_us.max(us);
        s.samples += 1;
        s.total_us = s.total_us.saturating_add(us);
        s.last_us = us;
    }
    pub fn snapshot(&self) -> LatencySnapshot {
        let mut s = self.0.lock().unwrap().clone();
        s.calculate();
        s
    }
    fn restore(&self, s: LatencySnapshot) {
        *self.0.lock().unwrap() = s;
    }
}
pub type Registry = Arc<
    std::sync::Mutex<
        std::collections::HashMap<(String, Option<std::net::SocketAddr>), std::sync::Weak<Traffic>>,
    >,
>;
pub fn counter(
    registry: &Registry,
    name: &str,
    member: Option<std::net::SocketAddr>,
) -> Arc<Traffic> {
    let mut entries = registry.lock().unwrap();
    let entry = entries.entry((name.into(), member)).or_default();
    if let Some(counter) = entry.upgrade() {
        return counter;
    }
    let counter = Arc::new(Traffic::default());
    *entry = Arc::downgrade(&counter);
    counter
}
pub fn prune(registry: &Registry) {
    registry
        .lock()
        .unwrap()
        .retain(|_, value| value.strong_count() > 0);
}
impl Traffic {
    pub fn member_enter(&self) {
        self.accepted.fetch_add(1, Ordering::Relaxed);
        let current = self.current.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak.fetch_max(current, Ordering::Relaxed);
    }
    pub fn restore(&self, s: Snapshot) {
        for (counter, value) in [
            (&self.accepted, s.accepted),
            (&self.rejected, s.rejected),
            (&self.peak, s.peak.max(self.current.load(Ordering::Relaxed))),
            (&self.completed, s.completed),
            (&self.failures, s.failures),
            (&self.session_timeouts, s.session_timeouts),
            (&self.transport_errors, s.transport_errors),
            (&self.backend_errors, s.backend_errors),
            (&self.up, s.bytes_in),
            (&self.down, s.bytes_out),
        ] {
            counter.store(value, Ordering::Relaxed);
        }
        self.connect_latency.restore(s.connect_latency);
        self.response_latency.restore(s.response_latency);
        self.probe_latency.restore(s.probe_latency);
    }
    pub fn reset(&self) {
        self.restore(Snapshot::default());
    }
}
pub fn restore_runtime(
    runtime: &crate::runtime::Runtime,
    saved: &serde_json::Value,
) -> anyhow::Result<()> {
    for pool in &runtime.pools {
        let servers = if saved.is_array() {
            saved
        } else {
            &saved["virtual_servers"]
        };
        let Some(server) = servers.as_array().and_then(|servers| {
            servers
                .iter()
                .find(|s| s["name"].as_str() == Some(&pool.config.name))
        }) else {
            continue;
        };
        if !server["traffic"].is_null() {
            pool.traffic
                .restore(serde_json::from_value(server["traffic"].clone())?);
        }
        for member in pool.members.lock().unwrap().iter() {
            if let Some(saved) = server["members"].as_array().and_then(|members| {
                members
                    .iter()
                    .find(|m| m["address"].as_str() == Some(&member.address.to_string()))
            }) && !saved["traffic"].is_null()
            {
                member
                    .traffic
                    .restore(serde_json::from_value(saved["traffic"].clone())?);
            }
        }
    }
    Ok(())
}
pub fn zero_snapshot(value: &mut serde_json::Value) {
    if let Some(pools) = value["pools"].as_array_mut() {
        for pool in pools {
            zero_traffic(&mut pool["traffic"]);
            pool["traffic"]["peak"] = serde_json::Value::Null;
        }
    }
    if let Some(servers) = value["virtual_servers"].as_array_mut() {
        for server in servers {
            zero_traffic(&mut server["traffic"]);
            if let Some(members) = server["members"].as_array_mut() {
                for member in members {
                    zero_traffic(&mut member["traffic"]);
                    for key in [
                        "total_connections",
                        "completed",
                        "failures",
                        "bytes_to_backend",
                        "bytes_to_client",
                    ] {
                        member[key] = 0.into();
                    }
                    member["peak_connections"] = member["active"].clone();
                }
            }
        }
    }
}
fn zero_traffic(value: &mut serde_json::Value) {
    let mut zero = serde_json::to_value(Snapshot::default()).unwrap();
    zero["current"] = value["current"].clone();
    zero["peak"] = value["current"].clone();
    *value = zero;
}
pub fn serialize<S: serde::Serializer>(
    traffic: &Arc<Traffic>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    traffic.snapshot().serialize(serializer)
}
pub fn members_value(members: &[crate::runtime::Member]) -> serde_json::Value {
    serde_json::Value::Array(
        members
            .iter()
            .map(|m| {
                let mut value = serde_json::to_value(m).expect("member serialization");
                let s = m.traffic.snapshot();
                for (key, n) in [
                    ("active", s.current),
                    ("total_connections", s.accepted),
                    ("peak_connections", s.peak),
                    ("completed", s.completed),
                    ("failures", s.failures),
                    ("bytes_to_backend", s.bytes_in),
                    ("bytes_to_client", s.bytes_out),
                ] {
                    value[key] = n.into();
                }
                value
            })
            .collect(),
    )
}
impl Traffic {
    pub fn snapshot(&self) -> Snapshot {
        let get = |counter: &AtomicU64| counter.load(Ordering::Relaxed);
        Snapshot {
            accepted: get(&self.accepted),
            rejected: get(&self.rejected),
            current: get(&self.current),
            peak: get(&self.peak),
            completed: get(&self.completed),
            failures: get(&self.failures),
            session_timeouts: get(&self.session_timeouts),
            transport_errors: get(&self.transport_errors),
            backend_errors: get(&self.backend_errors),
            connect_latency: self.connect_latency.snapshot(),
            response_latency: self.response_latency.snapshot(),
            probe_latency: self.probe_latency.snapshot(),
            bytes_in: get(&self.up),
            bytes_out: get(&self.down),
        }
    }
    pub fn enter(self: &Arc<Self>) -> TrafficPermit {
        let current = self.current.fetch_add(1, Ordering::Relaxed) + 1;
        self.peak.fetch_max(current, Ordering::Relaxed);
        TrafficPermit(self.clone())
    }
}
pub struct TrafficPermit(Arc<Traffic>);
impl Drop for TrafficPermit {
    fn drop(&mut self) {
        self.0.current.fetch_sub(1, Ordering::Relaxed);
    }
}
pub struct Counted<S> {
    pub stream: S,
    pub pool: Arc<Pool>,
    pub index: usize,
    pub backend: bool,
}
impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(n)) = result {
            let mut members = self.pool.members.lock().unwrap();
            if self.backend {
                members[self.index].bytes_to_backend += n as u64;
                members[self.index]
                    .traffic
                    .up
                    .fetch_add(n as u64, Ordering::Relaxed);
                self.pool.traffic.up.fetch_add(n as u64, Ordering::Relaxed);
            } else {
                members[self.index].bytes_to_client += n as u64;
                members[self.index]
                    .traffic
                    .down
                    .fetch_add(n as u64, Ordering::Relaxed);
                self.pool
                    .traffic
                    .down
                    .fetch_add(n as u64, Ordering::Relaxed);
            }
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn reset_preserves_live_gauges_and_shared_counters() {
        let registry = Registry::default();
        let counter = counter(&registry, "web", None);
        let same = super::counter(&registry, "web", None);
        assert!(Arc::ptr_eq(&counter, &same));
        let permit = counter.enter();
        counter.accepted.fetch_add(3, Ordering::Relaxed);
        counter
            .response_latency
            .record(std::time::Duration::from_millis(20));
        counter.reset();
        let s = counter.snapshot();
        assert_eq!((s.accepted, s.current, s.peak), (0, 1, 1));
        assert_eq!(s.response_latency.samples, 0);
        drop(permit);
        assert_eq!(counter.snapshot().current, 0);
    }
    #[test]
    fn weighted_latency_merge_and_durable_restore() {
        let first = Traffic::default();
        for ms in [10, 20, 30] {
            first
                .connect_latency
                .record(std::time::Duration::from_millis(ms));
        }
        let second = Traffic::default();
        second
            .connect_latency
            .record(std::time::Duration::from_millis(100));
        let mut merged = first.snapshot().connect_latency;
        merged.merge(&second.snapshot().connect_latency);
        assert_eq!(
            (
                merged.samples,
                merged.average_ms,
                merged.minimum_ms,
                merged.maximum_ms
            ),
            (4, Some(40.0), Some(10.0), Some(100.0))
        );
        let saved = serde_json::to_value(first.snapshot()).unwrap();
        let restored = Traffic::default();
        restored.restore(serde_json::from_value(saved).unwrap());
        assert_eq!(restored.snapshot().connect_latency.average_ms, Some(20.0));
        assert_eq!(restored.snapshot().current, 0);
    }
}
