//! Logical-object slot counters survive runtime replacement without retaining closed sessions.
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicUsize, Ordering},
    },
};
pub type Registry = Arc<Mutex<HashMap<(String, Option<SocketAddr>), Weak<AtomicUsize>>>>;
pub fn counter(registry: &Registry, name: &str, member: Option<SocketAddr>) -> Arc<AtomicUsize> {
    let mut entries = registry.lock().unwrap();
    let entry = entries.entry((name.to_owned(), member)).or_default();
    if let Some(counter) = entry.upgrade() {
        return counter;
    }
    let counter = Arc::new(AtomicUsize::new(0));
    *entry = Arc::downgrade(&counter);
    counter
}
pub fn prune(registry: &Registry) {
    registry
        .lock()
        .unwrap()
        .retain(|_, value| value.strong_count() > 0);
}
pub struct Permit(Arc<AtomicUsize>);
impl Permit {
    pub fn take(counter: &Arc<AtomicUsize>, limit: usize) -> Option<Self> {
        counter
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (limit == 0 || count < limit).then_some(count + 1)
            })
            .ok()?;
        Some(Self(counter.clone()))
    }
}
impl Drop for Permit {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}
pub fn serialize<S: serde::Serializer>(
    counter: &Arc<AtomicUsize>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_u64(counter.load(Ordering::SeqCst) as u64)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn concurrent_reservations_never_exceed_limit_and_release_on_drop() {
        let counter = Arc::new(AtomicUsize::new(0));
        let ready = Arc::new(std::sync::Barrier::new(9));
        let release = Arc::new(std::sync::Barrier::new(9));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let (counter, ready, release) = (counter.clone(), ready.clone(), release.clone());
            threads.push(std::thread::spawn(move || {
                let permit = Permit::take(&counter, 3);
                ready.wait();
                release.wait();
                permit.is_some()
            }));
        }
        ready.wait();
        assert_eq!(counter.load(Ordering::SeqCst), 3);
        release.wait();
        assert_eq!(
            threads
                .into_iter()
                .map(|t| usize::from(t.join().unwrap()))
                .sum::<usize>(),
            3
        );
        assert_eq!(counter.load(Ordering::SeqCst), 0);
    }
}
