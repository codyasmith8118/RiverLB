//! Bounded UDP conversations: client endpoint -> connected backend socket.
use super::*;
use std::sync::OnceLock;
use tokio::{
    net::UdpSocket,
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
};

// Shared across virtual servers and config generations, including queued packets.
const QUEUED_BYTES: usize = 8 * 1024 * 1024;
fn packet_budget() -> Arc<Semaphore> {
    static BUDGET: OnceLock<Arc<Semaphore>> = OnceLock::new();
    BUDGET
        .get_or_init(|| Arc::new(Semaphore::new(QUEUED_BYTES)))
        .clone()
}
struct Packet {
    bytes: Vec<u8>,
    _budget: OwnedSemaphorePermit,
}
struct Flow {
    runtime: Arc<Runtime>,
    reservation: Reservation,
    listener: Arc<UdpSocket>,
    client: SocketAddr,
    incoming: mpsc::Receiver<Packet>,
    stop: CancellationToken,
    _admission: Admission,
    _traffic: crate::traffic::TrafficPermit,
}
impl Runtime {
    pub(super) fn start_udp(
        self: &Arc<Self>,
        pool: Arc<Pool>,
        listener: Arc<UdpSocket>,
        stop: CancellationToken,
        tasks: &TaskTracker,
        active: Arc<AtomicUsize>,
    ) {
        let runtime = self.clone();
        let tasks_for_flows = tasks.clone();
        tasks.spawn(async move {
            let mut flows: HashMap<SocketAddr, mpsc::Sender<Packet>> = HashMap::new();
            let mut buffer = vec![0; 65536];
            let budget = packet_budget();
            let mut cleanup = tokio::time::interval(Duration::from_secs(1));
            loop {
                let received = tokio::select! {
                    biased;
                    _ = stop.cancelled() => break,
                    _ = cleanup.tick() => { flows.retain(|_, sender| !sender.is_closed()); continue; }
                    received = listener.recv_from(&mut buffer) => received,
                };
                let (size, client) = match received {
                    Ok(value) => value,
                    Err(error) => { tracing::error!(%error, "UDP VIP receive failed"); stop.cancel(); break; }
                };
                let Ok(permit) = budget.clone().try_acquire_many_owned((size + 1) as u32) else {
                    runtime.inspection.reject(crate::inspection::Rejection::UdpQueue); pool.traffic.rejected.fetch_add(1, Ordering::Relaxed); continue;
                };
                let packet = Packet { bytes: buffer[..size].to_vec(), _budget: permit };
                if flows.get(&client).is_some_and(|sender| sender.is_closed()) { flows.remove(&client); }
                if let Some(sender) = flows.get(&client) {
                    if sender.try_send(packet).is_err() { runtime.inspection.reject(crate::inspection::Rejection::UdpQueue); pool.traffic.rejected.fetch_add(1, Ordering::Relaxed); }
                    continue;
                }
                pool.traffic.accepted.fetch_add(1, Ordering::Relaxed);
                if active.fetch_update(Ordering::SeqCst, Ordering::SeqCst, |n| (n < runtime.config.max_connections).then_some(n + 1)).is_err() {
                    runtime.inspection.reject(crate::inspection::Rejection::GlobalLimit); pool.traffic.rejected.fetch_add(1, Ordering::Relaxed); continue;
                }
                let admission = Admission(active.clone());
                let Some(reservation) = pool.reserve(client.ip()) else {
                    runtime.inspection.reject(crate::inspection::Rejection::NoEligibleBackend); pool.traffic.rejected.fetch_add(1, Ordering::Relaxed); continue;
                };
                let (sender, incoming) = mpsc::channel(8);
                // A new channel always has space for its first datagram.
                if sender.try_send(packet).is_err() { continue; }
                flows.insert(client, sender);
                let flow = Flow { runtime: runtime.clone(), reservation, listener: listener.clone(), client, incoming,
                    stop: stop.clone(), _admission: admission, _traffic: pool.traffic.enter() };
                tasks_for_flows.spawn(flow.run());
            }
        });
    }
}
impl Flow {
    async fn backend(&self, address: SocketAddr) -> std::io::Result<UdpSocket> {
        let source =
            Runtime::backend_source(&self.runtime.config, &self.reservation.pool, false, address)
                .await?
                .unwrap_or_else(|| {
                    if address.is_ipv4() {
                        "0.0.0.0".parse().unwrap()
                    } else {
                        "::".parse().unwrap()
                    }
                });
        let socket = UdpSocket::bind(SocketAddr::new(source, 0)).await?;
        if let Some(vlan) = &self.reservation.pool.config.backend_vlan {
            crate::network::bind_device(&socket, self.runtime.config.network.device(vlan))?;
        }
        socket.connect(address).await?;
        Ok(socket)
    }
    async fn run(mut self) {
        let pool = self.reservation.pool.clone();
        let index = self.reservation.index;
        let address = pool.members.lock().unwrap()[index].address;
        let observation = self.runtime.inspection.observe(
            &pool.config.name,
            self.client,
            crate::inspection::Protocol::Udp,
            Some(address),
            self.runtime.inspection_generation,
        );
        let began = Instant::now();
        let connected = tokio::select! {
            biased;
            _ = self.stop.cancelled() => return,
            result = timeout(Duration::from_millis(self.runtime.config.connect_timeout_ms), self.backend(address)) => result,
        };
        let backend = match connected {
            Ok(Ok(socket)) => socket,
            _ => {
                pool.traffic.backend_errors.fetch_add(1, Ordering::Relaxed);
                self.failed();
                return;
            }
        };
        if let Some(flow) = &observation {
            flow.entry().forwarding();
        }
        // UDP connect selects a peer/source; it does not establish backend readiness.
        pool.traffic.connect_latency.record(began.elapsed());
        pool.members.lock().unwrap()[index]
            .traffic
            .connect_latency
            .record(began.elapsed());
        let idle = Duration::from_secs(pool.config.udp_idle_timeout_secs);
        let mut deadline = tokio::time::Instant::now() + idle;
        let mut buffer = vec![0; 65536];
        let mut first_request = None;
        let mut response_recorded = false;
        loop {
            tokio::select! {
                _ = self.stop.cancelled() => break,
                _ = tokio::time::sleep_until(deadline) => {
                    let mut members = pool.members.lock().unwrap();
                    members[index].completed += 1;
                    members[index].traffic.completed.fetch_add(1, Ordering::Relaxed);
                    pool.traffic.completed.fetch_add(1, Ordering::Relaxed);
                    break;
                }
                packet = self.incoming.recv() => {
                    let Some(packet) = packet else { break; };
                    let sent = tokio::select! { biased; _ = self.stop.cancelled() => break, _ = tokio::time::sleep_until(deadline) => break, result = backend.send(&packet.bytes) => result };
                    if sent.is_err() { self.failed(); break; }
                    if !response_recorded { first_request.get_or_insert_with(Instant::now); }
                    deadline = tokio::time::Instant::now() + idle;
                    let mut members = pool.members.lock().unwrap();
                    members[index].bytes_to_backend += packet.bytes.len() as u64;
                    members[index].traffic.up.fetch_add(packet.bytes.len() as u64, Ordering::Relaxed);
                    pool.traffic.up.fetch_add(packet.bytes.len() as u64, Ordering::Relaxed);
                }
                received = backend.recv(&mut buffer) => {
                    let size = match received { Ok(size) => size, Err(_) => { self.failed(); break; } };
                    let sent = tokio::select! { biased; _ = self.stop.cancelled() => break, _ = tokio::time::sleep_until(deadline) => break, result = self.listener.send_to(&buffer[..size], self.client) => result };
                    if sent.is_err() { self.failed(); break; }
                    deadline = tokio::time::Instant::now() + idle;
                    let mut members = pool.members.lock().unwrap();
                    members[index].bytes_to_client += size as u64;
                    members[index].traffic.down.fetch_add(size as u64, Ordering::Relaxed);
                    pool.traffic.down.fetch_add(size as u64, Ordering::Relaxed);
                    if let Some(started) = first_request.take() {
                        response_recorded = true;
                        pool.traffic.response_latency.record(started.elapsed());
                        members[index].traffic.response_latency.record(started.elapsed());
                    }
                }
            }
        }
    }
    fn failed(&self) {
        let pool = &self.reservation.pool;
        let mut members = pool.members.lock().unwrap();
        members[self.reservation.index].failures += 1;
        members[self.reservation.index]
            .traffic
            .failures
            .fetch_add(1, Ordering::Relaxed);
        pool.traffic.failures.fetch_add(1, Ordering::Relaxed);
        pool.traffic
            .transport_errors
            .fetch_add(1, Ordering::Relaxed);
    }
}
