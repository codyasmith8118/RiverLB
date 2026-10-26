//! Loopback configuration API with browser origin and host protection.
use crate::{config::Config, control::Control};
use axum::{
    Extension, Json, Router,
    extract::{Request, State},
    http::{Method, StatusCode},
    middleware::{self, Next},
    response::{Html, IntoResponse, Redirect, Response},
    routing::{get, post},
};
mod certificates;

use serde::Deserialize;
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc};

#[derive(Default)]
pub(crate) struct LoginBudget {
    sources: std::collections::HashMap<std::net::IpAddr, (std::time::Instant, u32)>,
}
impl LoginBudget {
    fn admit(&mut self, source: std::net::IpAddr, now: std::time::Instant) -> bool {
        let source = match source {
            std::net::IpAddr::V6(ip) => ip.to_ipv4_mapped().map(Into::into).unwrap_or(source),
            _ => source,
        };
        self.sources
            .retain(|_, (start, _)| now.duration_since(*start).as_secs() < 60);
        if !self.sources.contains_key(&source) && self.sources.len() >= 4096 {
            // Evict instead of denying all new sources when the table is full.
            if let Some(oldest) = self
                .sources
                .iter()
                .min_by_key(|(_, (start, _))| *start)
                .map(|(ip, _)| *ip)
            {
                self.sources.remove(&oldest);
            }
        }
        let (_, attempts) = self.sources.entry(source).or_insert((now, 0));
        if *attempts >= 10 {
            return false;
        }
        *attempts += 1;
        true
    }
}

struct DeadlineBody {
    inner: axum::body::Body,
    deadline: std::pin::Pin<Box<tokio::time::Sleep>>,
}

impl DeadlineBody {
    fn new(inner: axum::body::Body, duration: std::time::Duration) -> Self {
        Self {
            inner,
            deadline: Box::pin(tokio::time::sleep(duration)),
        }
    }
}
impl hyper::body::Body for DeadlineBody {
    type Data = axum::body::Bytes;
    type Error = axum::Error;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
        use std::future::Future;
        if self.deadline.as_mut().poll(cx).is_ready() {
            return std::task::Poll::Ready(Some(Err(axum::Error::new(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "Management request body deadline exceeded",
            )))));
        }
        std::pin::Pin::new(&mut self.inner).poll_frame(cx)
    }
    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}

async fn persistence_records(State(control): State<Arc<Control>>) -> Json<Value> {
    let generation = control.generation.lock().await;
    Json(
        json!({"revision":generation.revision,"virtual_servers":generation.runtime.pools.iter().map(|p| p.persistence_records()).collect::<Vec<_>>()}),
    )
}
async fn persistence_clear(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> ApiResult {
    // Complete the mutation even if the initiating browser disconnects.
    tokio::spawn(async move {
        let generation = control.generation.lock().await;
        let pool = generation
            .runtime
            .pools
            .iter()
            .find(|p| p.config.name == name)
            .ok_or_else(|| error(StatusCode::NOT_FOUND, "Unknown virtual server".into()))?;
        control
            .store
            .record_audit(&actor, &format!("persistence records cleared: {name}"))
            .await
            .map_err(|_| {
                error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Audit store unavailable; records unchanged".into(),
                )
            })?;
        Ok(Json(json!({"cleared":pool.clear_persistence()})))
    })
    .await
    .map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Management mutation failed".into(),
        )
    })?
}

fn session_token(headers: &axum::http::HeaderMap) -> String {
    headers
        .get("cookie")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("")
        .split(';')
        .find_map(|part| part.trim().strip_prefix("riverlb_session="))
        .unwrap_or("")
        .to_owned()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Credentials {
    username: String,
    password: String,
    #[serde(default)]
    code: Option<String>,
}
async fn login(
    State(control): State<Arc<Control>>,
    Extension(peer): Extension<SocketAddr>,
    Json(credentials): Json<Credentials>,
) -> Response {
    tokio::spawn(async move { login_inner(State(control), peer, Json(credentials)).await })
        .await
        .unwrap_or_else(|_| super_error())
}
async fn login_inner(
    State(control): State<Arc<Control>>,
    peer: SocketAddr,
    Json(credentials): Json<Credentials>,
) -> Response {
    if credentials.username.len() > 128 || credentials.password.len() > 1024 {
        return error(StatusCode::UNAUTHORIZED, "Invalid credentials".into()).into_response();
    }
    if !control
        .login_budget
        .lock()
        .await
        .admit(peer.ip(), std::time::Instant::now())
    {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sign-in attempts from this source; try again in one minute".into(),
        )
        .into_response();
    }
    // Bound concurrent Argon2 work without a shared timed lockout.
    let Ok(_slot) = control.login_slots.clone().try_acquire_owned() else {
        return error(
            StatusCode::TOO_MANY_REQUESTS,
            "Sign-in service busy; retry shortly".into(),
        )
        .into_response();
    };
    match control
        .store
        .login_with_mfa(
            &credentials.username,
            credentials.password,
            credentials.code.as_deref(),
        )
        .await
    {
        Ok(Some(token)) => {
            let secure = control
                .generation
                .lock()
                .await
                .runtime
                .management_tls
                .is_some();
            let cookie = format!(
                "riverlb_session={token}; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800{}",
                if secure { "; Secure" } else { "" }
            );
            (
                [("set-cookie", cookie)],
                Json(json!({"authenticated":true})),
            )
                .into_response()
        }
        Ok(None) => {
            let _ = control
                .store
                .record_audit("authentication", "failed login")
                .await;
            error(
                StatusCode::UNAUTHORIZED,
                "Invalid credentials or authenticator code".into(),
            )
            .into_response()
        }
        Err(error) => {
            tracing::error!(%error, "login store failed");
            super_error()
        }
    }
}
fn super_error() -> Response {
    error(
        StatusCode::SERVICE_UNAVAILABLE,
        "Authentication store unavailable".into(),
    )
    .into_response()
}
async fn logout(State(control): State<Arc<Control>>, headers: axum::http::HeaderMap) -> Response {
    tokio::spawn(async move { logout_inner(State(control), headers).await })
        .await
        .unwrap_or_else(|_| super_error())
}
async fn logout_inner(
    State(control): State<Arc<Control>>,
    headers: axum::http::HeaderMap,
) -> Response {
    if control
        .store
        .logout(&session_token(&headers))
        .await
        .is_err()
    {
        return super_error();
    }
    (
        [(
            "set-cookie",
            "riverlb_session=; HttpOnly; SameSite=Strict; Path=/; Max-Age=0",
        )],
        Json(json!({"authenticated":false})),
    )
        .into_response()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordChange {
    current_password: String,
    new_password: String,
    #[serde(default)]
    code: Option<String>,
}
async fn change_password(
    State(control): State<Arc<Control>>,
    Extension(user): Extension<String>,
    Json(change): Json<PasswordChange>,
) -> Response {
    tokio::spawn(async move {
        change_password_inner(State(control), Extension(user), Json(change)).await
    })
    .await
    .unwrap_or_else(|_| super_error())
}
async fn change_password_inner(
    State(control): State<Arc<Control>>,
    Extension(user): Extension<String>,
    Json(change): Json<PasswordChange>,
) -> Response {
    if change.current_password.len() > 1024 || !(12..=1024).contains(&change.new_password.len()) {
        return error(
            StatusCode::UNPROCESSABLE_ENTITY,
            "Password must contain 12–1024 bytes".into(),
        )
        .into_response();
    }
    match control
        .store
        .verify_credentials(&user, change.current_password, change.code.as_deref())
        .await
    {
        Ok(true) => {
            if control
                .store
                .manage_administrator(&user, &user, "password", Some(change.new_password))
                .await
                .is_err()
            {
                return super_error();
            }
            Json(json!({"message":"Password changed; sign in again"})).into_response()
        }
        Ok(false) => error(
            StatusCode::UNAUTHORIZED,
            "Invalid current password or authenticator code".into(),
        )
        .into_response(),
        Err(_) => super_error(),
    }
}
async fn status(State(control): State<Arc<Control>>) -> Json<Value> {
    let mut ha_status = control.ha_status().await;
    ha_status["interface_change"] = crate::interfaces::status().await;
    let generation = control.generation.lock().await;
    let runtime = &generation.runtime;
    let statistics = traffic_snapshot(runtime, generation.revision);
    let pools = runtime
        .config
        .pools
        .iter()
        .map(|definition| {
            let states = runtime
                .pools
                .iter()
                .filter(|pool| {
                    pool.config.enabled
                        && pool.config.default_pool.as_deref() == Some(&definition.name)
                })
                .map(|pool| availability(true, &pool.members.lock().unwrap()).to_owned())
                .collect::<Vec<_>>();
            let state = if states.iter().any(|s| s == "up") {
                "up"
            } else if states.iter().any(|s| s == "unavailable") {
                "unavailable"
            } else if states.is_empty() || states.iter().any(|s| s == "unknown") {
                "unknown"
            } else {
                "down"
            };
            let traffic = statistics["pools"]
                .as_array()
                .unwrap()
                .iter()
                .find(|p| p["name"] == definition.name)
                .unwrap()["traffic"]
                .clone();
            json!({"name":definition.name,"state":state,"traffic":traffic})
        })
        .collect::<Vec<_>>();
    Json(
        json!({"ha":ha_status,"version":env!("CARGO_PKG_VERSION"),"release_stage":include_str!("../appliance/branding/release-stage").trim(),"revision":generation.revision,"pools":pools,"virtual_servers":runtime.pools.iter().map(|pool| {
            let members = pool.members.lock().unwrap();
            json!({"name":pool.config.name,"state":availability(pool.config.enabled, &members),"listen":pool.config.listen,"algorithm":pool.config.algorithm,"default_pool":pool.config.default_pool,"enabled":pool.config.enabled,"description":pool.config.description,"app_url":pool.config.app_url,"monitor":pool.config.monitor,"traffic":pool.traffic.snapshot(),"connection_limit":pool.config.connection_limit,"admission_active":pool.admission.load(std::sync::atomic::Ordering::SeqCst),"priority_group_min_active":pool.config.priority_group_min_active,"source_nat":pool.config.source_nat,"members":crate::traffic::members_value(&members)})
        }).collect::<Vec<_>>()}),
    )
}
fn availability(enabled: bool, members: &[crate::runtime::Member]) -> &'static str {
    if !enabled {
        "disabled"
    } else if members.iter().any(|m| m.healthy && !m.draining) {
        "up"
    } else if members.iter().any(|m| m.healthy) {
        "unavailable"
    } else if members.is_empty() || members.iter().any(|m| m.last_probe.is_none()) {
        "unknown"
    } else {
        "down"
    }
}
async fn node_status(State(control): State<Arc<Control>>) -> Json<Value> {
    let generation = control.generation.lock().await;
    let runtime = &generation.runtime;
    let mut result = Vec::new();
    for node in &runtime.config.nodes {
        let mut instances = Vec::new();
        let mut active = 0;
        let mut completed = 0;
        let mut failures = 0;
        let mut connect_latency = crate::traffic::LatencySnapshot::default();
        let mut response_latency = crate::traffic::LatencySnapshot::default();
        let mut probe_latency = crate::traffic::LatencySnapshot::default();
        let mut healthy = false;
        let mut monitored = false;
        let mut accepting = false;
        for pool in &runtime.pools {
            let members = pool.members.lock().unwrap();
            if let Some(member) = members.iter().find(|m| m.address == node.address) {
                if pool.config.enabled {
                    healthy |= member.healthy;
                    accepting |= member.healthy && !member.draining;
                    monitored |= member.last_probe.is_some();
                }
                let snapshot = member.traffic.snapshot();
                active += snapshot.current;
                completed += snapshot.completed;
                failures += snapshot.failures;
                connect_latency.merge(&snapshot.connect_latency);
                response_latency.merge(&snapshot.response_latency);
                probe_latency.merge(&snapshot.probe_latency);
                instances.push(json!({"virtual_server":pool.config.name,"healthy":member.healthy,"draining":member.draining,"bytes_to_backend":snapshot.bytes_in,"bytes_to_client":snapshot.bytes_out}));
            }
        }
        for pool in &runtime.node_pools {
            if let Some(member) = pool
                .members
                .lock()
                .unwrap()
                .iter()
                .find(|m| m.address == node.address)
            {
                healthy |= member.healthy;
                accepting |= member.healthy;
                monitored |= member.last_probe.is_some();
                probe_latency.merge(&member.traffic.snapshot().probe_latency);
            }
        }
        let state = if !node.enabled {
            "Disabled"
        } else if !monitored {
            "Unused"
        } else if accepting {
            "Up"
        } else if healthy {
            "Unavailable"
        } else {
            "Down"
        };
        result.push(json!({"name":node.name,"address":node.address,"enabled":node.enabled,"description":node.description,"state":state,"active":active,"completed":completed,"failures":failures,"connect_latency":connect_latency,"response_latency":response_latency,"probe_latency":probe_latency,"instances":instances}));
    }
    Json(json!(result))
}
pub fn traffic_snapshot(runtime: &crate::runtime::Runtime, revision: u64) -> Value {
    let virtual_servers = runtime.pools.iter().map(|pool| json!({"name":pool.config.name,"default_pool":pool.config.default_pool,"traffic":pool.traffic.snapshot(),"members":crate::traffic::members_value(&pool.members.lock().unwrap())})).collect::<Vec<_>>();
    let pools = runtime
        .config
        .pools
        .iter()
        .map(|definition| {
            let mut total = crate::traffic::Snapshot::default();
            for pool in runtime
                .pools
                .iter()
                .filter(|pool| pool.config.default_pool.as_deref() == Some(&definition.name))
            {
                let snapshot = pool.traffic.snapshot();
                total.accepted += snapshot.accepted;
                total.rejected += snapshot.rejected;
                total.current += snapshot.current;
                total.completed += snapshot.completed;
                total.failures += snapshot.failures;
                total.session_timeouts += snapshot.session_timeouts;
                total.transport_errors += snapshot.transport_errors;
                total.backend_errors += snapshot.backend_errors;
                total.connect_latency.merge(&snapshot.connect_latency);
                total.response_latency.merge(&snapshot.response_latency);
                total.probe_latency.merge(&snapshot.probe_latency);
                total.bytes_in += snapshot.bytes_in;
                total.bytes_out += snapshot.bytes_out;
            }
            let mut total = serde_json::to_value(total).expect("serializable counters");
            total["peak"] = Value::Null; // Sum of separate peaks is not a concurrent pool peak.
            json!({"name":definition.name,"traffic":total})
        })
        .collect::<Vec<_>>();
    json!({"revision":revision,"epoch":*runtime.epoch.lock().unwrap(),"created":crate::storage::now(),"virtual_servers":virtual_servers,"pools":pools})
}
async fn statistics(State(control): State<Arc<Control>>) -> Json<Value> {
    let generation = control.generation.lock().await;
    Json(traffic_snapshot(&generation.runtime, generation.revision))
}
async fn reset_statistics(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    control
        .reset_statistics(&actor)
        .await
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    Ok(Json(
        json!({"message":"Statistics counters, latency measurements and history reset"}),
    ))
}
async fn configuration(State(control): State<Arc<Control>>) -> Json<Value> {
    let confirmation = crate::confirmation::view(&control).await;
    let generation = control.generation.lock().await;
    Json(
        json!({"confirmation":confirmation,"revision":generation.revision,"config":generation.runtime.config,"network_mode":if control.manage_network {"managed"} else {"external"}}),
    )
}
fn label(value: &str) -> String {
    value
        .replace('\\', "\\\\")
        .replace('"', "\\\"")
        .replace('\n', "\\n")
}
async fn metrics(State(control): State<Arc<Control>>) -> impl IntoResponse {
    let generation = control.generation.lock().await;
    let mut output = format!(
        "# HELP riverlb_config_revision Current configuration revision.\n# TYPE riverlb_config_revision gauge\nriverlb_config_revision {}\n",
        generation.revision
    );
    for (name, kind) in [
        ("connections_total", "counter"),
        ("connections_current", "gauge"),
        ("connections_peak", "gauge"),
        ("connections_rejected_total", "counter"),
        ("failures_total", "counter"),
        ("session_timeouts_total", "counter"),
        ("transport_errors_total", "counter"),
        ("backend_errors_total", "counter"),
        ("bytes_in_total", "counter"),
        ("bytes_out_total", "counter"),
        ("admission_active", "gauge"),
        ("connection_limit", "gauge"),
    ] {
        output.push_str(&format!("# TYPE riverlb_virtual_{name} {kind}\n"));
    }
    for scope in ["virtual", "member"] {
        for kind in ["connect", "response_headers", "probe"] {
            for suffix in ["sum", "count"] {
                output.push_str(&format!(
                    "# TYPE riverlb_{scope}_{kind}_latency_seconds_{suffix} counter\n"
                ));
            }
        }
    }
    for pool in &generation.runtime.pools {
        let snapshot = pool.traffic.snapshot();
        for (kind, latency) in [
            ("connect", &snapshot.connect_latency),
            ("response_headers", &snapshot.response_latency),
            ("probe", &snapshot.probe_latency),
        ] {
            output.push_str(&format!("riverlb_virtual_{kind}_latency_seconds_sum{{virtual_server=\"{}\"}} {}\nriverlb_virtual_{kind}_latency_seconds_count{{virtual_server=\"{}\"}} {}\n",label(&pool.config.name),latency.total_us as f64/1_000_000.0,label(&pool.config.name),latency.samples));
        }
        for (name, _kind, value) in [
            ("connections_total", "counter", snapshot.accepted),
            ("connections_current", "gauge", snapshot.current),
            ("connections_peak", "gauge", snapshot.peak),
            ("connections_rejected_total", "counter", snapshot.rejected),
            ("failures_total", "counter", snapshot.failures),
            (
                "session_timeouts_total",
                "counter",
                snapshot.session_timeouts,
            ),
            (
                "transport_errors_total",
                "counter",
                snapshot.transport_errors,
            ),
            ("backend_errors_total", "counter", snapshot.backend_errors),
            ("bytes_in_total", "counter", snapshot.bytes_in),
            ("bytes_out_total", "counter", snapshot.bytes_out),
            (
                "admission_active",
                "gauge",
                pool.admission.load(std::sync::atomic::Ordering::SeqCst) as u64,
            ),
            (
                "connection_limit",
                "gauge",
                pool.config.connection_limit as u64,
            ),
        ] {
            output.push_str(&format!(
                "riverlb_virtual_{name}{{virtual_server=\"{}\"}} {value}\n",
                label(&pool.config.name)
            ));
        }
    }
    let definitions = [
        ("healthy", "gauge", "Member health (1 up, 0 down)."),
        (
            "admission_active",
            "gauge",
            "Reserved member sessions across all live generations.",
        ),
        (
            "connection_limit",
            "gauge",
            "Member connection limit; zero means unlimited.",
        ),
        (
            "priority",
            "gauge",
            "Member priority group; higher groups are preferred.",
        ),
        (
            "active_connections",
            "gauge",
            "Active sessions in the current generation.",
        ),
        (
            "completed_sessions_total",
            "counter",
            "Successfully completed proxy sessions.",
        ),
        (
            "failures_total",
            "counter",
            "Backend connect or session failures.",
        ),
        (
            "bytes_to_backend_total",
            "counter",
            "Application bytes forwarded to backends, including active/failed sessions.",
        ),
        (
            "bytes_to_client_total",
            "counter",
            "Application bytes forwarded to clients, including active/failed sessions.",
        ),
    ];
    for (suffix, kind, help) in definitions {
        output.push_str(&format!(
            "# HELP riverlb_member_{suffix} {help}\n# TYPE riverlb_member_{suffix} {kind}\n"
        ));
        for pool in &generation.runtime.pools {
            for member in pool.members.lock().unwrap().iter() {
                let stats = member.traffic.snapshot();
                let value = match suffix {
                    "healthy" => u64::from(member.healthy),
                    "admission_active" => member
                        .admission_active
                        .load(std::sync::atomic::Ordering::SeqCst)
                        as u64,
                    "connection_limit" => member.connection_limit as u64,
                    "priority" => u64::from(member.priority),
                    "active_connections" => stats.current,
                    "completed_sessions_total" => stats.completed,
                    "failures_total" => stats.failures,
                    "bytes_to_backend_total" => stats.bytes_in,
                    _ => stats.bytes_out,
                };
                output.push_str(&format!(
                    "riverlb_member_{suffix}{{virtual_server=\"{}\",member=\"{}\"}} {value}\n",
                    label(&pool.config.name),
                    member.address
                ));
            }
        }
    }
    for pool in &generation.runtime.pools {
        for member in pool.members.lock().unwrap().iter() {
            let stats = member.traffic.snapshot();
            for (kind, latency) in [
                ("connect", &stats.connect_latency),
                ("response_headers", &stats.response_latency),
                ("probe", &stats.probe_latency),
            ] {
                output.push_str(&format!("riverlb_member_{kind}_latency_seconds_sum{{virtual_server=\"{}\",member=\"{}\"}} {}\nriverlb_member_{kind}_latency_seconds_count{{virtual_server=\"{}\",member=\"{}\"}} {}\n",label(&pool.config.name),member.address,latency.total_us as f64/1_000_000.0,label(&pool.config.name),member.address,latency.samples));
            }
        }
    }
    (
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        output,
    )
}
#[cfg(test)]
mod metric_tests {
    #[test]
    fn availability_distinguishes_disabled_pending_down_up_and_draining() {
        let config =
            crate::config::Config::load(std::path::Path::new("examples/riverlb.toml")).unwrap();
        let runtime = crate::runtime::Runtime::new(config).unwrap();
        let mut members = runtime.pools[0].members.lock().unwrap();
        assert_eq!(super::availability(false, &members), "disabled");
        assert_eq!(super::availability(true, &members), "unknown");
        for member in members.iter_mut() {
            member.last_probe = Some(1);
        }
        assert_eq!(super::availability(true, &members), "down");
        members[0].healthy = true;
        assert_eq!(super::availability(true, &members), "up");
        members[0].draining = true;
        assert_eq!(super::availability(true, &members), "unavailable");
        assert_eq!(super::availability(true, &[]), "unknown");
    }
    #[test]
    fn escapes_prometheus_labels() {
        assert_eq!(super::label("a\"b\\c\nd"), "a\\\"b\\\\c\\nd");
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Change {
    revision: u64,
    config: Config,
}
type ApiResult = Result<Json<Value>, (StatusCode, Json<Value>)>;
async fn backup_download(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    tokio::spawn(async move { backup_download_inner(State(control), Extension(actor)).await })
        .await
        .map_err(|_| {
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Backup download failed".into(),
            )
        })?
}
async fn backup_download_inner(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
) -> Result<Response, (StatusCode, Json<Value>)> {
    let _gate = control.change_gate.lock().await;
    if control.pending_configuration.lock().await.is_some() {
        return Err(error(
            StatusCode::CONFLICT,
            "Confirm or revert the configuration before creating a backup".into(),
        ));
    }
    let snapshot = control
        .store
        .backup()
        .await
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    control
        .store
        .record_audit(&actor, "private backup downloaded")
        .await
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    Ok((
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
            (
                "content-disposition",
                "attachment; filename=riverlb-backup.json",
            ),
        ],
        serde_json::to_vec(&snapshot).unwrap(),
    )
        .into_response())
}
async fn restore_stage(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
    Json(snapshot): Json<crate::backup::Snapshot>,
) -> ApiResult {
    tokio::spawn(async move {
        let _gate = control.change_gate.lock().await;
        if control.pending_configuration.lock().await.is_some() {
            return Err(error(StatusCode::CONFLICT,"Confirm or revert the pending configuration before staging a restore".into()));
        }
        control.store.stage_restore(&snapshot).await.map_err(|e|error(StatusCode::UNPROCESSABLE_ENTITY,e.to_string()))?;
        control.store.record_audit(&actor,"backup validated and staged for offline restore").await.map_err(|e|error(StatusCode::SERVICE_UNAVAILABLE,e.to_string()))?;
        Ok(Json(json!({"staged":true,"message":"Backup validated and staged. Stop RiverLB, run riverlb restore --database <database> --staged --replace, then restart and sign in using restored credentials."})))
    }).await.map_err(|_|error(StatusCode::SERVICE_UNAVAILABLE,"Restore staging failed".into()))?
}
async fn renewal_list(State(control): State<Arc<Control>>) -> ApiResult {
    Ok(Json(json!(control.store.acme_jobs().await.map_err(
        |e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string())
    )?)))
}
async fn renewal_save(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
    Json(settings): Json<crate::acme::Settings>,
) -> ApiResult {
    tokio::spawn(async move {
        control
            .store
            .set_acme_job(settings, &actor)
            .await
            .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
        control.acme_wake.notify_one();
        Ok(Json(
            json!({"message":"Renewal schedule saved; worker checks every 30 seconds."}),
        ))
    })
    .await
    .map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Schedule update failed".into(),
        )
    })?
}
async fn renewal_delete(
    State(control): State<Arc<Control>>,
    axum::extract::Path(name): axum::extract::Path<String>,
) -> ApiResult {
    tokio::spawn(async move {
        control
            .store
            .delete_acme_job(&name)
            .await
            .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
        Ok(Json(json!({"deleted":name})))
    })
    .await
    .map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Schedule deletion failed".into(),
        )
    })?
}
fn error(status: StatusCode, message: String) -> (StatusCode, Json<Value>) {
    (status, Json(json!({"error":message})))
}
async fn validate(State(control): State<Arc<Control>>, Json(config): Json<Config>) -> ApiResult {
    config
        .validate()
        .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    control
        .store
        .resolve_certificates(&config)
        .await
        .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    Ok(Json(json!({"valid":true})))
}
async fn network_plan(
    State(control): State<Arc<Control>>,
    Json(config): Json<Config>,
) -> ApiResult {
    config
        .validate()
        .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    let config = config
        .expand_domain_tls()
        .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    let generation = control.generation.lock().await;
    let steps = crate::network::provisioned(&generation.runtime.config)
        .and_then(|old| {
            crate::network::provisioned(&config).and_then(|new| crate::network::plan(&old, &new))
        })
        .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    let mut steps = steps;
    let rules = crate::firewall::desired(&config, control.manage_firewall)
        .await
        .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    steps.extend(crate::firewall::plan(&generation.firewall_rules, &rules));
    Ok(Json(
        json!({"mode":if control.manage_network {"managed"}else{"external"},"steps":steps}),
    ))
}
async fn interfaces() -> ApiResult {
    crate::network::interface_addresses()
        .await
        .map(|links| Json(json!(links)))
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))
}
async fn apply(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
    Json(change): Json<Change>,
) -> ApiResult {
    let began = std::time::Instant::now();
    let address = change.config.management;
    let scheme = if change.config.management_tls.is_some()
        || change.config.management_certificate.is_some()
    {
        "https"
    } else {
        "http"
    };
    let message = if !control.manage_network && !change.config.network.is_empty() {
        "Traffic configuration saved and applied. Network objects saved only because --external-network is enabled; Linux networking was not changed."
    } else if control.manage_network {
        "Configuration saved and applied to traffic and Linux networking"
    } else {
        "Traffic configuration saved and applied"
    };
    // Complete an admitted transaction even if its HTTP caller disconnects.
    let apply_control = control.clone();
    let revision = tokio::spawn(async move {
        apply_control
            .apply(change.config, change.revision, actor)
            .await
    })
    .await
    .map_err(|e| error(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map_err(|e| error(StatusCode::CONFLICT, format!("{e:#}")))?;
    Ok(Json(
        json!({"revision":revision,"management_url":format!("{scheme}://{address}"),"message":message,"confirmation":crate::confirmation::view(&control).await,"duration_ms":began.elapsed().as_millis() as u64}),
    ))
}
async fn protect(
    State((control, address, secure)): State<(Arc<Control>, SocketAddr, bool)>,
    mut request: Request,
    next: Next,
) -> Response {
    let peer = match request.extensions().get::<SocketAddr>().copied() {
        Some(p) => p.ip(),
        None if address.ip().is_loopback() => address.ip(),
        None => {
            return error(
                StatusCode::FORBIDDEN,
                "Management source address unavailable".into(),
            )
            .into_response();
        }
    };
    let settings = match control.store.security_settings().await {
        Ok(s) => s,
        Err(_) => return super_error(),
    };
    if !settings.allows_source(peer) {
        return error(
            StatusCode::FORBIDDEN,
            "Management access is restricted for this source address".into(),
        )
        .into_response();
    }
    let headers = request.headers();
    let scheme = if secure { "https" } else { "http" };
    let host = headers
        .get("host")
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");
    let allowed = [address.to_string(), format!("localhost:{}", address.port())];
    if !allowed.iter().any(|v| v == host) {
        return error(StatusCode::FORBIDDEN, "Invalid management host".into()).into_response();
    }
    if let Some(origin) = headers.get("origin")
        && origin.to_str().ok() != Some(format!("{scheme}://{host}").as_str())
    {
        return error(
            StatusCode::FORBIDDEN,
            "Cross-origin management requests are forbidden".into(),
        )
        .into_response();
    }
    if headers
        .get("sec-fetch-site")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v != "same-origin" && v != "none")
    {
        return error(
            StatusCode::FORBIDDEN,
            "Cross-site management requests are forbidden".into(),
        )
        .into_response();
    }
    if request.method() != Method::GET
        && headers
            .get("x-riverlb-request")
            .and_then(|v| v.to_str().ok())
            != Some("configure")
    {
        return error(
            StatusCode::FORBIDDEN,
            "Missing management request header".into(),
        )
        .into_response();
    }
    let public = matches!(
        request.uri().path(),
        "/login"
            | "/login.js"
            | "/appearance.js"
            | "/style.css"
            | "/favicon.svg"
            | "/healthz"
            | "/api/v1/auth/login"
    );
    if !public {
        let bearer = request
            .headers()
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "));
        let activity = request
            .headers()
            .get("x-riverlb-activity")
            .and_then(|v| v.to_str().ok())
            == Some("interactive");
        let user = match if let Some(token) = bearer {
            control.store.token_principal(token).await
        } else {
            control
                .store
                .session_principal(&session_token(request.headers()), activity)
                .await
        } {
            Ok(user) => user,
            Err(_) => {
                return error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Authentication store unavailable".into(),
                )
                .into_response();
            }
        };
        if let Some(principal) = user {
            if !principal.permits(request.method().as_str(), request.uri().path()) {
                return error(
                    StatusCode::FORBIDDEN,
                    "Your account or token does not permit this operation".into(),
                )
                .into_response();
            }
            request.extensions_mut().insert(principal.username.clone());
            request.extensions_mut().insert(principal);
        } else if request.uri().path() == "/" {
            return Redirect::to("/login").into_response();
        } else {
            return error(StatusCode::UNAUTHORIZED, "Sign in required".into()).into_response();
        }
    }
    if control.ha.is_some()
        && !control.data_plane_active()
        && request.method() != axum::http::Method::GET
        && request.method() != axum::http::Method::HEAD
        && !request.uri().path().starts_with("/api/v1/auth/")
        && !request.uri().path().starts_with("/api/v1/administrators")
        && !request.uri().path().starts_with("/api/v1/ha")
        && !request.uri().path().starts_with("/api/v1/security/")
        && !request.uri().path().starts_with("/api/v1/operations/")
        && !request.uri().path().starts_with("/api/v1/updates/")
        && !request
            .uri()
            .path()
            .starts_with("/api/v1/device-certificates")
    {
        return error(
            StatusCode::CONFLICT,
            "Standby traffic configuration is read-only; edit the active appliance".into(),
        )
        .into_response();
    }
    // Reserve each route's maximum body size (in MiB), independent of attacker-
    // supplied Content-Length. This also covers chunked uploads.
    let body_mib = match request.uri().path() {
        "/api/v1/updates/stage" => 180,
        "/api/v1/restore/stage" => 32,
        "/api/v1/operations/backup/restore" => 46,
        _ => 2,
    };
    let Ok(body_permit) = control
        .admin_body_slots
        .clone()
        .try_acquire_many_owned(body_mib)
    else {
        return error(
            StatusCode::SERVICE_UNAVAILABLE,
            "Management upload capacity busy; retry shortly".into(),
        )
        .into_response();
    };
    // Stream bodies with an absolute deadline, preserving route-specific size limits.
    let body = std::mem::replace(request.body_mut(), axum::body::Body::empty());
    *request.body_mut() =
        axum::body::Body::new(DeadlineBody::new(body, std::time::Duration::from_secs(120)));
    let certificate_edit = !matches!(request.method(), &Method::GET | &Method::HEAD)
        && (request.uri().path().starts_with("/api/v1/certificates")
            || request
                .uri()
                .path()
                .starts_with("/api/v1/device-certificates"));
    // Keep admission until the handler completes, including detached mutations
    // whose originating connection has gone away.
    let mut response = tokio::spawn(async move {
        let _body_permit = body_permit;
        if certificate_edit {
            let _gate = control.change_gate.lock().await;
            if control.pending_configuration.lock().await.is_some() {
                return error(StatusCode::CONFLICT, "Confirm or revert the pending configuration before changing certificate inventory".into()).into_response();
            }
            next.run(request).await
        } else {
            next.run(request).await
        }
    }).await.unwrap_or_else(|_| super_error());
    response
        .headers_mut()
        .insert("cache-control", "no-store".parse().unwrap());
    response
        .headers_mut()
        .insert("x-frame-options", "DENY".parse().unwrap());
    response
        .headers_mut()
        .insert("x-content-type-options", "nosniff".parse().unwrap());
    response
}
pub fn router(control: Arc<Control>, address: SocketAddr, secure: bool) -> Router {
    Router::new()
        .route(
            "/api/v1/audit",
            get(|State(control): State<Arc<Control>>| async move {
                control.store.audit().await.map(Json).map_err(|_| {
                    error(
                        StatusCode::SERVICE_UNAVAILABLE,
                        "Audit store unavailable".into(),
                    )
                })
            }),
        )
        .route(
            "/login",
            get(|| async { Html(include_str!("../web/login.html")) }),
        )
        .route(
            "/appearance.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../web/appearance.js"),
                )
            }),
        )
        .route(
            "/login.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../web/login.js"),
                )
            }),
        )
        .route(
            "/api/v1/auth/login",
            post(login).layer(axum::extract::DefaultBodyLimit::max(4096)),
        )
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/auth/password", post(change_password))
        .route(
            "/api/v1/administrators",
            get(administrator_list).post(administrator_change),
        )
        .route(
            "/",
            get(|| async { Html(include_str!("../web/index.html")) }),
        )
        .route(
            "/favicon.svg",
            get(|| async {
                (
                    [("content-type", "image/svg+xml")],
                    include_str!("../web/favicon.svg"),
                )
            }),
        )
        .route(
            "/fencing.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../web/fencing.js"),
                )
            }),
        )
        .route(
            "/statistics.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../web/statistics.js"),
                )
            }),
        )
        .route("/api/v1/statistics", get(statistics))
        .route("/api/v1/statistics/reset", post(reset_statistics))
        .route(
            "/api/v1/statistics/history",
            get(|State(control): State<Arc<Control>>| async move {
                control
                    .store
                    .traffic_history()
                    .await
                    .map(Json)
                    .map_err(|_| {
                        error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Statistics history unavailable".into(),
                        )
                    })
            }),
        )
        .route("/api/v1/status", get(status))
        .route("/api/v1/connections", get(crate::inspection::endpoint))
        .route("/api/v1/appliance", get(appliance_status))
        .route("/api/v1/ha", get(ha_group_get).put(ha_group_save))
        .route("/api/v1/ha/action", post(ha_group_action))
        .route("/metrics", get(metrics))
        .route(
            "/style.css",
            get(|| async {
                (
                    [("content-type", "text/css; charset=utf-8")],
                    include_str!("../web/style.css"),
                )
            }),
        )
        .route(
            "/app.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../web/app.js"),
                )
            }),
        )
        .route(
            "/api/v1/config/history",
            get(|State(control): State<Arc<Control>>| async move {
                control
                    .store
                    .configuration_history()
                    .await
                    .map(Json)
                    .map_err(|_| {
                        error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Configuration history unavailable".into(),
                        )
                    })
            }),
        )
        .route(
            "/api/v1/config/history/{revision}",
            get(
                |State(control): State<Arc<Control>>,
                 axum::extract::Path(revision): axum::extract::Path<u64>| async move {
                    match control.store.configuration_revision(revision).await {
                        Ok(Some(config)) => Ok(Json(config)),
                        Ok(None) => Err(error(
                            StatusCode::NOT_FOUND,
                            "Unknown configuration revision".into(),
                        )),
                        Err(_) => Err(error(
                            StatusCode::SERVICE_UNAVAILABLE,
                            "Configuration history unavailable".into(),
                        )),
                    }
                },
            ),
        )
        .merge(certificates::router(
            "/api/v1/certificates",
            crate::certificates::StoreKind::VirtualServer,
        ))
        .merge(certificates::router(
            "/api/v1/device-certificates",
            crate::certificates::StoreKind::Device,
        ))
        .route("/api/v1/nodes", get(node_status))
        .route("/api/v1/backup", post(backup_download))
        .route(
            "/api/v1/restore/stage",
            post(restore_stage).layer(axum::extract::DefaultBodyLimit::max(
                crate::backup::MAX_BYTES,
            )),
        )
        .route("/api/v1/renewals", get(renewal_list).post(renewal_save))
        .route(
            "/api/v1/renewals/{name}",
            axum::routing::delete(renewal_delete),
        )
        .route("/api/v1/persistence", get(persistence_records))
        .route("/api/v1/persistence/{name}/clear", post(persistence_clear))
        .route("/api/v1/config", get(configuration).put(apply))
        .route(
            "/api/v1/river-rules/builtins",
            get(|| async { Json(json!({"rule_sets": crate::http_proxy::builtin_rule_sets()})) }),
        )
        .route("/api/v1/config/validate", post(validate))
        .route("/api/v1/network/plan", post(network_plan))
        .route("/api/v1/network/interfaces", get(interfaces))
        .merge(crate::interfaces::router())
        .merge(crate::ha_deploy::router())
        .merge(crate::updates::router())
        .merge(crate::auth::router())
        .merge(crate::confirmation::router())
        .merge(crate::operations::router())
        .route("/healthz", get(|| async { "ok" }))
        .layer(Extension(crate::confirmation::Endpoint { address, secure }))
        .layer(middleware::from_fn_with_state(
            (control.clone(), address, secure),
            protect,
        ))
        .with_state(control)
}

async fn ha_group_get(State(control): State<Arc<Control>>) -> ApiResult {
    crate::ha_group::view(&control)
        .await
        .map(Json)
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))
}
async fn ha_group_save(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
    Json(group): Json<crate::ha_group::Group>,
) -> ApiResult {
    tokio::spawn(async move {
        crate::ha_group::save(&control, group, &actor)
            .await
            .map(Json)
            .map_err(|e| error(StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))
    })
    .await
    .map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "HA settings task failed".into(),
        )
    })?
}
async fn ha_group_action(
    State(control): State<Arc<Control>>,
    Extension(principal): Extension<crate::auth::Principal>,
    Extension(actor): Extension<String>,
    Json(action): Json<crate::ha_group::Action>,
) -> ApiResult {
    tokio::spawn(async move {
        if principal.role != crate::auth::Role::Administrator
            && !matches!(action.action.as_str(), "sync" | "failover" | "clear")
        {
            return Err(error(
                StatusCode::FORBIDDEN,
                "Cluster provisioning requires administrator access".into(),
            ));
        }
        crate::ha_group::action(&control, action, &actor)
            .await
            .map(Json)
            .map_err(|e| error(StatusCode::CONFLICT, e.to_string()))
    })
    .await
    .map_err(|_| {
        error(
            StatusCode::SERVICE_UNAVAILABLE,
            "HA action task failed".into(),
        )
    })?
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdministratorChange {
    username: String,
    action: String,
    current_password: String,
    new_password: Option<String>,
    #[serde(default)]
    role: Option<crate::auth::Role>,
    #[serde(default)]
    code: Option<String>,
}
async fn administrator_list(
    axum::extract::Query(options): axum::extract::Query<std::collections::HashMap<String, String>>,
    State(control): State<Arc<Control>>,
    Extension(user): Extension<String>,
) -> ApiResult {
    let users = control
        .store
        .account_inventory()
        .await
        .map_err(|e| error(StatusCode::SERVICE_UNAVAILABLE, e.to_string()))?;
    let users = if options.get("details").is_some_and(|v| v == "true") {
        users
    } else {
        json!(
            users
                .as_array()
                .unwrap()
                .iter()
                .map(|v| v["username"].clone())
                .collect::<Vec<_>>()
        )
    };
    Ok(Json(json!({"current_user":user,"administrators":users})))
}
async fn administrator_change(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
    Json(change): Json<AdministratorChange>,
) -> ApiResult {
    {
        let mut budget = control.administrator_budget.lock().await;
        if budget.0.elapsed().as_secs() >= 60 {
            *budget = (std::time::Instant::now(), 0);
        }
        if budget.1 >= 30 {
            return Err(error(
                StatusCode::TOO_MANY_REQUESTS,
                "Too many account changes; retry in one minute".into(),
            ));
        }
        budget.1 += 1;
    }
    tokio::spawn(async move {
        if change.current_password.len()>1024 {return Err(error(StatusCode::UNPROCESSABLE_ENTITY,"Invalid current password".into()));}
        if !control.store.verify_credentials(&actor,change.current_password,change.code.as_deref()).await.map_err(|_|error(StatusCode::SERVICE_UNAVAILABLE,"Authentication unavailable".into()))? {return Err(error(StatusCode::UNAUTHORIZED,"Invalid current password or authenticator code".into()));}
        control.store.manage_account(&actor,&change.username,&change.action,change.new_password,change.role).await.map_err(|e|error(StatusCode::CONFLICT,e.to_string()))?;
        Ok(Json(json!({"message":"Local administrator updated","sign_in_required":actor==change.username && change.action!="create"})))
    }).await.map_err(|_|error(StatusCode::SERVICE_UNAVAILABLE,"Account update failed".into()))?
}

async fn appliance_status(State(control): State<Arc<Control>>) -> Json<Value> {
    let mut status = control.ha_status().await;
    status["version"] = env!("CARGO_PKG_VERSION").into();
    status["release_stage"] = include_str!("../appliance/branding/release-stage")
        .trim()
        .into();
    status["confirmation"] = crate::confirmation::view(&control).await;
    status["interface_change"] = crate::interfaces::status().await;
    Json(status)
}

#[cfg(test)]
mod security_limit_tests {
    use super::*;
    use http_body_util::BodyExt;
    use std::time::{Duration, Instant};

    #[test]
    fn login_sources_are_isolated_normalized_expire_and_remain_bounded() {
        let mut budget = LoginBudget::default();
        let now = Instant::now();
        let first = "192.0.2.1".parse().unwrap();
        for _ in 0..10 {
            assert!(budget.admit(first, now));
        }
        assert!(!budget.admit(first, now));
        assert!(!budget.admit("::ffff:192.0.2.1".parse().unwrap(), now));
        assert!(budget.admit("192.0.2.2".parse().unwrap(), now));
        assert!(budget.admit(first, now + Duration::from_secs(60)));
        for i in 0..5000u32 {
            assert!(budget.admit(
                std::net::Ipv4Addr::from(i).into(),
                now + Duration::from_secs(60)
            ));
        }
        assert!(budget.sources.len() <= 4096);
    }

    struct Stalled;
    impl hyper::body::Body for Stalled {
        type Data = axum::body::Bytes;
        type Error = std::io::Error;
        fn poll_frame(
            self: std::pin::Pin<&mut Self>,
            _: &mut std::task::Context<'_>,
        ) -> std::task::Poll<Option<Result<hyper::body::Frame<Self::Data>, Self::Error>>> {
            std::task::Poll::Pending
        }
    }

    #[tokio::test]
    async fn stalled_body_expires_and_normal_body_is_preserved() {
        let stalled = DeadlineBody::new(axum::body::Body::new(Stalled), Duration::from_millis(5));
        let result = tokio::time::timeout(Duration::from_secs(1), stalled.collect())
            .await
            .unwrap();
        assert!(
            result
                .unwrap_err()
                .to_string()
                .contains("deadline exceeded")
        );
        let normal = DeadlineBody::new(axum::body::Body::from("payload"), Duration::from_secs(1));
        assert_eq!(normal.collect().await.unwrap().to_bytes(), "payload");
    }
}
