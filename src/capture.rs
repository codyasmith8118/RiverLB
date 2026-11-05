//! Administrator-authorized header capture through the fixed root broker only.
use crate::{auth::BrowserSession, control::Control};
use anyhow::{Result, ensure};
use axum::{
    Extension, Json, Router,
    body::{Body, Bytes},
    extract::{Path, State},
    http::StatusCode,
    response::Response,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD};
use hyper::body::{Frame, SizeHint};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    net::IpAddr,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::sync::{OwnedSemaphorePermit, mpsc};

const BASE: &str = "/api/v1/diagnostics/captures";
const MAX_BYTES: u64 = 16 * 1024 * 1024;
type ApiError = (StatusCode, Json<Value>);
type Shared = Arc<Control>;
type ApiResult = std::result::Result<Json<Value>, ApiError>;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub interface: String,
    pub host: IpAddr,
    pub port: u16,
    pub protocol: Protocol,
    pub duration_seconds: u64,
    pub max_bytes: u64,
    #[serde(default)]
    pub consent: bool,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
}
impl Request {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.consent,
            "Confirm consent to collect private traffic headers"
        );
        ensure!(
            !self.interface.is_empty()
                && self.interface.len() <= 15
                && self
                    .interface
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
                && self.interface.as_bytes()[0].is_ascii_alphanumeric()
                && self.interface != "lo",
            "Invalid capture interface"
        );
        ensure!(
            !self.host.is_unspecified() && !self.host.is_loopback() && !self.host.is_multicast(),
            "Use one unicast traffic endpoint"
        );
        match self.host {
            IpAddr::V4(ip) => ensure!(
                !ip.is_link_local() && ip.octets()[0] != 0 && ip.octets()[0] < 240,
                "Invalid capture address"
            ),
            IpAddr::V6(ip) => ensure!(
                !ip.is_unicast_link_local() && ip.to_ipv4_mapped().is_none(),
                "Invalid capture address"
            ),
        }
        ensure!(
            self.port != 0
                && ![22, 2223, 2224, 3121, 5404, 5405, 18090, 21064].contains(&self.port),
            "Protected or invalid capture port"
        );
        ensure!(
            (1..=60).contains(&self.duration_seconds)
                && (4096..=MAX_BYTES).contains(&self.max_bytes),
            "Capture exceeds diagnostic limits"
        );
        Ok(())
    }
    pub fn scope(&self) -> Result<String> {
        self.validate()?;
        Ok(format!(
            "capture_start:{:x}",
            Sha256::digest(serde_json::to_vec(self)?)
        ))
    }
    fn selector(&self) -> Result<Value> {
        self.validate()?;
        let mut value = serde_json::to_value(self)?;
        value.as_object_mut().unwrap().remove("consent");
        Ok(value)
    }
}
pub fn identifier(id: &str) -> Result<()> {
    ensure!(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "Invalid capture ID"
    );
    Ok(())
}
pub fn export_scope(id: &str) -> Result<String> {
    identifier(id)?;
    Ok(format!("capture_export:{id}"))
}
fn owner(actor: &str, session: &BrowserSession) -> String {
    format!(
        "{:x}",
        Sha256::digest(format!("RiverLB capture owner v1\0{actor}\0{}", session.0))
    )
}
fn error(status: StatusCode, text: &str) -> ApiError {
    (status, Json(json!({"error":text})))
}
async fn helper(parameters: Value) -> std::result::Result<Value, ApiError> {
    crate::privileged::call("capture", parameters)
        .await
        .map_err(|_| {
            error(
                StatusCode::SERVICE_UNAVAILABLE,
                "Capture unavailable or request outside diagnostic policy",
            )
        })
}
async fn admitted<T: Send + 'static>(
    operation: impl std::future::Future<Output = std::result::Result<T, ApiError>> + Send + 'static,
) -> std::result::Result<T, ApiError> {
    tokio::spawn(operation)
        .await
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Capture operation failed"))?
}
async fn interfaces() -> ApiResult {
    if !crate::privileged::enabled() {
        return Ok(Json(json!({"available":false,"interfaces":[]})));
    }
    let mut result = helper(json!({"operation":"interfaces"})).await?;
    result["available"] = Value::Bool(true);
    Ok(Json(result))
}
async fn current(
    Extension(actor): Extension<String>,
    Extension(session): Extension<BrowserSession>,
) -> ApiResult {
    if !crate::privileged::enabled() {
        return Ok(Json(json!({"state":"unavailable"})));
    }
    helper(json!({"operation":"status","owner":owner(&actor,&session)}))
        .await
        .map(Json)
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Start {
    request: Request,
    proof: String,
}
async fn start(
    State(control): State<Shared>,
    Extension(actor): Extension<String>,
    Extension(session): Extension<BrowserSession>,
    Extension(endpoint): Extension<crate::confirmation::Endpoint>,
    Json(body): Json<Start>,
) -> ApiResult {
    admitted(async move {
        let _changes = control.change_gate.lock().await;
        if control.pending_configuration.lock().await.is_some() || crate::interfaces::has_pending().await {
            return Err(error(StatusCode::CONFLICT,"Confirm or revert pending configuration before capture"));
        }
        let management_port=control.generation.lock().await.runtime.config.management.port();
        let protected_ports=vec![endpoint.address.port(),management_port].into_iter().filter(|p|*p!=0).collect::<Vec<_>>();

        let scope=body.request.scope().map_err(|_|error(StatusCode::UNPROCESSABLE_ENTITY,"Invalid selector, limits or consent"))?;
        authorize(&control,&actor,&session,&body.proof,&scope).await?;
        let result=helper(json!({"operation":"start","owner":owner(&actor,&session),"protected_ports":protected_ports,"request":body.request.selector().map_err(|_|error(StatusCode::UNPROCESSABLE_ENTITY,"Invalid capture request"))?})).await;
        control.store.record_audit(&actor,if result.is_ok(){"diagnostic capture started"}else{"diagnostic capture start failed"}).await
            .map_err(|_|error(StatusCode::SERVICE_UNAVAILABLE,"Audit unavailable"))?;
        result.map(Json)
    }).await
}
async fn authorize(
    control: &Control,
    actor: &str,
    session: &BrowserSession,
    proof: &str,
    scope: &str,
) -> std::result::Result<(), ApiError> {
    let valid = control
        .store
        .consume_sensitive_proof(actor, &session.0, proof, scope)
        .await
        .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Authorization unavailable"))?;
    if !valid {
        return Err(error(
            StatusCode::UNAUTHORIZED,
            "Fresh action-bound password and MFA proof required",
        ));
    }
    Ok(())
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Empty {}
async fn cancel(
    State(control): State<Shared>,
    Extension(actor): Extension<String>,
    Extension(session): Extension<BrowserSession>,
    Path(id): Path<String>,
    Json(_): Json<Empty>,
) -> ApiResult {
    lifecycle(control, actor, session, id, "cancel").await
}
async fn delete(
    State(control): State<Shared>,
    Extension(actor): Extension<String>,
    Extension(session): Extension<BrowserSession>,
    Path(id): Path<String>,
    Json(_): Json<Empty>,
) -> ApiResult {
    lifecycle(control, actor, session, id, "delete").await
}
async fn lifecycle(
    control: Shared,
    actor: String,
    session: BrowserSession,
    id: String,
    operation: &'static str,
) -> ApiResult {
    identifier(&id).map_err(|_| error(StatusCode::UNPROCESSABLE_ENTITY, "Invalid capture ID"))?;
    admitted(async move {
        let result =
            helper(json!({"operation":operation,"owner":owner(&actor,&session),"id":id})).await;
        control
            .store
            .record_audit(
                &actor,
                &format!(
                    "diagnostic capture {operation} {}",
                    if result.is_ok() { "accepted" } else { "denied" }
                ),
            )
            .await
            .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Audit unavailable"))?;
        result.map(Json)
    })
    .await
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Export {
    proof: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Chunk {
    offset: u64,
    total: u64,
    data: String,
    sha256: String,
}
impl Chunk {
    fn bytes(&self, offset: u64, total: u64, sha: &str) -> Result<Vec<u8>> {
        ensure!(
            self.offset == offset
                && self.total == total
                && self.sha256 == sha
                && (24..=MAX_BYTES).contains(&total)
                && self.data.len() <= 87384,
            "Invalid capture chunk"
        );
        let bytes = STANDARD.decode(&self.data)?;
        ensure!(
            !bytes.is_empty() && bytes.len() <= 65536 && offset + bytes.len() as u64 <= total,
            "Invalid capture chunk length"
        );
        Ok(bytes)
    }
}
async fn chunk(owner: &str, id: &str, offset: u64) -> Result<Chunk> {
    let value = crate::privileged::call(
        "capture",
        json!({"operation":"export","owner":owner,"id":id,"offset":offset}),
    )
    .await?;
    Ok(serde_json::from_value(value)?)
}
type OutputFrame = std::result::Result<Frame<Bytes>, std::io::Error>;
struct Download {
    receiver: mpsc::Receiver<OutputFrame>,
    _permit: OwnedSemaphorePermit,
    remaining: u64,
}
impl hyper::body::Body for Download {
    type Data = Bytes;
    type Error = std::io::Error;
    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<std::result::Result<Frame<Bytes>, Self::Error>>> {
        let polled = self.receiver.poll_recv(cx);
        if let Poll::Ready(Some(Ok(frame))) = &polled
            && let Some(bytes) = frame.data_ref()
        {
            self.remaining = self.remaining.saturating_sub(bytes.len() as u64);
        }
        polled
    }
    fn size_hint(&self) -> SizeHint {
        SizeHint::with_exact(self.remaining)
    }
    fn is_end_stream(&self) -> bool {
        self.remaining == 0
    }
}
async fn produce(
    control: Shared,
    actor: String,
    session: BrowserSession,
    id: String,
    owner: String,
    mut part: Chunk,
    sender: &mpsc::Sender<OutputFrame>,
) -> Result<()> {
    let total = part.total;
    let sha = part.sha256.clone();
    let mut offset = 0;
    let mut digest = Sha256::new();
    ensure!(
        sha.len() == 64 && sha.bytes().all(|b| b.is_ascii_hexdigit()),
        "Invalid capture integrity tag"
    );
    loop {
        let principal = control.store.session_principal(&session.0, false).await?;
        ensure!(
            !control.stop.is_cancelled()
                && principal.is_some_and(|p| p.username == actor
                    && p.role == crate::auth::Role::Administrator
                    && p.token_scope.is_none()),
            "Capture session revoked"
        );
        let bytes = part.bytes(offset, total, &sha)?;
        if offset == 0 {
            ensure!(
                bytes.starts_with(&[0xd4, 0xc3, 0xb2, 0xa1]),
                "Invalid PCAP header"
            );
        }
        digest.update(&bytes);
        offset += bytes.len() as u64;
        if offset == total {
            ensure!(
                format!("{:x}", digest.clone().finalize()) == sha,
                "Capture integrity check failed"
            );
        }
        sender
            .send(Ok(Frame::data(Bytes::from(bytes))))
            .await
            .map_err(|_| anyhow::anyhow!("Capture client disconnected"))?;
        if offset == total {
            break;
        }
        part = chunk(&owner, &id, offset).await?;
    }
    Ok(())
}
async fn export(
    State(control): State<Shared>,
    Extension(actor): Extension<String>,
    Extension(session): Extension<BrowserSession>,
    Path(id): Path<String>,
    Json(body): Json<Export>,
) -> std::result::Result<Response, ApiError> {
    let scope = export_scope(&id)
        .map_err(|_| error(StatusCode::UNPROCESSABLE_ENTITY, "Invalid capture ID"))?;
    admitted(async move {
        let permit = control
            .capture_exports
            .clone()
            .try_acquire_owned()
            .map_err(|_| {
                error(
                    StatusCode::CONFLICT,
                    "A capture download is already running",
                )
            })?;
        authorize(&control, &actor, &session, &body.proof, &scope).await?;
        control
            .store
            .record_audit(&actor, "diagnostic capture export started")
            .await
            .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Audit unavailable"))?;
        let owner = owner(&actor, &session);
        let first = chunk(&owner, &id, 0).await.map_err(|_| {
            error(
                StatusCode::CONFLICT,
                "Capture is unavailable, incomplete or expired",
            )
        })?;
        first
            .bytes(0, first.total, &first.sha256)
            .map_err(|_| error(StatusCode::SERVICE_UNAVAILABLE, "Invalid capture response"))?;
        let total = first.total;
        let filename = format!("attachment; filename=riverlb-capture-{id}.pcap");
        let (sender, receiver) = mpsc::channel(1);
        let stream_control = control.clone();
        let stream_actor = actor.clone();
        tokio::spawn(async move {
            let outcome = produce(
                stream_control.clone(),
                stream_actor.clone(),
                session,
                id,
                owner,
                first,
                &sender,
            )
            .await;
            let label = if outcome.is_ok() {
                "diagnostic capture exported"
            } else {
                "diagnostic capture export interrupted"
            };
            if stream_control.store.record_audit(&stream_actor,label).await.is_err() {
                tracing::warn!(actor=%stream_actor,"Diagnostic capture completion audit unavailable");
            }
            if outcome.is_err() {
                let _ = sender
                    .send(Err(std::io::Error::other(
                        "Capture expired, revoked or unavailable",
                    )))
                    .await;
            }
        });
        Response::builder()
            .header("content-type", "application/vnd.tcpdump.pcap")
            .header("content-length", total.to_string())
            .header("content-disposition", filename)
            .header("cache-control", "no-store")
            .header("x-content-type-options", "nosniff")
            .body(Body::new(Download {
                receiver,
                _permit: permit,
                remaining: total,
            }))
            .map_err(|_| {
                error(
                    StatusCode::SERVICE_UNAVAILABLE,
                    "Capture download unavailable",
                )
            })
    })
    .await
}
pub async fn management_change() -> Result<()> {
    if crate::privileged::enabled() {
        let status = crate::privileged::call("status", json!({})).await?;
        if status["features"]
            .as_array()
            .is_some_and(|f| f.iter().any(|v| v.as_str() == Some("capture_headers_v1")))
        {
            crate::privileged::call("capture", json!({"operation":"stop_all"})).await?;
        }
    }
    Ok(())
}
pub fn router() -> Router<Shared> {
    Router::new()
        .route(
            "/capture.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../web/capture.js"),
                )
            }),
        )
        .route(BASE, get(current))
        .route(&format!("{BASE}/interfaces"), get(interfaces))
        .route(&format!("{BASE}/start"), post(start))
        .route(&format!("{BASE}/{{id}}/cancel"), post(cancel))
        .route(&format!("{BASE}/{{id}}/delete"), post(delete))
        .route(&format!("{BASE}/{{id}}/export"), post(export))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn request() -> Request {
        serde_json::from_value(json!({"interface":"ens4","host":"fd88:16::100","port":18080,"protocol":"tcp","duration_seconds":15,"max_bytes":4096,"consent":true})).unwrap()
    }
    #[test]
    fn canonical_scope_binds_every_capture_setting_and_consent() {
        let original = request();
        let scope = original.scope().unwrap();
        let mut equivalent = request();
        equivalent.host = "fd88:0016:0000:0000:0000:0000:0000:0100".parse().unwrap();
        assert_eq!(scope, equivalent.scope().unwrap());
        let mut changed = request();
        changed.port = 18081;
        assert_ne!(scope, changed.scope().unwrap());
        changed = request();
        changed.max_bytes = 8192;
        assert_ne!(scope, changed.scope().unwrap());
        changed = request();
        changed.duration_seconds = 16;
        assert_ne!(scope, changed.scope().unwrap());
        changed = request();
        changed.consent = false;
        assert!(changed.scope().is_err());
        for interface in ["lo", "ens4;id", "../../ens4", "-ens4"] {
            changed = request();
            changed.interface = interface.into();
            assert!(changed.validate().is_err());
        }
        for port in [0, 22, 2223, 18090] {
            changed = request();
            changed.port = port;
            assert!(changed.validate().is_err());
        }
        assert!(export_scope("../private-key").is_err());
        assert_ne!(
            export_scope(&"a".repeat(32)).unwrap(),
            export_scope(&"b".repeat(32)).unwrap()
        );
    }
    #[test]
    fn strict_selector_types_and_session_owner_separation() {
        let value = serde_json::to_value(request()).unwrap();
        for (key, bad) in [
            ("filter", json!("port 80")),
            ("duration_seconds", json!(true)),
            ("host", json!("10.0.0.0/8")),
            ("protocol", json!("tcp or udp")),
        ] {
            let mut invalid = value.clone();
            invalid[key] = bad;
            assert!(serde_json::from_value::<Request>(invalid).is_err());
        }
        let a = BrowserSession("a".repeat(64));
        let b = BrowserSession("b".repeat(64));
        assert_ne!(owner("admin", &a), owner("admin", &b));
        assert_ne!(owner("admin", &a), owner("other", &a));
    }
    #[test]
    fn export_chunks_cannot_change_identity_size_or_position() {
        let part = Chunk {
            offset: 0,
            total: 24,
            data: STANDARD.encode([0u8; 24]),
            sha256: "a".repeat(64),
        };
        assert_eq!(part.bytes(0, 24, &"a".repeat(64)).unwrap().len(), 24);
        assert!(part.bytes(1, 24, &"a".repeat(64)).is_err());
        assert!(part.bytes(0, 25, &"a".repeat(64)).is_err());
        assert!(part.bytes(0, 24, &"b".repeat(64)).is_err());
    }
    #[tokio::test]
    async fn download_permit_survives_until_response_body_is_dropped() {
        let slots = Arc::new(tokio::sync::Semaphore::new(1));
        let permit = slots.clone().try_acquire_owned().unwrap();
        let (_sender, receiver) = mpsc::channel(1);
        let body = Download {
            receiver,
            _permit: permit,
            remaining: 24,
        };
        assert!(slots.clone().try_acquire_owned().is_err());
        drop(body);
        assert!(slots.try_acquire().is_ok());
    }
}
