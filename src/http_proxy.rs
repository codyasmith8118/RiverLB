//! Bounded HTTP/1 RiverRules engine and opaque server-side cookie affinity.
//! No user code is executed. All matches/actions are validated before activation.
use crate::runtime::{Pool, Runtime};
use anyhow::{Result, ensure};
use http_body_util::{BodyExt, Full, Limited, combinators::UnsyncBoxBody};
use hyper::{
    Request, Response,
    body::{Bytes, Incoming},
    header::{HeaderName, HeaderValue},
};
use hyper_util::rt::TokioIo;
use serde::{Deserialize, Serialize};
use std::{
    convert::Infallible,
    net::{IpAddr, SocketAddr},
    sync::{Arc, atomic::Ordering},
    time::Duration,
};

fn body_limit() -> usize {
    8 * 1024 * 1024
}
fn header_limit() -> usize {
    32768
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpProfile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub settings: HttpSettings,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HttpSettings {
    #[serde(default = "body_limit")]
    pub max_body_bytes: usize,
    #[serde(default = "header_limit")]
    pub max_header_bytes: usize,
    #[serde(default = "yes")]
    pub keep_alive: bool,
    #[serde(default)]
    pub streaming: bool,
    #[serde(default = "yes")]
    pub websockets: bool,
}
impl Default for HttpSettings {
    fn default() -> Self {
        Self {
            max_body_bytes: body_limit(),
            max_header_bytes: header_limit(),
            keep_alive: true,
            streaming: false,
            websockets: true,
        }
    }
}
impl HttpSettings {
    pub fn validate(&self) -> Result<()> {
        let max = if self.streaming {
            1024usize * 1024 * 1024 * 1024
        } else {
            64 * 1024 * 1024
        };
        ensure!(
            (1..=max).contains(&self.max_body_bytes),
            "HTTP body limit must be positive, at most 64 MiB buffered or 1 TiB streaming"
        );
        ensure!(
            (8192..=1048576).contains(&self.max_header_bytes),
            "HTTP header limit must be 8192..1048576 bytes"
        );
        Ok(())
    }
}
fn cookie_name() -> String {
    "RIVERLB".into()
}
fn cookie_ttl() -> u32 {
    3600
}
fn cookie_capacity() -> usize {
    10000
}
pub(crate) fn cookie_key(value: &str) -> String {
    use sha2::Digest;
    sha2::Sha256::digest(value.as_bytes())
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default = "header_limit")]
    pub max_header_bytes: usize,
    #[serde(default = "yes")]
    pub keep_alive: bool,
    #[serde(default)]
    pub streaming: bool,
    #[serde(default = "yes")]
    pub websockets: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie_profile: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rule_sets: Vec<String>,
    #[serde(default = "body_limit")]
    pub max_body_bytes: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cookie: Option<Cookie>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub rules: Vec<Rule>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Cookie {
    #[serde(default)]
    pub method: CookieMethod,
    #[serde(default = "yes")]
    pub http_only: bool,
    #[serde(default)]
    pub secure: Secure,
    #[serde(default)]
    pub same_site: SameSite,
    #[serde(default = "root_path")]
    pub path: String,
    #[serde(default)]
    pub domain: String,
    #[serde(default)]
    pub session_cookie: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expiration_secs: Option<u32>,
    #[serde(default = "yes")]
    pub always_send: bool,
    #[serde(default = "yes")]
    pub refresh_on_use: bool,
    #[serde(default)]
    pub hash_offset: usize,
    #[serde(default)]
    pub hash_length: usize,
    #[serde(default)]
    pub override_connection_limit: bool,
    #[serde(default = "cookie_name")]
    pub name: String,
    #[serde(default = "cookie_ttl")]
    pub ttl_secs: u32,
    #[serde(default = "cookie_capacity")]
    pub max_entries: usize,
}
fn yes() -> bool {
    true
}
fn root_path() -> String {
    "/".into()
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CookieMethod {
    #[default]
    Insert,
    Rewrite,
    Passive,
    Hash,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Secure {
    #[default]
    Auto,
    Always,
    Never,
}
#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SameSite {
    #[default]
    Lax,
    Strict,
    None,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CookieProfile {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub settings: Cookie,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct RuleSet {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub rules: Vec<Rule>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct BuiltinRuleSet {
    pub category: String,
    pub usage: String,
    pub name: String,
    pub description: String,
    pub rules: Vec<Rule>,
}
pub fn builtin_rule_sets() -> &'static [BuiltinRuleSet] {
    static CATALOG: std::sync::OnceLock<Vec<BuiltinRuleSet>> = std::sync::OnceLock::new();
    CATALOG.get_or_init(|| {
        serde_json::from_str(include_str!("river_rules.json"))
            .expect("validated built-in RiverRule catalog")
    })
}
pub fn builtin_rule_set(name: &str) -> Option<RuleSet> {
    builtin_rule_sets()
        .iter()
        .find(|entry| entry.name == name)
        .map(|entry| RuleSet {
            name: entry.name.clone(),
            description: entry.description.clone(),
            rules: entry.rules.clone(),
        })
}
impl Default for Cookie {
    fn default() -> Self {
        serde_json::from_str("{}").expect("cookie defaults")
    }
}
impl Cookie {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.expiration_secs.is_none_or(|n| n <= 315360000),
            "cookie expiration must be <=10 years"
        );
        ensure!(
            !self.name.is_empty()
                && self.name.len() <= 64
                && self
                    .name
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'),
            "invalid cookie name"
        );
        ensure!(
            (1..=86400).contains(&self.ttl_secs) && (1..=1000000).contains(&self.max_entries),
            "invalid cookie lifetime/capacity"
        );
        ensure!(
            self.path.starts_with('/')
                && self.path.len() <= 1024
                && self.path.bytes().all(|b| b > 32 && b < 127 && b != b';'),
            "invalid cookie Path"
        );
        ensure!(
            self.domain.len() <= 253
                && (self.domain.is_empty()
                    || (self
                        .domain
                        .strip_prefix('.')
                        .unwrap_or(&self.domain)
                        .split('.')
                        .all(|s| !s.is_empty()
                            && !s.starts_with('-')
                            && !s.ends_with('-')
                            && s.len() <= 63
                            && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
                        && !self.domain.ends_with('.'))),
            "invalid cookie Domain"
        );
        ensure!(
            self.hash_offset <= 4096 && self.hash_length <= 4096,
            "cookie hash bounds must be <=4096 bytes"
        );
        ensure!(
            !matches!(self.method, CookieMethod::Insert | CookieMethod::Rewrite)
                || self.same_site != SameSite::None
                || self.secure != Secure::Never,
            "SameSite=None requires Secure"
        );
        Ok(())
    }
    fn secure(&self, tls: bool) -> bool {
        self.secure == Secure::Always || (tls && self.secure == Secure::Auto)
    }
    fn value(&self, token: &str, tls: bool) -> String {
        let mut result = format!("{}={}; Path={}", self.name, token, self.path);
        if !self.session_cookie && self.expiration_secs != Some(0) {
            result.push_str(&format!(
                "; Max-Age={}",
                self.expiration_secs.unwrap_or(self.ttl_secs)
            ));
        }
        if !self.domain.is_empty() {
            result.push_str(&format!("; Domain={}", self.domain));
        }
        if self.http_only {
            result.push_str("; HttpOnly");
        }
        result.push_str(match self.same_site {
            SameSite::Lax => "; SameSite=Lax",
            SameSite::Strict => "; SameSite=Strict",
            SameSite::None => "; SameSite=None",
        });
        if self.secure(tls) {
            result.push_str("; Secure");
        }
        result
    }
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub name: String,
    #[serde(default)]
    pub when: Match,
    pub actions: Vec<Action>,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Match {
    pub host: Option<String>,
    pub path_prefix: Option<String>,
    pub path: Option<String>,
    pub tls: Option<bool>,
    pub method: Option<String>,
    pub header: Option<HeaderMatch>,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct HeaderMatch {
    pub name: String,
    pub value: String,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Action {
    Respond {
        status: u16,
        body: String,
    },
    Redirect {
        location: String,
    },
    RedirectHttps {
        #[serde(default)]
        host: Option<String>,
    },
    SetForwardedFor,
    SetProxyHeaders,
    RewritePath {
        path: String,
    },
    SetRequestHeader {
        name: String,
        value: String,
    },
    SetResponseHeader {
        name: String,
        value: String,
    },
    RemoveRequestHeader {
        name: String,
    },
    RemoveResponseHeader {
        name: String,
    },
    SelectMember {
        address: SocketAddr,
    },
}
fn safe_authority(host: &str) -> bool {
    !host.is_empty()
        && host.len() <= 255
        && !host.contains('@')
        && host
            .parse::<hyper::http::uri::Authority>()
            .is_ok_and(|authority| !authority.host().is_empty())
        && host.bytes().all(|b| b > 32 && b < 127)
}
fn https_location(
    host: Option<&str>,
    headers: &hyper::HeaderMap,
    uri: &hyper::Uri,
) -> Option<HeaderValue> {
    let destination = if let Some(host) = host {
        if !safe_authority(host) {
            return None;
        }
        host.to_owned()
    } else {
        if headers.get_all("host").iter().count() != 1 {
            return None;
        }
        let host = headers.get("host")?.to_str().ok()?;
        if !safe_authority(host) {
            return None;
        }
        host.parse::<hyper::http::uri::Authority>()
            .ok()?
            .host()
            .to_owned()
    };
    let location = format!(
        "https://{destination}{}",
        uri.path_and_query().map_or("/", |p| p.as_str())
    );
    if location.len() > 4096 {
        return None;
    }
    HeaderValue::from_str(&location).ok()
}
fn reserved(name: &str) -> bool {
    matches!(
        name.to_ascii_lowercase().as_str(),
        "host"
            | "content-length"
            | "transfer-encoding"
            | "connection"
            | "upgrade"
            | "trailer"
            | "te"
            | "keep-alive"
            | "proxy-connection"
            | "proxy-authorization"
            | "proxy-authenticate"
            | "cookie"
            | "set-cookie"
    )
}
fn header(name: &str, value: &str) -> Result<()> {
    ensure!(
        name.len() <= 128 && value.len() <= 4096 && !reserved(name),
        "rule cannot change framing, routing or cookie headers"
    );
    HeaderName::from_bytes(name.as_bytes())?;
    HeaderValue::from_str(value)?;
    Ok(())
}
fn path(value: &str) -> bool {
    value.starts_with('/')
        && !value.starts_with("//")
        && value.len() <= 4096
        && value.bytes().all(|b| b > 32 && b < 127 && b != b'#')
        && value.parse::<hyper::Uri>().is_ok()
}
impl Profile {
    pub fn validate(&self, members: &[SocketAddr]) -> Result<()> {
        HttpSettings {
            max_body_bytes: self.max_body_bytes,
            max_header_bytes: self.max_header_bytes,
            keep_alive: self.keep_alive,
            streaming: self.streaming,
            websockets: self.websockets,
        }
        .validate()?;
        if let Some(cookie) = &self.cookie {
            cookie.validate()?;
        }
        ensure!(
            self.rules.len() <= 128,
            "at most 128 RiverRules per virtual server"
        );
        let mut names = std::collections::HashSet::new();
        for rule in &self.rules {
            ensure!(
                !rule.name.is_empty()
                    && rule.name.len() <= 128
                    && (names.insert(&rule.name) || !self.rule_sets.is_empty()),
                "RiverRules require unique names of 1..128 bytes"
            );
            ensure!(
                !rule.actions.is_empty() && rule.actions.len() <= 16,
                "rules require 1..16 actions"
            );
            if let Some(host) = &rule.when.host {
                ensure!(
                    !host.is_empty()
                        && host.len() <= 255
                        && host.bytes().all(|b| b > 32 && b < 127),
                    "invalid rule Host"
                );
            }
            if let Some(prefix) = &rule.when.path_prefix {
                ensure!(path(prefix), "invalid rule path prefix");
            }
            if let Some(exact) = &rule.when.path {
                ensure!(
                    path(exact) && !exact.contains('?'),
                    "exact rule path must exclude the query"
                );
            }
            if let Some(method) = &rule.when.method {
                ensure!(method.len() <= 32, "method too long");
                hyper::Method::from_bytes(method.as_bytes())?;
            }
            if let Some(h) = &rule.when.header {
                ensure!(
                    h.name.len() <= 128 && h.value.len() <= 4096,
                    "header match too long"
                );
                HeaderName::from_bytes(h.name.as_bytes())?;
                HeaderValue::from_str(&h.value)?;
            }
            for action in &rule.actions {
                match action {
                    Action::Respond { status, body } => ensure!(
                        (200..=599).contains(status)
                            && ![204, 205, 304].contains(status)
                            && body.len() <= 65536,
                        "response requires status 200..599 with a body and at most 64 KiB text"
                    ),
                    Action::Redirect { location } => ensure!(
                        location.len() <= 4096
                            && (path(location)
                                || ((location.starts_with("https://")
                                    || location.starts_with("http://"))
                                    && location.parse::<hyper::Uri>().is_ok()))
                            && HeaderValue::from_str(location).is_ok(),
                        "redirect requires a safe origin path or HTTP(S) URL"
                    ),
                    Action::RedirectHttps { host } => {
                        if let Some(host) = host {
                            ensure!(
                                safe_authority(host),
                                "HTTPS redirect host must be a hostname or IP with an optional port"
                            );
                        }
                    }
                    Action::SetForwardedFor | Action::SetProxyHeaders => {}
                    Action::RewritePath { path: p } => {
                        ensure!(path(p), "rewrite requires an origin path")
                    }
                    Action::SetRequestHeader { name, value }
                    | Action::SetResponseHeader { name, value } => header(name, value)?,
                    Action::RemoveRequestHeader { name }
                    | Action::RemoveResponseHeader { name } => header(name, "")?,
                    Action::SelectMember { address } => ensure!(
                        members.contains(address),
                        "rule member must belong to the virtual server's pool"
                    ),
                }
            }
        }
        Ok(())
    }
}
impl Match {
    fn matches<B>(&self, request: &Request<B>, tls: bool) -> bool {
        self.host.as_ref().is_none_or(|h| {
            request
                .headers()
                .get("host")
                .and_then(|v| v.to_str().ok())
                .is_some_and(|v| v.eq_ignore_ascii_case(h))
        }) && self
            .path_prefix
            .as_ref()
            .is_none_or(|p| request.uri().path().starts_with(p))
            && self.path.as_ref().is_none_or(|p| request.uri().path() == p)
            && self.tls.is_none_or(|expected| expected == tls)
            && self
                .method
                .as_ref()
                .is_none_or(|m| request.method().as_str() == m)
            && self.header.as_ref().is_none_or(|h| {
                request
                    .headers()
                    .get_all(h.name.as_str())
                    .iter()
                    .any(|v| v.as_bytes() == h.value.as_bytes())
            })
    }
}
type Body = UnsyncBoxBody<Bytes, Box<dyn std::error::Error + Send + Sync>>;
fn response(status: u16, body: impl Into<Bytes>) -> Response<Body> {
    let mut response = Response::new(full(body.into()));
    *response.status_mut() = hyper::StatusCode::from_u16(status).unwrap();
    response
}
fn full(bytes: Bytes) -> Body {
    Full::new(bytes).map_err(|e| match e {}).boxed_unsync()
}
fn edit_headers(headers: &mut hyper::HeaderMap, actions: &[&Action]) {
    for action in actions {
        match action {
            Action::SetResponseHeader { name, value } => {
                headers.insert(
                    HeaderName::from_bytes(name.as_bytes()).unwrap(),
                    HeaderValue::from_str(value).unwrap(),
                );
            }
            Action::RemoveResponseHeader { name } => {
                headers.remove(name.as_str());
            }
            _ => unreachable!("response header edit"),
        }
    }
}
fn local_response(mut response: Response<Body>, actions: &[&Action]) -> Response<Body> {
    edit_headers(response.headers_mut(), actions);
    response
}
fn protect_header_nominations(headers: &mut hyper::HeaderMap, protected: &[&str]) {
    let tokens = headers
        .get_all("connection")
        .iter()
        .filter_map(|value| value.to_str().ok())
        .flat_map(|value| value.split(','))
        .map(str::trim)
        .filter(|token| {
            !token.is_empty()
                && !protected
                    .iter()
                    .any(|name| token.eq_ignore_ascii_case(name))
        })
        .collect::<Vec<_>>()
        .join(", ");
    headers.remove("connection");
    if !tokens.is_empty() {
        headers.insert("connection", HeaderValue::from_str(&tokens).unwrap());
    }
}
fn proxy_headers<B>(request: &mut Request<B>, source: IpAddr, tls: bool, port: u16) -> Result<()> {
    ensure!(
        request.headers().get_all("host").iter().count() == 1,
        "proxy headers require one Host header"
    );
    let host = request.headers().get("host").unwrap().clone();
    ensure!(
        host.to_str().is_ok_and(safe_authority),
        "invalid proxy Host header"
    );
    // Preserve handshake/header matching until the usual forwarding phase,
    // while preventing client Connection tokens from stripping trusted fields.
    protect_header_nominations(
        request.headers_mut(),
        &[
            "x-forwarded-for",
            "x-real-ip",
            "x-forwarded-proto",
            "x-forwarded-host",
            "x-forwarded-port",
        ],
    );
    let forwarded = request
        .headers()
        .keys()
        .filter(|name| name.as_str().starts_with("x-forwarded-"))
        .cloned()
        .collect::<Vec<_>>();
    for name in forwarded {
        request.headers_mut().remove(name);
    }
    let headers = request.headers_mut();
    headers.remove("forwarded");
    headers.insert(
        "x-forwarded-for",
        HeaderValue::from_str(&source.to_string())?,
    );
    headers.insert("x-real-ip", HeaderValue::from_str(&source.to_string())?);
    headers.insert(
        "x-forwarded-proto",
        HeaderValue::from_static(if tls { "https" } else { "http" }),
    );
    headers.insert("x-forwarded-host", host);
    headers.insert("x-forwarded-port", HeaderValue::from(port));
    Ok(())
}
fn strip_hop(headers: &mut hyper::HeaderMap) {
    let tokens = headers
        .get_all("connection")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(','))
        .filter_map(|v| HeaderName::from_bytes(v.trim().as_bytes()).ok())
        .collect::<Vec<_>>();
    for token in tokens {
        headers.remove(token);
    }
    for name in [
        "connection",
        "keep-alive",
        "proxy-connection",
        "proxy-authenticate",
        "proxy-authorization",
        "te",
        "trailer",
        "transfer-encoding",
        "upgrade",
    ] {
        headers.remove(name);
    }
}
struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
// Own the backend driver and admission until the streamed response ends or is dropped.
struct TransferBody {
    inner: Body,
    deadline: std::pin::Pin<Box<tokio::time::Sleep>>,
    pool: Arc<Pool>,
    index: usize,
    upload: bool,
    finished: bool,
    _reservation: Option<crate::runtime::Reservation>,
    _driver: Option<Driver>,
}
impl hyper::body::Body for TransferBody {
    type Data = Bytes;
    type Error = Box<dyn std::error::Error + Send + Sync>;
    fn poll_frame(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Result<hyper::body::Frame<Bytes>, Self::Error>>> {
        use std::{future::Future, task::Poll};
        if self.deadline.as_mut().poll(cx).is_ready() {
            return Poll::Ready(Some(Err(std::io::Error::new(
                std::io::ErrorKind::TimedOut,
                "HTTP transfer deadline",
            )
            .into())));
        }
        let result = loop {
            let frame = std::pin::Pin::new(&mut self.inner).poll_frame(cx);
            if matches!(&frame,Poll::Ready(Some(Ok(frame))) if frame.is_trailers()) {
                continue;
            }
            break frame;
        };
        if matches!(result, Poll::Ready(None)) && !self.finished {
            self.finished = true;
            if !self.upload {
                self.pool.members.lock().unwrap()[self.index].completed += 1;
                self.pool.members.lock().unwrap()[self.index]
                    .traffic
                    .completed
                    .fetch_add(1, Ordering::Relaxed);
                self.pool.traffic.completed.fetch_add(1, Ordering::Relaxed);
            }
        }
        result
    }
    fn size_hint(&self) -> hyper::body::SizeHint {
        self.inner.size_hint()
    }
}
impl Drop for TransferBody {
    fn drop(&mut self) {
        if !self.upload && !self.finished {
            self.pool.members.lock().unwrap()[self.index].failures += 1;
            self.pool.members.lock().unwrap()[self.index]
                .traffic
                .failures
                .fetch_add(1, Ordering::Relaxed);
            self.pool.traffic.failures.fetch_add(1, Ordering::Relaxed);
            self.pool
                .traffic
                .transport_errors
                .fetch_add(1, Ordering::Relaxed);
        }
    }
}
struct StopTunnel(tokio_util::sync::CancellationToken);
// Meter the plaintext backend HTTP stream once, including headers, chunk
// framing and upgraded bytes. Body wrappers only manage deadlines/admission.
struct BackendIo<S> {
    inner: S,
    pool: Arc<Pool>,
    index: usize,
}
impl<S: tokio::io::AsyncRead + Unpin> tokio::io::AsyncRead for BackendIo<S> {
    fn poll_read(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &mut tokio::io::ReadBuf<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        let before = buf.filled().len();
        let result = std::pin::Pin::new(&mut self.inner).poll_read(cx, buf);
        let n = (buf.filled().len() - before) as u64;
        if n == 0 {
            return result;
        }
        self.pool.members.lock().unwrap()[self.index].bytes_to_client += n;
        self.pool.members.lock().unwrap()[self.index]
            .traffic
            .down
            .fetch_add(n, Ordering::Relaxed);
        self.pool.traffic.down.fetch_add(n, Ordering::Relaxed);
        result
    }
}
impl<S: tokio::io::AsyncWrite + Unpin> tokio::io::AsyncWrite for BackendIo<S> {
    fn poll_write(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
        buf: &[u8],
    ) -> std::task::Poll<std::io::Result<usize>> {
        let result = std::pin::Pin::new(&mut self.inner).poll_write(cx, buf);
        if let std::task::Poll::Ready(Ok(n)) = result {
            self.pool.members.lock().unwrap()[self.index].bytes_to_backend += n as u64;
            self.pool.members.lock().unwrap()[self.index]
                .traffic
                .up
                .fetch_add(n as u64, Ordering::Relaxed);
            self.pool.traffic.up.fetch_add(n as u64, Ordering::Relaxed);
        }
        result
    }
    fn poll_flush(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<std::io::Result<()>> {
        std::pin::Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}
impl Drop for StopTunnel {
    fn drop(&mut self) {
        self.0.cancel();
    }
}
pub async fn serve<S>(
    client: S,
    pool: Arc<Pool>,
    config: crate::config::Config,
    source: IpAddr,
) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let settings = pool.config.http.as_ref().unwrap();
    let max_header_bytes = settings.max_header_bytes;
    let keep_alive = settings.keep_alive;
    let stop = StopTunnel(tokio_util::sync::CancellationToken::new());
    let done = Arc::new(std::sync::Mutex::new(None));
    let service_done = done.clone();
    let tunnel_stop = stop.0.clone();
    let service = hyper::service::service_fn(move |request| {
        let pool = pool.clone();
        let config = config.clone();
        let done = service_done.clone();
        let stop = tunnel_stop.clone();
        async move { Ok::<_, Infallible>(handle(request, pool, config, source, stop, done).await) }
    });
    hyper::server::conn::http1::Builder::new()
        .max_buf_size(max_header_bytes)
        .keep_alive(keep_alive)
        .serve_connection(TokioIo::new(client), service)
        .with_upgrades()
        .await?;
    let receiver = done.lock().unwrap().take();
    if let Some(receiver) = receiver {
        let _ = receiver.await;
    }
    Ok(())
}
async fn handle(
    mut request: Request<Incoming>,
    pool: Arc<Pool>,
    config: crate::config::Config,
    source: IpAddr,
    tunnel_stop: tokio_util::sync::CancellationToken,
    tunnel_done: Arc<std::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>>,
) -> Response<Body> {
    let profile = pool.config.http.as_ref().unwrap();
    if request.method() == hyper::Method::CONNECT
        || request.uri().scheme().is_some()
        || request.uri().authority().is_some()
    {
        return response(400, "Only origin-form HTTP/1 requests are supported");
    }
    if request.method() == hyper::Method::GET
        && let Some(token) = request
            .uri()
            .path()
            .strip_prefix("/.well-known/acme-challenge/")
    {
        let value = pool.acme_challenges.lock().unwrap().get(token).cloned();
        if let Some(value) = value {
            return response(200, value);
        }
    }
    let websocket = request.headers().contains_key("upgrade");
    use base64::Engine;
    let websocket_key_valid = request
        .headers()
        .get("sec-websocket-key")
        .and_then(|v| {
            base64::engine::general_purpose::STANDARD
                .decode(v.as_bytes())
                .ok()
        })
        .is_some_and(|v| v.len() == 16);
    if websocket
        && (!websocket_key_valid
            || request
                .headers()
                .get("sec-websocket-version")
                .is_none_or(|v| v != "13")
            || request.headers().contains_key("transfer-encoding")
            || request
                .headers()
                .get("content-length")
                .is_some_and(|v| v != "0"))
    {
        return response(400, "Invalid WebSocket handshake");
    }
    let expected_accept = if websocket {
        use sha1::Digest;
        let mut digest = sha1::Sha1::new();
        digest.update(request.headers()["sec-websocket-key"].as_bytes());
        digest.update(b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11");
        Some(base64::engine::general_purpose::STANDARD.encode(digest.finalize()))
    } else {
        None
    };
    if websocket
        && (!profile.websockets
            || request.method() != hyper::Method::GET
            || !request
                .headers()
                .get("upgrade")
                .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket"))
            || !request
                .headers()
                .get_all("connection")
                .iter()
                .filter_map(|v| v.to_str().ok())
                .flat_map(|v| v.split(','))
                .any(|v| v.trim().eq_ignore_ascii_case("upgrade")))
    {
        return response(400, "Unsupported HTTP upgrade");
    }
    let mut chosen = None;
    let domain_target = if pool.config.has_domain_routes {
        if request.headers().get_all("host").iter().count() != 1 {
            return response(400, "Domain routing requires one Host header");
        }
        let host = request
            .headers()
            .get("host")
            .and_then(|h| h.to_str().ok())
            .and_then(|h| h.parse::<hyper::http::uri::Authority>().ok())
            .map(|h| h.host().trim_end_matches('.').to_ascii_lowercase());
        let Some(host) = host else {
            return response(400, "Invalid Host header");
        };
        let target = pool.config.resolved_domains.get(&host).copied();
        if target.is_none()
            && pool
                .config
                .default_members
                .as_ref()
                .is_some_and(Vec::is_empty)
        {
            let mut miss = response(404, pool.config.hostname_miss_body.clone());
            miss.headers_mut().insert(
                hyper::header::CONTENT_TYPE,
                hyper::header::HeaderValue::from_static("text/plain; charset=utf-8"),
            );
            return miss;
        }
        target
    } else {
        None
    };
    let mut response_headers = Vec::new();
    let tls = pool.client_tls();
    for rule in &profile.rules {
        if !rule.when.matches(&request, tls) {
            continue;
        }
        for action in &rule.actions {
            match action {
                Action::Respond { status, body } => {
                    return local_response(response(*status, body.clone()), &response_headers);
                }
                Action::Redirect { location } => {
                    let mut r = response(302, Bytes::new());
                    r.headers_mut()
                        .insert("location", HeaderValue::from_str(location).unwrap());
                    return local_response(r, &response_headers);
                }
                Action::RedirectHttps { host } => {
                    let Some(location) =
                        https_location(host.as_deref(), request.headers(), request.uri())
                    else {
                        return local_response(
                            response(400, "Invalid HTTPS redirect destination"),
                            &response_headers,
                        );
                    };
                    let mut r = response(302, Bytes::new());
                    r.headers_mut().insert("location", location);
                    return local_response(r, &response_headers);
                }
                Action::SetForwardedFor => {
                    protect_header_nominations(request.headers_mut(), &["x-forwarded-for"]);
                    request.headers_mut().insert(
                        "x-forwarded-for",
                        HeaderValue::from_str(&source.to_string()).unwrap(),
                    );
                }
                Action::SetProxyHeaders => {
                    if proxy_headers(&mut request, source, tls, pool.config.listen.port()).is_err()
                    {
                        return local_response(
                            response(400, "Invalid proxy Host header"),
                            &response_headers,
                        );
                    }
                }
                Action::RewritePath { path } => *request.uri_mut() = path.parse().unwrap(),
                Action::SetRequestHeader { name, value } => {
                    protect_header_nominations(request.headers_mut(), &[name.as_str()]);
                    request.headers_mut().insert(
                        HeaderName::from_bytes(name.as_bytes()).unwrap(),
                        HeaderValue::from_str(value).unwrap(),
                    );
                }
                Action::RemoveRequestHeader { name } => {
                    request.headers_mut().remove(name.as_str());
                }
                Action::SetResponseHeader { .. } | Action::RemoveResponseHeader { .. } => {
                    response_headers.push(action)
                }
                Action::SelectMember { address } => chosen = Some(*address),
            }
        }
    }
    let cookie_token = profile.cookie.as_ref().and_then(|c| {
        // Host routing is authoritative; affinity must never cross hostname destinations.
        let values = request
            .headers()
            .get_all("cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .filter_map(|v| v.trim().split_once('='))
            .filter(|(name, _)| *name == c.name)
            .map(|(_, v)| v)
            .collect::<Vec<_>>();
        (values.len() == 1 && values[0].len() <= 4096 && !values[0].is_empty())
            .then(|| values[0].to_owned())
    });
    chosen = domain_target.or(chosen);
    let preferred =
        cookie_token
            .as_deref()
            .and_then(|t| match profile.cookie.as_ref().unwrap().method {
                CookieMethod::Hash => pool.hash_cookie_member(t),
                CookieMethod::Passive => pool.cookie_member(&cookie_key(t)),
                _ => pool.cookie_member(t),
            });
    let bypass = chosen.is_none()
        && preferred.is_some()
        && profile
            .cookie
            .as_ref()
            .is_some_and(|c| c.override_connection_limit);
    let Some(reservation) =
        pool.reserve_http(source, chosen.or(preferred), chosen.is_some(), bypass)
    else {
        pool.traffic.rejected.fetch_add(1, Ordering::Relaxed);
        return local_response(response(503, "No available backend"), &response_headers);
    };
    let address = pool.members.lock().unwrap()[reservation.index].address;
    let head = request.method() == hyper::Method::HEAD;
    let client_upgrade = websocket.then(|| hyper::upgrade::on(&mut request));
    let streaming = profile.streaming && !websocket;
    if let Some(length) = request
        .headers()
        .get("content-length")
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.parse::<usize>().ok())
        && length > profile.max_body_bytes
    {
        return local_response(
            response(413, "Request body exceeds the limit"),
            &response_headers,
        );
    }
    let (mut parts, body) = request.into_parts();
    let (body, sent) = if streaming {
        (
            TransferBody {
                inner: Limited::new(body, profile.max_body_bytes).boxed_unsync(),
                deadline: Box::pin(tokio::time::sleep(Duration::from_secs(
                    config.session_timeout_secs,
                ))),
                pool: pool.clone(),
                index: reservation.index,
                upload: true,
                finished: false,
                _reservation: None,
                _driver: None,
            }
            .boxed_unsync(),
            0,
        )
    } else {
        let body = match tokio::time::timeout(
            Duration::from_secs(config.session_timeout_secs),
            Limited::new(body, profile.max_body_bytes).collect(),
        )
        .await
        {
            Ok(Ok(body)) => body.to_bytes(),
            _ => {
                return local_response(
                    response(413, "Request body exceeds the limit or timed out"),
                    &response_headers,
                );
            }
        };
        let sent = body.len() as u64;
        (full(body), sent)
    };
    strip_hop(&mut parts.headers);
    if websocket {
        parts
            .headers
            .insert("connection", HeaderValue::from_static("upgrade"));
        parts
            .headers
            .insert("upgrade", HeaderValue::from_static("websocket"));
    }
    parts.headers.remove("expect");
    if !streaming {
        parts
            .headers
            .insert("content-length", HeaderValue::from(sent));
    }
    // Never send the load balancer's opaque cookie to the application.
    if let Some(cookie) = &profile.cookie
        && matches!(cookie.method, CookieMethod::Insert | CookieMethod::Rewrite)
    {
        let filtered = parts
            .headers
            .get_all("cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .flat_map(|v| v.split(';'))
            .filter(|v| {
                v.trim()
                    .split_once('=')
                    .is_none_or(|(name, _)| name != cookie.name)
            })
            .map(str::trim)
            .collect::<Vec<_>>()
            .join("; ");
        parts.headers.remove("cookie");
        if !filtered.is_empty() {
            parts
                .headers
                .insert("cookie", HeaderValue::from_str(&filtered).unwrap());
        }
    }
    let request = Request::from_parts(parts, body);
    let response_started = std::time::Instant::now();
    let result = tokio::time::timeout(Duration::from_secs(config.session_timeout_secs), async {
        let connect_started = std::time::Instant::now();
        let stream = tokio::time::timeout(
            Duration::from_millis(config.connect_timeout_ms),
            Runtime::http_backend(&config, &pool, address),
        )
        .await??;
        pool.traffic
            .connect_latency
            .record(connect_started.elapsed());
        pool.members.lock().unwrap()[reservation.index]
            .traffic
            .connect_latency
            .record(connect_started.elapsed());
        let stream = BackendIo {
            inner: stream,
            pool: pool.clone(),
            index: reservation.index,
        };
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(stream)).await?;
        let driver = Driver(tokio::spawn(async move {
            let _ = connection.with_upgrades().await;
        }));
        let mut response = sender.send_request(request).await?;
        pool.traffic
            .response_latency
            .record(response_started.elapsed());
        pool.members.lock().unwrap()[reservation.index]
            .traffic
            .response_latency
            .record(response_started.elapsed());
        let backend_upgrade = if response.status() == 101 {
            ensure!(
                websocket
                    && response
                        .headers()
                        .get("sec-websocket-accept")
                        .and_then(|v| v.to_str().ok())
                        == expected_accept.as_deref()
                    && response
                        .headers()
                        .get_all("connection")
                        .iter()
                        .filter_map(|v| v.to_str().ok())
                        .flat_map(|v| v.split(','))
                        .any(|v| v.trim().eq_ignore_ascii_case("upgrade"))
                    && response
                        .headers()
                        .get("upgrade")
                        .is_some_and(|v| v.as_bytes().eq_ignore_ascii_case(b"websocket")),
                "invalid backend upgrade"
            );
            Some(hyper::upgrade::on(&mut response))
        } else {
            None
        };
        let (parts, body) = response.into_parts();
        if streaming || backend_upgrade.is_some() {
            if let Some(length) = parts
                .headers
                .get("content-length")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.parse::<usize>().ok())
            {
                ensure!(
                    length <= profile.max_body_bytes,
                    "Backend body exceeds limit"
                );
            }
            return anyhow::Ok((
                parts,
                Limited::new(body, profile.max_body_bytes).boxed_unsync(),
                0,
                Some(driver),
                backend_upgrade,
            ));
        }
        let body = Limited::new(body, profile.max_body_bytes)
            .collect()
            .await
            .map_err(anyhow::Error::from_boxed)?
            .to_bytes();
        let received = body.len() as u64;
        anyhow::Ok((parts, full(body), received, None, None))
    })
    .await;
    let (mut parts, body, received, driver, backend_upgrade) = match result {
        Ok(Ok(result)) => result,
        _ => {
            pool.members.lock().unwrap()[reservation.index].failures += 1;
            pool.members.lock().unwrap()[reservation.index]
                .traffic
                .failures
                .fetch_add(1, Ordering::Relaxed);
            pool.traffic.failures.fetch_add(1, Ordering::Relaxed);
            pool.traffic.backend_errors.fetch_add(1, Ordering::Relaxed);
            return local_response(
                response(502, "Backend HTTP exchange failed"),
                &response_headers,
            );
        }
    };
    strip_hop(&mut parts.headers);
    if backend_upgrade.is_some() {
        parts
            .headers
            .insert("connection", HeaderValue::from_static("upgrade"));
        parts
            .headers
            .insert("upgrade", HeaderValue::from_static("websocket"));
        parts.headers.remove("content-length");
    } else if !streaming && !head && parts.status != 304 {
        parts
            .headers
            .insert("content-length", HeaderValue::from(received));
    }
    edit_headers(&mut parts.headers, &response_headers);
    if let Some(cookie) = &profile.cookie {
        let app_values = parts
            .headers
            .get_all("set-cookie")
            .iter()
            .filter_map(|v| v.to_str().ok())
            .filter_map(|v| v.split(';').next()?.split_once('='))
            .filter(|(name, _)| name.trim() == cookie.name)
            .map(|(_, value)| value)
            .collect::<Vec<_>>();
        let app_cookie = app_values.len() == 1;
        if cookie.method == CookieMethod::Passive
            && app_cookie
            && !app_values[0].is_empty()
            && app_values[0].len() <= 4096
        {
            pool.learn_cookie(&cookie_key(app_values[0]), address);
        }
        if matches!(cookie.method, CookieMethod::Insert | CookieMethod::Rewrite) {
            let values = parts
                .headers
                .get_all("set-cookie")
                .iter()
                .filter(|v| {
                    v.to_str()
                        .ok()
                        .and_then(|v| v.split(';').next())
                        .and_then(|v| v.split_once('='))
                        .is_none_or(|(name, _)| name.trim() != cookie.name)
                })
                .cloned()
                .collect::<Vec<_>>();
            parts.headers.remove("set-cookie");
            for value in values {
                parts.headers.append("set-cookie", value);
            }
            parts.headers.insert(
                "cache-control",
                HeaderValue::from_static("private, no-store"),
            );
            if (cookie.method == CookieMethod::Insert || app_cookie)
                && let Some(token) = pool.issue_cookie(cookie_token.as_deref(), address)
                && (cookie.always_send
                    || cookie.method == CookieMethod::Rewrite
                    || cookie_token.as_deref() != Some(token.as_str()))
            {
                let value = cookie.value(
                    &token,
                    pool.config.tls.is_some() || pool.config.certificate.is_some(),
                );
                parts
                    .headers
                    .append("set-cookie", HeaderValue::from_str(&value).unwrap());
            }
        }
    }
    if let Some(backend_upgrade) = backend_upgrade {
        let (sender, receiver) = tokio::sync::oneshot::channel();
        *tunnel_done.lock().unwrap() = Some(receiver);
        tokio::spawn(async move {
            let _driver = driver;
            let result = tokio::select! {
                _ = tunnel_stop.cancelled() => Err(anyhow::anyhow!("tunnel cancelled")),
                result = async {
                    let (client, backend) = tokio::try_join!(client_upgrade.unwrap(),backend_upgrade)?;
                    let mut backend=TokioIo::new(backend);
                    anyhow::Ok(tokio::io::copy_bidirectional(&mut TokioIo::new(client),&mut backend).await?)
                } => result,
            };
            match result {
                Ok((_up, _down)) => {
                    let mut members = pool.members.lock().unwrap();
                    members[reservation.index].completed += 1;
                    members[reservation.index]
                        .traffic
                        .completed
                        .fetch_add(1, Ordering::Relaxed);
                    pool.traffic.completed.fetch_add(1, Ordering::Relaxed);
                }
                Err(_) => {
                    pool.members.lock().unwrap()[reservation.index].failures += 1;
                    pool.members.lock().unwrap()[reservation.index]
                        .traffic
                        .failures
                        .fetch_add(1, Ordering::Relaxed);
                    pool.traffic.failures.fetch_add(1, Ordering::Relaxed);
                    pool.traffic
                        .transport_errors
                        .fetch_add(1, Ordering::Relaxed);
                }
            }
            drop(reservation);
            let _ = sender.send(());
        });
        return Response::from_parts(parts, full(Bytes::new()));
    }
    if streaming {
        let finished = hyper::body::Body::is_end_stream(&body);
        if finished {
            pool.members.lock().unwrap()[reservation.index].completed += 1;
            pool.members.lock().unwrap()[reservation.index]
                .traffic
                .completed
                .fetch_add(1, Ordering::Relaxed);
            pool.traffic.completed.fetch_add(1, Ordering::Relaxed);
        }
        let body = TransferBody {
            inner: body,
            deadline: Box::pin(tokio::time::sleep(Duration::from_secs(
                config.session_timeout_secs,
            ))),
            pool: pool.clone(),
            index: reservation.index,
            upload: false,
            finished,
            _reservation: Some(reservation),
            _driver: driver,
        };
        return Response::from_parts(parts, body.boxed_unsync());
    }
    {
        let mut members = pool.members.lock().unwrap();
        let m = &mut members[reservation.index];
        m.completed += 1;
        m.traffic.completed.fetch_add(1, Ordering::Relaxed);
    }
    pool.traffic.completed.fetch_add(1, Ordering::Relaxed);
    Response::from_parts(parts, body)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn https_redirect_preserves_path_query_and_validates_destination() {
        let mut headers = hyper::HeaderMap::new();
        headers.insert("host", HeaderValue::from_static("app.example:80"));
        let uri: hyper::Uri = "/some/path?one=two".parse().unwrap();
        assert_eq!(
            https_location(None, &headers, &uri).unwrap(),
            "https://app.example/some/path?one=two"
        );
        assert_eq!(
            https_location(Some("fixed.example:8443"), &headers, &uri).unwrap(),
            "https://fixed.example:8443/some/path?one=two"
        );
        headers.insert("host", HeaderValue::from_static("[2001:db8::1]:80"));
        assert_eq!(
            https_location(None, &headers, &uri).unwrap(),
            "https://[2001:db8::1]/some/path?one=two"
        );
        for invalid in [
            "user@evil.example",
            "https://app.example",
            "bad host",
            "app.example/path",
            "",
            ":80",
        ] {
            assert!(!safe_authority(invalid));
            assert!(https_location(Some(invalid), &headers, &uri).is_none());
        }
        headers.append("host", HeaderValue::from_static("another.example"));
        assert!(https_location(None, &headers, &uri).is_none());
        headers.clear();
        assert!(https_location(None, &headers, &uri).is_none());
    }
    #[test]
    fn validates_bounded_rules_and_protects_framing() {
        let mut p: Profile = serde_json::from_str(r#"{"cookie":{},"rules":[{"name":"deny","when":{"path_prefix":"/private"},"actions":[{"kind":"respond","status":403,"body":"Forbidden"}]}]}"#).unwrap();
        p.validate(&[]).unwrap();
        p.rules[0].actions = vec![Action::SetRequestHeader {
            name: "Content-Length".into(),
            value: "0".into(),
        }];
        assert!(p.validate(&[]).is_err());
        p.rules[0].actions = vec![Action::RewritePath {
            path: "https://other/".into(),
        }];
        assert!(p.validate(&[]).is_err());
        assert!(serde_json::from_str::<Profile>(r#"{"rules":[],"script":"exec"}"#).is_err());
        for action in [
            Action::RemoveRequestHeader {
                name: "Host".into(),
            },
            Action::RemoveResponseHeader {
                name: "Set-Cookie".into(),
            },
        ] {
            p.rules[0].actions = vec![action];
            assert!(p.validate(&[]).is_err());
        }
        p.rules[0].actions = vec![Action::SetProxyHeaders];
        p.rules[0].when.path = Some("/healthz?full=true".into());
        assert!(p.validate(&[]).is_err());
    }
    #[test]
    fn catalog_entries_are_valid_and_unique() {
        let mut names = std::collections::HashSet::new();
        assert!(builtin_rule_sets().len() >= 25);
        for entry in builtin_rule_sets() {
            assert!(names.insert(&entry.name));
            assert!(
                entry.name.starts_with("builtin-")
                    && !entry.category.is_empty()
                    && !entry.usage.is_empty()
            );
            let mut profile: Profile = serde_json::from_str("{}").unwrap();
            profile.rules = entry.rules.clone();
            profile
                .validate(&[])
                .unwrap_or_else(|error| panic!("{}: {error}", entry.name));
        }
    }
    #[test]
    fn exact_paths_tls_and_proxy_context_use_connection_data() {
        let matcher: Match = serde_json::from_str(r#"{"path":"/healthz","tls":true}"#).unwrap();
        let mut request = Request::builder()
            .uri("/healthz?detail=1")
            .header("host", "app.example:8443")
            .header("x-forwarded-for", "203.0.113.1")
            .header("x-forwarded-proto", "forged")
            .header("x-forwarded-extra", "forged")
            .header("x-real-ip", "203.0.113.2")
            .header("forwarded", "for=203.0.113.3")
            .header("connection", "upgrade, x-forwarded-for, x-hop")
            .header("upgrade", "websocket")
            .header("x-hop", "hop-by-hop")
            .body(())
            .unwrap();
        assert!(matcher.matches(&request, true));
        assert!(!matcher.matches(&request, false));
        *request.uri_mut() = "/healthz-extra".parse().unwrap();
        assert!(!matcher.matches(&request, true));
        proxy_headers(&mut request, "2001:db8::7".parse().unwrap(), true, 8443).unwrap();
        assert_eq!(request.headers()["upgrade"], "websocket");
        assert_eq!(request.headers()["connection"], "upgrade, x-hop");
        strip_hop(request.headers_mut());
        assert_eq!(request.headers()["x-forwarded-for"], "2001:db8::7");
        assert_eq!(request.headers()["x-real-ip"], "2001:db8::7");
        assert_eq!(request.headers()["x-forwarded-proto"], "https");
        assert_eq!(request.headers()["x-forwarded-host"], "app.example:8443");
        assert_eq!(request.headers()["x-forwarded-port"], "8443");
        for name in ["forwarded", "x-forwarded-extra", "x-hop"] {
            assert!(!request.headers().contains_key(name));
        }
        request
            .headers_mut()
            .append("host", HeaderValue::from_static("other.example"));
        assert!(proxy_headers(&mut request, "127.0.0.1".parse().unwrap(), false, 80).is_err());
    }
    #[test]
    fn local_response_headers_follow_rule_action_order() {
        let set = Action::SetResponseHeader {
            name: "Retry-After".into(),
            value: "60".into(),
        };
        let remove = Action::RemoveResponseHeader {
            name: "retry-after".into(),
        };
        let content = Action::SetResponseHeader {
            name: "Content-Type".into(),
            value: "text/plain; charset=utf-8".into(),
        };
        let response = local_response(response(503, "Maintenance"), &[&set, &remove, &content]);
        assert_eq!(response.status(), 503);
        assert!(!response.headers().contains_key("retry-after"));
        assert_eq!(
            response.headers()["content-type"],
            "text/plain; charset=utf-8"
        );
    }
    #[test]
    fn cookie_attributes_and_profile_defaults_are_validated() {
        let mut c = Cookie::default();
        c.validate().unwrap();
        assert!(
            c.value("token", true)
                .contains("HttpOnly; SameSite=Lax; Secure")
        );
        c.session_cookie = true;
        c.http_only = false;
        c.domain = "home.example".into();
        c.path = "/app".into();
        let value = c.value("token", false);
        assert!(
            !value.contains("Max-Age")
                && !value.contains("HttpOnly")
                && value.contains("Domain=home.example")
        );
        c.path = "/; injected".into();
        assert!(c.validate().is_err());
        c.path = "/".into();
        c.domain = "..invalid".into();
        assert!(c.validate().is_err());
        c.domain = "home.example".into();
        c.same_site = SameSite::None;
        c.secure = Secure::Never;
        assert!(c.validate().is_err());
    }
}
