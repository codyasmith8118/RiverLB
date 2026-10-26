//! Management authorization and RFC 6238 one-time passwords.
use anyhow::{Result, ensure};
use rand::{RngCore, rngs::OsRng};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    #[default]
    Administrator,
    Operator,
    ReadOnly,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TokenScope {
    Monitoring,
    Read,
    Configure,
}
#[derive(Clone, Debug, Serialize)]
pub struct Principal {
    pub username: String,
    pub role: Role,
    pub token_scope: Option<TokenScope>,
}
impl Principal {
    pub fn permits(&self, method: &str, path: &str) -> bool {
        if path == "/api/v1/connections" && self.role == Role::ReadOnly {
            return false;
        }
        let read = matches!(method, "GET" | "HEAD");
        let monitoring = matches!(
            path,
            "/healthz"
                | "/metrics"
                | "/api/v1/status"
                | "/api/v1/appliance"
                | "/api/v1/nodes"
                | "/api/v1/statistics"
                | "/api/v1/statistics/history"
                | "/api/v1/operations/health"
        );
        let private = path.starts_with("/api/v1/administrators")
            || path.starts_with("/api/v1/security/")
            || path.starts_with("/api/v1/backup")
            || path.starts_with("/api/v1/restore")
            || path.starts_with("/api/v1/audit")
            || (path.starts_with("/api/v1/operations/") && !path.ends_with("/health"))
            || path.starts_with("/api/v1/updates/")
            || path.starts_with("/api/v1/network/adapters")
            || path.starts_with("/api/v1/network/adapter-change")
            || path.starts_with("/api/v1/ha/deployment")
            || path.contains("/private-key")
            || path.contains("/export");
        let traffic = matches!(
            path,
            "/api/v1/config"
                | "/api/v1/config/validate"
                | "/api/v1/config/preview"
                | "/api/v1/config/confirm"
                | "/api/v1/config/revert"
        ) || path.starts_with("/api/v1/persistence/")
            || path == "/api/v1/statistics/reset";
        let operations = path == "/api/v1/statistics/reset"
            || path == "/api/v1/ha/action"
            || (path.starts_with("/api/v1/persistence/") && path.ends_with("/clear"));
        let allowed = match self.role {
            Role::Administrator => true,
            Role::Operator => {
                (read && !private)
                    || operations
                    || path.starts_with("/api/v1/auth/")
                    || path.starts_with("/api/v1/security/mfa")
            }
            Role::ReadOnly => {
                (read && !private)
                    || path.starts_with("/api/v1/auth/")
                    || path.starts_with("/api/v1/security/mfa")
            }
        };
        allowed
            && match self.token_scope {
                None => true,
                Some(TokenScope::Monitoring) => read && monitoring,
                Some(TokenScope::Read) => read && !private && !path.starts_with("/api/v1/auth/"),
                Some(TokenScope::Configure) => {
                    !private && !path.starts_with("/api/v1/auth/") && ((read) || traffic)
                }
            }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecuritySettings {
    pub idle_timeout_secs: u64,
    pub source_allowlist: Vec<String>,
}
impl Default for SecuritySettings {
    fn default() -> Self {
        Self {
            idle_timeout_secs: 1800,
            source_allowlist: Vec::new(),
        }
    }
}
impl SecuritySettings {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            (60..=28800).contains(&self.idle_timeout_secs),
            "Idle timeout must be between 60 and 28800 seconds"
        );
        ensure!(
            self.source_allowlist.len() <= 64,
            "At most 64 management source networks are allowed"
        );
        for network in &self.source_allowlist {
            parse_network(network)?;
        }
        Ok(())
    }
    pub fn allows_source(&self, ip: IpAddr) -> bool {
        let ip = match ip {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        self.source_allowlist.is_empty()
            || self.source_allowlist.iter().any(|net| {
                parse_network(net).is_ok_and(|(address, prefix)| same_network(address, ip, prefix))
            })
    }
}
fn parse_network(text: &str) -> Result<(IpAddr, u32)> {
    let (address, prefix) = text
        .split_once('/')
        .map_or((text, None), |(a, p)| (a, Some(p)));
    let address: IpAddr = address.parse()?;
    let max = if address.is_ipv4() { 32 } else { 128 };
    let prefix = prefix.map(str::parse).transpose()?.unwrap_or(max);
    ensure!(prefix <= max, "Invalid network prefix");
    Ok((address, prefix))
}
fn same_network(network: IpAddr, source: IpAddr, prefix: u32) -> bool {
    match (network, source) {
        (IpAddr::V4(a), IpAddr::V4(b)) => {
            prefix == 0 || u32::from(a) >> (32 - prefix) == u32::from(b) >> (32 - prefix)
        }
        (IpAddr::V6(a), IpAddr::V6(b)) => {
            prefix == 0 || u128::from(a) >> (128 - prefix) == u128::from(b) >> (128 - prefix)
        }
        _ => false,
    }
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AccountSecurity {
    pub role: Role,
    pub mfa_secret: String,
    pub pending_secret: String,
    pub pending_expires: i64,
    pub last_counter: i64,
    pub recovery_hashes: Vec<String>,
}
impl AccountSecurity {
    pub fn validate(&self) -> Result<()> {
        for secret in [&self.mfa_secret, &self.pending_secret] {
            ensure!(
                secret.is_empty() || (secret.len() == 32 && decode32(secret).is_ok()),
                "Invalid authenticator secret"
            );
        }
        ensure!(
            self.last_counter >= 0 && self.pending_expires >= 0,
            "Invalid authenticator state"
        );
        ensure!(
            self.recovery_hashes.len() <= 10
                && self
                    .recovery_hashes
                    .iter()
                    .all(|h| h.len() == 64 && h.bytes().all(|b| b.is_ascii_hexdigit())),
            "Invalid recovery code hashes"
        );
        ensure!(
            self.recovery_hashes
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                == self.recovery_hashes.len(),
            "Duplicate recovery code hashes"
        );
        ensure!(
            !self.mfa_secret.is_empty() || self.recovery_hashes.is_empty(),
            "Recovery codes require an enrolled authenticator"
        );
        ensure!(
            self.pending_secret.is_empty() == (self.pending_expires == 0),
            "Invalid pending authenticator expiry"
        );
        Ok(())
    }
}
pub fn random_hex(bytes: usize) -> String {
    let mut data = vec![0; bytes];
    OsRng.fill_bytes(&mut data);
    data.iter().map(|b| format!("{b:02x}")).collect()
}
const BASE32: &[u8; 32] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
pub fn new_totp_secret() -> String {
    let mut bytes = [0u8; 20];
    OsRng.fill_bytes(&mut bytes);
    base32(&bytes)
}
fn base32(bytes: &[u8]) -> String {
    let mut output = String::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for b in bytes {
        acc = (acc << 8) | u32::from(*b);
        bits += 8;
        while bits >= 5 {
            bits -= 5;
            output.push(BASE32[((acc >> bits) & 31) as usize] as char);
        }
    }
    if bits > 0 {
        output.push(BASE32[((acc << (5 - bits)) & 31) as usize] as char);
    }
    output
}
fn decode32(text: &str) -> Result<Vec<u8>> {
    let mut output = Vec::new();
    let mut acc = 0u32;
    let mut bits = 0;
    for c in text.bytes() {
        let n = BASE32
            .iter()
            .position(|b| *b == c)
            .ok_or_else(|| anyhow::anyhow!("Invalid authenticator secret"))?;
        acc = (acc << 5) | n as u32;
        bits += 5;
        if bits >= 8 {
            bits -= 8;
            output.push(((acc >> bits) & 255) as u8);
        }
    }
    ensure!(output.len() >= 20, "Invalid authenticator secret");
    Ok(output)
}
pub fn totp_at(secret: &str, counter: i64) -> Result<String> {
    ensure!(counter >= 0, "Invalid authenticator counter");
    let key = ring::hmac::Key::new(
        ring::hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY,
        &decode32(secret)?,
    );
    let signature = ring::hmac::sign(&key, &(counter as u64).to_be_bytes());
    let data = signature.as_ref();
    let offset = (data[19] & 15) as usize;
    let code = (u32::from_be_bytes(data[offset..offset + 4].try_into().unwrap()) & 0x7fff_ffff)
        % 1_000_000;
    Ok(format!("{code:06}"))
}
pub fn verify_totp(secret: &str, supplied: &str, now: i64, previous: i64) -> Option<i64> {
    if supplied.len() != 6 || !supplied.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let counter = now / 30;
    [counter - 1, counter, counter + 1]
        .into_iter()
        .filter(|n| *n > previous)
        .find(|n| {
            totp_at(secret, *n).is_ok_and(|code| {
                let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"RiverLB OTP comparison");
                let tag = ring::hmac::sign(&key, code.as_bytes());
                ring::hmac::verify(&key, supplied.as_bytes(), tag.as_ref()).is_ok()
            })
        })
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rfc6238_sha1_vector_and_replay_window() {
        let secret = base32(b"12345678901234567890");
        assert_eq!(totp_at(&secret, 59 / 30).unwrap(), "287082");
        assert_eq!(verify_totp(&secret, "287082", 59, 0), Some(1));
        assert_eq!(verify_totp(&secret, "287082", 59, 1), None);
        assert_eq!(verify_totp(&secret, "287082", 120, 0), None);
    }
    #[test]
    fn roles_and_tokens_never_grant_more_than_account() {
        let mut p = Principal {
            username: "reader".into(),
            role: Role::ReadOnly,
            token_scope: None,
        };
        assert!(p.permits("GET", "/api/v1/status"));
        assert!(!p.permits("PUT", "/api/v1/config"));
        assert!(!p.permits("GET", "/api/v1/certificates/cert/private-key"));
        p.role = Role::Operator;
        assert!(p.permits("POST", "/api/v1/ha/action"));
        assert!(!p.permits("PUT", "/api/v1/ha"));
        assert!(!p.permits("POST", "/api/v1/administrators"));
        assert!(!p.permits("POST", "/api/v1/network/adapters"));
        assert!(!p.permits("POST", "/api/v1/network/adapter-change/confirm"));
        assert!(!p.permits("GET", "/api/v1/ha/deployment"));
        assert!(!p.permits("POST", "/api/v1/ha/deployment"));
        p.role = Role::Administrator;
        p.token_scope = Some(TokenScope::Monitoring);
        assert!(p.permits("GET", "/metrics"));
        assert!(!p.permits("GET", "/api/v1/config"));
        p.token_scope = Some(TokenScope::Configure);
        assert!(p.permits("PUT", "/api/v1/config"));
        assert!(!p.permits("POST", "/api/v1/security/tokens"));
        assert!(!p.permits("POST", "/api/v1/network/adapters"));
        assert!(!p.permits("POST", "/api/v1/ha/deployment"));
        p.token_scope = None;
        assert!(p.permits("POST", "/api/v1/network/adapters"));
        p.role = Role::ReadOnly;
        assert!(!p.permits("PUT", "/api/v1/config"));
    }
    #[test]
    fn allowlist_matches_both_families_without_trusting_forwarding_headers() {
        let settings = SecuritySettings {
            source_allowlist: vec!["192.0.2.0/24".into(), "2001:db8::/32".into()],
            ..Default::default()
        };
        settings.validate().unwrap();
        assert!(settings.allows_source("192.0.2.6".parse().unwrap()));
        assert!(!settings.allows_source("198.51.100.1".parse().unwrap()));
        assert!(settings.allows_source("2001:db8::7".parse().unwrap()));
        assert!(settings.allows_source("::ffff:192.0.2.6".parse().unwrap()));
        assert!(
            SecuritySettings {
                source_allowlist: vec!["192.0.2.0/33".into()],
                ..Default::default()
            }
            .validate()
            .is_err()
        );
    }
}

type ApiError = (axum::http::StatusCode, axum::Json<serde_json::Value>);
fn failure(e: anyhow::Error) -> (axum::http::StatusCode, axum::Json<serde_json::Value>) {
    (
        axum::http::StatusCode::CONFLICT,
        axum::Json(serde_json::json!({"error":e.to_string()})),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecurityChange {
    settings: SecuritySettings,
    current_password: String,
    #[serde(default)]
    code: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Proof {
    current_password: String,
    #[serde(default)]
    code: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Code {
    code: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewToken {
    name: String,
    scope: TokenScope,
    lifetime_secs: u64,
    current_password: String,
    #[serde(default)]
    code: Option<String>,
}
pub(crate) async fn reauthenticate(
    control: &crate::control::Control,
    actor: &str,
    password: String,
    code: Option<&str>,
) -> Result<()> {
    ensure!(password.len() <= 1024, "Invalid password length");
    security_budget(control).await?;
    ensure!(
        control
            .store
            .verify_credentials(actor, password, code)
            .await?,
        "Invalid password or authenticator code"
    );
    Ok(())
}
async fn security_budget(control: &crate::control::Control) -> Result<()> {
    let mut budget = control.administrator_budget.lock().await;
    if budget.0.elapsed().as_secs() >= 60 {
        *budget = (std::time::Instant::now(), 0);
    }
    ensure!(
        budget.1 < 30,
        "Too many security changes; try again in one minute"
    );
    budget.1 += 1;
    Ok(())
}
async fn admitted<T: Send + 'static>(
    operation: impl std::future::Future<Output = std::result::Result<T, ApiError>> + Send + 'static,
) -> std::result::Result<T, ApiError> {
    tokio::spawn(operation)
        .await
        .map_err(|_| failure(anyhow::anyhow!("Security operation failed")))?
}
pub fn router() -> axum::Router<std::sync::Arc<crate::control::Control>> {
    use axum::{
        Extension, Json, Router,
        extract::{Path, State},
        routing::{get, post},
    };
    use serde_json::json;
    use std::sync::Arc;
    type Shared = Arc<crate::control::Control>;
    Router::new()
        .route("/accounts.js",get(||async { ([("content-type","text/javascript; charset=utf-8")],include_str!("../web/accounts.js")) }))
        .route("/api/v1/auth/me",get(|Extension(principal):Extension<Principal>|async move{Json(json!(principal))}))
        .route("/api/v1/security/settings",get(|State(c):State<Shared>|async move{c.store.security_settings().await.map(|s|Json(json!(s))).map_err(failure)}).put(|State(c):State<Shared>,Extension(actor):Extension<String>,Extension(peer):Extension<std::net::SocketAddr>,Json(change):Json<SecurityChange>|async move{admitted(async move{
            reauthenticate(&c,&actor,change.current_password,change.code.as_deref()).await.map_err(failure)?;
            change.settings.validate().map_err(failure)?;
            if !change.settings.allows_source(peer.ip()) {return Err(failure(anyhow::anyhow!("The allowlist must include your current source address to preserve management access")));}
            c.store.set_security_settings(change.settings,&actor).await.map_err(failure)?;Ok(Json(json!({"message":"Security policy saved"})))
        }).await}))
        .route("/api/v1/security/mfa",get(|State(c):State<Shared>,Extension(actor):Extension<String>|async move{c.store.mfa_status(&actor).await.map(Json).map_err(failure)}))
        .route("/api/v1/security/mfa/enroll",post(|State(c):State<Shared>,Extension(actor):Extension<String>,Json(proof):Json<Proof>|async move{admitted(async move{
            reauthenticate(&c,&actor,proof.current_password,proof.code.as_deref()).await.map_err(failure)?;c.store.enroll_mfa(&actor).await.map(Json).map_err(failure)
        }).await}))
        .route("/api/v1/security/mfa/confirm",post(|State(c):State<Shared>,Extension(actor):Extension<String>,Json(code):Json<Code>|async move{admitted(async move{security_budget(&c).await.map_err(failure)?;c.store.confirm_mfa(&actor,&code.code).await.map(|codes|Json(json!({"message":"MFA enabled. Store these recovery codes safely and sign in again.","recovery_codes":codes}))).map_err(failure)}).await}))
        .route("/api/v1/security/mfa/disable",post(|State(c):State<Shared>,Extension(actor):Extension<String>,Json(proof):Json<Proof>|async move{admitted(async move{
            reauthenticate(&c,&actor,proof.current_password,proof.code.as_deref()).await.map_err(failure)?;c.store.disable_mfa(&actor).await.map_err(failure)?;Ok::<_,ApiError>(Json(json!({"message":"MFA disabled; sign in again"})))
        }).await}))
        .route("/api/v1/security/tokens",get(|State(c):State<Shared>,Extension(actor):Extension<String>|async move{c.store.api_tokens(&actor).await.map(Json).map_err(failure)}).post(|State(c):State<Shared>,Extension(actor):Extension<String>,Json(token):Json<NewToken>|async move{admitted(async move{
            reauthenticate(&c,&actor,token.current_password,token.code.as_deref()).await.map_err(failure)?;c.store.create_api_token(&actor,&token.name,token.scope,token.lifetime_secs).await.map(Json).map_err(failure)
        }).await}))
        .route("/api/v1/security/tokens/{id}",axum::routing::delete(|State(c):State<Shared>,Extension(actor):Extension<String>,Path(id):Path<String>|async move{admitted(async move{c.store.revoke_api_token(&actor,&id).await.map_err(failure)?;Ok::<_,ApiError>(Json(json!({"message":"Token revoked"})))}).await}))
}
