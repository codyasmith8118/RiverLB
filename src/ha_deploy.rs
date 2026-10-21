//! Administrator-only, reauthenticated requests to a fixed systemd HA helper.
use crate::{control::Control, ha};
use anyhow::{Context, Result, ensure};
use axum::{Extension, Json, Router, extract::State, http::StatusCode, routing::get};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    path::Path,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};
const RUN: &str = "/run/riverlb-ha-deploy";
static GATE: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());
static FENCING_CATALOG: OnceLock<tokio::sync::Mutex<Option<(Instant, Value)>>> = OnceLock::new();

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    action: String,
    current_password: String,
    #[serde(default)]
    code: Option<String>,
    #[serde(default)]
    cluster_password: String,
    #[serde(default)]
    peer_sync_key: String,
    #[serde(default)]
    peer_host_key: String,
    #[serde(default)]
    peer_host_fingerprint: String,
    #[serde(default)]
    fence_resource: String,
    #[serde(default)]
    fence_agent: String,
    #[serde(default)]
    fence_parameters: std::collections::BTreeMap<String, String>,
    #[serde(default = "default_probe_action")]
    fence_probe_action: String,
    #[serde(default)]
    fence_target: String,
}
fn default_probe_action() -> String {
    "list".into()
}
impl Request {
    fn validate(&self) -> Result<()> {
        ensure!(
            matches!(
                self.action.as_str(),
                "prepare" | "trust" | "authenticate" | "start" | "fence" | "fence_probe"
            ),
            "Unknown deployment action"
        );
        ensure!(
            self.cluster_password.len() <= 1024
                && self.peer_sync_key.len() <= 256
                && self.peer_host_key.len() <= 256
                && self.peer_host_fingerprint.len() <= 128,
            "Deployment field exceeds its limit"
        );
        if matches!(self.action.as_str(), "prepare" | "authenticate") {
            ensure!(
                self.cluster_password.len() >= 12
                    && !self.cluster_password.contains(['\r', '\n', '\0']),
                "Use a cluster password of 12–1024 bytes without line breaks"
            );
        }
        ensure!(
            self.fence_resource.len() <= 128
                && self.fence_agent.len() <= 128
                && self.fence_target.len() <= 128
                && matches!(self.fence_probe_action.as_str(), "list" | "status")
                && self.fence_parameters.len() <= 64
                && self.fence_parameters.iter().all(|(k, v)| k.len() <= 128
                    && v.len() <= 4096
                    && !v.contains(['\0', '\r', '\n'])),
            "Invalid fencing parameter size"
        );
        Ok(())
    }
}
fn read_optional(path: &Path) -> Result<Value> {
    if !path.exists() {
        return Ok(Value::Null);
    }
    ensure!(
        std::fs::symlink_metadata(path)?.is_file() && std::fs::metadata(path)?.len() <= 65536,
        "Unsafe HA status file"
    );
    Ok(serde_json::from_slice(&std::fs::read(path)?)?)
}
async fn status() -> Result<Value> {
    let busy = unit_busy().await.unwrap_or(false);
    if !busy {
        reap_request()?;
    }
    let mut job = read_optional(&Path::new(RUN).join("result.json"))?;
    if job["running"] == true && !busy {
        job["running"] = json!(false);
        job["ok"] = json!(false);
        job["message"] = json!(
            "The deployment helper stopped before completion. Inspect its journal, then retry the operation."
        );
    }
    Ok(
        json!({"installed":Path::new("/usr/libexec/riverlb/riverlb-ha-deploy").is_file(),
        "identity":read_optional(Path::new("/etc/riverlb/ha-deployment-identity.json"))?,
        "job":job,"busy":busy}),
    )
}
fn reap_request() -> Result<()> {
    let path = Path::new(RUN).join("request.json");
    if !path.exists() {
        return Ok(());
    }
    let info = std::fs::symlink_metadata(&path)?;
    ensure!(info.is_file(), "Unsafe queued HA request");
    if info.modified()?.elapsed().unwrap_or_default().as_secs() > 60 {
        std::fs::remove_file(path)?;
    }
    Ok(())
}
async fn unit_busy() -> Result<bool> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(3),
        tokio::process::Command::new("/usr/bin/systemctl")
            .args([
                "show",
                "--property=ActiveState",
                "--value",
                "riverlb-ha-deploy.service",
            ])
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    ensure!(
        output.status.success(),
        "Could not inspect the HA deployment helper"
    );
    Ok(matches!(
        String::from_utf8_lossy(&output.stdout).trim(),
        "active" | "activating" | "deactivating" | "reloading"
    ))
}
type ApiResult = std::result::Result<Json<Value>, (StatusCode, Json<Value>)>;
fn error(e: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"error":e.to_string()})),
    )
}
async fn view() -> ApiResult {
    status().await.map(Json).map_err(error)
}
async fn fencing_catalog() -> Result<Value> {
    let helper = Path::new("/usr/libexec/riverlb/riverlb-ha-deploy");
    if !helper.is_file() {
        return Ok(json!({"installed":false,"platforms":[],"agents":[]}));
    }
    let mut cache = FENCING_CATALOG
        .get_or_init(|| tokio::sync::Mutex::new(None))
        .lock()
        .await;
    if let Some((created, value)) = &*cache
        && created.elapsed() < Duration::from_secs(300)
    {
        return Ok(value.clone());
    }
    let output = tokio::time::timeout(
        Duration::from_secs(60),
        tokio::process::Command::new(helper)
            .arg("--fencing-catalog")
            .kill_on_drop(true)
            .output(),
    )
    .await
    .context("Fencing discovery timed out")??;
    ensure!(
        output.status.success(),
        "Could not discover installed fencing agents"
    );
    ensure!(
        output.stdout.len() <= 1048576,
        "Fencing metadata exceeds its limit"
    );
    let mut value: Value =
        serde_json::from_slice(&output.stdout).context("Invalid fencing catalog")?;
    value["installed"] = json!(true);
    *cache = Some((Instant::now(), value.clone()));
    Ok(value)
}
async fn view_fencing() -> ApiResult {
    fencing_catalog().await.map(Json).map_err(error)
}
async fn submit(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
    Extension(endpoint): Extension<crate::confirmation::Endpoint>,
    Json(request): Json<Request>,
) -> ApiResult {
    tokio::spawn(async move {
        submit_inner(&control, &actor, endpoint, request)
            .await
            .map(Json)
            .map_err(error)
    })
    .await
    .map_err(error)?
}
async fn submit_inner(
    control: &Control,
    actor: &str,
    endpoint: crate::confirmation::Endpoint,
    request: Request,
) -> Result<Value> {
    request.validate()?;
    ensure!(endpoint.secure, "HA deployment requires HTTPS management");
    crate::auth::reauthenticate(
        control,
        actor,
        request.current_password,
        request.code.as_deref(),
    )
    .await?;
    let _gate = GATE.lock().await;
    let _changes = control.change_gate.lock().await;
    ensure!(
        control.manage_network,
        "HA deployment requires managed networking"
    );
    ensure!(
        !crate::interfaces::has_pending().await
            && control.pending_configuration.lock().await.is_none(),
        "Confirm or revert pending configuration changes first"
    );
    ensure!(
        request.action == "fence_probe" || control.ha.is_none() || !control.data_plane_active(),
        "Move traffic to the peer before deploying HA on this appliance"
    );
    ensure!(
        control.ha_config_path == Path::new("/etc/riverlb/ha.json"),
        "GUI deployment requires the installed appliance configuration paths"
    );
    ensure!(control.ha_config_path.exists(), "Save the HA group first");
    ensure!(
        Path::new("/usr/libexec/riverlb/riverlb-ha-deploy").is_file(),
        "Install the updated appliance HA RPM; new ISOs include it"
    );
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let directory = std::fs::symlink_metadata(RUN)
        .context("HA deployment runtime directory missing; reinstall the HA RPM")?;
    ensure!(
        directory.is_dir() && directory.uid() == 0 && directory.permissions().mode() & 0o077 == 0,
        "Unsafe HA deployment runtime directory"
    );
    ensure!(
        !unit_busy().await?,
        "An HA deployment operation is already running"
    );
    reap_request()?;
    let path = Path::new(RUN).join("request.json");
    ensure!(!path.exists(), "An HA deployment request is already queued");
    control
        .store
        .record_audit(
            actor,
            &format!("HA deployment {} requested", request.action),
        )
        .await?;
    let job = rand::random::<u128>().to_string();
    let payload = json!({"job":job,"created":crate::storage::now(),"action":request.action,
        "cluster_password":request.cluster_password,"peer_sync_key":request.peer_sync_key,
        "peer_host_key":request.peer_host_key,"peer_host_fingerprint":request.peer_host_fingerprint,
        "fence_resource":request.fence_resource,"fence_agent":request.fence_agent,"fence_parameters":request.fence_parameters,
        "fence_probe_action":request.fence_probe_action,"fence_target":request.fence_target});
    ensure!(
        serde_json::to_vec(&payload)?.len() <= 16384,
        "HA deployment request exceeds 16 KiB"
    );
    ha::private_write(&path, &payload)?;
    let start = tokio::process::Command::new("/usr/bin/systemctl")
        .args(["start", "--no-block", "riverlb-ha-deploy.service"])
        .status()
        .await;
    if !start.is_ok_and(|s| s.success()) {
        std::fs::remove_file(&path)?;
        anyhow::bail!("Could not start the HA deployment helper");
    }
    Ok(
        json!({"job":job,"message":"HA deployment operation queued. Refresh deployment status to follow progress."}),
    )
}
pub fn router() -> Router<Arc<Control>> {
    Router::new()
        .route("/api/v1/ha/deployment", get(view).post(submit))
        .route("/api/v1/ha/deployment/fencing", get(view_fencing))
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_fixed_actions_and_ephemeral_passwords() {
        let mut r:Request=serde_json::from_value(json!({"action":"prepare","current_password":"proof","cluster_password":"a-long-password"})).unwrap();
        r.validate().unwrap();
        r.cluster_password.push('\n');
        assert!(r.validate().is_err());
        r.action = "shell".into();
        assert!(r.validate().is_err());
        assert!(
            serde_json::from_value::<Request>(
                json!({"action":"start","current_password":"proof","command":"id"})
            )
            .is_err()
        );
    }
    #[test]
    fn fencing_probes_only_accept_read_only_operations_and_single_line_values() {
        let mut request: Request = serde_json::from_value(json!({"action":"fence_probe","current_password":"proof","fence_agent":"fence_vmware_rest","fence_parameters":{"password":"private"}})).unwrap();
        request.validate().unwrap();
        request.fence_probe_action = "off".into();
        assert!(request.validate().is_err());
        request.fence_probe_action = "status".into();
        request
            .fence_parameters
            .insert("password".into(), "private\naction=off".into());
        assert!(request.validate().is_err());
    }
}
