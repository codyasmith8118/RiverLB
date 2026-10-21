//! Durable confirm-or-revert protection for management and Linux network edits.
use crate::{config::Config, control::Control};
use anyhow::{Context, Result, ensure};
use axum::{
    Extension, Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::Arc,
};

pub const CONFIRM_SECONDS: i64 = 120;
const MAX_JOURNAL: usize = 8 * 1024 * 1024;
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Pending {
    pub format: u32,
    pub old_config: Config,
    pub new_config: Config,
    pub old_firewall: crate::firewall::Rules,
    pub new_firewall: crate::firewall::Rules,
    pub previous_revision: u64,
    pub revision: u64,
    pub deadline: i64,
    pub actor: String,
}
#[derive(Clone, Copy)]
pub struct Endpoint {
    pub address: SocketAddr,
    pub secure: bool,
}

pub fn path(database: &Path) -> PathBuf {
    database.with_extension("confirmation.json")
}
pub fn required(old: &Config, new: &Config) -> bool {
    old.management != new.management
        || serde_json::to_value((
            &old.management_protocol,
            &old.management_tls,
            &old.management_certificate,
            &old.network,
        ))
        .ok()
            != serde_json::to_value((
                &new.management_protocol,
                &new.management_tls,
                &new.management_certificate,
                &new.network,
            ))
            .ok()
}
pub fn url(config: &Config) -> String {
    format!(
        "{}://{}",
        if config.management_tls.is_some() || config.management_certificate.is_some() {
            "https"
        } else {
            "http"
        },
        config.management
    )
}
impl Pending {
    pub fn new(
        old_config: Config,
        new_config: Config,
        old_firewall: crate::firewall::Rules,
        previous_revision: u64,
        actor: String,
    ) -> Self {
        Self {
            format: 2,
            old_config,
            new_config,
            old_firewall,
            new_firewall: Default::default(),
            previous_revision,
            revision: previous_revision + 1,
            deadline: crate::storage::now() + CONFIRM_SECONDS,
            actor,
        }
    }
    pub fn save(&self, target: &Path) -> Result<()> {
        use std::{io::Write, os::unix::fs::OpenOptionsExt};
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_JOURNAL,
            "confirmation journal exceeds supported size"
        );
        let temporary = target.with_extension(format!("pending-{:016x}", rand::random::<u64>()));
        let result = (|| {
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)?;
            file.write_all(&bytes)?;
            file.sync_all()?;
            std::fs::rename(&temporary, target)?;
            std::fs::File::open(target.parent().context("journal parent")?)?.sync_all()?;
            anyhow::Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(temporary);
        }
        result
    }
    pub fn load(target: &Path) -> Result<Option<Self>> {
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let file = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(target)
        {
            Ok(f) => f,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(e) => return Err(e.into()),
        };
        let meta = file.metadata()?;
        // SAFETY: geteuid has no pointer arguments.
        ensure!(
            meta.is_file()
                && meta.uid() == unsafe { libc::geteuid() }
                && meta.mode() & 0o077 == 0
                && meta.len() <= MAX_JOURNAL as u64,
            "unsafe confirmation journal"
        );
        let journal: Self = serde_json::from_reader(std::io::BufReader::new(file))?;
        ensure!(
            journal.format == 2
                && journal.previous_revision.checked_add(1) == Some(journal.revision)
                && journal.revision.checked_add(1).is_some(),
            "invalid confirmation journal"
        );
        journal.old_config.validate()?;
        journal.new_config.validate()?;
        Ok(Some(journal))
    }
}
pub fn clear(target: &Path) -> Result<()> {
    match std::fs::remove_file(target) {
        Ok(()) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(e) => return Err(e.into()),
    }
    std::fs::File::open(target.parent().context("journal parent")?)?.sync_all()?;
    Ok(())
}
pub async fn recover(
    store: &crate::storage::Store,
    target: &Path,
    manage_network: bool,
    ha: Option<&crate::ha::State>,
) -> Result<()> {
    if let Some(pending) = Pending::load(target)? {
        let (current, revision) = store
            .load()
            .await?
            .context("confirmation journal without configuration")?;
        ensure!(
            revision == pending.previous_revision
                || revision == pending.revision
                || revision == pending.revision + 1,
            "confirmation journal revision mismatch; console recovery required"
        );
        if revision == pending.previous_revision || revision == pending.revision + 1 {
            ensure!(
                serde_json::to_value(&current)? == serde_json::to_value(&pending.old_config)?,
                "Recovery revision does not match the previous configuration"
            );
        } else {
            ensure!(
                serde_json::to_value(&current)? == serde_json::to_value(&pending.new_config)?,
                "Trial revision does not match the journal configuration"
            );
        }
        if manage_network {
            let previous = crate::network::provisioned(&pending.old_config)?;
            let trial = crate::network::provisioned(&pending.new_config)?;
            // HA always restarts as standby. Recovery must never reintroduce
            // floating ownership before the cluster has established authority.
            let restored = crate::ha::network(&pending.old_config, ha, ha.is_none())?;
            // Validate link identities before any historical ownership cleanup.
            let restore_steps = crate::network::recovery_plan(&previous, &trial, &restored).await?;
            let mut steps = Vec::new();
            if let Some(state) = ha {
                steps.extend(state.recovery_steps(crate::firewall::active(true).await?)?);
            }
            steps.extend(restore_steps);
            crate::network::Transaction::reconcile(steps).await?;
            let enabled = crate::firewall::active(true).await?;
            if enabled {
                let mut owned = pending.old_firewall.clone();
                owned.extend(pending.new_firewall.iter().cloned());
                let local = crate::firewall::desired(
                    &crate::ha::effective(&pending.old_config, ha, ha.is_none()),
                    true,
                )
                .await?;
                let mut steps = crate::firewall::plan(&owned, &local);
                // A crash may have removed a common rule before re-adding it.
                steps.extend(crate::firewall::plan(&Default::default(), &local));
                crate::network::Transaction::reconcile(steps).await?;
            }
        }
        if revision == pending.revision {
            store
                .save(
                    &pending.old_config,
                    revision + 1,
                    "startup recovery of unconfirmed configuration",
                )
                .await?;
            tracing::warn!(
                revision,
                "restored unconfirmed management/network configuration before startup"
            );
        }
        clear(target)?;
    }
    Ok(())
}
pub async fn view(control: &Control) -> Value {
    let pending = control.pending_configuration.lock().await;
    match pending.as_ref() {
        Some(p) => {
            json!({"pending":true,"revision":p.revision,"previous_revision":p.previous_revision,"deadline":p.deadline,"remaining_seconds":(p.deadline-crate::storage::now()).max(0),"previous_management_url":url(&p.old_config),"actor":p.actor})
        }
        None => json!({"pending":false}),
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Decision {
    revision: u64,
}
type ApiResult = Result<Json<Value>, (StatusCode, String)>;
pub fn router() -> Router<Arc<Control>> {
    Router::new()
        .route(
            "/api/v1/config/confirmation",
            get(|State(control): State<Arc<Control>>| async move { Json(view(&control).await) }),
        )
        .route("/api/v1/config/confirm", post(confirm))
        .route("/api/v1/config/revert", post(revert))
        .route("/api/v1/config/preview", post(preview))
}
async fn confirm(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
    Extension(endpoint): Extension<Endpoint>,
    Json(decision): Json<Decision>,
) -> ApiResult {
    tokio::spawn(async move {
        control
            .confirm_configuration(decision.revision, &actor, endpoint)
            .await
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map(|revision| {
        Json(json!({"revision":revision,"message":"Configuration confirmed and applied"}))
    })
    .map_err(|e| (StatusCode::CONFLICT, e.to_string()))
}
async fn revert(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
    Json(decision): Json<Decision>,
) -> ApiResult {
    tokio::spawn(async move {
        control
            .revert_configuration(decision.revision, &actor)
            .await
    })
    .await
    .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?
    .map(|revision| Json(json!({"revision":revision,"message":"Previous configuration restored"})))
    .map_err(|e| (StatusCode::CONFLICT, e.to_string()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Preview {
    revision: u64,
    config: Config,
}
fn differences(old: &Value, new: &Value, path: &str, result: &mut Vec<Value>) {
    if old == new {
        return;
    }
    if let (Some(a), Some(b)) = (old.as_object(), new.as_object()) {
        let keys: std::collections::BTreeSet<_> = a.keys().chain(b.keys()).collect();
        for key in keys {
            differences(
                a.get(key).unwrap_or(&Value::Null),
                b.get(key).unwrap_or(&Value::Null),
                &format!("{path}/{key}"),
                result,
            );
        }
    } else {
        result.push(json!({"path":path,"before":old,"after":new}));
    }
}
async fn preview(State(control): State<Arc<Control>>, Json(change): Json<Preview>) -> ApiResult {
    change
        .config
        .validate()
        .map_err(|e| (StatusCode::UNPROCESSABLE_ENTITY, e.to_string()))?;
    let generation = control.generation.lock().await;
    if generation.revision != change.revision {
        return Err((
            StatusCode::CONFLICT,
            "Configuration changed; reload before reviewing".into(),
        ));
    }
    let mut comparison = generation.runtime.config.clone();
    if !control.manage_network {
        comparison.network = change.config.network.clone();
    }
    let mut changes = Vec::new();
    differences(
        &serde_json::to_value(&generation.runtime.config).unwrap(),
        &serde_json::to_value(&change.config).unwrap(),
        "",
        &mut changes,
    );
    Ok(Json(
        json!({"revision":change.revision,"changes":changes,"confirmation_required":required(&comparison,&change.config),"confirmation_seconds":CONFIRM_SECONDS}),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn detects_risk_and_journal_roundtrip() {
        let old = Config::load(Path::new("examples/riverlb.toml")).unwrap();
        let mut new = old.clone();
        new.management.set_port(19090);
        assert!(!required(&old, &old));
        assert!(required(&old, &new));
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("confirmation.json");
        let pending = Pending::new(old, new, Default::default(), 42, "admin".into());
        pending.save(&target).unwrap();
        assert_eq!(Pending::load(&target).unwrap().unwrap().revision, 43);
        let mut oversized = pending.clone();
        oversized.actor = "x".repeat(MAX_JOURNAL);
        assert!(oversized.save(&target).is_err());
        assert_eq!(Pending::load(&target).unwrap().unwrap().actor, "admin");
        clear(&target).unwrap();
        assert!(Pending::load(&target).unwrap().is_none());
    }
    #[tokio::test]
    async fn crash_recovers_committed_change_but_not_uncommitted_journal() {
        let dir = tempfile::tempdir().unwrap();
        let database = dir.path().join("test.db");
        let target = path(&database);
        let store = crate::storage::Store::open(&database).await.unwrap();
        let old = Config::load(Path::new("examples/riverlb.toml")).unwrap();
        let mut changed = old.clone();
        changed.management.set_port(19090);
        store.save(&old, 1, "fixture").await.unwrap();
        Pending::new(
            old.clone(),
            changed.clone(),
            Default::default(),
            1,
            "admin".into(),
        )
        .save(&target)
        .unwrap();
        recover(&store, &target, false, None).await.unwrap();
        assert_eq!(store.load().await.unwrap().unwrap().1, 1);
        Pending::new(
            old.clone(),
            changed.clone(),
            Default::default(),
            1,
            "admin".into(),
        )
        .save(&target)
        .unwrap();
        store.save(&changed, 2, "fixture").await.unwrap();
        recover(&store, &target, false, None).await.unwrap();
        let (restored, revision) = store.load().await.unwrap().unwrap();
        assert_eq!(restored.management, old.management);
        assert_eq!(revision, 3);
    }
}
