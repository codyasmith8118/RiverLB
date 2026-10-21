//! Signed offline application bundles. Publisher trust is provisioned outside the GUI.
use anyhow::{Context, Result, ensure};
use axum::{
    Extension, Json, Router,
    extract::State,
    http::StatusCode,
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    path::{Path, PathBuf},
    sync::Arc,
};
const MAX_PAYLOAD: usize = 128 * 1024 * 1024;
const MAX_BUNDLE: usize = 180 * 1024 * 1024;
pub const TRUST: &str = "/etc/riverlb-updater/update-trust.json";
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub format: u32,
    pub product: String,
    pub version: String,
    pub sequence: u64,
    pub architecture: String,
    pub platform: String,
    pub minimum_schema: u32,
    pub maximum_schema: u32,
    pub created: i64,
    pub expires: i64,
    pub payload_length: u64,
    pub payload_sha256: String,
    pub key_id: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub manifest: String,
    pub signature: String,
    pub payload: String,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Trust {
    pub format: u32,
    pub keys: Vec<TrustedKey>,
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrustedKey {
    pub id: String,
    pub public_key: String,
}
fn trust(path: &Path) -> Result<Trust> {
    load_trust(path, 0)
}
fn load_trust(path: &Path, owner: u32) -> Result<Trust> {
    use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
    let file=std::fs::OpenOptions::new().read(true).custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK).open(path).context("Install the publisher public key in /etc/riverlb-updater/update-trust.json from the console before using signed updates")?;
    let meta = file.metadata()?;
    ensure!(
        meta.is_file() && meta.uid() == owner && meta.mode() & 0o022 == 0 && meta.len() <= 65536,
        "Update trust must be a root-owned regular file without group/world write access"
    );
    let trust: Trust = serde_json::from_reader(std::io::BufReader::new(file))?;
    ensure!(
        trust.format == 1 && !trust.keys.is_empty() && trust.keys.len() <= 16,
        "Invalid update trust store"
    );
    Ok(trust)
}
fn verify(bundle: &Bundle, trust: &Trust, sequence: u64, now: i64) -> Result<(Manifest, Vec<u8>)> {
    ensure!(
        bundle.manifest.len() <= 16384
            && bundle.signature.len() <= 128
            && bundle.payload.len() <= MAX_PAYLOAD.div_ceil(3) * 4,
        "Update exceeds supported size"
    );
    let manifest: Manifest = serde_json::from_str(&bundle.manifest)?;
    let key = trust
        .keys
        .iter()
        .find(|k| k.id == manifest.key_id)
        .context("Unknown update signing key")?;
    let key = BASE64.decode(&key.public_key)?;
    ensure!(key.len() == 32, "Invalid Ed25519 public key");
    ring::signature::UnparsedPublicKey::new(&ring::signature::ED25519, key)
        .verify(
            bundle.manifest.as_bytes(),
            &BASE64.decode(&bundle.signature)?,
        )
        .map_err(|_| anyhow::anyhow!("Update signature verification failed"))?;
    ensure!(
        manifest.format == 1 && manifest.product == "RiverLB",
        "Unsupported update product/format"
    );
    ensure!(
        manifest.architecture == "x86_64" && manifest.platform == "almalinux-10",
        "Unsupported update platform"
    );
    ensure!(
        manifest.minimum_schema <= 6 && manifest.maximum_schema >= 6,
        "Update database schema is incompatible"
    );
    ensure!(
        manifest.sequence > sequence,
        "Update sequence must be newer than the highest accepted sequence"
    );
    ensure!(
        manifest.created <= now + 300
            && now < manifest.expires
            && manifest.expires > manifest.created
            && manifest.expires - manifest.created <= 366 * 86400,
        "Update metadata expired or the appliance clock is incorrect"
    );
    ensure!(
        !manifest.version.is_empty()
            && manifest.version.len() <= 64
            && manifest
                .version
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b".-_".contains(&b)),
        "Invalid update version"
    );
    let payload = BASE64.decode(&bundle.payload)?;
    ensure!(
        payload.len() >= 64
            && payload.len() <= MAX_PAYLOAD
            && payload.len() as u64 == manifest.payload_length,
        "Update payload length mismatch"
    );
    ensure!(
        format!("{:x}", Sha256::digest(&payload)) == manifest.payload_sha256,
        "Update payload checksum mismatch"
    );
    ensure!(
        &payload[..6] == b"\x7fELF\x02\x01" && payload[18..20] == [62, 0],
        "Update payload must be an x86-64 ELF executable"
    );
    Ok((manifest, payload))
}
pub fn verify_file(bundle_path: &Path, trust_path: &Path, sequence: u64) -> Result<Manifest> {
    use std::os::unix::fs::OpenOptionsExt;
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(bundle_path)?;
    ensure!(
        file.metadata()?.is_file() && file.metadata()?.len() <= MAX_BUNDLE as u64,
        "Invalid update file"
    );
    // Buffer file reads: serde_json's reader otherwise issues tiny reads for
    // every byte of the full application payload.
    let bundle: Bundle = serde_json::from_reader(std::io::BufReader::new(file))?;
    // An explicit alternate key file is useful for offline build verification only.
    // Installed activation always passes the fixed root-owned TRUST path.
    let owner = if trust_path == Path::new(TRUST) {
        0
    } else {
        unsafe { libc::geteuid() }
    };
    Ok(verify(
        &bundle,
        &load_trust(trust_path, owner)?,
        sequence,
        crate::storage::now(),
    )?
    .0)
}
pub struct Updates {
    pub path: PathBuf,
    pub staged: PathBuf,
    gate: tokio::sync::Mutex<()>,
}
impl Updates {
    pub fn new(database: &Path) -> Self {
        Self {
            path: database.with_extension("updates.json"),
            staged: database.with_extension("update-bundle.json"),
            gate: tokio::sync::Mutex::new(()),
        }
    }
    pub fn status(&self) -> Result<Value> {
        let state = if self.path.exists() {
            ensure!(
                std::fs::symlink_metadata(&self.path)?.is_file()
                    && std::fs::metadata(&self.path)?.len() <= 1024 * 1024,
                "Unsafe update state"
            );
            serde_json::from_slice(&std::fs::read(&self.path)?)?
        } else {
            json!({"highest_sequence":0,"history":[]})
        };
        let mut state: Value = state;
        let high = Path::new("/var/lib/riverlb-updater/status.json");
        if high.exists() {
            use std::os::unix::fs::MetadataExt;
            let meta = std::fs::symlink_metadata(high)?;
            ensure!(
                meta.is_file()
                    && meta.uid() == 0
                    && meta.mode() & 0o022 == 0
                    && meta.len() <= 1024 * 1024,
                "Unsafe privileged update status"
            );
            let trusted: Value = serde_json::from_slice(&std::fs::read(high)?)?;
            state["highest_sequence"] = trusted["highest_sequence"].clone();
            state["history"] = trusted["history"].clone();
        }
        if !self.staged.exists() {
            state["candidate"] = Value::Null;
        }
        Ok(
            json!({"installed_version":env!("CARGO_PKG_VERSION"),"trust_configured":trust(Path::new(TRUST)).is_ok(),"state":state,"staged":self.staged.exists(),"activation_supported":Path::new("/usr/libexec/riverlb/riverlb-update").exists(),"mode":"signed_offline"}),
        )
    }
}
fn atomic_write(path: &Path, data: &[u8]) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    if path.exists() {
        ensure!(
            std::fs::symlink_metadata(path)?.is_file(),
            "Unsafe update file"
        );
    }
    let tmp = path.with_extension(format!("{:016x}.new", rand::random::<u64>()));
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(&tmp)?;
    let result = (|| {
        file.write_all(data)?;
        file.sync_all()?;
        std::fs::rename(&tmp, path)?;
        std::fs::File::open(path.parent().context("Update directory")?)?.sync_all()?;
        anyhow::Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(tmp);
    }
    result
}
type ApiResult = std::result::Result<Json<Value>, (StatusCode, Json<Value>)>;
fn check(condition: bool, message: &str) -> Result<()> {
    ensure!(condition, "{message}");
    Ok(())
}
fn error(e: anyhow::Error) -> (StatusCode, Json<Value>) {
    (StatusCode::CONFLICT, Json(json!({"error":e.to_string()})))
}
async fn stage(
    State(c): State<Arc<crate::control::Control>>,
    Extension(actor): Extension<String>,
    Json(bundle): Json<Bundle>,
) -> ApiResult {
    tokio::spawn(async move {
        let _gate=c.updates.gate.lock().await;
        check(c.pending_configuration.lock().await.is_none(),"Confirm the configuration before staging an update").map_err(error)?;
        let highest=c.updates.status().map_err(error)?["state"]["highest_sequence"].as_u64().unwrap_or(0);
        let bundle_path=c.updates.staged.clone();let state_path=c.updates.path.clone();
        let manifest=tokio::task::spawn_blocking(move||{let (manifest,_)=verify(&bundle,&trust(Path::new(TRUST))?,highest,crate::storage::now())?;atomic_write(&bundle_path,&serde_json::to_vec(&bundle)?)?;anyhow::Ok(manifest)}).await.map_err(|e|error(e.into()))?.map_err(error)?;
        let mut state=c.updates.status().map_err(error)?["state"].clone();state["candidate"]=json!(manifest);atomic_write(&state_path,&serde_json::to_vec(&state).unwrap()).map_err(error)?;
        c.store.record_audit(&actor,&format!("Signed update staged: {} sequence {}",manifest.version,manifest.sequence)).await.map_err(error)?;
        Ok(Json(json!({"message":"Signed update verified and staged. Review the version before activation.","manifest":manifest})))
    }).await.map_err(|e|error(e.into()))?
}
async fn activate(
    State(c): State<Arc<crate::control::Control>>,
    Extension(actor): Extension<String>,
) -> ApiResult {
    tokio::spawn(async move {
        let _gate=c.updates.gate.lock().await;
        check(c.pending_configuration.lock().await.is_none(),"Confirm the configuration before updating").map_err(error)?;
        check(c.ha.is_none(),"Signed offline activation currently supports standalone appliances. HA rolling update qualification is required before activation on an HA pair.").map_err(error)?;
        check(c.updates.staged.exists() && c.updates.staged==Path::new("/var/lib/riverlb/riverlb.update-bundle.json"),"Activation requires an installed appliance; repository instances can verify bundles through the CLI").map_err(error)?;
        c.store.record_audit(&actor,"Signed offline update activation requested").await.map_err(error)?;
        let output=tokio::process::Command::new("/usr/bin/systemctl").args(["start","--no-block","riverlb-update.service"]).kill_on_drop(true).output().await.map_err(|e|error(e.into()))?;
        check(output.status.success(),"Could not start the installed update service").map_err(error)?;
        Ok(Json(json!({"message":"Update activation started. Management will reconnect after readiness checks; a failed update restores the previous application and database."})))
    }).await.map_err(|e|error(e.into()))?
}
pub fn router() -> Router<Arc<crate::control::Control>> {
    Router::new().route("/release.js",get(||async{([("content-type","text/javascript; charset=utf-8")],include_str!("../web/release.js"))}))
        .route("/api/v1/updates/status",get(|State(c):State<Arc<crate::control::Control>>|async move{
            let mut status=c.updates.status().map_err(error)?;
            let installed=c.updates.staged==Path::new("/var/lib/riverlb/riverlb.update-bundle.json") && Path::new("/usr/libexec/riverlb/riverlb-update").exists();
            status["activation_supported"]=json!(installed && c.ha.is_none());
            status["activation_reason"]=json!(if c.ha.is_some(){"HA rolling update qualification is required before activating on a pair."}else if !installed{"Activation requires an installed standalone appliance. Repository builds can verify bundles using the CLI."}else{""});
            Ok::<_,(StatusCode,Json<Value>)>(Json(status))
        }))
        .route("/api/v1/updates/stage",post(stage).layer(axum::extract::DefaultBodyLimit::max(MAX_BUNDLE)))
        .route("/api/v1/updates/activate",post(activate))
}
#[cfg(test)]
mod tests {
    use super::*;
    use ring::signature::KeyPair;
    #[test]
    fn signatures_expiry_sequence_platform_and_payload_are_required() {
        let key = ring::signature::Ed25519KeyPair::from_pkcs8(
            ring::signature::Ed25519KeyPair::generate_pkcs8(&ring::rand::SystemRandom::new())
                .unwrap()
                .as_ref(),
        )
        .unwrap();
        let trust = Trust {
            format: 1,
            keys: vec![TrustedKey {
                id: "fixture".into(),
                public_key: BASE64.encode(key.public_key().as_ref()),
            }],
        };
        let mut payload = vec![0; 64];
        payload[..6].copy_from_slice(b"\x7fELF\x02\x01");
        payload[18] = 62;
        let manifest = Manifest {
            format: 1,
            product: "RiverLB".into(),
            version: "0.1.1".into(),
            sequence: 2,
            architecture: "x86_64".into(),
            platform: "almalinux-10".into(),
            minimum_schema: 6,
            maximum_schema: 6,
            created: 1000,
            expires: 2000,
            payload_length: 64,
            payload_sha256: format!("{:x}", Sha256::digest(&payload)),
            key_id: "fixture".into(),
        };
        let text = serde_json::to_string(&manifest).unwrap();
        let mut bundle = Bundle {
            signature: BASE64.encode(key.sign(text.as_bytes()).as_ref()),
            manifest: text,
            payload: BASE64.encode(&payload),
        };
        assert!(verify(&bundle, &trust, 1, 1500).is_ok());
        assert!(verify(&bundle, &trust, 2, 1500).is_err());
        assert!(verify(&bundle, &trust, 1, 2000).is_err());
        payload[40] = 1;
        bundle.payload = BASE64.encode(&payload);
        assert!(verify(&bundle, &trust, 1, 1500).is_err());
        bundle.manifest.push(' ');
        assert!(verify(&bundle, &trust, 1, 1500).is_err());
    }
}
