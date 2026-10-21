//! Local appliance operations. Settings and encryption keys never enter traffic sync.
use anyhow::{Context, Result, ensure};
use axum::{
    Extension, Json, Router,
    extract::{Query, State},
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::{get, post},
};
use base64::{Engine, engine::general_purpose::STANDARD as BASE64};
use rand::{RngCore, rngs::OsRng};
use ring::aead;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};

const ENVELOPE_FORMAT: &str = "riverlb-encrypted-backup-v1";
const KDF: &str = "argon2id-v19-m32768-t3-p1";
const MAX_ENCRYPTED_BYTES: usize = 46 * 1024 * 1024;
const MAX_SETTINGS_BYTES: usize = 256 * 1024;

#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct AlertSettings {
    pub enabled: bool,
    pub cpu_percent: u8,
    pub memory_percent: u8,
    pub disk_free_percent: u8,
    pub certificate_days: u16,
    pub pool_unavailable: bool,
    pub ha_errors: bool,
    pub time_unsynchronized: bool,
    pub pending_configuration: bool,
    pub webhook_url: String,
    pub webhook_ca: String,
    pub syslog_address: String,
    pub forward_audit: bool,
}
impl Default for AlertSettings {
    fn default() -> Self {
        Self {
            enabled: true,
            cpu_percent: 90,
            memory_percent: 90,
            disk_free_percent: 10,
            certificate_days: 30,
            pool_unavailable: true,
            ha_errors: true,
            time_unsynchronized: true,
            pending_configuration: true,
            webhook_url: String::new(),
            webhook_ca: "system".into(),
            syslog_address: String::new(),
            forward_audit: false,
        }
    }
}
#[derive(Clone, PartialEq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct BackupSettings {
    pub enabled: bool,
    pub destination: String,
    pub interval_hours: u16,
    pub retain: u16,
}
impl Default for BackupSettings {
    fn default() -> Self {
        Self {
            enabled: false,
            destination: String::new(),
            interval_hours: 24,
            retain: 14,
        }
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Settings {
    pub alerts: AlertSettings,
    pub backups: BackupSettings,
    pub audit_retention_days: u32,
    pub audit_max_records: u32,
}
impl Default for Settings {
    fn default() -> Self {
        Self {
            alerts: Default::default(),
            backups: Default::default(),
            audit_retention_days: 365,
            audit_max_records: 100000,
        }
    }
}
impl Settings {
    fn validate(&self) -> Result<()> {
        ensure!(
            (1..=100).contains(&self.alerts.cpu_percent)
                && (1..=100).contains(&self.alerts.memory_percent)
                && (1..=99).contains(&self.alerts.disk_free_percent),
            "alert percentages are outside their allowed ranges"
        );
        ensure!(
            (1..=365).contains(&self.alerts.certificate_days),
            "certificate warning must be 1–365 days"
        );
        ensure!(
            (1..=8760).contains(&self.backups.interval_hours)
                && (1..=365).contains(&self.backups.retain),
            "backup interval or retention is outside its allowed range"
        );
        ensure!(
            (1..=3650).contains(&self.audit_retention_days)
                && (1000..=1000000).contains(&self.audit_max_records),
            "audit retention must be 1–3650 days and 1000–1000000 records"
        );
        if !self.alerts.webhook_url.is_empty() {
            Webhook::parse(&self.alerts.webhook_url)?;
        }
        ensure!(
            self.alerts.webhook_ca == "system"
                || (self.alerts.webhook_ca.len() <= 4096
                    && Path::new(&self.alerts.webhook_ca).is_absolute()),
            "webhook trust must be system or an absolute CA path"
        );
        if !self.alerts.webhook_url.is_empty() && self.alerts.webhook_ca != "system" {
            let metadata = std::fs::metadata(&self.alerts.webhook_ca)
                .context("webhook CA file unavailable")?;
            ensure!(
                metadata.is_file() && metadata.len() <= 2 * 1024 * 1024,
                "webhook CA must be a regular PEM file under 2 MiB"
            );
        }
        if !self.alerts.syslog_address.is_empty() {
            let address: std::net::SocketAddr = self
                .alerts
                .syslog_address
                .parse()
                .context("syslog destination must be an IP address and nonzero port")?;
            ensure!(
                address.port() > 0 && !address.ip().is_unspecified(),
                "invalid syslog destination"
            );
        }
        ensure!(
            !self.alerts.forward_audit || !self.alerts.syslog_address.is_empty(),
            "configure a syslog destination before enabling audit forwarding"
        );
        ensure!(
            self.backups.destination.len() <= 4096,
            "backup destination is too long"
        );
        if self.backups.enabled {
            validate_destination(Path::new(&self.backups.destination))?;
        }
        Ok(())
    }
}
#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupKey {
    salt: String,
    key: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct BackupStatus {
    last_attempt: Option<i64>,
    last_success: Option<i64>,
    last_error: Option<String>,
    last_file: Option<String>,
    next_attempt: Option<i64>,
    running: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Alert {
    pub id: String,
    pub severity: String,
    pub message: String,
    pub first_seen: i64,
    pub last_seen: i64,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct PrivateState {
    settings: Settings,
    backup_key: Option<BackupKey>,
    backup_status: BackupStatus,
    alerts: Vec<Alert>,
    last_delivery: Option<i64>,
    delivery_error: Option<String>,
    last_forwarded_audit_id: i64,
    notifications: Vec<Value>,
    notification_next_attempt: i64,
    notification_failures: u8,
}
pub struct Operations {
    path: PathBuf,
    disk_path: PathBuf,
    state: Mutex<PrivateState>,
    save_gate: Mutex<()>,
    crypto_gate: Mutex<()>,
    backup_gate: Mutex<()>,
    sample_gate: Mutex<()>,
    cpu: Mutex<Option<(u64, u64)>>,
}
impl Operations {
    pub fn open(database: &Path) -> Result<Self> {
        let path = database.with_extension("operations.json");
        use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
        let mut state: PrivateState = match std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&path)
        {
            Ok(file) => {
                let metadata = file.metadata()?;
                // SAFETY: geteuid has no pointer arguments.
                ensure!(
                    metadata.is_file()
                        && metadata.uid() == unsafe { libc::geteuid() }
                        && metadata.len() <= MAX_SETTINGS_BYTES as u64
                        && metadata.mode() & 0o077 == 0,
                    "operations state must be a private regular file owned by the service (0600)"
                );
                serde_json::from_reader(file)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => PrivateState::default(),
            Err(error) => return Err(error.into()),
        };
        if let Some(key) = &state.backup_key {
            ensure!(
                BASE64.decode(&key.salt)?.len() == 16 && BASE64.decode(&key.key)?.len() == 32,
                "invalid stored backup key"
            );
        }
        ensure!(
            state.alerts.len() <= 500
                && state.notifications.len() <= 100
                && state.last_forwarded_audit_id >= 0,
            "invalid operations state bounds"
        );
        if state.backup_status.running {
            state.backup_status.last_error =
                Some("The previous backup was interrupted before completion".into());
            state.backup_status.next_attempt = Some(crate::storage::now() + 300);
            state.backup_status.running = false;
        }
        // A disconnected backup mount should raise an alert, never prevent startup.
        let disk_path = database.parent().unwrap_or(Path::new(".")).to_owned();
        Ok(Self {
            path,
            disk_path,
            state: Mutex::new(state),
            save_gate: Mutex::new(()),
            crypto_gate: Mutex::new(()),
            backup_gate: Mutex::new(()),
            sample_gate: Mutex::new(()),
            cpu: Mutex::new(None),
        })
    }
    async fn persist(&self, state: &PrivateState) -> Result<()> {
        let path = self.path.clone();
        let data = serde_json::to_vec_pretty(state)?;
        ensure!(
            data.len() <= MAX_SETTINGS_BYTES,
            "operations state exceeds its bounded storage limit"
        );
        tokio::task::spawn_blocking(move || private_write(&path, &data, true)).await??;
        Ok(())
    }
    async fn public(&self) -> Value {
        let state = self.state.lock().await;
        json!({"settings":state.settings,"backup_key_configured":state.backup_key.is_some(),"backup_status":state.backup_status,
            "alerts":state.alerts,"last_delivery":state.last_delivery,"delivery_error":state.delivery_error,
            "queued_notifications":state.notifications.len(),"next_delivery_attempt":state.notification_next_attempt,
            "last_forwarded_audit_id":state.last_forwarded_audit_id})
    }
}
fn private_write(path: &Path, data: &[u8], replace: bool) -> Result<()> {
    use std::{io::Write, os::unix::fs::OpenOptionsExt};
    if let Ok(metadata) = std::fs::symlink_metadata(path) {
        use std::os::unix::fs::MetadataExt;
        // SAFETY: geteuid has no pointer arguments.
        ensure!(
            replace
                && metadata.is_file()
                && metadata.uid() == unsafe { libc::geteuid() }
                && metadata.mode() & 0o077 == 0,
            "refusing to overwrite an existing, linked or nonprivate file"
        );
    }
    let temporary = path.with_extension(format!("{:032x}.new", rand::random::<u128>()));
    let result = (|| {
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW)
            .open(&temporary)?;
        file.write_all(data)?;
        file.sync_all()?;
        if replace {
            std::fs::rename(&temporary, path)?;
        } else {
            std::fs::hard_link(&temporary, path)?;
            std::fs::remove_file(&temporary)?;
        }
        std::fs::File::open(path.parent().unwrap_or(Path::new(".")))?.sync_all()?;
        anyhow::Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(temporary);
    }
    result
}
fn derive(passphrase: &str, salt: &[u8]) -> Result<[u8; 32]> {
    ensure!(
        (12..=1024).contains(&passphrase.len()),
        "backup passphrase must contain 12–1024 bytes"
    );
    ensure!(salt.len() == 16, "invalid backup salt");
    let params = argon2::Params::new(32768, 3, 1, Some(32))
        .map_err(|_| anyhow::anyhow!("invalid encryption parameters"))?;
    let mut key = [0; 32];
    argon2::Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params)
        .hash_password_into(passphrase.as_bytes(), salt, &mut key)
        .map_err(|_| anyhow::anyhow!("backup key derivation failed"))?;
    Ok(key)
}
fn new_key(passphrase: &str) -> Result<BackupKey> {
    let mut salt = [0; 16];
    OsRng.fill_bytes(&mut salt);
    let key = derive(passphrase, &salt)?;
    Ok(BackupKey {
        salt: BASE64.encode(salt),
        key: BASE64.encode(key),
    })
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Envelope {
    pub format: String,
    pub cipher: String,
    pub kdf: String,
    pub salt: String,
    pub nonce: String,
    pub created: i64,
    pub ciphertext: String,
}
impl Envelope {
    fn aad(&self) -> Result<Vec<u8>> {
        Ok(serde_json::to_vec(&(
            &self.format,
            &self.cipher,
            &self.kdf,
            &self.salt,
            self.created,
        ))?)
    }
    fn encrypt(snapshot: &crate::backup::Snapshot, key: &BackupKey) -> Result<Self> {
        let mut nonce = [0; 12];
        OsRng.fill_bytes(&mut nonce);
        let mut envelope = Self {
            format: ENVELOPE_FORMAT.into(),
            cipher: "aes-256-gcm".into(),
            kdf: KDF.into(),
            salt: key.salt.clone(),
            nonce: BASE64.encode(nonce),
            created: crate::storage::now(),
            ciphertext: String::new(),
        };
        let bytes = BASE64.decode(&key.key)?;
        ensure!(bytes.len() == 32, "invalid backup encryption key");
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &bytes)
                .map_err(|_| anyhow::anyhow!("invalid encryption key"))?,
        );
        let mut data = serde_json::to_vec(snapshot)?;
        ensure!(
            data.len() <= crate::backup::MAX_BYTES,
            "backup exceeds size limit"
        );
        key.seal_in_place_append_tag(
            aead::Nonce::assume_unique_for_key(nonce),
            aead::Aad::from(envelope.aad()?),
            &mut data,
        )
        .map_err(|_| anyhow::anyhow!("backup encryption failed"))?;
        envelope.ciphertext = BASE64.encode(data);
        Ok(envelope)
    }
    fn decrypt(self, passphrase: &str) -> Result<crate::backup::Snapshot> {
        ensure!(
            self.format == ENVELOPE_FORMAT && self.cipher == "aes-256-gcm" && self.kdf == KDF,
            "unsupported encrypted backup format"
        );
        ensure!(
            self.ciphertext.len() <= (crate::backup::MAX_BYTES + 16).div_ceil(3) * 4,
            "encrypted backup exceeds size limit"
        );
        ensure!(
            self.salt.len() == 24 && self.nonce.len() == 16,
            "invalid encrypted backup salt or nonce length"
        );
        let salt = BASE64.decode(&self.salt)?;
        let nonce: [u8; 12] = BASE64
            .decode(&self.nonce)?
            .try_into()
            .map_err(|_| anyhow::anyhow!("invalid backup nonce"))?;
        let secret = derive(passphrase, &salt)?;
        let key = aead::LessSafeKey::new(
            aead::UnboundKey::new(&aead::AES_256_GCM, &secret)
                .map_err(|_| anyhow::anyhow!("invalid encryption key"))?,
        );
        let mut data = BASE64.decode(&self.ciphertext)?;
        let plain = key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(self.aad()?),
                &mut data,
            )
            .map_err(|_| {
                anyhow::anyhow!(
                    "backup authentication failed; incorrect passphrase or modified file"
                )
            })?;
        let snapshot: crate::backup::Snapshot = serde_json::from_slice(plain)?;
        snapshot.validate()?;
        Ok(snapshot)
    }
}
fn decode_mount_path(value: &str) -> String {
    value
        .replace("\\040", " ")
        .replace("\\011", "\t")
        .replace("\\134", "\\")
}
fn mounted_destination(path: &Path, mountinfo: &str) -> bool {
    mountinfo
        .lines()
        .filter_map(|line| {
            let (before, after) = line.split_once(" - ")?;
            let point = PathBuf::from(decode_mount_path(before.split_whitespace().nth(4)?));
            let kind = after.split_whitespace().next()?;
            Some((point, kind))
        })
        .any(|(point, kind)| {
            point != Path::new("/")
                && path.starts_with(point)
                && !["tmpfs", "devtmpfs", "proc", "sysfs", "overlay", "ramfs"].contains(&kind)
        })
}
fn validate_destination(path: &Path) -> Result<()> {
    ensure!(
        path.is_absolute() && path.components().count() > 2,
        "choose an absolute directory on separately mounted storage"
    );
    ensure!(
        path.components().all(|c| !matches!(
            c,
            std::path::Component::ParentDir | std::path::Component::CurDir
        )),
        "backup paths must not contain . or .."
    );
    let canonical =
        std::fs::canonicalize(path).context("backup destination must exist before scheduling")?;
    ensure!(
        canonical == path && canonical.is_dir(),
        "backup destination must be a real directory without symbolic links"
    );
    for protected in ["/etc", "/usr", "/boot", "/dev", "/proc", "/sys", "/run"] {
        ensure!(
            !path.starts_with(protected),
            "choose a backup storage directory outside system paths"
        );
    }
    ensure!(
        mounted_destination(path, &std::fs::read_to_string("/proc/self/mountinfo")?),
        "backup destination must be on a separate mounted filesystem; mount off-appliance storage before enabling the schedule"
    );
    Ok(())
}
fn owned_backup_name(name: &str) -> bool {
    let Some(middle) = name
        .strip_prefix("riverlb-")
        .and_then(|n| n.strip_suffix(".rlbenc"))
    else {
        return false;
    };
    let Some((time, random)) = middle.split_once('-') else {
        return false;
    };
    !time.is_empty()
        && time.len() <= 20
        && time.bytes().all(|b| b.is_ascii_digit())
        && random.len() == 32
        && random.bytes().all(|b| b.is_ascii_hexdigit())
}
fn write_backup(directory: &Path, bytes: &[u8], retain: u16) -> Result<String> {
    let name = format!(
        "riverlb-{}-{:032x}.rlbenc",
        crate::storage::now(),
        rand::random::<u128>()
    );
    private_write(&directory.join(&name), bytes, false)?;
    let mut owned = Vec::new();
    for entry in std::fs::read_dir(directory)? {
        let entry = entry?;
        let filename = entry.file_name().to_string_lossy().into_owned();
        if owned_backup_name(&filename) && entry.file_type()?.is_file() {
            let created = filename
                .split('-')
                .nth(1)
                .and_then(|v| v.parse::<i64>().ok())
                .unwrap_or(0);
            owned.push((created, filename));
        }
    }
    owned.sort();
    owned.reverse();
    // Never prune until the new encrypted file has been written and synced.
    for (_, old_name) in owned
        .into_iter()
        .filter(|(_, old_name)| old_name != &name)
        .skip(usize::from(retain.saturating_sub(1)))
    {
        std::fs::remove_file(directory.join(old_name))?;
    }
    Ok(name)
}

#[derive(Clone)]
struct Webhook {
    host: String,
    port: u16,
    path: String,
    authority: String,
}
impl Webhook {
    fn parse(url: &str) -> Result<Self> {
        ensure!(
            url.len() <= 2048 && url.bytes().all(|b| (33..127).contains(&b)) && !url.contains('#'),
            "invalid webhook URL"
        );
        let uri: hyper::Uri = url.parse().context("invalid webhook URL")?;
        ensure!(
            uri.scheme_str() == Some("https"),
            "webhook requires verified HTTPS"
        );
        let authority = uri.authority().context("webhook requires a hostname")?;
        ensure!(
            !authority.as_str().contains('@'),
            "webhook URL must not contain credentials"
        );
        let host = uri
            .host()
            .context("webhook requires a hostname")?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_owned();
        let port = uri.port_u16().unwrap_or(443);
        ensure!(port > 0, "invalid webhook port");
        Ok(Self {
            host,
            port,
            path: uri
                .path_and_query()
                .map(|p| p.as_str())
                .unwrap_or("/")
                .into(),
            authority: authority.as_str().into(),
        })
    }
}
async fn webhook(settings: &AlertSettings, payload: Value) -> Result<()> {
    let endpoint = Webhook::parse(&settings.webhook_url)?;
    let data = serde_json::to_vec(&payload)?;
    ensure!(data.len() <= 65536, "alert payload exceeds limit");
    let ca = settings.webhook_ca.clone();
    let server = endpoint.host.clone();
    let connector = tokio::task::spawn_blocking(move || {
        crate::server_tls::Profile {
            name: "operations-webhook".into(),
            server_name: server,
            ca_certificate: ca,
        }
        .connector()
    })
    .await??;
    tokio::time::timeout(Duration::from_secs(5),async {
        let socket=tokio::net::TcpStream::connect((endpoint.host.as_str(),endpoint.port)).await?;
        let name=tokio_rustls::rustls::pki_types::ServerName::try_from(endpoint.host.clone())?;
        let mut stream=connector.connect(name,socket).await?;
        stream.write_all(format!("POST {} HTTP/1.1\r\nHost: {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",endpoint.path,endpoint.authority,data.len()).as_bytes()).await?;
        stream.write_all(&data).await?;
        let mut header=Vec::new();let mut byte=[0];
        while header.len()<8192 && !header.ends_with(b"\r\n\r\n") {ensure!(stream.read(&mut byte).await?>0,"webhook returned an incomplete response");header.push(byte[0]);}
        ensure!(header.ends_with(b"\r\n\r\n"),"webhook response headers exceed 8 KiB");
        let line=std::str::from_utf8(&header)?.lines().next().unwrap_or("");
        ensure!(line.starts_with("HTTP/1."),"webhook returned an invalid HTTP response");
        let code=line.split_whitespace().nth(1).and_then(|v|v.parse::<u16>().ok()).context("invalid webhook response")?;
        ensure!((200..300).contains(&code),"webhook returned HTTP {code}");anyhow::Ok(())
    }).await.context("webhook delivery exceeded five seconds")??;
    Ok(())
}
fn syslog_text(value: &str) -> String {
    let mut output = String::new();
    for character in value.chars() {
        let character = if character.is_control() {
            ' '
        } else {
            character
        };
        if output.len() + character.len_utf8() > 850 {
            break;
        }
        output.push(character);
    }
    output
}
async fn syslog(address: &str, text: &str) -> Result<()> {
    let destination: std::net::SocketAddr = address.parse()?;
    tokio::time::timeout(Duration::from_secs(2), async {
        let bind = if destination.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        };
        let socket = tokio::net::UdpSocket::bind(bind).await?;
        let now = time::OffsetDateTime::now_utc();
        let timestamp = format!(
            "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
            now.year(),
            u8::from(now.month()),
            now.day(),
            now.hour(),
            now.minute(),
            now.second()
        );
        socket
            .send_to(
                format!(
                    "<132>1 {timestamp} - riverlb {} event - {}",
                    std::process::id(),
                    syslog_text(text)
                )
                .as_bytes(),
                destination,
            )
            .await?;
        anyhow::Ok(())
    })
    .await
    .context("syslog delivery exceeded two seconds")??;
    Ok(())
}

fn read_cpu() -> Option<(u64, u64)> {
    let line = std::fs::read_to_string("/proc/stat")
        .ok()?
        .lines()
        .next()?
        .to_owned();
    let counts = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .map(str::parse::<u64>)
        .collect::<std::result::Result<Vec<_>, _>>()
        .ok()?;
    if counts.len() < 5 {
        return None;
    };
    Some((counts.iter().sum(), counts[3] + counts[4]))
}
fn memory() -> Value {
    let info = std::fs::read_to_string("/proc/meminfo").unwrap_or_default();
    let values: BTreeMap<_, _> = info
        .lines()
        .filter_map(|line| {
            let mut fields = line.split_whitespace();
            Some((
                fields.next()?.trim_end_matches(':'),
                fields.next()?.parse::<u64>().ok()?.saturating_mul(1024),
            ))
        })
        .collect();
    let total = values.get("MemTotal").copied().unwrap_or(0);
    let available = values.get("MemAvailable").copied().unwrap_or(0);
    json!({"total_bytes":total,"available_bytes":available,"used_percent":if total>0{Some(100.0*(total.saturating_sub(available))as f64/total as f64)}else{None}})
}
fn disk(path: &Path) -> Value {
    use std::os::unix::ffi::OsStrExt;
    let Ok(path) = std::ffi::CString::new(path.as_os_str().as_bytes()) else {
        return json!(null);
    };
    let mut stats = std::mem::MaybeUninit::<libc::statvfs>::zeroed();
    // statvfs only reads filesystem metadata; the initialized output is read on success.
    if unsafe { libc::statvfs(path.as_ptr(), stats.as_mut_ptr()) } != 0 {
        return json!(null);
    };
    let stats = unsafe { stats.assume_init() };
    let total = stats.f_blocks.saturating_mul(stats.f_frsize);
    let available = stats.f_bavail.saturating_mul(stats.f_frsize);
    json!({"total_bytes":total,"available_bytes":available,"free_percent":if total>0{Some(100.0*available as f64/total as f64)}else{None}})
}
fn synchronized_time() -> Option<bool> {
    let mut clock = std::mem::MaybeUninit::<libc::timex>::zeroed();
    // modes=0 queries kernel time discipline and does not change the clock.
    let result = unsafe { libc::adjtimex(clock.as_mut_ptr()) };
    if result < 0 {
        return None;
    };
    let clock = unsafe { clock.assume_init() };
    Some(clock.status & libc::STA_UNSYNC == 0 && result != libc::TIME_ERROR)
}
fn interfaces() -> Vec<Value> {
    let mut result = Vec::new();
    if let Ok(entries) = std::fs::read_dir("/sys/class/net") {
        for entry in entries.flatten().take(128) {
            let path = entry.path();
            let text = |name: &str| {
                std::fs::read_to_string(path.join(name))
                    .ok()
                    .map(|v| v.trim().to_owned())
            };
            result.push(json!({"name":entry.file_name().to_string_lossy(),"state":text("operstate"),"mtu":text("mtu").and_then(|v|v.parse::<u64>().ok()),
                "rx_bytes":text("statistics/rx_bytes").and_then(|v|v.parse::<u64>().ok()),"tx_bytes":text("statistics/tx_bytes").and_then(|v|v.parse::<u64>().ok()),
                "rx_errors":text("statistics/rx_errors").and_then(|v|v.parse::<u64>().ok()),"tx_errors":text("statistics/tx_errors").and_then(|v|v.parse::<u64>().ok())}));
        }
    }
    result.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    result
}
async fn health(control: &crate::control::Control) -> Result<Value> {
    let current = read_cpu();
    let mut last = control.operations.cpu.lock().await;
    let percent = current
        .zip(*last)
        .and_then(|((total, idle), (old_total, old_idle))| {
            let elapsed = total.checked_sub(old_total)?;
            if elapsed == 0 {
                return None;
            };
            Some(
                100.0 * (elapsed.saturating_sub(idle.saturating_sub(old_idle))) as f64
                    / elapsed as f64,
            )
        });
    *last = current;
    drop(last);
    let path = control.operations.disk_path.clone();
    let hardware=tokio::task::spawn_blocking(move || json!({"memory":memory(),"disk":disk(&path),"interfaces":interfaces(),"time_synchronized":synchronized_time(),
        "uptime_seconds":std::fs::read_to_string("/proc/uptime").ok().and_then(|s|s.split_whitespace().next()?.parse::<f64>().ok()),
        "load_average":std::fs::read_to_string("/proc/loadavg").ok().map(|s|s.split_whitespace().take(3).filter_map(|v|v.parse::<f64>().ok()).collect::<Vec<_>>()),
        "kernel":std::fs::read_to_string("/proc/sys/kernel/osrelease").unwrap_or_default().trim()})).await?;
    let generation = control.generation.lock().await;
    let revision = generation.revision;
    let servers=generation.runtime.pools.iter().map(|pool| {
        let members=pool.members.lock().unwrap();let healthy=members.iter().filter(|m|m.healthy&&!m.draining).count();
        json!({"name":pool.config.name,"enabled":pool.config.enabled,"available_members":healthy,"total_members":members.len(),"state":if !pool.config.enabled{"disabled"}else if healthy>0{"up"}else{"down"}})
    }).collect::<Vec<_>>();
    drop(generation);
    let mut certificates = Vec::new();
    for scope in [
        crate::certificates::StoreKind::Device,
        crate::certificates::StoreKind::VirtualServer,
    ] {
        for cert in control.store.certificates_in(scope).await? {
            certificates.push(json!({"name":cert.name,"store":scope,"days_remaining":cert.days_remaining,"valid_now":cert.valid_now,"not_after":cert.not_after}));
        }
    }
    let appliance = control.ha_status().await;
    let confirmation = crate::confirmation::view(control).await;
    Ok(
        json!({"created":crate::storage::now(),"version":env!("CARGO_PKG_VERSION"),"revision":revision,"cpu_percent":percent,"system":hardware,"pending_configuration":confirmation["pending"],
        "virtual_servers":servers,"certificates":certificates,"ha":{"role":appliance["role"],"configuration_sync":appliance["configuration_sync"],"sync_error":appliance["sync_error"]}}),
    )
}
fn alert_conditions(
    health: &Value,
    settings: &Settings,
    backup: &BackupStatus,
) -> Vec<(String, String, String)> {
    if !settings.alerts.enabled {
        return Vec::new();
    };
    let mut alerts = Vec::new();
    let mut add = |id: &str, severity: &str, message: String| {
        alerts.push((id.to_owned(), severity.to_owned(), message))
    };
    if health["cpu_percent"]
        .as_f64()
        .is_some_and(|v| v >= f64::from(settings.alerts.cpu_percent))
    {
        add(
            "cpu",
            "warning",
            format!("CPU utilization exceeds {}%", settings.alerts.cpu_percent),
        );
    }
    if health["system"]["memory"]["used_percent"]
        .as_f64()
        .is_some_and(|v| v >= f64::from(settings.alerts.memory_percent))
    {
        add(
            "memory",
            "warning",
            format!(
                "Memory utilization exceeds {}%",
                settings.alerts.memory_percent
            ),
        );
    }
    if health["system"]["disk"]["free_percent"]
        .as_f64()
        .is_some_and(|v| v <= f64::from(settings.alerts.disk_free_percent))
    {
        add(
            "disk",
            "critical",
            format!(
                "Application filesystem has less than {}% free space",
                settings.alerts.disk_free_percent
            ),
        );
    }
    if settings.alerts.time_unsynchronized && health["system"]["time_synchronized"] == false {
        add(
            "time",
            "warning",
            "Kernel clock is not synchronized; verify the appliance time service".into(),
        );
    }
    if let Some(certificates) = health["certificates"].as_array() {
        for cert in certificates {
            if cert["days_remaining"]
                .as_i64()
                .is_some_and(|n| n <= i64::from(settings.alerts.certificate_days))
            {
                add(
                    &format!("certificate:{}:{}", cert["store"], cert["name"]),
                    "warning",
                    format!(
                        "{} certificate {} expires in {} days",
                        cert["store"].as_str().unwrap_or(""),
                        cert["name"].as_str().unwrap_or(""),
                        cert["days_remaining"]
                    ),
                );
            }
        }
    }
    if settings.alerts.pool_unavailable
        && let Some(servers) = health["virtual_servers"].as_array()
    {
        for server in servers {
            if server["state"] == "down" {
                add(
                    &format!("pool:{}", server["name"]),
                    "critical",
                    format!(
                        "Virtual server {} has no available pool members",
                        server["name"].as_str().unwrap_or("")
                    ),
                );
            }
        }
    }
    if settings.alerts.ha_errors
        && (health["ha"]["role"] == "fault"
            || health["ha"]["sync_error"]
                .as_str()
                .is_some_and(|v| !v.is_empty()))
    {
        add(
            "ha",
            "critical",
            "HA ownership or configuration synchronization requires attention".into(),
        );
    }
    if settings.alerts.pending_configuration && health["pending_configuration"] == true {
        add(
            "configuration",
            "warning",
            "Management or network changes await confirmation and will revert unless confirmed"
                .into(),
        );
    }
    if settings.backups.enabled && backup.last_error.is_some() {
        add(
            "backup",
            "critical",
            "The scheduled encrypted backup failed; review Backup status".into(),
        );
    }
    alerts
}
fn update_alerts(
    state: &mut PrivateState,
    conditions: Vec<(String, String, String)>,
    now: i64,
) -> Vec<Value> {
    let mut events = Vec::new();
    let mut current = Vec::new();
    for (id, severity, message) in conditions.into_iter().take(500) {
        let old = state.alerts.iter().find(|alert| alert.id == id);
        let alert = Alert {
            id,
            severity,
            message,
            first_seen: old.map(|v| v.first_seen).unwrap_or(now),
            last_seen: now,
        };
        if old.is_none() {
            events.push(json!({"event":"alert","alert":alert}));
        }
        current.push(alert);
    }
    for old in &state.alerts {
        if !current.iter().any(|v| v.id == old.id) {
            events.push(json!({"event":"resolved","alert":old}));
        }
    }
    state.alerts = current;
    events
}
async fn perform_backup(control: &crate::control::Control, actor: &str) -> Result<Value> {
    let _gate = control
        .operations
        .backup_gate
        .try_lock()
        .context("an encrypted backup is already running")?;
    let (settings, key) = {
        let mut state = control.operations.state.lock().await;
        let key = state
            .backup_key
            .clone()
            .context("set a backup encryption passphrase first")?;
        state.backup_status.running = true;
        state.backup_status.last_attempt = Some(crate::storage::now());
        if let Err(error) = control.operations.persist(&state).await {
            state.backup_status.running = false;
            return Err(error);
        }
        (state.settings.backups.clone(), key)
    };
    let result = async {
        let destination = PathBuf::from(&settings.destination);
        tokio::task::spawn_blocking(move || validate_destination(&destination)).await??;
        let snapshot = capture_snapshot(control).await?;
        tokio::task::spawn_blocking(move || {
            let envelope = Envelope::encrypt(&snapshot, &key)?;
            write_backup(
                Path::new(&settings.destination),
                &serde_json::to_vec(&envelope)?,
                settings.retain,
            )
        })
        .await?
    }
    .await;
    {
        let mut state = control.operations.state.lock().await;
        state.backup_status.running = false;
        let now = crate::storage::now();
        match &result {
            Ok(file) => {
                state.backup_status.last_success = Some(now);
                state.backup_status.last_file = Some(file.clone());
                state.backup_status.last_error = None;
            }
            Err(error) if error.downcast_ref::<CaptureDeferred>().is_some() => {}
            Err(error) => state.backup_status.last_error = Some(error.to_string()),
        }
        state.backup_status.next_attempt = Some(
            now + if result.is_ok() {
                i64::from(state.settings.backups.interval_hours) * 3600
            } else {
                300
            },
        );
        control.operations.persist(&state).await?;
    }
    match result {
        Ok(file) => {
            control
                .store
                .record_audit(actor, "encrypted backup created on mounted storage")
                .await?;
            Ok(json!({"message":"Encrypted backup saved to mounted storage","file":file}))
        }
        Err(error) => Err(error),
    }
}
async fn sample(control: &crate::control::Control, maintenance: bool) -> Result<()> {
    let _sample = control
        .operations
        .sample_gate
        .try_lock()
        .context("an appliance health check is already running")?;
    let snapshot = health(control).await?;
    let (settings, events, attempt) = {
        let mut state = control.operations.state.lock().await;
        let settings = state.settings.clone();
        let conditions = alert_conditions(&snapshot, &settings, &state.backup_status);
        let events = update_alerts(&mut state, conditions, crate::storage::now());
        if settings.alerts.webhook_url.is_empty() && settings.alerts.syslog_address.is_empty() {
            state.notifications.clear();
        } else {
            state.notifications.extend(events);
            // Drop the oldest transitions during a prolonged outage; keep a bounded queue.
            let extra = state.notifications.len().saturating_sub(100);
            state.notifications.drain(..extra);
        }
        let attempt = state.notification_next_attempt <= crate::storage::now();
        let batch = if attempt {
            state
                .notifications
                .iter()
                .take(20)
                .cloned()
                .collect::<Vec<_>>()
        } else {
            Vec::new()
        };
        control.operations.persist(&state).await?;
        (settings, batch, attempt)
    };
    let mut errors = Vec::new();
    let mut delivered = false;
    // One bounded batch per sample, with persisted exponential retry backoff.
    if !events.is_empty() {
        if !settings.alerts.webhook_url.is_empty() {
            match webhook(
                &settings.alerts,
                json!({"product":"RiverLB","created":crate::storage::now(),"events":events}),
            )
            .await
            {
                Ok(()) => delivered = true,
                Err(error) => errors.push(format!("Webhook: {error}")),
            }
        }
        if !settings.alerts.syslog_address.is_empty() {
            for event in events.iter().take(20) {
                match syslog(
                    &settings.alerts.syslog_address,
                    &format!(
                        "{} {}",
                        event["event"].as_str().unwrap_or("alert"),
                        event["alert"]["message"].as_str().unwrap_or("")
                    ),
                )
                .await
                {
                    Ok(()) => delivered = true,
                    Err(error) => {
                        errors.push(format!("Syslog: {error}"));
                        break;
                    }
                }
            }
        }
    }
    if settings.alerts.forward_audit {
        let mut cursor = control
            .operations
            .state
            .lock()
            .await
            .last_forwarded_audit_id;
        let latest = control.store.audit_page("", "", 0, 1).await?;
        let maximum = latest["entries"][0]["id"].as_i64().unwrap_or(0);
        // Offline restores may replace the audit inventory with an older snapshot.
        if maximum < cursor {
            cursor = 0;
            control
                .operations
                .state
                .lock()
                .await
                .last_forwarded_audit_id = 0;
        }
        let entries = control.store.audit_since(cursor, 200).await?;
        let began = std::time::Instant::now();
        for entry in entries {
            if began.elapsed() >= Duration::from_secs(5) {
                break;
            }
            if let Err(error) = syslog(
                &settings.alerts.syslog_address,
                &format!(
                    "audit id={} actor={} action={}",
                    entry["id"],
                    entry["actor"].as_str().unwrap_or(""),
                    entry["action"].as_str().unwrap_or("")
                ),
            )
            .await
            {
                errors.push(format!("Audit syslog: {error}"));
                break;
            }
            control
                .operations
                .state
                .lock()
                .await
                .last_forwarded_audit_id = entry["id"].as_i64().unwrap_or(cursor);
            delivered = true;
        }
    }
    {
        let mut state = control.operations.state.lock().await;
        if delivered {
            state.last_delivery = Some(crate::storage::now());
        }
        if attempt && !events.is_empty() {
            if errors.is_empty() {
                state.notifications.drain(..events.len());
                state.notification_failures = 0;
                state.notification_next_attempt = 0;
                state.delivery_error = None;
            } else {
                state.notification_failures = state.notification_failures.saturating_add(1).min(8);
                state.notification_next_attempt = crate::storage::now()
                    + (30i64 * 2i64.pow(u32::from(state.notification_failures))).min(3600);
                state.delivery_error = Some(errors.join("; "));
            }
        } else if !errors.is_empty() {
            state.delivery_error = Some(errors.join("; "));
        }
        control.operations.persist(&state).await?;
    }
    let run = {
        let state = control.operations.state.lock().await;
        state.settings.backups.enabled
            && state
                .backup_status
                .next_attempt
                .is_none_or(|n| n <= crate::storage::now())
    };
    let confirmed = control.pending_configuration.lock().await.is_none();
    if maintenance
        && run
        && confirmed
        && let Err(error) = perform_backup(control, "backup scheduler").await
    {
        tracing::warn!("scheduled encrypted backup failed: {error}");
    }
    if maintenance {
        control
            .store
            .prune_audit(settings.audit_retention_days, settings.audit_max_records)
            .await?;
    }
    Ok(())
}
pub fn start(control: Arc<crate::control::Control>) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(Duration::from_secs(30));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {_ = control.stop.cancelled()=>break,_=interval.tick()=>{if let Err(error)=sample(&control,true).await{tracing::warn!("appliance operations sampling failed: {error}");}}}
        }
    })
}

type ApiResult = std::result::Result<Json<Value>, (StatusCode, Json<Value>)>;
fn api_error(error: anyhow::Error) -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"error":error.to_string()})),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SettingsChange {
    settings: Settings,
    #[serde(default)]
    backup_passphrase: Option<String>,
}
async fn save_inner(
    control: Arc<crate::control::Control>,
    actor: String,
    change: SettingsChange,
) -> ApiResult {
    let _gate = control.operations.save_gate.lock().await;
    let settings = change.settings;
    let validation = settings.clone();
    tokio::task::spawn_blocking(move || validation.validate())
        .await
        .map_err(|e| api_error(e.into()))?
        .map_err(api_error)?;
    let new_key = if let Some(passphrase) = change.backup_passphrase.filter(|v| !v.is_empty()) {
        let _crypto = control.operations.crypto_gate.lock().await;
        Some(
            tokio::task::spawn_blocking(move || new_key(&passphrase))
                .await
                .map_err(|e| api_error(e.into()))?
                .map_err(api_error)?,
        )
    } else {
        None
    };
    {
        let mut state = control.operations.state.lock().await;
        let mut next = state.clone();
        next.settings = settings;
        if let Some(key) = new_key {
            next.backup_key = Some(key);
        }
        if next.settings.backups.enabled && next.backup_key.is_none() {
            return Err(api_error(anyhow::anyhow!(
                "a backup encryption passphrase is required before scheduling"
            )));
        }
        if next.settings.backups != state.settings.backups {
            next.backup_status.next_attempt = if next.settings.backups.enabled {
                Some(crate::storage::now() + i64::from(next.settings.backups.interval_hours) * 3600)
            } else {
                None
            };
        }
        control
            .store
            .record_audit(&actor, "appliance operations settings updated")
            .await
            .map_err(api_error)?;
        control.operations.persist(&next).await.map_err(api_error)?;
        *state = next;
    }
    Ok(Json(control.operations.public().await))
}
async fn save(
    State(control): State<Arc<crate::control::Control>>,
    Extension(actor): Extension<String>,
    Json(change): Json<SettingsChange>,
) -> ApiResult {
    tokio::spawn(save_inner(control, actor, change))
        .await
        .map_err(|e| api_error(e.into()))?
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Passphrase {
    passphrase: String,
}
#[derive(Debug)]
struct CaptureDeferred;
impl std::fmt::Display for CaptureDeferred {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "confirm or revert the pending configuration before creating a backup"
        )
    }
}
impl std::error::Error for CaptureDeferred {}
async fn capture_snapshot(control: &crate::control::Control) -> Result<crate::backup::Snapshot> {
    let _configuration = control.change_gate.lock().await;
    if control.pending_configuration.lock().await.is_some() {
        return Err(CaptureDeferred.into());
    }
    control.store.backup().await
}
async fn download_inner(
    control: Arc<crate::control::Control>,
    actor: String,
    request: Passphrase,
) -> std::result::Result<Response, (StatusCode, Json<Value>)> {
    ensure_api(
        (12..=1024).contains(&request.passphrase.len()),
        "backup passphrase must contain 12–1024 bytes",
    )?;
    let _gate = control.operations.crypto_gate.lock().await;
    let snapshot = capture_snapshot(&control).await.map_err(api_error)?;
    let bytes = tokio::task::spawn_blocking(move || {
        let key = new_key(&request.passphrase)?;
        let envelope = Envelope::encrypt(&snapshot, &key)?;
        anyhow::Ok(serde_json::to_vec(&envelope)?)
    })
    .await
    .map_err(|e| api_error(e.into()))?
    .map_err(api_error)?;
    control
        .store
        .record_audit(&actor, "encrypted backup downloaded")
        .await
        .map_err(api_error)?;
    Ok((
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
            (
                "content-disposition",
                "attachment; filename=riverlb-backup.rlbenc",
            ),
        ],
        bytes,
    )
        .into_response())
}
async fn download(
    State(control): State<Arc<crate::control::Control>>,
    Extension(actor): Extension<String>,
    Json(request): Json<Passphrase>,
) -> std::result::Result<Response, (StatusCode, Json<Value>)> {
    tokio::spawn(download_inner(control, actor, request))
        .await
        .map_err(|e| api_error(e.into()))?
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RestoreRequest {
    backup: Envelope,
    passphrase: String,
    #[serde(default)]
    stage: bool,
}
async fn restore_inner(
    control: Arc<crate::control::Control>,
    actor: String,
    request: RestoreRequest,
) -> ApiResult {
    let _gate = control.operations.crypto_gate.lock().await;
    let snapshot = tokio::task::spawn_blocking(move || request.backup.decrypt(&request.passphrase))
        .await
        .map_err(|e| api_error(e.into()))?
        .map_err(api_error)?;
    let summary = json!({"created":snapshot.created,"format":snapshot.format,"configuration_revisions":snapshot.tables["configurations"].len(),
        "administrators":snapshot.tables["administrators"].len(),"device_certificates":snapshot.tables.get("device_certificates").map(Vec::len).unwrap_or(0),"virtual_server_certificates":snapshot.tables["certificates"].len()});
    if request.stage {
        let _configuration = control.change_gate.lock().await;
        if control.pending_configuration.lock().await.is_some() {
            return Err(api_error(anyhow::anyhow!(
                "confirm or revert the pending configuration before staging a restore"
            )));
        }
        control
            .store
            .stage_restore(&snapshot)
            .await
            .map_err(api_error)?;
        control
            .store
            .record_audit(
                &actor,
                "encrypted backup validated and staged for offline restore",
            )
            .await
            .map_err(api_error)?;
    }
    Ok(Json(
        json!({"valid":true,"staged":request.stage,"summary":summary,
        "message":if request.stage{"Backup staged. Stop RiverLB, run riverlb restore --database <database> --staged --replace, restart, and sign in with a restored account. Sessions and API tokens are revoked. Local backup schedules remain unchanged."}else{"Backup authenticated and validated. Review this summary before staging the restore."}}),
    ))
}
async fn restore(
    State(control): State<Arc<crate::control::Control>>,
    Extension(actor): Extension<String>,
    Json(request): Json<RestoreRequest>,
) -> ApiResult {
    tokio::spawn(restore_inner(control, actor, request))
        .await
        .map_err(|e| api_error(e.into()))?
}
#[derive(Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
struct AuditQuery {
    query: String,
    actor: String,
    offset: u32,
    limit: Option<u32>,
}
async fn audit(
    State(control): State<Arc<crate::control::Control>>,
    Query(query): Query<AuditQuery>,
) -> ApiResult {
    ensure_api(
        query.query.len() <= 256 && query.actor.len() <= 128 && query.offset <= 1000000,
        "invalid audit search bounds",
    )?;
    let limit = query.limit.unwrap_or(50);
    ensure_api((1..=200).contains(&limit), "audit page size must be 1–200")?;
    Ok(Json(
        control
            .store
            .audit_page(&query.query, &query.actor, query.offset, limit)
            .await
            .map_err(api_error)?,
    ))
}
fn ensure_api(valid: bool, message: &str) -> std::result::Result<(), (StatusCode, Json<Value>)> {
    if valid {
        Ok(())
    } else {
        Err(api_error(anyhow::anyhow!("{message}")))
    }
}
fn redacted_support(
    snapshot: &Value,
    configuration: &crate::config::Config,
    audit_count: u64,
) -> Value {
    // A positive allowlist is intentional: arbitrary config strings, scripts, header values,
    // file contents, audit actions, accounts, key material and logs cannot leak into the bundle.
    let servers=snapshot["virtual_servers"].as_array().into_iter().flatten().enumerate().map(|(index,server)|json!({
        "object":format!("virtual-server-{}",index+1),"enabled":server["enabled"],"state":server["state"],"available_members":server["available_members"],"total_members":server["total_members"]})).collect::<Vec<_>>();
    let certificates=snapshot["certificates"].as_array().into_iter().flatten().map(|cert|json!({"store":cert["store"],"days_remaining":cert["days_remaining"],"valid_now":cert["valid_now"],"not_after":cert["not_after"]})).collect::<Vec<_>>();
    let ifaces=snapshot["system"]["interfaces"].as_array().into_iter().flatten().enumerate().map(|(index,iface)|json!({"object":format!("interface-{}",index+1),"state":iface["state"],"mtu":iface["mtu"],"rx_bytes":iface["rx_bytes"],"tx_bytes":iface["tx_bytes"],"rx_errors":iface["rx_errors"],"tx_errors":iface["tx_errors"]})).collect::<Vec<_>>();
    json!({"format":"riverlb-redacted-support-v1","created":snapshot["created"],"version":snapshot["version"],"revision":snapshot["revision"],
        "system":{"cpu_percent":snapshot["cpu_percent"],"memory":snapshot["system"]["memory"],"disk":snapshot["system"]["disk"],"uptime_seconds":snapshot["system"]["uptime_seconds"],"load_average":snapshot["system"]["load_average"],"time_synchronized":snapshot["system"]["time_synchronized"],"kernel":snapshot["system"]["kernel"],"interfaces":ifaces},
        "ha":{"role":snapshot["ha"]["role"],"configuration_sync":snapshot["ha"]["configuration_sync"]},"virtual_servers":servers,"certificates":certificates,
        "configuration_inventory":{"pools":configuration.pools.len(),"nodes":configuration.nodes.len(),"monitors":configuration.health_monitors.len(),"virtual_servers":configuration.virtual_servers.len(),"vlans":configuration.network.vlans.len(),"self_ips":configuration.network.self_ips.len(),"routes":configuration.network.routes.len()},
        "audit_records":audit_count,"redaction":"Only fixed system metrics and object counts are included. Configuration values, addresses, hostnames, logs, audit text, credentials, certificates, private keys, rule text and file contents are excluded."})
}
async fn support_inner(
    control: Arc<crate::control::Control>,
    actor: String,
) -> std::result::Result<Response, (StatusCode, Json<Value>)> {
    let snapshot = health(&control).await.map_err(api_error)?;
    let config = control.generation.lock().await.runtime.config.clone();
    let audit = control
        .store
        .audit_page("", "", 0, 1)
        .await
        .map_err(api_error)?;
    let report = redacted_support(&snapshot, &config, audit["total"].as_u64().unwrap_or(0));
    control
        .store
        .record_audit(&actor, "redacted support bundle downloaded")
        .await
        .map_err(api_error)?;
    Ok((
        [
            ("content-type", "application/json"),
            ("cache-control", "no-store"),
            (
                "content-disposition",
                "attachment; filename=riverlb-support.json",
            ),
        ],
        serde_json::to_vec_pretty(&report).unwrap(),
    )
        .into_response())
}
async fn support(
    State(control): State<Arc<crate::control::Control>>,
    Extension(actor): Extension<String>,
) -> std::result::Result<Response, (StatusCode, Json<Value>)> {
    tokio::spawn(support_inner(control, actor))
        .await
        .map_err(|e| api_error(e.into()))?
}
async fn refresh(State(control): State<Arc<crate::control::Control>>) -> ApiResult {
    tokio::spawn(async move {
        sample(&control, false).await.map_err(api_error)?;
        Ok(Json(control.operations.public().await))
    })
    .await
    .map_err(|e| api_error(e.into()))?
}
async fn run_backup(
    State(control): State<Arc<crate::control::Control>>,
    Extension(actor): Extension<String>,
) -> ApiResult {
    tokio::spawn(async move {
        perform_backup(&control, &actor)
            .await
            .map(Json)
            .map_err(api_error)
    })
    .await
    .map_err(|e| api_error(e.into()))?
}
pub fn router() -> Router<Arc<crate::control::Control>> {
    Router::new()
        .route(
            "/operations.js",
            get(|| async {
                (
                    [("content-type", "text/javascript; charset=utf-8")],
                    include_str!("../web/operations.js"),
                )
            }),
        )
        .route(
            "/api/v1/operations/settings",
            get(
                |State(control): State<Arc<crate::control::Control>>| async move {
                    Json(control.operations.public().await)
                },
            )
            .put(save),
        )
        .route(
            "/api/v1/operations/health",
            get(
                |State(control): State<Arc<crate::control::Control>>| async move {
                    health(&control).await.map(Json).map_err(api_error)
                },
            ),
        )
        .route("/api/v1/operations/alerts/refresh", post(refresh))
        .route("/api/v1/operations/backup/run", post(run_backup))
        .route("/api/v1/operations/backup/download", post(download))
        .route(
            "/api/v1/operations/backup/restore",
            post(restore).layer(axum::extract::DefaultBodyLimit::max(MAX_ENCRYPTED_BYTES)),
        )
        .route("/api/v1/operations/audit", get(audit))
        .route("/api/v1/operations/support", post(support))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn encrypted_snapshot_authenticates_passphrase_payload_and_metadata() {
        let directory = tempfile::tempdir().unwrap();
        let store = crate::storage::Store::open(&directory.path().join("fixture.db"))
            .await
            .unwrap();
        let config = crate::config::Config::load(Path::new("examples/riverlb.toml")).unwrap();
        store.save(&config, 1, "fixture").await.unwrap();
        store
            .set_admin("admin", "fixture-admin-password-123".into())
            .await
            .unwrap();
        let snapshot = store.backup().await.unwrap();
        let password = "backups-are-private-fixture-123";
        let key = new_key(password).unwrap();
        let envelope = Envelope::encrypt(&snapshot, &key).unwrap();
        let encoded = serde_json::to_vec(&envelope).unwrap();
        let decrypted: Envelope = serde_json::from_slice(&encoded).unwrap();
        assert_eq!(decrypted.decrypt(password).unwrap().sha256, snapshot.sha256);
        let wrong: Envelope = serde_json::from_slice(&encoded).unwrap();
        assert!(
            wrong
                .decrypt("incorrect-fixture-passphrase")
                .err()
                .unwrap()
                .to_string()
                .contains("authentication failed")
        );
        let mut altered: Envelope = serde_json::from_slice(&encoded).unwrap();
        altered.created += 1;
        assert!(altered.decrypt(password).is_err());
        let mut altered: Envelope = serde_json::from_slice(&encoded).unwrap();
        let mut payload = BASE64.decode(&altered.ciphertext).unwrap();
        payload[0] ^= 1;
        altered.ciphertext = BASE64.encode(payload);
        assert!(altered.decrypt(password).is_err());
        assert!(
            !String::from_utf8(encoded)
                .unwrap()
                .contains("fixture-admin-password")
        );
        let second = Envelope::encrypt(&snapshot, &key).unwrap();
        assert_ne!(envelope.nonce, second.nonce);
    }

    #[test]
    fn retention_only_removes_owned_files_and_keeps_the_new_file() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().unwrap();
        let unrelated = directory.path().join("riverlb-backup.json");
        std::fs::write(&unrelated, b"operator data").unwrap();
        let similar = directory.path().join("riverlb-1234-not-our-file.rlbenc");
        std::fs::write(&similar, b"operator data").unwrap();
        let linked = directory
            .path()
            .join("riverlb-1111-00000000000000000000000000000000.rlbenc");
        symlink(&unrelated, &linked).unwrap();
        for _ in 0..4 {
            write_backup(directory.path(), b"encrypted", 2).unwrap();
        }
        let newest = write_backup(directory.path(), b"newest encrypted", 1).unwrap();
        assert!(directory.path().join(newest).is_file());
        assert_eq!(std::fs::read(&unrelated).unwrap(), b"operator data");
        assert!(similar.is_file() && linked.is_symlink());
        let files = std::fs::read_dir(directory.path())
            .unwrap()
            .map(|entry| entry.unwrap())
            .filter(|entry| {
                entry.file_type().unwrap().is_file()
                    && owned_backup_name(&entry.file_name().to_string_lossy())
            })
            .collect::<Vec<_>>();
        assert_eq!(files.len(), 1);
        assert_eq!(
            files[0].metadata().unwrap().permissions().mode() & 0o777,
            0o600
        );
    }

    #[test]
    fn private_state_rejects_symlinks_unprotected_files_and_invalid_key() {
        use std::os::unix::fs::{PermissionsExt, symlink};
        let directory = tempfile::tempdir().unwrap();
        let database = directory.path().join("fixture.db");
        let path = database.with_extension("operations.json");
        private_write(&path, b"{}", false).unwrap();
        assert!(Operations::open(&database).is_ok());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        assert!(Operations::open(&database).is_err());
        assert!(private_write(&path, b"{}", true).is_err());
        std::fs::remove_file(&path).unwrap();
        let real = directory.path().join("real.json");
        private_write(&real, b"{}", false).unwrap();
        symlink(&real, &path).unwrap();
        assert!(Operations::open(&database).is_err());
        assert!(private_write(&path, b"{}", true).is_err());
        std::fs::remove_file(&path).unwrap();
        private_write(&path, br#"{"backup_key":{"salt":"","key":""}}"#, false).unwrap();
        assert!(Operations::open(&database).is_err());
    }

    #[test]
    fn mounted_storage_and_webhooks_are_explicit_and_bounded() {
        let mounts = "1 0 8:0 / / rw - ext4 /dev/root rw\n2 1 0:4 / /run rw - tmpfs tmpfs rw\n3 1 0:5 / /mnt/backup\\040store rw - nfs4 server:/backup rw\n";
        assert!(!mounted_destination(
            Path::new("/home/admin/backups"),
            mounts
        ));
        assert!(!mounted_destination(Path::new("/run/backups"), mounts));
        assert!(mounted_destination(
            Path::new("/mnt/backup store/riverlb"),
            mounts
        ));
        assert!(Webhook::parse("https://example.test:8443/alerts?q=riverlb").is_ok());
        for url in [
            "http://example.test/alerts",
            "https://user:pass@example.test/alerts",
            "https://example.test/#fragment",
            "https://example.test/\r\nmalformed",
        ] {
            assert!(Webhook::parse(url).is_err());
        }
        assert!(derive("short", &[0; 16]).is_err());
        assert!(derive("long-enough-fixture-password", &[0; 15]).is_err());
        assert!(syslog_text(&"é".repeat(1000)).len() <= 850);
        assert!(!syslog_text("fixture\r\nforged event").contains('\n'));
    }

    #[test]
    fn alert_transitions_preserve_first_seen_and_report_resolution() {
        let settings = Settings {
            backups: BackupSettings {
                enabled: true,
                ..Default::default()
            },
            ..Default::default()
        };
        let mut state = PrivateState::default();
        let backup = BackupStatus {
            last_error: Some("fixture failed".into()),
            ..Default::default()
        };
        let health = json!({"cpu_percent":99,"system":{"memory":{"used_percent":99},"disk":{"free_percent":1},"time_synchronized":false},
            "certificates":[{"name":"fixture","store":"device","days_remaining":-1}],"virtual_servers":[{"name":"fixture","state":"down"}],
            "pending_configuration":true,"ha":{"role":"fault","sync_error":null}});
        let conditions = alert_conditions(&health, &settings, &backup);
        assert_eq!(conditions.len(), 9);
        let events = update_alerts(&mut state, conditions.clone(), 100);
        assert_eq!(events.len(), 9);
        assert!(update_alerts(&mut state, conditions, 200).is_empty());
        assert!(
            state
                .alerts
                .iter()
                .all(|a| a.first_seen == 100 && a.last_seen == 200)
        );
        let resolved = update_alerts(&mut state, Vec::new(), 300);
        assert_eq!(resolved.len(), 9);
        assert!(resolved.iter().all(|event| event["event"] == "resolved"));
        let disabled = Settings {
            alerts: AlertSettings {
                enabled: false,
                ..Default::default()
            },
            ..Default::default()
        };
        assert!(alert_conditions(&health, &disabled, &backup).is_empty());
    }

    #[test]
    fn support_bundle_uses_an_allowlist_for_all_operator_strings() {
        let mut config = crate::config::Config::load(Path::new("examples/riverlb.toml")).unwrap();
        config.virtual_servers[0].name = "secret-name-do-not-export".into();
        let snapshot = json!({"created":100,"version":"fixture","revision":1,"cpu_percent":12,"system":{"kernel":"test","interfaces":[{"name":"secret-interface","state":"up","mtu":1500}]},
            "ha":{"role":"active","configuration_sync":"synced","sync_error":"secret-token-in-error"},
            "virtual_servers":[{"name":"secret-virtual-server","enabled":true,"state":"up","available_members":1,"total_members":2}],
            "certificates":[{"name":"secret-cert-name","store":"device","days_remaining":100,"not_after":1000000,"private_key":"secret-private-key"}],
            "logs":"secret-credentials", "audit":[{"actor":"secret-user","action":"secret-password"}]});
        let result = redacted_support(&snapshot, &config, 7).to_string();
        assert!(!result.contains("secret-"));
        assert!(
            result.contains("virtual-server-1")
                && result.contains("interface-1")
                && result.contains("1500")
        );
        assert_eq!(redacted_support(&snapshot, &config, 7)["audit_records"], 7);
    }

    #[tokio::test]
    async fn audit_search_pagination_and_forwarding_use_stable_ids() {
        let directory = tempfile::tempdir().unwrap();
        let store = crate::storage::Store::open(&directory.path().join("fixture.db"))
            .await
            .unwrap();
        store
            .record_audit("alice", "first config updated")
            .await
            .unwrap();
        store
            .record_audit("bob", "second configuration updated")
            .await
            .unwrap();
        store
            .record_audit("alice", "third account created")
            .await
            .unwrap();
        let first = store.audit_page("config", "", 0, 1).await.unwrap();
        assert_eq!(first["total"], 2);
        assert_eq!(first["entries"][0]["actor"], "bob");
        let second = store.audit_page("config", "", 1, 1).await.unwrap();
        assert_eq!(second["entries"][0]["actor"], "alice");
        assert_eq!(
            store.audit_page("", "alice", 0, 10).await.unwrap()["total"],
            2
        );
        assert_eq!(
            store.audit_page("' OR 1=1 --", "", 0, 10).await.unwrap()["total"],
            0
        );
        let rows = store.audit_since(0, 2).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0]["actor"], "alice");
        let next = store
            .audit_since(rows[1]["id"].as_i64().unwrap(), 2)
            .await
            .unwrap();
        assert_eq!(next.len(), 1);
        assert_eq!(next[0]["action"], "third account created");
        assert!(store.audit_page("", "", 0, 201).await.is_err());
        assert!(store.prune_audit(0, 1000).await.is_err());
    }
}
