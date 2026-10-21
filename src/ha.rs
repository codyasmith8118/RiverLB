//! Pacemaker-controlled data-plane ownership and private peer replication.
use crate::{config::Config, control::Control, network::Network};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    path::{Path, PathBuf},
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, Ordering},
    },
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
pub const MAX_BYTES: usize = 32 * 1024 * 1024;
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default = "automatic_sync")]
    pub automatic_sync: bool,
    pub cluster_id: String,
    pub node_id: String,
    pub peer_id: String,
    pub socket: PathBuf,
    pub state_file: PathBuf,
    pub authority: PathBuf,
    pub floating_self_ips: Vec<String>,
    pub ssh_target: String,
    #[serde(default = "ssh_port")]
    pub ssh_port: u16,
    #[serde(default = "ssh_program")]
    pub ssh_program: PathBuf,
    pub ssh_identity: PathBuf,
    pub ssh_known_hosts: PathBuf,
    pub peer_socket: PathBuf,
    pub peer_binary: PathBuf,
    #[serde(default = "sync_interval")]
    pub sync_interval_secs: u64,
    #[serde(default = "sync_age")]
    pub max_sync_age_secs: u64,
}
fn automatic_sync() -> bool {
    true
}
fn ssh_program() -> PathBuf {
    PathBuf::from("/usr/bin/ssh")
}
fn ssh_port() -> u16 {
    22
}
fn sync_interval() -> u64 {
    2
}
fn sync_age() -> u64 {
    300
}
fn identifier(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}
impl Settings {
    pub fn load(path: &Path) -> Result<Self> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = std::fs::metadata(path)?;
        ensure!(
            metadata.uid() == 0 && metadata.permissions().mode() & 0o077 == 0,
            "HA settings must have private permissions (0600)"
        );
        let settings: Self = serde_json::from_slice(&std::fs::read(path)?)?;
        for path in [&settings.socket, &settings.state_file] {
            let directory = std::fs::metadata(path.parent().context("HA directory missing")?)?;
            ensure!(
                directory.is_dir()
                    && directory.uid() == 0
                    && directory.permissions().mode() & 0o022 == 0,
                "HA directories must be root-owned and not writable by other users"
            );
        }
        settings.validate()?;
        Ok(settings)
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(self.ssh_port != 0, "Invalid HA SSH port");
        ensure!(
            identifier(&self.cluster_id)
                && identifier(&self.node_id)
                && identifier(&self.peer_id)
                && self.node_id != self.peer_id,
            "invalid HA cluster/node identity"
        );
        ensure!(
            (1..=60).contains(&self.sync_interval_secs)
                && self.max_sync_age_secs >= self.sync_interval_secs * 3
                && self.max_sync_age_secs <= 3600,
            "invalid HA synchronization timing"
        );
        ensure!(
            !self.ssh_target.starts_with('-')
                && self
                    .ssh_target
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"@_.:-[]".contains(&c))
                && !self.ssh_target.is_empty(),
            "invalid HA SSH target"
        );
        for p in [
            &self.socket,
            &self.state_file,
            &self.authority,
            &self.ssh_identity,
            &self.ssh_program,
            &self.ssh_known_hosts,
            &self.peer_socket,
            &self.peer_binary,
        ] {
            ensure!(
                p.is_absolute()
                    && p.to_str().is_some_and(|s| s
                        .bytes()
                        .all(|c| c.is_ascii_alphanumeric() || b"/_-.".contains(&c))),
                "HA paths must be absolute safe paths"
            );
        }
        let mut names = std::collections::HashSet::new();
        ensure!(
            self.floating_self_ips
                .iter()
                .all(|s| identifier(s) && names.insert(s)),
            "duplicate or invalid floating self IP name"
        );
        Ok(())
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Certificate {
    pub name: String,
    pub certificate: String,
    pub private_key: String,
}
#[derive(Clone, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct Material {
    pub requests: Vec<(String, String, String, Vec<String>, i64)>,
    pub renewals: Vec<crate::acme::Job>,
    pub accounts: Vec<(String, String)>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Bundle {
    pub format: u32,
    pub cluster_id: String,
    pub source_id: String,
    pub created: i64,
    pub revision: u64,
    pub floating_self_ips: Vec<String>,
    pub config: Config,
    pub certificates: Vec<Certificate>,
    pub persistence: Vec<crate::runtime::PersistenceReplica>,
    pub material: Material,
}
impl Bundle {
    pub fn fingerprint(&self) -> Result<String> {
        use sha2::{Digest, Sha256};
        let mut config = self.config.clone();
        config.management = "127.0.0.1:1".parse()?;
        config.management_protocol = None;
        config.management_tls = None;
        config.management_certificate = None;
        for vlan in &mut config.network.vlans {
            vlan.interface.clear();
        }
        config
            .network
            .self_ips
            .retain(|ip| self.floating_self_ips.contains(&ip.name));
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&(
                config,
                &self.certificates,
                &self.material
            ))?)
        ))
    }
    pub fn overlay(&self, local: &Config) -> Config {
        let mut config = self.config.clone();
        config.management = local.management;
        config.management_protocol = local.management_protocol;
        config.management_tls = local.management_tls.clone();
        config.management_certificate = local.management_certificate.clone();
        config
            .network
            .self_ips
            .retain(|ip| self.floating_self_ips.contains(&ip.name));
        config.network.self_ips.extend(
            local
                .network
                .self_ips
                .iter()
                .filter(|ip| !self.floating_self_ips.contains(&ip.name))
                .cloned(),
        );
        for vlan in &mut config.network.vlans {
            if let Some(local) = local.network.vlans.iter().find(|v| v.name == vlan.name) {
                vlan.interface = local.interface.clone();
            }
        }
        config
    }
}
#[derive(Default, Clone, Deserialize, Serialize)]
pub struct Status {
    pub role: String,
    pub peer_revision: Option<u64>,
    pub last_received: Option<i64>,
    #[serde(default)]
    pub checkpoint_time: Option<i64>,
    #[serde(default)]
    pub last_source_time: Option<i64>,
    pub last_sent: Option<i64>,
    pub sync_error: Option<String>,
    pub fingerprint: Option<String>,
    pub seed: bool,
    #[serde(default)]
    pub activated_at: Option<i64>,
}
#[derive(Serialize, Deserialize)]
struct Checkpoint {
    cluster_id: String,
    node_id: String,
    status: Status,
    persistence: Vec<crate::runtime::PersistenceReplica>,
}
#[derive(Serialize, Deserialize)]
struct OwnershipJournal {
    cluster_id: String,
    node_id: String,
    configurations: Vec<(Config, Vec<String>)>,
    firewall: crate::firewall::Rules,
}
pub(crate) fn private_write(path: &Path, value: &impl Serialize) -> Result<()> {
    use std::io::Write;
    use std::os::unix::fs::OpenOptionsExt;
    let temporary = path.with_extension(format!("{:032x}.new", rand::random::<u128>()));
    let mut file = std::fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&temporary)?;
    let result = (|| {
        file.write_all(&serde_json::to_vec(value)?)?;
        file.sync_all()?;
        std::fs::rename(&temporary, path)?;
        std::fs::File::open(path.parent().context("HA state parent missing")?)?.sync_all()?;
        anyhow::Ok(())
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}
pub struct State {
    pub settings: Settings,
    pub automatic_sync: AtomicBool,
    sync: tokio::sync::Mutex<()>,
    pub active: AtomicBool,
    pub status: Mutex<Status>,
    pub sessions: Mutex<tokio_util::sync::CancellationToken>,
    pub persistence: Mutex<Vec<crate::runtime::PersistenceReplica>>,
}
impl State {
    pub fn new(settings: Settings) -> Result<Arc<Self>> {
        let checkpoint = if settings.state_file.exists() {
            use std::os::unix::fs::{MetadataExt, PermissionsExt};
            let metadata = std::fs::metadata(&settings.state_file)?;
            ensure!(
                metadata.uid() == 0 && metadata.permissions().mode() & 0o077 == 0,
                "HA checkpoint must be root-owned and private"
            );
            serde_json::from_slice::<Checkpoint>(&std::fs::read(&settings.state_file)?)?
        } else {
            Checkpoint {
                cluster_id: settings.cluster_id.clone(),
                node_id: settings.node_id.clone(),
                status: Status::default(),
                persistence: vec![],
            }
        };
        ensure!(
            checkpoint.cluster_id == settings.cluster_id && checkpoint.node_id == settings.node_id,
            "HA checkpoint belongs to a different node"
        );
        let mut status = checkpoint.status;
        status.role = "standby".into();
        status.seed = false;
        Ok(Arc::new(Self {
            automatic_sync: AtomicBool::new(settings.automatic_sync),
            sync: tokio::sync::Mutex::new(()),
            settings,
            active: AtomicBool::new(false),
            persistence: Mutex::new(checkpoint.persistence),
            status: Mutex::new(status),
            sessions: Mutex::new(tokio_util::sync::CancellationToken::new()),
        }))
    }
    pub fn record_ownership(
        &self,
        configurations: Vec<Config>,
        firewall: crate::firewall::Rules,
    ) -> Result<()> {
        let journal = OwnershipJournal {
            cluster_id: self.settings.cluster_id.clone(),
            node_id: self.settings.node_id.clone(),
            configurations: configurations
                .into_iter()
                .map(|c| (c, self.settings.floating_self_ips.clone()))
                .collect(),
            firewall,
        };
        private_write(
            &self.settings.state_file.with_extension("ownership.json"),
            &journal,
        )
    }
    pub fn recovery_steps(&self, manage_firewall: bool) -> Result<Vec<crate::network::Step>> {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let path = self.settings.state_file.with_extension("ownership.json");
        if !path.exists() {
            return Ok(vec![]);
        }
        let metadata = std::fs::metadata(&path)?;
        ensure!(
            metadata.uid() == 0 && metadata.permissions().mode() & 0o077 == 0,
            "HA ownership journal must be private and root-owned"
        );
        let journal: OwnershipJournal = serde_json::from_slice(&std::fs::read(&path)?)?;
        ensure!(
            journal.cluster_id == self.settings.cluster_id
                && journal.node_id == self.settings.node_id,
            "HA journal belongs to a different node"
        );
        let mut steps = Vec::new();
        for (config, names) in journal.configurations {
            config.network.validate()?;
            let full = crate::network::provisioned(&config)?;
            let mut standby = config.clone();
            for vs in &mut standby.virtual_servers {
                vs.enabled = false;
            }
            standby
                .network
                .self_ips
                .retain(|ip| !names.contains(&ip.name));
            // Historical ownership only authorizes withdrawal. Never install
            // retained policies or gateways from an obsolete configuration.
            // The startup caller provisions the current standby target next.
            steps.extend(
                crate::network::plan(&full, &crate::network::provisioned(&standby)?)?
                    .into_iter()
                    .filter(|step| match step.command.as_slice() {
                        [object, operation, ..] if object == "address" => operation == "del",
                        [family, object, operation, ..]
                            if matches!(family.as_str(), "-4" | "-6")
                                && matches!(object.as_str(), "route" | "rule") =>
                        {
                            operation == "del"
                        }
                        _ => false,
                    }),
            );
        }
        if manage_firewall {
            steps.extend(crate::firewall::plan(
                &journal.firewall,
                &Default::default(),
            ));
        }
        Ok(steps)
    }
    pub fn status(&self) -> Status {
        self.status.lock().unwrap().clone()
    }
    pub fn save(&self) -> Result<()> {
        use std::io::Write;
        use std::os::unix::fs::OpenOptionsExt;
        let path = &self.settings.state_file;
        let temporary = path.with_extension(format!("{:032x}.new", rand::random::<u128>()));
        let mut file = std::fs::OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&temporary)
            .context("create HA checkpoint")?;
        let result = (|| {
            file.write_all(&serde_json::to_vec(&Checkpoint {
                cluster_id: self.settings.cluster_id.clone(),
                node_id: self.settings.node_id.clone(),
                status: self.status(),
                persistence: self.persistence.lock().unwrap().clone(),
            })?)?;
            file.sync_all()?;
            std::fs::rename(&temporary, path)?;
            std::fs::File::open(path.parent().context("HA state parent")?)?.sync_all()?;
            anyhow::Ok(())
        })();
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }
}
pub fn effective(config: &Config, state: Option<&State>, active: bool) -> Config {
    let mut effective = config.clone();
    if let Some(state) = state
        && !active
    {
        for server in &mut effective.virtual_servers {
            server.enabled = false;
        }
        effective
            .network
            .self_ips
            .retain(|ip| !state.settings.floating_self_ips.contains(&ip.name));
    }
    effective
}
pub fn network(config: &Config, state: Option<&State>, active: bool) -> Result<Network> {
    crate::network::provisioned(&effective(config, state, active))
}
#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Request {
    pub action: String,
    #[serde(default)]
    pub bundle: Option<Bundle>,
}
#[derive(Deserialize)]
struct Authority {
    quorate: bool,
    fencing: bool,
    owner: Option<String>,
}
pub async fn authority(state: &State) -> Result<Option<String>> {
    let output = tokio::time::timeout(
        std::time::Duration::from_secs(5),
        tokio::process::Command::new(&state.settings.authority)
            .kill_on_drop(true)
            .output(),
    )
    .await??;
    ensure!(
        output.status.success(),
        "HA ownership authority unavailable"
    );
    let result: Authority = serde_json::from_slice(&output.stdout)?;
    ensure!(
        result.quorate && result.fencing,
        "HA activation requires quorum and configured fencing"
    );
    Ok(result.owner)
}
pub async fn call(path: &Path, request: &Request) -> Result<serde_json::Value> {
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let mut stream = tokio::net::UnixStream::connect(path).await?;
        let bytes = serde_json::to_vec(request)?;
        ensure!(bytes.len() <= MAX_BYTES, "HA payload too large");
        stream.write_all(&bytes).await?;
        stream.shutdown().await?;
        let mut bytes = Vec::new();
        stream
            .take((MAX_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .await?;
        ensure!(bytes.len() <= MAX_BYTES, "HA response too large");
        let value: serde_json::Value = serde_json::from_slice(&bytes)?;
        ensure!(
            value["ok"] == true,
            "{}",
            value["error"].as_str().unwrap_or("HA operation failed")
        );
        Ok(value["result"].clone())
    })
    .await?
}
pub async fn start(control: Arc<Control>) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let state = control.ha.as_ref().context("HA disabled")?;
    let path = &state.settings.socket;
    if path.exists() {
        ensure!(
            tokio::net::UnixStream::connect(path).await.is_err(),
            "HA socket already in use"
        );
        std::fs::remove_file(path)?;
    }
    let listener = tokio::net::UnixListener::bind(path)?;
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    let acceptor = control.clone();
    tokio::spawn(async move {
        loop {
            let accepted = tokio::select! {_=acceptor.stop.cancelled()=>break,result=listener.accept()=>result};
            let Ok((stream, _)) = accepted else {
                acceptor.stop.cancel();
                break;
            };
            let Ok(credentials) = stream.peer_cred() else {
                continue;
            };
            if credentials.uid() != 0 {
                continue;
            }
            let control = acceptor.clone();
            tokio::spawn(async move {
                let mut stream = stream;
                let operation = async {
                    let mut bytes = Vec::new();
                    (&mut stream)
                        .take((MAX_BYTES + 1) as u64)
                        .read_to_end(&mut bytes)
                        .await?;
                    ensure!(bytes.len() <= MAX_BYTES, "HA request too large");
                    let request: Request = serde_json::from_slice(&bytes)?;
                    tokio::spawn(dispatch(control, request)).await?
                };
                let result =
                    tokio::time::timeout(std::time::Duration::from_secs(55), operation).await;
                let value = match result {
                    Ok(Ok(result)) => serde_json::json!({"ok":true,"result":result}),
                    Ok(Err(error)) => serde_json::json!({"ok":false,"error":error.to_string()}),
                    Err(_) => serde_json::json!({"ok":false,"error":"HA operation timed out"}),
                };
                if let Ok(bytes) = serde_json::to_vec(&value) {
                    let _ = stream.write_all(&bytes).await;
                }
            });
        }
    });
    let watcher = control.clone();
    tokio::spawn(async move {
        let state = watcher.ha.as_ref().unwrap();
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(2));
        loop {
            tokio::select! {_=watcher.stop.cancelled()=>break,_=timer.tick()=>{}}
            // Manual configuration sync does not relax traffic ownership checks.
            if !state.active.load(Ordering::SeqCst) {
                continue;
            }
            let valid = match authority(state).await {
                Ok(Some(owner)) => owner == state.settings.node_id,
                Ok(None) => state
                    .status()
                    .activated_at
                    .is_some_and(|t| crate::storage::now() - t < 15),
                Err(_) => false,
            };
            if !valid {
                tracing::error!("HA authority lost; withdrawing traffic ownership");
                if let Err(error) = watcher.set_ha_active(false).await {
                    tracing::error!(%error,"HA withdrawal failed; cluster fencing required");
                    watcher.stop.cancel();
                }
            }
        }
    });
    let syncer = control.clone();
    tokio::spawn(async move {
        let state = syncer.ha.as_ref().unwrap();
        let mut timer = tokio::time::interval(std::time::Duration::from_secs(
            state.settings.sync_interval_secs,
        ));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {_=syncer.stop.cancelled()=>break,_=timer.tick()=>{}}
            if !state.active.load(Ordering::SeqCst) {
                continue;
            }
            if !state.automatic_sync.load(Ordering::SeqCst)
                && !state
                    .settings
                    .state_file
                    .with_extension("synced.json")
                    .exists()
            {
                continue;
            }
            let result = send_inner(&syncer, true).await;
            let mut status = state.status.lock().unwrap();
            match result {
                Ok(()) => {
                    status.last_sent = Some(crate::storage::now());
                    status.sync_error = None
                }
                Err(e) => {
                    status.sync_error = Some(e.to_string());
                    tracing::warn!(error=%e,"HA synchronization failed");
                }
            }
        }
    });
    Ok(())
}
async fn dispatch(control: Arc<Control>, request: Request) -> Result<serde_json::Value> {
    let state = control.ha.as_ref().context("HA disabled")?;
    match request.action.as_str() {
        "status" => Ok(control.ha_status().await),
        "seed" => {
            ensure!(
                !state.active.load(Ordering::SeqCst),
                "seed requires standby"
            );
            let generation = control.generation.lock().await;
            generation.runtime.config.validate()?;
            state.status.lock().unwrap().seed = true;
            control
                .store
                .record_audit("local HA controller", "HA initial seed authorized")
                .await?;
            Ok(serde_json::json!({"seeded":true}))
        }
        "activate" => {
            control.set_ha_active(true).await?;
            Ok(serde_json::to_value(state.status())?)
        }
        "deactivate" => {
            control.set_ha_active(false).await?;
            Ok(serde_json::to_value(state.status())?)
        }
        "export" => Ok(serde_json::to_value(export(&control).await?)?),
        "receive" => {
            let bundle = request.bundle.context("missing synchronization bundle")?;
            receive(&control, bundle).await?;
            Ok(serde_json::to_value(state.status())?)
        }
        "sync" => {
            send(&control).await?;
            Ok(serde_json::json!({"synchronized":true}))
        }
        _ => anyhow::bail!("unknown HA action"),
    }
}
pub async fn export(control: &Control) -> Result<Bundle> {
    let _gate = control.change_gate.lock().await;
    ensure!(
        control.pending_configuration.lock().await.is_none(),
        "Confirm the pending configuration before HA synchronization or failover"
    );
    let state = control.ha.as_ref().context("HA disabled")?;
    let generation = control.generation.lock().await;
    ensure!(
        state.active.load(Ordering::SeqCst),
        "only active owner may export"
    );
    Ok(Bundle {
        format: 1,
        cluster_id: state.settings.cluster_id.clone(),
        source_id: state.settings.node_id.clone(),
        created: crate::storage::now(),
        revision: generation.revision,
        floating_self_ips: state.settings.floating_self_ips.clone(),
        config: generation.runtime.config.clone(),
        certificates: control.store.ha_certificates().await?,
        material: control.store.ha_material().await?,
        persistence: generation
            .runtime
            .pools
            .iter()
            .map(|p| p.export_persistence())
            .collect::<Result<Vec<_>>>()?,
    })
}
async fn receive(control: &Arc<Control>, bundle: Bundle) -> Result<()> {
    let state = control.ha.as_ref().context("HA disabled")?;
    ensure!(
        bundle.format == 1
            && bundle.cluster_id == state.settings.cluster_id
            && bundle.source_id == state.settings.peer_id,
        "HA synchronization identity mismatch"
    );
    ensure!(
        bundle.floating_self_ips == state.settings.floating_self_ips,
        "HA floating self IP definitions differ"
    );
    let now = crate::storage::now();
    ensure!(
        bundle.created <= now + 5
            && now - bundle.created <= state.settings.max_sync_age_secs as i64,
        "expired or future HA synchronization bundle"
    );
    ensure!(
        authority(state).await? == Some(bundle.source_id.clone()),
        "peer is not confirmed active owner"
    );
    control.receive_ha_bundle(bundle).await
}
pub(crate) async fn send(control: &Control) -> Result<()> {
    send_inner(control, false).await
}
async fn send_inner(control: &Control, periodic: bool) -> Result<()> {
    use std::process::Stdio;
    let state = control.ha.as_ref().context("HA disabled")?;
    let _sync = state.sync.lock().await;
    let mut bundle = export(control).await?;
    if periodic && !state.automatic_sync.load(Ordering::SeqCst) {
        let path = state.settings.state_file.with_extension("synced.json");
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata = std::fs::metadata(&path)?;
        ensure!(
            metadata.uid() == 0 && metadata.permissions().mode() & 0o077 == 0,
            "HA synchronized snapshot must be root-owned and private"
        );
        let mut previous: Bundle = serde_json::from_slice(&std::fs::read(path)?)?;
        ensure!(
            previous.cluster_id == bundle.cluster_id && previous.source_id == bundle.source_id,
            "Synchronized snapshot belongs to another appliance"
        );
        if previous.fingerprint()? != bundle.fingerprint()? {
            // Refresh the last committed peer configuration without leaking pending edits.
            previous.created = bundle.created;
            bundle = previous;
        }
    }
    let bytes = serde_json::to_vec(&bundle)?;
    ensure!(
        bytes.len() <= MAX_BYTES,
        "HA synchronization exceeds 32 MiB"
    );
    let settings = &state.settings;
    let remote = format!(
        "{} ha --socket {} receive",
        settings.peer_binary.display(),
        settings.peer_socket.display()
    );
    tokio::time::timeout(std::time::Duration::from_secs(60), async {
        let mut child = tokio::process::Command::new(&settings.ssh_program)
            .kill_on_drop(true)
            .args([
                "-F",
                "/dev/null",
                "-o",
                "BatchMode=yes",
                "-o",
                "StrictHostKeyChecking=yes",
                "-o",
                "ConnectTimeout=5",
                "-o",
                "ServerAliveInterval=5",
                "-o",
                "ServerAliveCountMax=2",
                "-o",
            ])
            .arg(format!(
                "UserKnownHostsFile={}",
                settings.ssh_known_hosts.display()
            ))
            .arg("-i")
            .arg(&settings.ssh_identity)
            .arg("-p")
            .arg(settings.ssh_port.to_string())
            .arg("--")
            .arg(&settings.ssh_target)
            .arg(remote)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?;
        child
            .stdin
            .take()
            .context("SSH stdin")?
            .write_all(&bytes)
            .await?;
        let output = child.wait_with_output().await?;
        ensure!(
            output.status.success(),
            "peer synchronization rejected or SSH failed"
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout)?;
        ensure!(
            result["role"] == "standby",
            "peer did not acknowledge standby state"
        );
        anyhow::Ok(())
    })
    .await??;
    if state.active.load(Ordering::SeqCst) {
        {
            let mut status = state.status.lock().unwrap();
            status.last_sent = Some(crate::storage::now());
            status.checkpoint_time = status.last_sent;
            status.fingerprint = Some(bundle.fingerprint()?);
            status.sync_error = None;
        }
        *state.persistence.lock().unwrap() = bundle.persistence.clone();
        private_write(
            &state.settings.state_file.with_extension("synced.json"),
            &bundle,
        )?;
        state.save()?;
    }
    Ok(())
}
