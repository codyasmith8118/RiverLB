//! Device-local NetworkManager settings, protected by NM's independent rollback timer.
use crate::control::Control;
use anyhow::{Context, Result, bail, ensure};
use axum::{
    Extension, Json, Router,
    extract::{Path, State},
    http::StatusCode,
    routing::{get, post},
};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{
    net::IpAddr,
    sync::Arc,
    time::{Duration, Instant},
};

const NM: &str = "org.freedesktop.NetworkManager";
const NM_PATH: &str = "/org/freedesktop/NetworkManager";
const SECONDS: u64 = 90;
static PENDING: tokio::sync::Mutex<Option<Pending>> = tokio::sync::Mutex::const_new(None);

struct Pending {
    checkpoint: String,
    token: String,
    ifname: String,
    deadline: Instant,
    save: Option<(String, bool)>,
    ready: bool,
    disabled: bool,
}
#[derive(Clone, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Method {
    #[default]
    Disabled,
    Manual,
    Auto,
}
impl Method {
    fn name(&self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::Manual => "manual",
            Self::Auto => "auto",
        }
    }
}
#[derive(Clone, Debug, Default, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct Family {
    method: Method,
    addresses: Vec<String>,
    gateway: Option<IpAddr>,
    dns: Vec<IpAddr>,
    default_route: bool,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    ifname: String,
    uuid: Option<String>,
    autoconnect: bool,
    mtu: u32,
    route_metric: u32,
    ipv4: Family,
    ipv6: Family,
    #[serde(default)]
    activate_only: bool,
    #[serde(default)]
    disable: bool,
}
fn safe_interface(name: &str) -> bool {
    name != "lo"
        && !name.is_empty()
        && name.len() <= 15
        && !name.starts_with('-')
        && name != "."
        && name != ".."
        && name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
}
fn uuid(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(i, b)| {
            if [8, 13, 18, 23].contains(&i) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}
impl Settings {
    fn validate(&self) -> Result<()> {
        ensure!(
            !(self.disable && self.activate_only),
            "Choose enable or disable, not both"
        );
        ensure!(
            !self.disable || self.uuid.is_some(),
            "Configure this interface before disabling its connection"
        );
        ensure!(
            safe_interface(&self.ifname),
            "Invalid Ethernet interface name"
        );
        ensure!(
            self.uuid.as_deref().is_none_or(uuid),
            "Invalid connection identifier"
        );
        ensure!((1280..=9216).contains(&self.mtu), "MTU must be 1280–9216");
        ensure!(
            (1..=65535).contains(&self.route_metric),
            "Route metric must be 1–65535"
        );
        for (family, v4) in [(&self.ipv4, true), (&self.ipv6, false)] {
            ensure!(
                family.addresses.len() <= 16 && family.dns.len() <= 8,
                "Too many addresses or DNS servers"
            );
            ensure!(
                family.method != Method::Manual || !family.addresses.is_empty(),
                "Static addressing requires an address and prefix"
            );
            ensure!(
                family.method == Method::Manual || family.addresses.is_empty(),
                "Static addresses require Manual addressing"
            );
            ensure!(
                family.method != Method::Disabled
                    || (family.gateway.is_none() && family.dns.is_empty() && !family.default_route),
                "Disabled addressing cannot have a gateway, DNS or default route"
            );
            ensure!(
                family.gateway.is_none() || family.default_route,
                "Enable default routing to set a gateway; use Static Routes for other routes"
            );
            let valid = |ip: IpAddr| {
                ip.is_ipv4() == v4
                    && !ip.is_unspecified()
                    && !ip.is_multicast()
                    && !ip.is_loopback()
            };
            for address in &family.addresses {
                let (ip, _) = crate::network::cidr(address)?;
                ensure!(
                    valid(ip),
                    "Address must be unicast and in the selected IP family"
                );
            }
            for ip in family.dns.iter().copied().chain(family.gateway) {
                ensure!(
                    valid(ip),
                    "Gateway and DNS must be unicast and in the selected IP family"
                );
            }
        }
        Ok(())
    }
    fn properties(&self) -> Vec<String> {
        let mut args = vec![
            "connection.interface-name".into(),
            self.ifname.clone(),
            "connection.autoconnect".into(),
            yes(self.autoconnect).into(),
            "802-3-ethernet.mtu".into(),
            self.mtu.to_string(),
        ];
        for (prefix, family) in [("ipv4", &self.ipv4), ("ipv6", &self.ipv6)] {
            for (key, value) in [
                ("method", family.method.name().to_string()),
                ("addresses", family.addresses.join(",")),
                (
                    "gateway",
                    family.gateway.map(|ip| ip.to_string()).unwrap_or_default(),
                ),
                (
                    "dns",
                    family
                        .dns
                        .iter()
                        .map(ToString::to_string)
                        .collect::<Vec<_>>()
                        .join(","),
                ),
                ("never-default", yes(!family.default_route).into()),
                ("ignore-auto-dns", yes(!family.default_route).into()),
                ("route-metric", self.route_metric.to_string()),
            ] {
                args.push(format!("{prefix}.{key}"));
                args.push(value);
            }
        }
        args
    }
}
fn keep_management(settings: &Settings, before: &Settings, management: IpAddr) -> Result<()> {
    let (new, old) = if management.is_ipv4() {
        (&settings.ipv4, &before.ipv4)
    } else {
        (&settings.ipv6, &before.ipv6)
    };
    ensure!(
        (new.method == Method::Auto && old.method == Method::Auto)
            || (new.method == Method::Manual
                && new
                    .addresses
                    .iter()
                    .any(|a| crate::network::cidr(a).is_ok_and(|(ip, _)| ip == management))),
        "Keep the current management IP in this profile. To migrate it, add the new IP alongside it, change the management binding/certificate in Settings, then remove the old IP"
    );
    ensure!(
        settings.autoconnect,
        "The management connection must reconnect on boot"
    );
    Ok(())
}
fn yes(value: bool) -> &'static str {
    if value { "yes" } else { "no" }
}

#[derive(Clone)]
struct Backend {
    nmcli: std::path::PathBuf,
    busctl: std::path::PathBuf,
    ip: std::path::PathBuf,
}
impl Default for Backend {
    fn default() -> Self {
        Self {
            nmcli: "/usr/bin/nmcli".into(),
            busctl: "/usr/bin/busctl".into(),
            ip: "/usr/sbin/ip".into(),
        }
    }
}
impl Backend {
    async fn run(&self, program: &std::path::Path, args: &[String]) -> Result<String> {
        let result = tokio::time::timeout(
            Duration::from_secs(25),
            tokio::process::Command::new(program)
                .env("LC_ALL", "C")
                .env("LANG", "C")
                .args(args)
                .kill_on_drop(true)
                .output(),
        )
        .await
        .context("NetworkManager operation timed out")??;
        ensure!(
            result.status.success(),
            "NetworkManager: {}",
            String::from_utf8_lossy(&result.stderr).trim()
        );
        Ok(String::from_utf8(result.stdout)?.trim_end().to_string())
    }
    async fn nm(&self, args: &[&str]) -> Result<String> {
        let args = [
            vec!["--wait".into(), "15".into(), "--escape".into(), "no".into()],
            args.iter().map(|s| s.to_string()).collect(),
        ]
        .concat();
        self.run(&self.nmcli, &args)
            .await
            .context("Interface editing requires NetworkManager and administrator privileges")
    }
    async fn call(&self, method: &str, args: &[&str]) -> Result<Value> {
        let args = [
            vec![
                "--system".into(),
                "--timeout=3s".into(),
                "--json=short".into(),
                "call".into(),
                NM.into(),
                NM_PATH.into(),
                NM.into(),
                method.into(),
            ],
            args.iter().map(|s| s.to_string()).collect(),
        ]
        .concat();
        let text = self.run(&self.busctl, &args).await?;
        if text.is_empty() {
            Ok(Value::Null)
        } else {
            Ok(serde_json::from_str(&text)?)
        }
    }
    async fn profile(&self, ifname: &str) -> Result<Option<String>> {
        ensure!(safe_interface(ifname), "Invalid Ethernet interface name");
        let text = self
            .nm(&[
                "-g",
                "GENERAL.TYPE,GENERAL.CON-UUID",
                "device",
                "show",
                ifname,
            ])
            .await?;
        let mut lines = text.lines();
        ensure!(
            lines.next() == Some("ethernet"),
            "Only Ethernet adapters can be edited here; configure VLANs on the VLAN page"
        );
        if let Some(id) = lines.next().filter(|id| uuid(id)) {
            return Ok(Some(id.to_string()));
        }
        // Prefer an existing saved profile on a disconnected adapter; don't
        // create a competing profile each time the adapter is edited.
        let all = self.nm(&["-g", "UUID", "connection", "show"]).await?;
        ensure!(
            all.lines().count() <= 64,
            "Too many saved profiles; reconcile unused NetworkManager connections first"
        );
        let mut matches = vec![];
        for id in all.lines().filter(|id| uuid(id)) {
            let bound = self
                .nm(&[
                    "-g",
                    "connection.interface-name",
                    "connection",
                    "show",
                    "uuid",
                    id,
                ])
                .await?;
            if bound == ifname {
                matches.push(id.to_string());
            }
        }
        ensure!(
            matches.len() <= 1,
            "Multiple saved profiles use this interface; select one from the console first"
        );
        Ok(matches.pop())
    }
    async fn read(&self, ifname: &str) -> Result<Settings> {
        let id = self.profile(ifname).await?;
        let mut settings = Settings {
            ifname: ifname.into(),
            uuid: id.clone(),
            autoconnect: true,
            mtu: 1500,
            route_metric: 600,
            ipv4: Family::default(),
            ipv6: Family::default(),
            activate_only: false,
            disable: false,
        };
        let Some(id) = id else { return Ok(settings) };
        let fields = "connection.type,connection.controller,connection.autoconnect,802-3-ethernet.mtu,ipv4.route-metric,ipv4.method,ipv4.addresses,ipv4.gateway,ipv4.dns,ipv4.never-default,ipv6.method,ipv6.addresses,ipv6.gateway,ipv6.dns,ipv6.never-default";
        let text = self
            .nm(&["-g", fields, "connection", "show", "uuid", &id])
            .await?;
        let rows = text.split('\n').collect::<Vec<_>>();
        ensure!(rows.len() == 15, "Unexpected NetworkManager profile output");
        ensure!(
            rows[0] == "802-3-ethernet" && matches!(rows[1], "" | "--"),
            "Bridge/bond member profiles must be managed through their controller"
        );
        settings.autoconnect = rows[2] == "yes";
        settings.mtu = rows[3]
            .parse::<u32>()
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or(1500);
        settings.route_metric = rows[4]
            .parse::<u32>()
            .ok()
            .filter(|n| *n > 0)
            .unwrap_or(100);
        settings.ipv4 = read_family(&rows[5..10])?;
        settings.ipv6 = read_family(&rows[10..15])?;
        Ok(settings)
    }
    async fn checkpoint(&self, ifname: &str) -> Result<String> {
        let device = self.call("GetDeviceByIpIface", &["s", ifname]).await?;
        let device = device["data"][0]
            .as_str()
            .context("Missing NetworkManager device path")?;
        // Flag 2 removes profiles created by this trial on rollback. Do not
        // destroy others' checkpoints or allow overlapping device snapshots.
        let result = self
            .call(
                "CheckpointCreate",
                &["aouu", "1", device, &SECONDS.to_string(), "2"],
            )
            .await?;
        let path = result["data"][0]
            .as_str()
            .context("Missing NetworkManager checkpoint path")?;
        ensure!(
            path.starts_with("/org/freedesktop/NetworkManager/Checkpoint/"),
            "Invalid checkpoint path"
        );
        Ok(path.into())
    }
    async fn rollback(&self, checkpoint: &str) -> Result<()> {
        let result = self.call("CheckpointRollback", &["o", checkpoint]).await?;
        let results = result["data"][0]
            .as_object()
            .context("Missing NetworkManager rollback results")?;
        ensure!(
            !results.is_empty() && results.values().all(|v| v.as_u64() == Some(0)),
            "NetworkManager could not restore every interface: {results:?}"
        );
        Ok(())
    }
    async fn checkpoint_exists(&self, checkpoint: &str) -> Result<bool> {
        let args = [
            "--system",
            "--timeout=3s",
            "--json=short",
            "get-property",
            NM,
            NM_PATH,
            NM,
            "Checkpoints",
        ]
        .map(str::to_string);
        let output = self.run(&self.busctl, &args).await?;
        let result: Value = serde_json::from_str(&output)?;
        let paths = result["data"]
            .as_array()
            .context("Missing NetworkManager checkpoints")?;
        Ok(paths.iter().any(|value| value.as_str() == Some(checkpoint)))
    }
    async fn is_active(&self, ifname: &str) -> Result<bool> {
        let text = self
            .nm(&["-g", "GENERAL.CON-UUID", "device", "show", ifname])
            .await?;
        Ok(uuid(&text))
    }
    async fn activate(&self, settings: &Settings) -> Result<String> {
        if settings.activate_only {
            self.nm(&[
                "connection",
                "modify",
                "--temporary",
                "uuid",
                settings.uuid.as_deref().context("No saved profile")?,
                "connection.autoconnect",
                "yes",
            ])
            .await?;
        }
        let mut args = vec!["--wait".into(), "15".into(), "connection".into()];
        // Trials only change NetworkManager memory. A reboot before confirmation
        // therefore retains the previous on-disk profile, not the trial.
        if let Some(id) = &settings.uuid {
            args.extend([
                "modify".into(),
                "--temporary".into(),
                "uuid".into(),
                id.clone(),
            ]);
        } else {
            args.extend([
                "add".into(),
                "save".into(),
                "no".into(),
                "type".into(),
                "ethernet".into(),
                "ifname".into(),
                settings.ifname.clone(),
                "con-name".into(),
                format!("RiverLB {}", settings.ifname),
            ]);
        }
        args.extend(settings.properties());
        if !settings.activate_only {
            self.run(&self.nmcli, &args).await?;
        }
        let id = self
            .profile(&settings.ifname)
            .await?
            .context("Saved profile not found")?;
        self.nm(&["connection", "up", "uuid", &id, "ifname", &settings.ifname])
            .await?;
        Ok(id)
    }
    async fn disable(&self, settings: &Settings) -> Result<String> {
        let id = settings
            .uuid
            .as_deref()
            .context("No saved profile to disable")?;
        self.nm(&[
            "connection",
            "modify",
            "--temporary",
            "uuid",
            id,
            "connection.autoconnect",
            "no",
        ])
        .await?;
        if self.is_active(&settings.ifname).await? {
            self.nm(&["device", "disconnect", &settings.ifname]).await?;
        }
        self.run(
            &self.ip,
            &[
                "link".into(),
                "set".into(),
                "dev".into(),
                settings.ifname.clone(),
                "down".into(),
            ],
        )
        .await?;
        Ok(id.to_owned())
    }
}
fn read_family(rows: &[&str]) -> Result<Family> {
    let method = match rows[0] {
        "disabled" => Method::Disabled,
        "manual" => Method::Manual,
        "auto" => Method::Auto,
        other => bail!("Addressing method {other} is not editable here"),
    };
    let split = |s: &str| {
        s.split(',')
            .map(str::trim)
            .filter(|v| !v.is_empty() && *v != "--")
            .map(str::to_string)
            .collect::<Vec<_>>()
    };
    let default_route = method != Method::Disabled && rows[4] == "no";
    Ok(Family {
        method,
        addresses: split(rows[1]),
        gateway: if matches!(rows[2], "" | "--") {
            None
        } else {
            Some(rows[2].parse()?)
        },
        dns: split(rows[3])
            .iter()
            .map(|s| s.parse())
            .collect::<std::result::Result<_, _>>()?,
        default_route,
    })
}
async fn expire(pending: &mut Option<Pending>) {
    if let Some(trial) = pending.as_ref()
        && trial.deadline <= Instant::now()
        && matches!(
            Backend::default()
                .checkpoint_exists(&trial.checkpoint)
                .await,
            Ok(false)
        )
    {
        *pending = None;
    }
}
pub async fn has_pending() -> bool {
    let mut pending = PENDING.lock().await;
    expire(&mut pending).await;
    pending.is_some()
}
fn view(pending: &Option<Pending>) -> Value {
    match pending {
        Some(p) => {
            json!({"pending":true,"token":p.token,"ifname":p.ifname,"can_confirm":p.ready,"seconds_remaining":p.deadline.saturating_duration_since(Instant::now()).as_secs()})
        }
        None => json!({"pending":false}),
    }
}
type ApiResult = std::result::Result<Json<Value>, (StatusCode, Json<Value>)>;
fn error(e: impl std::fmt::Display) -> (StatusCode, Json<Value>) {
    (
        StatusCode::UNPROCESSABLE_ENTITY,
        Json(json!({"error":e.to_string()})),
    )
}
async fn read(Path(ifname): Path<String>, State(control): State<Arc<Control>>) -> ApiResult {
    let backend = Backend::default();
    let settings = backend.read(&ifname).await.map_err(error)?;
    let active = backend.is_active(&ifname).await.map_err(error)?;
    Ok(Json(
        json!({"settings":settings,"active":active,"editing_supported":control.manage_network}),
    ))
}
pub async fn status() -> Value {
    let mut p = PENDING.lock().await;
    expire(&mut p).await;
    view(&p)
}
async fn pending() -> Json<Value> {
    Json(status().await)
}
async fn apply(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
    Json(settings): Json<Settings>,
) -> ApiResult {
    // A lost browser connection must not cancel a partially applied operation.
    tokio::spawn(async move {
        apply_inner(&control, &actor, settings)
            .await
            .map(Json)
            .map_err(error)
    })
    .await
    .map_err(error)?
}
async fn apply_inner(control: &Control, actor: &str, settings: Settings) -> Result<Value> {
    settings.validate()?;
    let _gate = control.change_gate.lock().await;
    ensure!(
        control.manage_network,
        "Interface editing requires managed network mode"
    );
    ensure!(
        control.pending_configuration.lock().await.is_none(),
        "Confirm or revert the pending traffic configuration first"
    );
    let config = control.generation.lock().await.runtime.config.clone();
    let mut pending = PENDING.lock().await;
    expire(&mut pending).await;
    ensure!(
        pending.is_none(),
        "Confirm or revert the pending interface change first"
    );
    let network = crate::network::provisioned(&config)?;
    ensure!(
        !settings.disable || !network.vlans.iter().any(|v| v.interface == settings.ifname),
        "Remove or move this interface's configured VLANs and traffic addresses before disabling it"
    );
    ensure!(
        !network.self_ips.iter().any(|ip| network
            .vlans
            .iter()
            .any(|v| v.name == ip.vlan && v.tag.is_none() && v.interface == settings.ifname)),
        "This adapter carries managed untagged self IPs or VIPs. Move those addresses to a tagged VLAN or remove them before changing its OS profile"
    );
    ensure!(
        settings.mtu >= 1500
            || !network
                .vlans
                .iter()
                .any(|v| v.interface == settings.ifname && v.tag.is_some()),
        "A parent with managed VLANs must retain an MTU of at least 1500"
    );
    let backend = Backend::default();
    let before = backend.read(&settings.ifname).await?;
    ensure!(
        before.uuid == settings.uuid,
        "Interface profile changed; reload before applying"
    );
    ensure!(
        !settings.activate_only || settings.uuid.is_some(),
        "No saved profile to activate"
    );
    ensure!(
        settings.uuid.is_none()
            || backend.is_active(&settings.ifname).await?
            || settings.activate_only
            || settings.disable,
        "Activate the saved connection and confirm connectivity before editing its settings"
    );
    // The listener remains bound to its configured IP. Retain that IP during
    // static changes; use a secondary address to migrate management safely.
    let links = crate::network::interface_addresses().await?;
    let management = config.management.ip();
    let carries_management = links.iter().any(|link| {
        link["ifname"].as_str() == Some(&settings.ifname)
            && link["addr_info"].as_array().is_some_and(|a| {
                a.iter().any(|a| {
                    a["local"].as_str().and_then(|s| s.parse::<IpAddr>().ok()) == Some(management)
                })
            })
    });
    ensure!(
        !settings.disable || !carries_management,
        "Move the management listener to another interface before disabling this interface"
    );
    if carries_management && !settings.activate_only {
        keep_management(&settings, &before, management)?;
    }
    control
        .store
        .record_audit(
            actor,
            &format!("interface {} trial requested", settings.ifname),
        )
        .await?;
    let checkpoint = backend.checkpoint(&settings.ifname).await?;
    let mut trial = Pending {
        checkpoint,
        token: rand::random::<u128>().to_string(),
        ifname: settings.ifname.clone(),
        deadline: Instant::now() + Duration::from_secs(SECONDS),
        save: None,
        ready: false,
        disabled: settings.disable,
    };
    let activated = if settings.disable {
        backend.disable(&settings).await
    } else {
        backend.activate(&settings).await
    };
    let id = match activated {
        Ok(id) => id,
        Err(cause) => {
            let restored = backend.rollback(&trial.checkpoint).await;
            if let Err(rollback) = restored {
                *pending = Some(trial);
                bail!(
                    "Interface apply failed: {cause}; rollback also failed: {rollback}. NetworkManager's timeout remains armed; check the console"
                );
            }
            bail!("Interface apply failed; previous profile restored: {cause}");
        }
    };
    trial.save = Some((
        id,
        !settings.disable && (settings.activate_only || settings.autoconnect),
    ));
    trial.ready = true;
    *pending = Some(trial);
    Ok(view(&pending))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Confirmation {
    token: String,
}
async fn finish(
    control: &Control,
    actor: &str,
    confirmation: Confirmation,
    keep: bool,
) -> Result<Value> {
    let _gate = control.change_gate.lock().await;
    let mut pending = PENDING.lock().await;
    expire(&mut pending).await;
    let trial = pending
        .as_ref()
        .context("No interface change is awaiting confirmation")?;
    ensure!(
        trial.token == confirmation.token,
        "Interface trial changed; refresh before confirming"
    );
    control
        .store
        .record_audit(
            actor,
            &format!(
                "interface {} {} requested",
                trial.ifname,
                if keep { "confirmation" } else { "rollback" }
            ),
        )
        .await?;
    let backend = Backend::default();
    if keep {
        ensure!(
            trial.ready,
            "This trial failed; revert it or recover the interface from the console"
        );
        ensure!(
            trial.deadline > Instant::now(),
            "The confirmation window has expired; wait for rollback and refresh"
        );
        ensure!(
            backend.checkpoint_exists(&trial.checkpoint).await?,
            "The NetworkManager checkpoint no longer exists. Do not save this trial; inspect the interface from the console and reload its settings"
        );
        if let Some((uuid, autoconnect)) = &trial.save {
            if trial.disabled {
                ensure!(
                    !backend.is_active(&trial.ifname).await?,
                    "The interface was reactivated; revert and retry disabling it"
                );
            } else {
                ensure!(
                    backend
                        .nm(&["-g", "GENERAL.CON-UUID", "device", "show", &trial.ifname])
                        .await?
                        == *uuid,
                    "The active interface profile changed; revert this trial and reload"
                );
            }
            backend
                .nm(&[
                    "connection",
                    "modify",
                    "uuid",
                    uuid,
                    "connection.autoconnect",
                    yes(*autoconnect),
                ])
                .await?;
        }
        backend
            .call("CheckpointDestroy", &["o", &trial.checkpoint])
            .await?;
    } else {
        backend.rollback(&trial.checkpoint).await?;
    }
    *pending = None;
    Ok(
        json!({"pending":false,"message":if keep {"Interface configuration applied"}else{"Previous interface configuration restored"}}),
    )
}
async fn confirm(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
    Json(request): Json<Confirmation>,
) -> ApiResult {
    tokio::spawn(async move {
        finish(&control, &actor, request, true)
            .await
            .map(Json)
            .map_err(error)
    })
    .await
    .map_err(error)?
}
async fn revert(
    State(control): State<Arc<Control>>,
    Extension(actor): Extension<String>,
    Json(request): Json<Confirmation>,
) -> ApiResult {
    tokio::spawn(async move {
        finish(&control, &actor, request, false)
            .await
            .map(Json)
            .map_err(error)
    })
    .await
    .map_err(error)?
}
pub fn router() -> Router<Arc<Control>> {
    Router::new()
        .route("/api/v1/network/adapters/{ifname}", get(read))
        .route("/api/v1/network/adapters", post(apply))
        .route("/api/v1/network/adapter-change", get(pending))
        .route("/api/v1/network/adapter-change/confirm", post(confirm))
        .route("/api/v1/network/adapter-change/revert", post(revert))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    fn settings() -> Settings {
        Settings {
            ifname: "eth1".into(),
            uuid: None,
            autoconnect: true,
            mtu: 1500,
            route_metric: 600,
            ipv4: Family::default(),
            ipv6: Family::default(),
            activate_only: false,
            disable: false,
        }
    }
    #[test]
    fn rejects_unsafe_addresses_and_preserves_route_opt_in() {
        let mut s = settings();
        s.validate().unwrap();
        let properties = s.properties();
        for property in [
            "ipv4.never-default",
            "ipv6.never-default",
            "ipv4.ignore-auto-dns",
            "ipv6.ignore-auto-dns",
        ] {
            let index = properties.iter().position(|p| p == property).unwrap();
            assert_eq!(properties[index + 1], "yes");
        }
        s.ipv4.method = Method::Manual;
        assert!(s.validate().is_err());
        s.ipv4.addresses = vec!["192.0.2.10/24".into()];
        s.validate().unwrap();
        s.ipv4.gateway = Some("192.0.2.1".parse().unwrap());
        assert!(s.validate().is_err());
        s.ipv4.default_route = true;
        s.validate().unwrap();
        s.ipv4.addresses = vec!["2001:db8::1/64".into()];
        assert!(s.validate().is_err());
        s.ipv4.addresses = vec!["192.0.2.10/24".into()];
        for bad in ["--help", "lo", "../eth0", "a;reboot"] {
            s.ifname = bad.into();
            assert!(s.validate().is_err());
        }
        s.ifname = "eth1".into();
        s.uuid = Some("--help".into());
        assert!(s.validate().is_err());
    }
    #[test]
    fn reads_ipv6_and_rejects_unsupported_profile_methods() {
        let family = read_family(&[
            "manual",
            "2001:db8::10/64,2001:db8::11/64",
            "2001:db8::1",
            "2001:db8::53",
            "no",
        ])
        .unwrap();
        assert_eq!(family.addresses.len(), 2);
        assert!(family.default_route);
        let disabled = read_family(&["disabled", "", "", "", "no"]).unwrap();
        assert!(!disabled.default_route);
        assert!(read_family(&["shared", "", "", "", "no"]).is_err());
    }
    #[test]
    fn management_address_changes_require_retaining_the_bound_ip() {
        let mut before = settings();
        before.ipv4.method = Method::Auto;
        let mut trial = before.clone();
        let address = "192.0.2.10".parse().unwrap();
        keep_management(&trial, &before, address).unwrap();
        trial.ipv4.method = Method::Manual;
        trial.ipv4.addresses = vec!["192.0.2.11/24".into()];
        assert!(keep_management(&trial, &before, address).is_err());
        trial.ipv4.addresses.push("192.0.2.10/24".into());
        keep_management(&trial, &before, address).unwrap();
        trial.autoconnect = false;
        assert!(keep_management(&trial, &before, address).is_err());
    }
    struct Fixture(std::path::PathBuf);
    impl Drop for Fixture {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }
    fn backend() -> (Fixture, Backend) {
        let dir =
            std::env::temp_dir().join(format!("riverlb-interface-test-{}", rand::random::<u128>()));
        std::fs::create_dir(&dir).unwrap();
        let script = r#"#!/usr/bin/python3
import json,pathlib,sys
root=pathlib.Path(sys.argv[0]).parent
args=sys.argv[1:]
with (root/'calls').open('a') as f:f.write(json.dumps([pathlib.Path(sys.argv[0]).name,args])+'\n')
if pathlib.Path(sys.argv[0]).name=='busctl':
 if 'get-property' in args:
  print(json.dumps({'type':'ao','data':['/org/freedesktop/NetworkManager/Checkpoint/4']}));sys.exit(0)
 method=args[args.index('call')+4]
 if method=='GetDeviceByIpIface':value={'type':'o','data':['/org/freedesktop/NetworkManager/Devices/2']}
 elif method=='CheckpointCreate':value={'type':'o','data':['/org/freedesktop/NetworkManager/Checkpoint/4']}
 elif method=='CheckpointRollback':value={'type':'a{su}','data':[{'/org/freedesktop/NetworkManager/Devices/2':0}]}
 else:sys.exit(0)
 print(json.dumps(value))
elif '-g' in args:
 field=args[args.index('-g')+1]
 if field=='GENERAL.TYPE,GENERAL.CON-UUID':print('ethernet\n11111111-1111-4111-8111-111111111111')
 elif field=='GENERAL.CON-UUID':print('11111111-1111-4111-8111-111111111111')
 elif field.startswith('connection.type,'):print('802-3-ethernet\n\nyes\n0\n-1\nauto\n\n\n\nno\ndisabled\n\n\n\nyes')
 else:raise RuntimeError(field)
elif 'up' in args and (root/'fail-up').exists():
 print('fixture activation failed',file=sys.stderr);sys.exit(1)
"#;
        for name in ["nmcli", "busctl", "ip"] {
            let path = dir.join(name);
            std::fs::write(&path, script).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }
        let backend = Backend {
            nmcli: dir.join("nmcli"),
            busctl: dir.join("busctl"),
            ip: dir.join("ip"),
        };
        (Fixture(dir), backend)
    }
    #[tokio::test]
    async fn enabling_saved_profile_does_not_modify_addressing() {
        let (fixture, b) = backend();
        let mut s = b.read("eth1").await.unwrap();
        s.activate_only = true;
        b.activate(&s).await.unwrap();
        let log = std::fs::read_to_string(fixture.0.join("calls")).unwrap();
        let calls = log
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(
            calls
                .iter()
                .any(|call| call[1].as_array().unwrap().contains(&json!("up")))
        );
        assert!(!calls.iter().any(|call| {
            call[1]
                .as_array()
                .unwrap()
                .iter()
                .any(|arg| arg == "ipv4.method" || arg == "ipv4.addresses" || arg == "add")
        }));
    }
    #[tokio::test]
    async fn disabling_disconnects_and_lowers_link_without_saving_early() {
        let (fixture, b) = backend();
        let mut s = b.read("eth1").await.unwrap();
        s.disable = true;
        s.validate().unwrap();
        b.disable(&s).await.unwrap();
        let log = std::fs::read_to_string(fixture.0.join("calls")).unwrap();
        let calls = log
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(
            calls
                .iter()
                .any(|c| c[1].as_array().unwrap().contains(&json!("disconnect")))
        );
        assert!(
            calls
                .iter()
                .any(|c| c[0] == "ip" && c[1] == json!(["link", "set", "dev", "eth1", "down"]))
        );
        assert!(
            calls
                .iter()
                .filter(|c| c[1].as_array().unwrap().contains(&json!("modify")))
                .all(|c| c[1].as_array().unwrap().contains(&json!("--temporary")))
        );
    }
    #[tokio::test]
    async fn nm_trials_remain_temporary_and_checkpoint_is_scoped() {
        let (fixture, b) = backend();
        let read = b.read("eth1").await.unwrap();
        assert_eq!(read.route_metric, 100);
        assert_eq!(read.ipv4.method, Method::Auto);
        let checkpoint = b.checkpoint("eth1").await.unwrap();
        assert!(b.checkpoint_exists(&checkpoint).await.unwrap());
        let mut s = settings();
        s.uuid = read.uuid;
        b.activate(&s).await.unwrap();
        s.uuid = None;
        b.activate(&s).await.unwrap();
        b.rollback(&checkpoint).await.unwrap();
        let log = std::fs::read_to_string(fixture.0.join("calls")).unwrap();
        let calls = log
            .lines()
            .map(|line| serde_json::from_str::<Value>(line).unwrap())
            .collect::<Vec<_>>();
        assert!(calls.iter().any(|call| {
            call[1]
                .as_array()
                .unwrap()
                .windows(2)
                .any(|pair| pair == [json!("modify"), json!("--temporary")])
        }));
        assert!(calls.iter().any(|call| {
            call[1]
                .as_array()
                .unwrap()
                .windows(2)
                .any(|pair| pair == [json!("save"), json!("no")])
        }));
        let cp = calls
            .iter()
            .find(|call| {
                call[1]
                    .as_array()
                    .unwrap()
                    .contains(&json!("CheckpointCreate"))
            })
            .unwrap();
        let arguments = cp[1].as_array().unwrap();
        let start = arguments
            .iter()
            .position(|arg| arg == "CheckpointCreate")
            .unwrap()
            + 1;
        assert_eq!(
            &arguments[start..],
            &[
                json!("aouu"),
                json!("1"),
                json!("/org/freedesktop/NetworkManager/Devices/2"),
                json!("90"),
                json!("2")
            ]
        );
        std::fs::write(fixture.0.join("fail-up"), "").unwrap();
        assert!(b.activate(&s).await.is_err());
    }
}
