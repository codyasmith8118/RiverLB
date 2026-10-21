//! Local HA group administration. Traffic ownership remains with Pacemaker.
use crate::{control::Control, ha};
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use std::{net::IpAddr, sync::atomic::Ordering};
use tokio::io::AsyncWriteExt;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Group {
    pub cluster_id: String,
    pub node_id: String,
    pub peer_id: String,
    pub local_address: IpAddr,
    pub peer_address: IpAddr,
    pub automatic_sync: bool,
    pub floating_self_ips: Vec<String>,
    #[serde(default)]
    pub fencing_resources: Vec<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub action: String,
}

fn read_group(path: &std::path::Path) -> Result<Group> {
    let mut value: Value = serde_json::from_slice(&std::fs::read(path)?)?;
    if let Some(object) = value.as_object_mut() {
        for key in ["fencing_host", "local_vm_id", "peer_vm_id"] {
            object.remove(key);
        }
    }
    Ok(serde_json::from_value(value)?)
}
pub async fn view(control: &Control) -> Result<Value> {
    let path = control.ha_config_path.with_extension("group.json");
    let group: Option<Group> = if path.exists() {
        Some(read_group(&path)?)
    } else {
        None
    };
    let settings = if control.ha_config_path.exists() {
        Some(ha::Settings::load(&control.ha_config_path)?)
    } else {
        None
    };
    let status = control.ha_status().await;
    let configuration_sync = status["configuration_sync"].clone();
    Ok(
        json!({"configuration_sync":configuration_sync,"group":group,"settings":settings,"status":status,
        "restart_required": match (&settings,&control.ha) {
            (Some(saved),Some(live)) => {
                let mut current=live.settings.clone();
                current.automatic_sync=live.automatic_sync.load(Ordering::SeqCst);
                serde_json::to_value(saved)? != serde_json::to_value(current)?
            },
            (Some(_),None) => true,
            _ => false
        }}),
    )
}
fn valid_id(id: &str) -> bool {
    !id.is_empty()
        && !id.starts_with('-')
        && id.len() <= 128
        && id
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_.-".contains(&c))
}
impl Group {
    fn validate(&self) -> Result<()> {
        ensure!(
            valid_id(&self.cluster_id)
                && valid_id(&self.node_id)
                && valid_id(&self.peer_id)
                && self.node_id != self.peer_id,
            "Invalid group/device names"
        );
        ensure!(
            self.local_address != self.peer_address
                && !self.local_address.is_unspecified()
                && !self.peer_address.is_unspecified()
                && !self.local_address.is_loopback()
                && !self.peer_address.is_loopback(),
            "Use different reachable appliance addresses"
        );
        ensure!(
            self.fencing_resources.iter().all(|name| valid_id(name)),
            "Invalid fencing resource ID"
        );
        ensure!(
            self.fencing_resources
                .iter()
                .collect::<std::collections::HashSet<_>>()
                .len()
                == self.fencing_resources.len(),
            "Duplicate fencing resource ID"
        );
        Ok(())
    }
}
pub async fn save(control: &Control, group: Group, actor: &str) -> Result<Value> {
    group.validate()?;
    ensure!(control.manage_network, "HA requires managed networking");
    let generation = control.generation.lock().await;
    ensure!(
        group.floating_self_ips.iter().all(|name| generation
            .runtime
            .config
            .network
            .self_ips
            .iter()
            .any(|ip| &ip.name == name)),
        "Select floating self IP names already configured on this appliance"
    );
    let existing = if control.ha_config_path.exists() {
        Some(ha::Settings::load(&control.ha_config_path)?)
    } else {
        None
    };
    let mut settings=existing.clone().unwrap_or(serde_json::from_value(json!({
        "cluster_id":group.cluster_id,"node_id":group.node_id,"peer_id":group.peer_id,
        "socket":"/run/riverlb/ha.sock","state_file":"/var/lib/riverlb/ha-state.json",
        "authority":"/usr/libexec/riverlb/riverlb-authority","floating_self_ips":group.floating_self_ips,
        "ssh_target":format!("root@{}",group.peer_address),
        "ssh_identity":"/etc/riverlb/ha-sync-ed25519","ssh_known_hosts":"/etc/riverlb/ha-known-hosts",
        "peer_socket":"/run/riverlb/ha.sock","peer_binary":"/usr/bin/riverlb"
    }))?);
    settings.cluster_id = group.cluster_id.clone();
    settings.node_id = group.node_id.clone();
    settings.peer_id = group.peer_id.clone();
    settings.ssh_target = format!("root@{}", group.peer_address);
    settings.floating_self_ips = group.floating_self_ips.clone();
    settings.automatic_sync = group.automatic_sync;
    settings.validate()?;
    let mut same = existing.clone();
    if let Some(s) = &mut same {
        s.automatic_sync = group.automatic_sync;
    }
    let structural = match same {
        Some(s) => serde_json::to_value(s)? != serde_json::to_value(&settings)?,
        None => true,
    };
    ensure!(
        !structural || control.ha.is_none() || !control.data_plane_active(),
        "Move traffic to the peer before changing group membership or floating ownership"
    );
    use std::os::unix::fs::{MetadataExt, PermissionsExt};
    let parent = control
        .ha_config_path
        .parent()
        .context("HA settings directory missing")?;
    let directory = std::fs::metadata(parent)?;
    ensure!(
        directory.uid() == 0 && directory.permissions().mode() & 0o022 == 0,
        "HA group settings require a root-owned directory that others cannot modify"
    );
    // New HA locations are private; no arbitrary executable or credential paths are accepted from the browser.
    if existing.is_none() {
        for path in [&settings.socket, &settings.state_file] {
            let directory = path.parent().context("HA directory missing")?;
            if !directory.exists() {
                std::fs::create_dir_all(directory)?;
                std::fs::set_permissions(directory, std::fs::Permissions::from_mode(0o700))?;
            }
        }
    }
    ha::private_write(&control.ha_config_path, &settings)?;
    ha::private_write(&control.ha_config_path.with_extension("group.json"), &group)?;
    if !structural && let Some(state) = &control.ha {
        state
            .automatic_sync
            .store(group.automatic_sync, Ordering::SeqCst);
    }
    control
        .store
        .record_audit(actor, "HA group settings saved")
        .await?;
    Ok(
        json!({"message": if structural {"HA group saved. Restart the appliance service in HA mode before provisioning the cluster."}else{"HA synchronization mode applied."},"restart_required":structural}),
    )
}
pub async fn action(control: &Control, action: Action, actor: &str) -> Result<Value> {
    let state = control
        .ha
        .as_ref()
        .context("Save the group and restart in HA mode first")?;
    ensure!(!control.stop.is_cancelled(), "Appliance is stopping");
    match action.action.as_str() {
        "sync" => {
            ha::send(control).await?;
        }
        "seed" => {
            let _generation = control.generation.lock().await;
            ensure!(
                !control.data_plane_active(),
                "Initial seed requires standby"
            );
            state.status.lock().unwrap().seed = true;
        }
        "setup" | "enable" | "failover" | "clear" => {
            if action.action == "failover" && control.data_plane_active() {
                ha::send(control).await?;
            }
            if action.action == "failover" {
                ensure!(
                    matches!(
                        control.ha_status().await["role"].as_str(),
                        Some("active" | "standby")
                    ),
                    "Faulted appliance cannot request failover"
                );
                ha::authority(state).await?;
                ensure!(
                    state
                        .status()
                        .checkpoint_time
                        .is_some_and(|t| crate::storage::now() - t
                            <= state.settings.max_sync_age_secs as i64),
                    "Synchronize a current checkpoint before failover"
                );
            }
            let group = read_group(&control.ha_config_path.with_extension("group.json"))?;
            group.validate()?;
            ensure!(
                group.cluster_id == state.settings.cluster_id
                    && group.node_id == state.settings.node_id
                    && group.peer_id == state.settings.peer_id,
                "Restart to apply group membership before cluster actions"
            );
            let target = if control.data_plane_active() {
                &group.peer_id
            } else {
                &group.node_id
            };
            let request = json!({"action":action.action,"group":group,"target":target});
            let mut command = tokio::process::Command::new("/usr/libexec/riverlb/riverlb-cluster");
            command
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::piped())
                .stderr(std::process::Stdio::piped());
            // Do not cancel a cluster transaction when the browser disconnects or a request times out.
            let mut child = command
                .spawn()
                .context("Install deploy/ha integration and pre-authenticate pcs hosts first")?;
            let mut stdin = child.stdin.take().unwrap();
            stdin.write_all(&serde_json::to_vec(&request)?).await?;
            drop(stdin);
            let output = child.wait_with_output().await?;
            ensure!(
                output.status.success(),
                "Cluster action failed: {}",
                String::from_utf8_lossy(&output.stderr)
            );
        }
        _ => anyhow::bail!("Unknown HA group action"),
    }
    control
        .store
        .record_audit(actor, &format!("HA group action: {}", action.action))
        .await?;
    Ok(json!({"message":match action.action.as_str() {
        "sync"=>"Traffic configuration and persistence synchronized.",
        "setup"=>"Two-appliance cluster provisioned. Configure platform fencing resources, seed one initial primary, then enable traffic.",
        "enable"=>"Cluster traffic enabled.",
        "failover"=>"Failover requested. Pacemaker will stop or fence the old owner before promotion.",
        "clear"=>"Temporary failover placement cleared.",
        _=>"Initial primary seeded for this process."
    }}))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn group() -> Group {
        serde_json::from_value(json!({"cluster_id":"pair","node_id":"a","peer_id":"b",
            "local_address":"192.0.2.10","peer_address":"192.0.2.20","automatic_sync":false,
            "floating_self_ips":[],"fencing_resources":["fence-node-a","fence-node-b"]}))
        .unwrap()
    }
    #[test]
    fn rejects_duplicate_fencing_identity_and_invalid_membership() {
        let mut g = group();
        g.validate().unwrap();
        g.fencing_resources.push("fence-node-a".into());
        assert!(g.validate().is_err());
        let mut g = group();
        g.peer_id = g.node_id.clone();
        assert!(g.validate().is_err());
        let mut g = group();
        g.peer_address = "127.0.0.1".parse().unwrap();
        assert!(g.validate().is_err());
        let mut g = group();
        g.node_id = "--force".into();
        assert!(g.validate().is_err());
        // Executable arguments cannot contain shell syntax.
        g.node_id = "node;command".into();
        assert!(g.validate().is_err());
    }
}
