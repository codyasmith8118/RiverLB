//! Source translation for full-proxy backend sockets. No transparent packet NAT.
use crate::{config::Config, network::cidr};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "mode", rename_all = "snake_case", deny_unknown_fields)]
pub enum SourceNat {
    Automap,
    Snat { addresses: Vec<IpAddr> },
}
impl SourceNat {
    pub fn validate(&self, config: &Config, members: &[std::net::SocketAddr]) -> Result<()> {
        match self {
            Self::Snat { addresses } => {
                ensure!(
                    !addresses.is_empty() && addresses.len() <= 256,
                    "SNAT requires 1–256 translation addresses"
                );
                let mut seen = std::collections::HashSet::new();
                for ip in addresses {
                    ensure!(
                        !ip.is_unspecified() && !ip.is_multicast() && seen.insert(*ip),
                        "SNAT addresses must be unique unicast addresses"
                    );
                }
                for member in members {
                    ensure!(
                        addresses.iter().any(|ip| ip.is_ipv4() == member.is_ipv4()),
                        "SNAT requires a translation address for every backend address family"
                    );
                }
            }
            Self::Automap => {
                for member in members {
                    ensure!(
                        config.network.self_ips.iter().any(|ip| cidr(&ip.address)
                            .is_ok_and(|(ip, _)| ip.is_ipv4() == member.is_ipv4())),
                        "automap requires configured self IPs for every backend address family"
                    );
                }
            }
        }
        Ok(())
    }
}
pub fn select_automap(
    config: &Config,
    destination: IpAddr,
    device: &str,
    preferred: Option<IpAddr>,
) -> Result<IpAddr> {
    let mut candidates = Vec::new();
    for ip in &config.network.self_ips {
        let vlan = config
            .network
            .vlans
            .iter()
            .find(|v| v.name == ip.vlan)
            .expect("validated VLAN");
        let interface = if vlan.tag.is_some() {
            &vlan.name
        } else {
            &vlan.interface
        };
        let (ip, _) = cidr(&ip.address)?;
        if interface == device && ip.is_ipv4() == destination.is_ipv4() {
            candidates.push(ip);
        }
    }
    ensure!(
        !candidates.is_empty(),
        "automap has no self IP on egress interface {device}"
    );
    Ok(preferred
        .filter(|ip| candidates.contains(ip))
        .unwrap_or(candidates[0]))
}
pub async fn automap_on(
    config: &Config,
    destination: IpAddr,
    vlan: Option<&str>,
) -> std::io::Result<IpAddr> {
    let family = if destination.is_ipv4() { "-4" } else { "-6" };
    let mut command = tokio::process::Command::new("/usr/sbin/ip");
    command
        .kill_on_drop(true)
        .args([family, "-j", "route", "get", &destination.to_string()]);
    if let Some(vlan) = vlan {
        command.args(["oif", config.network.device(vlan)]);
    }
    let result = command.output().await?;
    if !result.status.success() {
        return Err(std::io::Error::other("automap route lookup failed"));
    }
    let routes: serde_json::Value =
        serde_json::from_slice(&result.stdout).map_err(std::io::Error::other)?;
    let route = routes
        .get(0)
        .ok_or_else(|| std::io::Error::other("automap route missing"))?;
    let device = route["dev"]
        .as_str()
        .ok_or_else(|| std::io::Error::other("automap route has no egress interface"))?;
    let preferred = route["prefsrc"].as_str().and_then(|ip| ip.parse().ok());
    if let Some(vlan) = vlan
        && device != config.network.device(vlan)
    {
        return Err(std::io::Error::other(
            "automap route does not use selected backend VLAN",
        ));
    }
    select_automap(config, destination, device, preferred).map_err(std::io::Error::other)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn automap_matches_egress_and_prefers_route_source() {
        let mut config = Config::load(std::path::Path::new("examples/networking.toml")).unwrap();
        let ip = &config.network.self_ips[0];
        let vlan = config
            .network
            .vlans
            .iter()
            .find(|v| v.name == ip.vlan)
            .unwrap();
        let device = if vlan.tag.is_some() {
            vlan.name.clone()
        } else {
            vlan.interface.clone()
        };
        let source = cidr(&ip.address).unwrap().0;
        let destination = "198.51.100.20".parse().unwrap();
        assert_eq!(
            select_automap(&config, destination, &device, Some(source)).unwrap(),
            source
        );
        assert!(select_automap(&config, destination, "unrelated", None).is_err());
        let mut second = config.network.self_ips[0].clone();
        second.name = "second".into();
        second.address = "192.0.2.99/24".into();
        config.network.self_ips.push(second);
        let preferred = "192.0.2.99".parse().unwrap();
        assert_eq!(
            select_automap(&config, destination, &device, Some(preferred)).unwrap(),
            preferred
        );
    }
    #[test]
    fn snat_rejects_empty_duplicate_and_wrong_family_addresses() {
        let config = Config::load(std::path::Path::new("examples/riverlb.toml")).unwrap();
        let members = &config.virtual_servers[0].members;
        for addresses in [
            vec![],
            vec!["0.0.0.0".parse().unwrap()],
            vec!["::1".parse().unwrap()],
            vec!["127.0.0.2".parse().unwrap(); 2],
        ] {
            assert!(
                SourceNat::Snat { addresses }
                    .validate(&config, members)
                    .is_err()
            );
        }
        SourceNat::Snat {
            addresses: vec!["127.0.0.2".parse().unwrap()],
        }
        .validate(&config, members)
        .unwrap();
        assert!(SourceNat::Automap.validate(&config, members).is_err());
    }
}
