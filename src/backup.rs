//! Versioned logical snapshots; no copying a live database/WAL pair.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
pub const MAX_BYTES: usize = 32 * 1024 * 1024;
// 'i' integer, 's' text. SQL identifiers never come from uploaded data.
pub const TABLES: &[(&str, &str)] = &[
    ("administrators", "ss"),
    ("configurations", "isis"),
    ("audit", "iiss"),
    ("traffic_samples", "iiis"),
    ("certificates", "sssi"),
    ("acme_jobs", "ss"),
    ("acme_accounts", "ss"),
    ("device_certificates", "sssi"),
    ("certificate_requests", "ssssi"),
    ("auth_accounts", "ss"),
    ("auth_settings", "is"),
];
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub format: u32,
    pub created: i64,
    pub tables: BTreeMap<String, Vec<Vec<Value>>>,
    pub sha256: String,
}
impl Snapshot {
    pub fn seal(tables: BTreeMap<String, Vec<Vec<Value>>>) -> Result<Self> {
        let mut snapshot = Self {
            format: 3,
            created: crate::storage::now(),
            tables,
            sha256: String::new(),
        };
        snapshot.sha256 = snapshot.checksum()?;
        ensure!(
            serde_json::to_vec(&snapshot)?.len() <= MAX_BYTES,
            "backup exceeds 32 MiB limit"
        );
        Ok(snapshot)
    }
    fn checksum(&self) -> Result<String> {
        Ok(format!(
            "{:x}",
            Sha256::digest(serde_json::to_vec(&(
                self.format,
                self.created,
                &self.tables
            ))?)
        ))
    }
    pub fn validate(&self) -> Result<()> {
        ensure!(matches!(self.format, 1..=3), "unsupported backup format");
        ensure!(self.checksum()? == self.sha256, "backup checksum mismatch");
        ensure!(
            serde_json::to_vec(self)?.len() <= MAX_BYTES,
            "backup exceeds 32 MiB limit"
        );
        ensure!(
            self.tables.len()
                == if self.format == 1 {
                    TABLES.len() - 4
                } else if self.format == 2 {
                    TABLES.len() - 2
                } else {
                    TABLES.len()
                },
            "backup table inventory mismatch"
        );
        for (table, types) in TABLES {
            if self.format == 1 && ["device_certificates", "certificate_requests"].contains(table) {
                continue;
            }
            if self.format < 3 && ["auth_accounts", "auth_settings"].contains(table) {
                continue;
            }
            let rows = self.tables.get(*table).context("missing backup table")?;
            ensure!(rows.len() <= 100000, "too many backup records");
            let mut keys = std::collections::HashSet::new();
            for row in rows {
                ensure!(
                    row.len() == types.len()
                        && row.iter().zip(types.bytes()).all(|(v, t)| if t == b'i' {
                            v.as_i64().is_some()
                        } else {
                            v.is_string()
                        }),
                    "invalid backup row for {table}"
                );
                ensure!(
                    keys.insert(row[0].to_string()),
                    "duplicate backup primary key for {table}"
                );
            }
        }
        ensure!(
            !self.tables["administrators"].is_empty(),
            "backup must contain an administrator"
        );
        for row in &self.tables["administrators"] {
            argon2::PasswordHash::new(row[1].as_str().unwrap())
                .map_err(|_| anyhow::anyhow!("invalid administrator password hash"))?;
        }
        if self.format >= 3 {
            ensure!(
                self.tables["auth_settings"].len() <= 1
                    && self.tables["auth_settings"]
                        .iter()
                        .all(|row| row[0].as_i64() == Some(1)),
                "invalid backup authentication settings inventory"
            );
            for row in &self.tables["auth_accounts"] {
                ensure!(
                    self.tables["administrators"]
                        .iter()
                        .any(|admin| admin[0] == row[0]),
                    "backup contains orphan account security metadata"
                );
                let security: crate::auth::AccountSecurity =
                    serde_json::from_str(row[1].as_str().unwrap())?;
                security.validate()?;
            }
            let mut administrators = 0;
            for row in &self.tables["administrators"] {
                let account = self.tables["auth_accounts"].iter().find(|a| a[0] == row[0]);
                let security: crate::auth::AccountSecurity = account
                    .map(|a| serde_json::from_str(a[1].as_str().unwrap()))
                    .transpose()?
                    .unwrap_or_default();
                if security.role == crate::auth::Role::Administrator {
                    administrators += 1;
                }
            }
            ensure!(
                administrators > 0,
                "backup must retain an administrator role"
            );
            for row in &self.tables["auth_settings"] {
                let settings: crate::auth::SecuritySettings =
                    serde_json::from_str(row[1].as_str().unwrap())?;
                settings.validate()?;
            }
        }
        let latest = self.tables["configurations"]
            .iter()
            .max_by_key(|r| r[0].as_i64().unwrap())
            .context("backup has no configuration")?;
        let config: crate::config::Config = serde_json::from_str(latest[1].as_str().unwrap())?;
        config.validate()?;
        let config = config.expand_domain_tls()?;
        let mut certificates = crate::certificates::Resolved::new();
        for row in &self.tables["certificates"] {
            let name = row[0].as_str().unwrap();
            crate::certificates::validate_name(name)?;
            certificates.insert(
                name.to_owned(),
                crate::certificates::server_config(
                    row[1].as_str().unwrap(),
                    row[2].as_str().unwrap(),
                )?,
            );
            let metadata = crate::certificates::metadata(name, row[1].as_str().unwrap(), 0)?;
            for vs in &config.virtual_servers {
                for (host, assigned) in &vs.sni_certificates {
                    if assigned == name {
                        ensure!(
                            metadata
                                .dns_names
                                .iter()
                                .any(|p| crate::certificates::matches_dns(p, host)),
                            "backup SNI certificate mismatch"
                        );
                    }
                }
            }
        }
        if self.format == 1 {
            if let Some(name) = &config.management_certificate
                && let Some(cert) = certificates.get(name).cloned()
            {
                certificates.insert(crate::certificates::StoreKind::Device.key(name), cert);
            }
        } else {
            for row in &self.tables["device_certificates"] {
                let name = row[0].as_str().unwrap();
                crate::certificates::validate_name(name)?;
                certificates.insert(
                    crate::certificates::StoreKind::Device.key(name),
                    crate::certificates::server_config(
                        row[1].as_str().unwrap(),
                        row[2].as_str().unwrap(),
                    )?,
                );
                crate::certificates::metadata(name, row[1].as_str().unwrap(), 0)?;
            }
            for row in &self.tables["certificate_requests"] {
                let id = row[0].as_str().unwrap();
                let (scope, name) = id.split_once(':').context("invalid CSR store key")?;
                ensure!(
                    ["device", "virtual_server"].contains(&scope),
                    "invalid CSR store"
                );
                crate::certificates::validate_name(name)?;
                let names: Vec<String> = serde_json::from_str(row[3].as_str().unwrap())?;
                crate::certificates::validate_request(
                    row[1].as_str().unwrap(),
                    row[2].as_str().unwrap(),
                    &names,
                )?;
            }
        }
        crate::runtime::Runtime::with_certificates(
            config,
            &certificates,
            Default::default(),
            Default::default(),
            Default::default(),
        )?;
        for row in &self.tables["acme_jobs"] {
            let job: crate::acme::Job = serde_json::from_str(row[1].as_str().unwrap())?;
            ensure!(
                row[0].as_str() == Some(&job.settings.name),
                "ACME schedule name mismatch"
            );
            job.settings.validate()?;
        }
        for row in &self.tables["acme_accounts"] {
            let _: instant_acme::AccountCredentials =
                serde_json::from_str(row[1].as_str().unwrap())?;
        }
        Ok(())
    }
}
