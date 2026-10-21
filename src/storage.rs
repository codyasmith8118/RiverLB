//! Rust-native SQLite-compatible durable control plane; no SQL on the traffic path.
use crate::config::Config;
use anyhow::{Context, Result, ensure};
use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use rand::rngs::OsRng;
use sha2::{Digest, Sha256};
use std::{
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::sync::Mutex;

pub struct Store {
    connection: Mutex<turso::Connection>,
    _database: turso::Database,
    dummy_hash: String,
    _lock: std::fs::File,
}

pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs() as i64
}
fn digest(token: &str) -> String {
    format!("{:x}", Sha256::digest(token.as_bytes()))
}
pub async fn hash_password(password: String) -> Result<String> {
    ensure!(
        (12..=1024).contains(&password.len()),
        "password must contain 12–1024 bytes"
    );
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|e| anyhow::anyhow!("{e}"))
    })
    .await?
}
async fn migrate_device_certificates(conn: &turso::Connection) -> Result<()> {
    let mut rows = conn.query("SELECT json FROM configurations", ()).await?;
    let mut names = std::collections::HashSet::new();
    while let Some(row) = rows.next().await? {
        let config: Config = serde_json::from_str(&row.get::<String>(0)?)?;
        if let Some(name) = config.management_certificate {
            names.insert(name);
        }
    }
    drop(rows);
    for name in names {
        conn.execute(
            "INSERT OR IGNORE INTO device_certificates SELECT * FROM certificates WHERE name=?1",
            [name],
        )
        .await?;
    }
    Ok(())
}
async fn account_security(
    conn: &turso::Connection,
    username: &str,
) -> Result<crate::auth::AccountSecurity> {
    let mut rows = conn
        .query(
            "SELECT json FROM auth_accounts WHERE username=?1",
            [username],
        )
        .await?;
    let account: crate::auth::AccountSecurity = match rows.next().await? {
        Some(row) => serde_json::from_str(&row.get::<String>(0)?)?,
        None => Default::default(),
    };
    account.validate()?;
    Ok(account)
}
async fn save_account_security(
    conn: &turso::Connection,
    username: &str,
    account: &crate::auth::AccountSecurity,
) -> Result<()> {
    conn.execute("INSERT INTO auth_accounts (username,json) VALUES (?1,?2) ON CONFLICT(username) DO UPDATE SET json=excluded.json",turso::params![username,serde_json::to_string(account)?]).await?;
    Ok(())
}
async fn security_settings(conn: &turso::Connection) -> Result<crate::auth::SecuritySettings> {
    let mut rows = conn
        .query("SELECT json FROM auth_settings WHERE id=1", ())
        .await?;
    let settings: crate::auth::SecuritySettings = match rows.next().await? {
        Some(row) => serde_json::from_str(&row.get::<String>(0)?)?,
        None => Default::default(),
    };
    settings.validate()?;
    Ok(settings)
}
async fn auth_transaction<T>(
    conn: &turso::Connection,
    operation: impl std::future::Future<Output = Result<T>>,
) -> Result<T> {
    conn.execute("BEGIN IMMEDIATE", ()).await?;
    let result = operation.await;
    match result {
        Ok(value) => match conn.execute("COMMIT", ()).await {
            Ok(_) => Ok(value),
            Err(error) => {
                let _ = conn.execute("ROLLBACK", ()).await;
                Err(error.into())
            }
        },
        Err(error) => {
            let _ = conn.execute("ROLLBACK", ()).await;
            Err(error)
        }
    }
}
async fn require_account(conn: &turso::Connection, username: &str) -> Result<()> {
    let mut rows = conn
        .query(
            "SELECT username FROM administrators WHERE username=?1",
            [username],
        )
        .await?;
    ensure!(rows.next().await?.is_some(), "Account no longer exists");
    Ok(())
}
async fn revoke_account_sessions(conn: &turso::Connection, username: &str) -> Result<()> {
    conn.execute("DELETE FROM auth_session_activity WHERE token_hash IN (SELECT token_hash FROM sessions WHERE username=?1)",[username]).await?;
    conn.execute("DELETE FROM sessions WHERE username=?1", [username])
        .await?;
    Ok(())
}
impl Store {
    pub async fn security_settings(&self) -> Result<crate::auth::SecuritySettings> {
        security_settings(&*self.connection.lock().await).await
    }
    pub async fn set_security_settings(
        &self,
        settings: crate::auth::SecuritySettings,
        actor: &str,
    ) -> Result<()> {
        settings.validate()?;
        let conn = self.connection.lock().await;
        auth_transaction(&conn,async {
        require_account(&conn,actor).await?;
        ensure!(account_security(&conn,actor).await?.role==crate::auth::Role::Administrator,"Administrator role required");
        conn.execute("INSERT INTO auth_settings (id,json) VALUES (1,?1) ON CONFLICT(id) DO UPDATE SET json=excluded.json",[serde_json::to_string(&settings)?]).await?;
        conn.execute("INSERT INTO audit (created,actor,action) VALUES (?1,?2,'management security policy updated')",turso::params![now(),actor]).await?;Ok(())
        }).await
    }
    pub async fn account_inventory(&self) -> Result<serde_json::Value> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query("SELECT username FROM administrators ORDER BY username", ())
            .await?;
        let mut users = Vec::new();
        while let Some(row) = rows.next().await? {
            let username = row.get::<String>(0)?;
            let security = account_security(&conn, &username).await?;
            users.push(serde_json::json!({"username":username,"role":security.role,"mfa_enabled":!security.mfa_secret.is_empty(),"recovery_codes_remaining":security.recovery_hashes.len()}));
        }
        Ok(serde_json::json!(users))
    }
    pub async fn mfa_status(&self, username: &str) -> Result<serde_json::Value> {
        let security = account_security(&*self.connection.lock().await, username).await?;
        Ok(
            serde_json::json!({"enabled":!security.mfa_secret.is_empty(),"recovery_codes_remaining":security.recovery_hashes.len()}),
        )
    }
    pub async fn enroll_mfa(&self, username: &str) -> Result<serde_json::Value> {
        let conn = self.connection.lock().await;
        auth_transaction(&conn,async {
        require_account(&conn,username).await?;let mut security=account_security(&conn,username).await?;
        ensure!(security.mfa_secret.is_empty(),"Disable the current authenticator before enrolling another");
        security.pending_secret=crate::auth::new_totp_secret();security.pending_expires=now()+600;
        save_account_security(&conn,username,&security).await?;
        conn.execute("INSERT INTO audit (created,actor,action) VALUES (?1,?2,'MFA enrollment started')",turso::params![now(),username]).await?;
        let label=username.bytes().map(|b|if b.is_ascii_alphanumeric() || b"-_.".contains(&b){(b as char).to_string()}else{format!("%{b:02X}")}).collect::<String>();
        Ok(serde_json::json!({"secret":security.pending_secret,"uri":format!("otpauth://totp/RiverLB:{label}?secret={}&issuer=RiverLB&algorithm=SHA1&digits=6&period=30",security.pending_secret),"expires":security.pending_expires}))
        }).await
    }
    pub async fn confirm_mfa(&self, username: &str, code: &str) -> Result<Vec<String>> {
        let conn = self.connection.lock().await;
        auth_transaction(&conn,async {
        require_account(&conn,username).await?;let mut security=account_security(&conn,username).await?;
        ensure!(!security.pending_secret.is_empty() && security.pending_expires>now(),"Authenticator enrollment expired; start again");
        let counter=crate::auth::verify_totp(&security.pending_secret,code,now(),0).context("Invalid authenticator code")?;
        let codes=(0..10).map(|_|crate::auth::random_hex(10)).collect::<Vec<_>>();
        security.mfa_secret=std::mem::take(&mut security.pending_secret);security.pending_expires=0;security.last_counter=counter;
        security.recovery_hashes=codes.iter().map(|c|digest(c)).collect();
        save_account_security(&conn,username,&security).await?;
        revoke_account_sessions(&conn,username).await?;
        conn.execute("DELETE FROM api_tokens WHERE username=?1",[username]).await?;
        conn.execute("INSERT INTO audit (created,actor,action) VALUES (?1,?2,'MFA enabled; existing sessions and API tokens revoked')",turso::params![now(),username]).await?;
        Ok(codes)
        }).await
    }
    pub async fn disable_mfa(&self, username: &str) -> Result<()> {
        let conn = self.connection.lock().await;
        auth_transaction(&conn,async {
        require_account(&conn,username).await?;let mut security=account_security(&conn,username).await?;
        security.mfa_secret.clear();security.pending_secret.clear();security.pending_expires=0;security.recovery_hashes.clear();security.last_counter=0;
        save_account_security(&conn,username,&security).await?;
        revoke_account_sessions(&conn,username).await?;
        conn.execute("DELETE FROM api_tokens WHERE username=?1",[username]).await?;
        conn.execute("INSERT INTO audit (created,actor,action) VALUES (?1,?2,'MFA disabled; sessions and API tokens revoked')",turso::params![now(),username]).await?;Ok(())
        }).await
    }
    pub async fn create_api_token(
        &self,
        username: &str,
        name: &str,
        scope: crate::auth::TokenScope,
        lifetime_secs: u64,
    ) -> Result<serde_json::Value> {
        ensure!(
            !name.trim().is_empty() && name.len() <= 128,
            "Token name must contain 1–128 bytes"
        );
        ensure!(
            (60..=31_536_000).contains(&lifetime_secs),
            "Token lifetime must be 60 seconds to one year"
        );
        let conn = self.connection.lock().await;
        auth_transaction(&conn,async {
        require_account(&conn,username).await?;
        let mut rows=conn.query("SELECT COUNT(*) FROM api_tokens WHERE username=?1 AND expires>?2",turso::params![username,now()]).await?;
        ensure!(rows.next().await?.unwrap().get::<i64>(0)?<100,"At most 100 active tokens per account");drop(rows);
        let account=account_security(&conn,username).await?;
        ensure!(scope!=crate::auth::TokenScope::Configure || account.role==crate::auth::Role::Administrator,"Only administrators can create configuration tokens");
        let id=crate::auth::random_hex(16);let token=format!("rlb_{}",crate::auth::random_hex(32));let expires=now()+lifetime_secs as i64;
        conn.execute("INSERT INTO api_tokens VALUES (?1,?2,?3,?4,?5,?6,?7,0)",turso::params![id.as_str(),digest(&token),username,name,serde_json::to_string(&scope)?,now(),expires]).await?;
        conn.execute("INSERT INTO audit (created,actor,action) VALUES (?1,?2,?3)",turso::params![now(),username,format!("API token created: {name}; scope {scope:?}")]).await?;
        Ok(serde_json::json!({"id":id,"token":token,"name":name,"scope":scope,"expires":expires}))
        }).await
    }
    pub async fn api_tokens(&self, username: &str) -> Result<serde_json::Value> {
        let conn = self.connection.lock().await;
        let mut rows=conn.query("SELECT id,name,scope,created,expires,last_used FROM api_tokens WHERE username=?1 ORDER BY created DESC",[username]).await?;
        let mut tokens = Vec::new();
        while let Some(row) = rows.next().await? {
            tokens.push(serde_json::json!({"id":row.get::<String>(0)?,"name":row.get::<String>(1)?,"scope":serde_json::from_str::<crate::auth::TokenScope>(&row.get::<String>(2)?)?,"created":row.get::<i64>(3)?,"expires":row.get::<i64>(4)?,"last_used":row.get::<i64>(5)?}));
        }
        Ok(serde_json::json!(tokens))
    }
    pub async fn revoke_api_token(&self, username: &str, id: &str) -> Result<()> {
        let conn = self.connection.lock().await;
        auth_transaction(&conn, async {
            conn.execute(
                "DELETE FROM api_tokens WHERE username=?1 AND id=?2",
                turso::params![username, id],
            )
            .await?;
            conn.execute(
                "INSERT INTO audit (created,actor,action) VALUES (?1,?2,?3)",
                turso::params![now(), username, format!("API token revoked: {id}")],
            )
            .await?;
            Ok(())
        })
        .await
    }
    pub async fn token_principal(&self, token: &str) -> Result<Option<crate::auth::Principal>> {
        if token.len() != 68 || !token.starts_with("rlb_") {
            return Ok(None);
        }
        let conn = self.connection.lock().await;
        let mut rows=conn.query("SELECT api_tokens.username,scope FROM api_tokens JOIN administrators ON administrators.username=api_tokens.username WHERE token_hash=?1 AND expires>?2",turso::params![digest(token),now()]).await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let username = row.get::<String>(0)?;
        let scope = serde_json::from_str(&row.get::<String>(1)?)?;
        drop(rows);
        let role = account_security(&conn, &username).await?.role;
        conn.execute(
            "UPDATE api_tokens SET last_used=?2 WHERE token_hash=?1",
            turso::params![digest(token), now()],
        )
        .await?;
        Ok(Some(crate::auth::Principal {
            username,
            role,
            token_scope: Some(scope),
        }))
    }
    pub async fn backup(&self) -> Result<crate::backup::Snapshot> {
        let conn = self.connection.lock().await;
        conn.execute("BEGIN", ()).await?;
        let result = async {
            let mut tables = std::collections::BTreeMap::new();
            for (table, types) in crate::backup::TABLES {
                let mut rows = conn.query(&format!("SELECT * FROM {table}"), ()).await?;
                let mut values = Vec::new();
                while let Some(row) = rows.next().await? {
                    let mut fields = Vec::new();
                    for (i, ty) in types.bytes().enumerate() {
                        fields.push(if ty == b'i' {
                            serde_json::json!(row.get::<i64>(i)?)
                        } else {
                            serde_json::json!(row.get::<String>(i)?)
                        });
                    }
                    values.push(fields);
                }
                tables.insert(table.to_string(), values);
            }
            crate::backup::Snapshot::seal(tables)
        }
        .await;
        let _ = conn.execute("ROLLBACK", ()).await;
        result
    }
    pub async fn stage_restore(&self, snapshot: &crate::backup::Snapshot) -> Result<()> {
        snapshot.validate()?;
        self.connection.lock().await.execute("INSERT INTO restore_stage (id,json) VALUES (1,?1) ON CONFLICT(id) DO UPDATE SET json=excluded.json",[serde_json::to_string(snapshot)?]).await?;
        Ok(())
    }
    pub async fn staged_restore(&self) -> Result<Option<crate::backup::Snapshot>> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query("SELECT json FROM restore_stage WHERE id=1", ())
            .await?;
        rows.next()
            .await?
            .map(|r| Ok(serde_json::from_str(&r.get::<String>(0)?)?))
            .transpose()
    }
    pub async fn restore(&self, snapshot: &crate::backup::Snapshot) -> Result<()> {
        snapshot.validate()?;
        let conn = self.connection.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result=async {
            for (table,types) in crate::backup::TABLES {
                conn.execute(&format!("DELETE FROM {table}"),()).await?;
                let placeholders=(1..=types.len()).map(|i|format!("?{i}")).collect::<Vec<_>>().join(",");
                for row in snapshot.tables.get(*table).into_iter().flatten() {
                    let params=row.iter().map(|v|if let Some(n)=v.as_i64(){turso::Value::Integer(n)}else{turso::Value::Text(v.as_str().unwrap().to_owned())}).collect::<Vec<_>>();
                    conn.execute(&format!("INSERT INTO {table} VALUES ({placeholders})"),params).await?;
                }
            }
            if snapshot.format == 1 { migrate_device_certificates(&conn).await?; }
            conn.execute("DELETE FROM sessions",()).await?;
            conn.execute("DELETE FROM api_tokens",()).await?;
            conn.execute("DELETE FROM auth_session_activity",()).await?;
            conn.execute("DELETE FROM restore_stage",()).await?;
            conn.execute("INSERT INTO audit (created,actor,action) VALUES (?1,'local CLI','backup restored; sessions revoked')",[now()]).await?;
            conn.execute("COMMIT",()).await?;anyhow::Ok(())
        }.await;
        if result.is_err() {
            let _ = conn.execute("ROLLBACK", ()).await;
        }
        result
    }
    pub async fn acme_jobs(&self) -> Result<Vec<crate::acme::Job>> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query("SELECT json FROM acme_jobs ORDER BY name", ())
            .await?;
        let mut jobs = Vec::new();
        while let Some(row) = rows.next().await? {
            jobs.push(serde_json::from_str(&row.get::<String>(0)?)?);
        }
        Ok(jobs)
    }
    pub async fn set_acme_job(&self, settings: crate::acme::Settings, actor: &str) -> Result<()> {
        settings.validate()?;
        let job = crate::acme::Job {
            settings,
            next_attempt: 0,
            last_success: None,
            last_error: None,
            failures: 0,
        };
        let conn = self.connection.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result=async {
        let mut rows=conn.query("SELECT COUNT(*) FROM acme_jobs WHERE name<>?1",[job.settings.name.as_str()]).await?;
        ensure!(rows.next().await?.unwrap().get::<i64>(0)? < 100,"ACME schedule inventory is limited to 100 jobs");drop(rows);
        conn.execute("INSERT INTO acme_jobs (name,json) VALUES (?1,?2) ON CONFLICT(name) DO UPDATE SET json=excluded.json",turso::params![job.settings.name.as_str(),serde_json::to_string(&job)?]).await?;
        conn.execute(
            "INSERT INTO audit (created,actor,action) VALUES (?1,?2,?3)",
            turso::params![
                now(),
                actor,
                format!("ACME schedule updated: {}", job.settings.name)
            ],
        )
        .await?;
        conn.execute("COMMIT",()).await?;anyhow::Ok(())
        }.await;
        if result.is_err() {
            let _ = conn.execute("ROLLBACK", ()).await;
        }
        result
    }
    pub async fn acme_job_unchanged(&self, settings: &crate::acme::Settings) -> Result<bool> {
        Ok(self
            .acme_jobs()
            .await?
            .iter()
            .any(|j| &j.settings == settings))
    }
    pub async fn finish_acme_job(&self, job: &crate::acme::Job) -> Result<()> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query(
                "SELECT json FROM acme_jobs WHERE name=?1",
                [job.settings.name.as_str()],
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(());
        };
        let current: crate::acme::Job = serde_json::from_str(&row.get::<String>(0)?)?;
        drop(rows);
        if current.settings == job.settings {
            conn.execute(
                "UPDATE acme_jobs SET json=?1 WHERE name=?2",
                turso::params![serde_json::to_string(job)?, job.settings.name.as_str()],
            )
            .await?;
        }
        Ok(())
    }
    pub async fn delete_acme_job(&self, name: &str) -> Result<()> {
        self.connection
            .lock()
            .await
            .execute("DELETE FROM acme_jobs WHERE name=?1", [name])
            .await?;
        Ok(())
    }
    pub async fn acme_account(&self, name: &str) -> Result<Option<String>> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query("SELECT json FROM acme_accounts WHERE name=?1", [name])
            .await?;
        Ok(rows.next().await?.map(|r| r.get::<String>(0)).transpose()?)
    }
    pub async fn save_acme_account(&self, name: &str, json: &str) -> Result<()> {
        self.connection.lock().await.execute("INSERT INTO acme_accounts (name,json) VALUES (?1,?2) ON CONFLICT(name) DO UPDATE SET json=excluded.json",turso::params![name,json]).await?;
        Ok(())
    }
    pub async fn record_audit(&self, actor: &str, action: &str) -> Result<()> {
        self.connection
            .lock()
            .await
            .execute(
                "INSERT INTO audit (created, actor, action) VALUES (?1,?2,?3)",
                turso::params![now(), actor, action],
            )
            .await?;
        Ok(())
    }
    pub async fn resolve_certificates(
        &self,
        config: &Config,
    ) -> Result<crate::certificates::Resolved> {
        let config = config.expand_domain_tls()?;
        let mut resolved = crate::certificates::Resolved::new();
        if config.management_certificate.is_none()
            && config
                .virtual_servers
                .iter()
                .all(|vs| vs.certificate.is_none() && vs.sni_certificates.is_empty())
            && config
                .domain_routes
                .iter()
                .all(|route| route.certificate.is_none())
        {
            return Ok(resolved);
        }
        let began = std::time::Instant::now();
        let conn = self.connection.lock().await;
        tracing::debug!(
            wait_ms = began.elapsed().as_millis() as u64,
            "certificate database lock acquired"
        );
        let mut names = Vec::new();
        if let Some(name) = &config.management_certificate {
            let mut rows = conn
                .query(
                    "SELECT certificate, private_key FROM device_certificates WHERE name=?1",
                    [name.as_str()],
                )
                .await?;
            let row = rows
                .next()
                .await?
                .context("unknown device certificate for management")?;
            resolved.insert(
                crate::certificates::StoreKind::Device.key(name),
                crate::certificates::server_config(&row.get::<String>(0)?, &row.get::<String>(1)?)?,
            );
        }
        for vs in &config.virtual_servers {
            if let Some(name) = &vs.certificate {
                names.push(name.clone());
            }
            for name in vs.sni_certificates.values() {
                names.push(name.clone());
            }
        }
        names.extend(
            config
                .domain_routes
                .iter()
                .filter_map(|r| r.certificate.clone()),
        );
        for name in &names {
            if resolved.contains_key(name) {
                continue;
            }
            let mut rows = conn
                .query(
                    "SELECT certificate, private_key FROM certificates WHERE name=?1",
                    [name.as_str()],
                )
                .await?;
            let row = rows
                .next()
                .await?
                .ok_or_else(|| anyhow::anyhow!("unknown managed certificate {name}"))?;
            resolved.insert(
                name.clone(),
                crate::certificates::server_config(&row.get::<String>(0)?, &row.get::<String>(1)?)?,
            );
        }
        for vs in &config.virtual_servers {
            for (host, name) in &vs.sni_certificates {
                let mut rows = conn
                    .query(
                        "SELECT certificate FROM certificates WHERE name=?1",
                        [name.as_str()],
                    )
                    .await?;
                let pem = rows
                    .next()
                    .await?
                    .context("unknown SNI certificate")?
                    .get::<String>(0)?;
                let metadata = crate::certificates::metadata(name, &pem, 0)?;
                ensure!(
                    metadata
                        .dns_names
                        .iter()
                        .any(|pattern| crate::certificates::matches_dns(pattern, host)),
                    "SNI certificate does not cover hostname {host}"
                );
            }
        }
        for route in &config.domain_routes {
            if let Some(name) = &route.certificate {
                let mut rows = conn
                    .query(
                        "SELECT certificate FROM certificates WHERE name=?1",
                        [name.as_str()],
                    )
                    .await?;
                let pem = rows
                    .next()
                    .await?
                    .context("unknown route certificate")?
                    .get::<String>(0)?;
                let metadata = crate::certificates::metadata(name, &pem, 0)?;
                ensure!(
                    metadata
                        .dns_names
                        .iter()
                        .any(|pattern| crate::certificates::matches_dns(pattern, &route.hostname)),
                    "route certificate does not cover hostname {}",
                    route.hostname
                );
            }
        }
        Ok(resolved)
    }
    pub async fn certificates_in(
        &self,
        scope: crate::certificates::StoreKind,
    ) -> Result<Vec<crate::certificates::Metadata>> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query(
                &format!(
                    "SELECT name, certificate, created FROM {} ORDER BY name",
                    scope.table()
                ),
                (),
            )
            .await?;
        let mut result = Vec::new();
        while let Some(row) = rows.next().await? {
            result.push(crate::certificates::metadata(
                &row.get::<String>(0)?,
                &row.get::<String>(1)?,
                row.get::<i64>(2)?,
            )?);
        }
        Ok(result)
    }
    pub async fn certificate_pem_in(
        &self,
        scope: crate::certificates::StoreKind,
        name: &str,
    ) -> Result<Option<String>> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query(
                &format!("SELECT certificate FROM {} WHERE name=?1", scope.table()),
                [name],
            )
            .await?;
        Ok(rows
            .next()
            .await?
            .map(|row| row.get::<String>(0))
            .transpose()?)
    }
    pub async fn import_certificate_in(
        &self,
        scope: crate::certificates::StoreKind,
        name: &str,
        certificate: &str,
        private_key: &str,
        actor: &str,
    ) -> Result<()> {
        crate::certificates::validate_name(name)?;
        crate::certificates::server_config(certificate, private_key)?;
        crate::certificates::metadata(name, certificate, now())?;
        let conn = self.connection.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result = async {
            let mut pending=conn.query("SELECT COUNT(*) FROM certificate_requests WHERE name=?1",[scope.request_key(name)]).await?;
            ensure!(pending.next().await?.unwrap().get::<i64>(0)? == 0,"a CSR is pending under this name; complete the request or choose another name");drop(pending);
            let mut rows = conn.query(&format!("SELECT COUNT(*) FROM {}", scope.table()), ()).await?;
            ensure!(rows.next().await?.unwrap().get::<i64>(0)? < 1000, "certificate inventory is limited to 1000 objects");
            drop(rows);
            conn.execute(&format!("INSERT INTO {} (name, certificate, private_key, created) VALUES (?1,?2,?3,?4)", scope.table()), turso::params![name,certificate,private_key,now()]).await.map_err(|_| anyhow::anyhow!("certificate name already exists or store unavailable; use a new name for rotation"))?;
            conn.execute("INSERT INTO audit (created, actor, action) VALUES (?1,?2,?3)", turso::params![now(),actor,format!("certificate imported: {name}")]).await?;
            conn.execute("COMMIT", ()).await?;
            anyhow::Ok(())
        }.await;
        if result.is_err() {
            let _ = conn.execute("ROLLBACK", ()).await;
        }
        result
    }
    pub async fn delete_certificate_in(
        &self,
        scope: crate::certificates::StoreKind,
        name: &str,
        actor: &str,
    ) -> Result<bool> {
        let conn = self.connection.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result = async {
            let mut rows = conn
                .query(
                    &format!("SELECT name FROM {} WHERE name=?1", scope.table()),
                    [name],
                )
                .await?;
            let exists = rows.next().await?.is_some();
            drop(rows);
            if exists {
                conn.execute(
                    &format!("DELETE FROM {} WHERE name=?1", scope.table()),
                    [name],
                )
                .await?;
                conn.execute(
                    "INSERT INTO audit (created, actor, action) VALUES (?1,?2,?3)",
                    turso::params![now(), actor, format!("certificate deleted: {name}")],
                )
                .await?;
            }
            conn.execute("COMMIT", ()).await?;
            anyhow::Ok(exists)
        }
        .await;
        if result.is_err() {
            let _ = conn.execute("ROLLBACK", ()).await;
        }
        result
    }
    pub async fn certificate_requests(
        &self,
        scope: crate::certificates::StoreKind,
    ) -> Result<serde_json::Value> {
        let conn = self.connection.lock().await;
        let prefix = scope.request_key("");
        let mut rows = conn.query("SELECT name,csr,names,created FROM certificate_requests WHERE name LIKE ?1 ORDER BY name", [format!("{prefix}%")]).await?;
        let mut objects = Vec::new();
        while let Some(row) = rows.next().await? {
            let key = row.get::<String>(0)?;
            objects.push(serde_json::json!({"name":key.strip_prefix(&prefix).unwrap(),"csr":row.get::<String>(1)?,"names":serde_json::from_str::<Vec<String>>(&row.get::<String>(2)?)?,"created":row.get::<i64>(3)?}));
        }
        Ok(serde_json::json!(objects))
    }
    pub async fn create_certificate_request(
        &self,
        scope: crate::certificates::StoreKind,
        request: &crate::certificates::Generate,
        actor: &str,
    ) -> Result<String> {
        crate::certificates::validate_name(&request.name)?;
        let names = request.names()?;
        let (csr, private_key) = request.csr()?;
        let conn = self.connection.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result = async {
            let mut rows = conn
                .query(
                    &format!("SELECT COUNT(*) FROM {} WHERE name=?1", scope.table()),
                    [request.name.as_str()],
                )
                .await?;
            ensure!(
                rows.next().await?.unwrap().get::<i64>(0)? == 0,
                "certificate already exists; use a new name"
            );
            drop(rows);
            let mut rows = conn
                .query("SELECT COUNT(*) FROM certificate_requests", ())
                .await?;
            ensure!(
                rows.next().await?.unwrap().get::<i64>(0)? < 1000,
                "CSR inventory is limited to 1000 requests"
            );
            drop(rows);
            conn.execute(
                "INSERT INTO certificate_requests VALUES (?1,?2,?3,?4,?5)",
                turso::params![
                    scope.request_key(&request.name),
                    csr.as_str(),
                    private_key,
                    serde_json::to_string(&names)?,
                    now()
                ],
            )
            .await
            .context("CSR name already exists or store unavailable")?;
            conn.execute(
                "INSERT INTO audit (created,actor,action) VALUES (?1,?2,?3)",
                turso::params![
                    now(),
                    actor,
                    format!("CSR created: {}", scope.request_key(&request.name))
                ],
            )
            .await?;
            conn.execute("COMMIT", ()).await?;
            anyhow::Ok(csr)
        }
        .await;
        if result.is_err() {
            let _ = conn.execute("ROLLBACK", ()).await;
        }
        result
    }
    pub async fn complete_certificate_request(
        &self,
        scope: crate::certificates::StoreKind,
        name: &str,
        pem: &str,
        actor: &str,
    ) -> Result<()> {
        let conn = self.connection.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result = async {
            let mut rows = conn
                .query(
                    "SELECT private_key,names FROM certificate_requests WHERE name=?1",
                    [scope.request_key(name)],
                )
                .await?;
            let row = rows.next().await?.context("unknown pending CSR")?;
            let key = row.get::<String>(0)?;
            let names: Vec<String> = serde_json::from_str(&row.get::<String>(1)?)?;
            drop(rows);
            crate::certificates::server_config(pem, &key)?;
            crate::certificates::covers_names(pem, &names)?;
            let mut rows = conn
                .query(&format!("SELECT COUNT(*) FROM {}", scope.table()), ())
                .await?;
            ensure!(
                rows.next().await?.unwrap().get::<i64>(0)? < 1000,
                "certificate inventory is limited to 1000 objects"
            );
            drop(rows);
            conn.execute(
                &format!("INSERT INTO {} VALUES (?1,?2,?3,?4)", scope.table()),
                turso::params![name, pem, key, now()],
            )
            .await
            .context("certificate already exists; choose a new request name")?;
            conn.execute(
                "DELETE FROM certificate_requests WHERE name=?1",
                [scope.request_key(name)],
            )
            .await?;
            conn.execute(
                "INSERT INTO audit (created,actor,action) VALUES (?1,?2,?3)",
                turso::params![
                    now(),
                    actor,
                    format!("CSR completed: {}", scope.request_key(name))
                ],
            )
            .await?;
            conn.execute("COMMIT", ()).await?;
            anyhow::Ok(())
        }
        .await;
        if result.is_err() {
            let _ = conn.execute("ROLLBACK", ()).await;
        }
        result
    }
    pub async fn delete_certificate_request(
        &self,
        scope: crate::certificates::StoreKind,
        name: &str,
        actor: &str,
    ) -> Result<()> {
        let conn = self.connection.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result = async {
            conn.execute(
                "DELETE FROM certificate_requests WHERE name=?1",
                [scope.request_key(name)],
            )
            .await?;
            conn.execute(
                "INSERT INTO audit (created,actor,action) VALUES (?1,?2,?3)",
                turso::params![
                    now(),
                    actor,
                    format!("CSR deleted: {}", scope.request_key(name))
                ],
            )
            .await?;
            conn.execute("COMMIT", ()).await?;
            anyhow::Ok(())
        }
        .await;
        if result.is_err() {
            let _ = conn.execute("ROLLBACK", ()).await;
        }
        result
    }
    pub async fn configuration_history(&self) -> Result<serde_json::Value> {
        let conn = self.connection.lock().await;
        let mut rows = conn.query("SELECT revision, created, actor FROM configurations ORDER BY revision DESC LIMIT 100", ()).await?;
        let mut entries = Vec::new();
        while let Some(row) = rows.next().await? {
            entries.push(serde_json::json!({"revision":row.get::<i64>(0)?,"created":row.get::<i64>(1)?,"actor":row.get::<String>(2)?}));
        }
        Ok(serde_json::json!(entries))
    }
    pub async fn configuration_revision(&self, revision: u64) -> Result<Option<Config>> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query(
                "SELECT json FROM configurations WHERE revision=?1",
                [i64::try_from(revision)?],
            )
            .await?;
        match rows.next().await? {
            Some(row) => Ok(Some(serde_json::from_str(&row.get::<String>(0)?)?)),
            None => Ok(None),
        }
    }
    pub async fn latest_traffic(&self) -> Result<Option<serde_json::Value>> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query(
                "SELECT json FROM traffic_samples ORDER BY id DESC LIMIT 1",
                (),
            )
            .await?;
        Ok(match rows.next().await? {
            Some(row) => Some(serde_json::from_str(&row.get::<String>(0)?)?),
            None => None,
        })
    }
    pub async fn reset_traffic(
        &self,
        revision: u64,
        snapshot: serde_json::Value,
        actor: &str,
    ) -> Result<()> {
        let conn = self.connection.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result = async {
            conn.execute("DELETE FROM traffic_samples", ()).await?;
            conn.execute(
                "INSERT INTO traffic_samples (created,revision,json) VALUES (?1,?2,?3)",
                turso::params![now(), revision as i64, serde_json::to_string(&snapshot)?],
            )
            .await?;
            conn.execute(
                "INSERT INTO audit (created, actor, action) VALUES (?1,?2,?3)",
                turso::params![now(), actor, "statistics reset"],
            )
            .await?;
            conn.execute("COMMIT", ()).await?;
            anyhow::Ok(())
        }
        .await;
        if result.is_err() {
            let _ = conn.execute("ROLLBACK", ()).await;
        }
        result
    }
    pub async fn record_traffic(&self, revision: u64, snapshot: serde_json::Value) -> Result<()> {
        let conn = self.connection.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result = async {
            conn.execute("INSERT INTO traffic_samples (created, revision, json) VALUES (?1, ?2, ?3)", turso::params![now(), revision as i64, serde_json::to_string(&snapshot)?]).await?;
            conn.execute("DELETE FROM traffic_samples WHERE created<?1", [now()-604800]).await?;
            conn.execute("DELETE FROM traffic_samples WHERE id<(SELECT id FROM traffic_samples ORDER BY id DESC LIMIT 1 OFFSET 19999)", ()).await?;
            conn.execute("COMMIT", ()).await?;
            anyhow::Ok(())
        }.await;
        if result.is_err() {
            let _ = conn.execute("ROLLBACK", ()).await;
        }
        result
    }
    pub async fn traffic_history(&self) -> Result<serde_json::Value> {
        let samples = {
            let conn = self.connection.lock().await;
            let mut rows=conn.query("SELECT created, revision, json FROM traffic_samples ORDER BY id DESC LIMIT 300",()).await?;
            let mut samples = Vec::new();
            while let Some(row) = rows.next().await? {
                samples.push((
                    row.get::<i64>(0)?,
                    row.get::<i64>(1)?,
                    row.get::<String>(2)?,
                ));
            }
            samples
        };
        // Large snapshots must not occupy the shared connection or async worker while parsing.
        tokio::task::spawn_blocking(move || {
            let mut entries=Vec::new();
            for (created,revision,text) in samples {
                let snapshot=serde_json::from_str::<serde_json::Value>(&text)?;
                let servers=if snapshot.is_array(){snapshot.clone()}else{snapshot["virtual_servers"].clone()};
                entries.push(serde_json::json!({"created":created,"revision":revision,"epoch":snapshot.get("epoch"),"virtual_servers":servers}));
            }
            entries.reverse();
            anyhow::Ok(serde_json::json!(entries))
        }).await.context("traffic history worker failed")?
    }
    pub async fn audit(&self) -> Result<serde_json::Value> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query(
                "SELECT created, actor, action FROM audit ORDER BY id DESC LIMIT 100",
                (),
            )
            .await?;
        let mut entries = Vec::new();
        while let Some(row) = rows.next().await? {
            entries.push(serde_json::json!({"created": row.get::<i64>(0)?, "actor": row.get::<String>(1)?, "action": row.get::<String>(2)?}));
        }
        Ok(serde_json::json!(entries))
    }
    pub async fn open(path: &Path) -> Result<Self> {
        use fs2::FileExt;
        use std::os::unix::fs::OpenOptionsExt;
        let lock = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(format!("{}.lock", path.display()))?;
        lock.try_lock_exclusive().map_err(|_| anyhow::anyhow!("database is in use; stop the other RiverLB process before local administrator or database commands"))?;
        // Creation is private even when the caller's umask is permissive.
        let _ = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .mode(0o600)
            .open(path)?;
        let database = turso::Builder::new_local(path.to_string_lossy().as_ref())
            .build()
            .await?;
        let connection = database.connect()?;
        connection.execute("BEGIN IMMEDIATE", ()).await?;
        for sql in [
            "CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS administrators (username TEXT PRIMARY KEY, password_hash TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS sessions (token_hash TEXT PRIMARY KEY, username TEXT NOT NULL, expires INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS configurations (revision INTEGER PRIMARY KEY, json TEXT NOT NULL, created INTEGER NOT NULL, actor TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, created INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS traffic_samples (id INTEGER PRIMARY KEY, created INTEGER NOT NULL, revision INTEGER NOT NULL, json TEXT NOT NULL)",
            "CREATE INDEX IF NOT EXISTS traffic_samples_created ON traffic_samples (created)",
            "CREATE TABLE IF NOT EXISTS certificates (name TEXT PRIMARY KEY, certificate TEXT NOT NULL, private_key TEXT NOT NULL, created INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS device_certificates (name TEXT PRIMARY KEY, certificate TEXT NOT NULL, private_key TEXT NOT NULL, created INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS certificate_requests (name TEXT PRIMARY KEY, csr TEXT NOT NULL, private_key TEXT NOT NULL, names TEXT NOT NULL, created INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS acme_jobs (name TEXT PRIMARY KEY, json TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS acme_accounts (name TEXT PRIMARY KEY, json TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS restore_stage (id INTEGER PRIMARY KEY, json TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS auth_accounts (username TEXT PRIMARY KEY, json TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS auth_settings (id INTEGER PRIMARY KEY, json TEXT NOT NULL)",
            "CREATE TABLE IF NOT EXISTS auth_session_activity (token_hash TEXT PRIMARY KEY, last_seen INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS api_tokens (id TEXT PRIMARY KEY, token_hash TEXT NOT NULL UNIQUE, username TEXT NOT NULL, name TEXT NOT NULL, scope TEXT NOT NULL, created INTEGER NOT NULL, expires INTEGER NOT NULL, last_used INTEGER NOT NULL)",
        ] {
            connection.execute(sql, ()).await?;
        }
        let mut versions = connection
            .query("SELECT version FROM schema_version", ())
            .await?;
        let version = versions
            .next()
            .await?
            .map(|row| row.get::<i64>(0))
            .transpose()?;
        drop(versions);
        match version {
            Some(1..=4) => {
                migrate_device_certificates(&connection).await?;
                connection
                    .execute("UPDATE schema_version SET version=6", ())
                    .await?;
            }
            Some(5) => {
                connection
                    .execute("UPDATE schema_version SET version=6", ())
                    .await?;
            }
            Some(6) => {}
            None => {
                connection
                    .execute("INSERT INTO schema_version VALUES (6)", ())
                    .await?;
            }
            _ => {
                connection.execute("ROLLBACK", ()).await?;
                anyhow::bail!("unsupported database schema");
            }
        }
        // Audit forwarding uses IDs as cursors; retention must never recycle an ID.
        let mut definition = connection
            .query(
                "SELECT sql FROM sqlite_master WHERE type='table' AND name='audit'",
                (),
            )
            .await?;
        let audit_sql = definition
            .next()
            .await?
            .context("audit table missing")?
            .get::<String>(0)?;
        drop(definition);
        if !audit_sql.to_ascii_uppercase().contains("AUTOINCREMENT") {
            connection.execute("CREATE TABLE audit_monotonic (id INTEGER PRIMARY KEY AUTOINCREMENT, created INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL)",()).await?;
            connection
                .execute("INSERT INTO audit_monotonic SELECT * FROM audit", ())
                .await?;
            connection.execute("DROP TABLE audit", ()).await?;
            connection
                .execute("ALTER TABLE audit_monotonic RENAME TO audit", ())
                .await?;
        }
        connection.execute("COMMIT", ()).await?;
        Ok(Self {
            connection: Mutex::new(connection),
            _database: database,
            dummy_hash: hash_password("unusable-dummy-password".into()).await?,
            _lock: lock,
        })
    }
    pub async fn load(&self) -> Result<Option<(Config, u64)>> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query(
                "SELECT json, revision FROM configurations ORDER BY revision DESC LIMIT 1",
                (),
            )
            .await?;
        if let Some(row) = rows.next().await? {
            Ok(Some((
                serde_json::from_str(&row.get::<String>(0)?)?,
                row.get::<i64>(1)? as u64,
            )))
        } else {
            Ok(None)
        }
    }
    pub async fn save(&self, config: &Config, revision: u64, actor: &str) -> Result<()> {
        self.save_with_certificate(config, revision, actor, None)
            .await
    }
    pub async fn ha_certificates(&self) -> Result<Vec<crate::ha::Certificate>> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query(
                "SELECT name,certificate,private_key FROM certificates ORDER BY name",
                (),
            )
            .await?;
        let mut certs = Vec::new();
        while let Some(row) = rows.next().await? {
            certs.push(crate::ha::Certificate {
                name: row.get(0)?,
                certificate: row.get(1)?,
                private_key: row.get(2)?,
            });
        }
        Ok(certs)
    }
    pub async fn ha_material(&self) -> Result<crate::ha::Material> {
        let conn = self.connection.lock().await;
        let mut material = crate::ha::Material::default();
        let mut rows=conn.query("SELECT name,csr,private_key,names,created FROM certificate_requests WHERE name LIKE 'virtual_server:%' ORDER BY name",()).await?;
        while let Some(row) = rows.next().await? {
            material.requests.push((
                row.get::<String>(0)?
                    .trim_start_matches("virtual_server:")
                    .to_owned(),
                row.get(1)?,
                row.get(2)?,
                serde_json::from_str(&row.get::<String>(3)?)?,
                row.get(4)?,
            ));
        }
        drop(rows);
        let mut rows = conn
            .query("SELECT json FROM acme_jobs ORDER BY name", ())
            .await?;
        while let Some(row) = rows.next().await? {
            let job: crate::acme::Job = serde_json::from_str(&row.get::<String>(0)?)?;
            if job.settings.store == crate::certificates::StoreKind::VirtualServer {
                material.renewals.push(job);
            }
        }
        drop(rows);
        let keys = material
            .renewals
            .iter()
            .map(|j| format!("{}|{}", j.settings.directory, j.settings.email))
            .collect::<std::collections::HashSet<_>>();
        for key in keys {
            let mut rows = conn
                .query(
                    "SELECT json FROM acme_accounts WHERE name=?1",
                    [key.as_str()],
                )
                .await?;
            if let Some(row) = rows.next().await? {
                material.accounts.push((key, row.get(0)?));
            }
        }
        material.accounts.sort_by(|a, b| a.0.cmp(&b.0));
        Ok(material)
    }
    pub async fn save_ha_configuration(
        &self,
        config: &Config,
        revision: u64,
        certificates: &[crate::ha::Certificate],
        material: &crate::ha::Material,
    ) -> Result<()> {
        let conn = self.connection.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result=async {
            conn.execute("DELETE FROM certificates",()).await?;
            for cert in certificates {conn.execute("INSERT INTO certificates VALUES (?1,?2,?3,?4)",turso::params![cert.name.as_str(),cert.certificate.as_str(),cert.private_key.as_str(),now()]).await?;}
            conn.execute("DELETE FROM certificate_requests WHERE name LIKE 'virtual_server:%'",()).await?;
            for (name,csr,key,names,created) in &material.requests {conn.execute("INSERT INTO certificate_requests VALUES (?1,?2,?3,?4,?5)",turso::params![format!("virtual_server:{name}"),csr.as_str(),key.as_str(),serde_json::to_string(names)?,*created]).await?;}
            let mut rows=conn.query("SELECT name,json FROM acme_jobs",()).await?;let mut remove=Vec::new();
            while let Some(row)=rows.next().await? {let job:crate::acme::Job=serde_json::from_str(&row.get::<String>(1)?)?;if job.settings.store==crate::certificates::StoreKind::VirtualServer {remove.push(row.get::<String>(0)?);}}drop(rows);
            for name in remove {conn.execute("DELETE FROM acme_jobs WHERE name=?1",[name]).await?;}
            for job in &material.renewals {conn.execute("INSERT INTO acme_jobs VALUES (?1,?2)",turso::params![job.settings.name.as_str(),serde_json::to_string(job)?]).await?;}
            for (name,credentials) in &material.accounts {conn.execute("INSERT INTO acme_accounts VALUES (?1,?2) ON CONFLICT(name) DO UPDATE SET json=excluded.json",turso::params![name.as_str(),credentials.as_str()]).await?;}
            conn.execute("INSERT INTO configurations VALUES (?1,?2,?3,'HA peer synchronization')",turso::params![revision as i64,serde_json::to_string(config)?,now()]).await?;
            conn.execute("INSERT INTO audit (created,actor,action) VALUES (?1,'HA peer','traffic configuration synchronized')",[now()]).await?;
            conn.execute("COMMIT",()).await?;anyhow::Ok(())
        }.await;
        if result.is_err() {
            let _ = conn.execute("ROLLBACK", ()).await;
        }
        result
    }
    pub async fn save_with_certificate(
        &self,
        config: &Config,
        revision: u64,
        actor: &str,
        certificate: Option<&crate::acme::Issued>,
    ) -> Result<()> {
        let conn = self.connection.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result = async {
            if let Some(cert) = certificate {
                let mut rows=conn.query(&format!("SELECT COUNT(*) FROM {} WHERE name<>?1",cert.store.table()),[cert.name.as_str()]).await?;
                ensure!(rows.next().await?.unwrap().get::<i64>(0)? < 1000,"certificate inventory is limited to 1000 objects");drop(rows);
                conn.execute(&format!("INSERT INTO {} (name,certificate,private_key,created) VALUES (?1,?2,?3,?4) ON CONFLICT(name) DO UPDATE SET certificate=excluded.certificate,private_key=excluded.private_key,created=excluded.created",cert.store.table()),turso::params![cert.name.as_str(),cert.certificate.as_str(),cert.private_key.as_str(),now()]).await?;
            }
            conn.execute("INSERT INTO configurations VALUES (?1, ?2, ?3, ?4)", turso::params![revision as i64, serde_json::to_string(config)?, now(), actor]).await?;
            conn.execute("INSERT INTO audit (created, actor, action) VALUES (?1, ?2, 'configuration applied')", turso::params![now(), actor]).await?;
            conn.execute("COMMIT", ()).await?;
            anyhow::Ok(())
        }.await;
        if result.is_err() {
            let _ = conn.execute("ROLLBACK", ()).await;
        }
        result
    }
    pub async fn set_admin(&self, username: &str, password: String) -> Result<()> {
        ensure!(
            !username.is_empty()
                && username.len() <= 128
                && username
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c)),
            "invalid username"
        );
        let hash = hash_password(password).await?;
        let conn = self.connection.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result = async {
            conn.execute("INSERT INTO administrators VALUES (?1, ?2) ON CONFLICT(username) DO UPDATE SET password_hash=excluded.password_hash", [username, &hash]).await?;
            revoke_account_sessions(&conn,username).await?;
            conn.execute("INSERT INTO auth_accounts (username,json) VALUES (?1,?2) ON CONFLICT(username) DO UPDATE SET json=excluded.json",turso::params![username,serde_json::to_string(&crate::auth::AccountSecurity::default())?]).await?;
            conn.execute("DELETE FROM api_tokens WHERE username=?1", [username]).await?;
            conn.execute("INSERT INTO audit (created, actor, action) VALUES (?1, ?2, 'administrator password set')", turso::params![now(), username]).await?;
            conn.execute("COMMIT", ()).await?;
            anyhow::Ok(())
        }.await;
        if result.is_err() {
            let _ = conn.execute("ROLLBACK", ()).await;
        }
        result
    }

    #[cfg(test)]
    pub async fn administrators(&self) -> Result<Vec<String>> {
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query("SELECT username FROM administrators ORDER BY username", ())
            .await?;
        let mut users = vec![];
        while let Some(row) = rows.next().await? {
            users.push(row.get::<String>(0)?);
        }
        Ok(users)
    }
    pub async fn manage_administrator(
        &self,
        actor: &str,
        username: &str,
        action: &str,
        password: Option<String>,
    ) -> Result<()> {
        self.manage_account(actor, username, action, password, None)
            .await
    }
    pub async fn manage_account(
        &self,
        actor: &str,
        username: &str,
        action: &str,
        password: Option<String>,
        role: Option<crate::auth::Role>,
    ) -> Result<()> {
        ensure!(
            !username.is_empty()
                && username.len() <= 128
                && username
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_-.".contains(c)),
            "Invalid username"
        );
        ensure!(
            matches!(action, "create" | "password" | "delete" | "revoke" | "role"),
            "Unknown account action"
        );
        let hash = if matches!(action, "create" | "password") {
            Some(hash_password(password.context("New password required")?).await?)
        } else {
            None
        };
        let conn = self.connection.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result = async {
            require_account(&conn, actor).await?;
            ensure!(
                account_security(&conn, actor).await?.role == crate::auth::Role::Administrator
                    || (actor == username && matches!(action, "password" | "revoke")),
                "Administrator role required for account changes"
            );
            let mut rows = conn
                .query(
                    "SELECT username FROM administrators WHERE username=?1",
                    [username],
                )
                .await?;
            let exists = rows.next().await?.is_some();
            drop(rows);
            ensure!(
                if action == "create" { !exists } else { exists },
                if action == "create" {
                    "Account already exists"
                } else {
                    "Account not found"
                }
            );
            let mut security = account_security(&conn, username).await?;
            if action == "role" {
                ensure!(role.is_some(), "Role required");
            }
            if (action == "delete"
                || (action == "role" && role != Some(crate::auth::Role::Administrator)))
                && security.role == crate::auth::Role::Administrator
            {
                let mut users = conn
                    .query("SELECT username FROM administrators", ())
                    .await?;
                let mut count = 0;
                while let Some(user) = users.next().await? {
                    if account_security(&conn, &user.get::<String>(0)?).await?.role
                        == crate::auth::Role::Administrator
                    {
                        count += 1;
                    }
                }
                ensure!(count > 1, "Cannot remove or demote the last administrator");
            }
            if action == "delete" {
                ensure!(actor != username, "Cannot delete your signed-in account");
                let mut rows = conn
                    .query("SELECT COUNT(*) FROM administrators", ())
                    .await?;
                ensure!(
                    rows.next()
                        .await?
                        .context("Account count missing")?
                        .get::<i64>(0)?
                        > 1,
                    "Cannot delete the last administrator"
                );
                drop(rows);
                conn.execute("DELETE FROM administrators WHERE username=?1", [username])
                    .await?;
                conn.execute("DELETE FROM auth_accounts WHERE username=?1", [username])
                    .await?;
            } else if action == "create" {
                conn.execute(
                    "INSERT INTO administrators VALUES (?1,?2)",
                    turso::params![username, hash.as_deref().unwrap()],
                )
                .await?;
                security.role = role.unwrap_or_default();
                save_account_security(&conn, username, &security).await?;
            } else if action == "password" {
                conn.execute(
                    "UPDATE administrators SET password_hash=?2 WHERE username=?1",
                    turso::params![username, hash.as_deref().unwrap()],
                )
                .await?;
            } else if action == "role" {
                security.role = role.unwrap();
                save_account_security(&conn, username, &security).await?;
            }
            revoke_account_sessions(&conn, username).await?;
            conn.execute("DELETE FROM api_tokens WHERE username=?1", [username])
                .await?;
            conn.execute(
                "INSERT INTO audit (created,actor,action) VALUES (?1,?2,?3)",
                turso::params![
                    now(),
                    actor,
                    format!("local administrator {action}: {username}")
                ],
            )
            .await?;
            conn.execute("COMMIT", ()).await?;
            anyhow::Ok(())
        }
        .await;
        if result.is_err() {
            let _ = conn.execute("ROLLBACK", ()).await;
        }
        result
    }
    #[cfg(test)]
    pub async fn login(&self, username: &str, password: String) -> Result<Option<String>> {
        self.login_with_mfa(username, password, None).await
    }
    pub async fn login_with_mfa(
        &self,
        username: &str,
        password: String,
        code: Option<&str>,
    ) -> Result<Option<String>> {
        let Some((verified_hash, verified_secret)) =
            self.verified_credentials(username, password, code).await?
        else {
            return Ok(None);
        };
        self.issue_verified_session(username, verified_hash, verified_secret)
            .await
    }
    async fn issue_verified_session(
        &self,
        username: &str,
        verified_hash: String,
        verified_secret: String,
    ) -> Result<Option<String>> {
        let token = crate::auth::random_hex(32);
        let conn = self.connection.lock().await;
        auth_transaction(&conn,async {
        // A reset or MFA change after verification must never mint a new session.
        let mut rows=conn.query("SELECT password_hash FROM administrators WHERE username=?1",[username]).await?;
        let unchanged=rows.next().await?.is_some_and(|row|row.get::<String>(0).is_ok_and(|hash|hash==verified_hash));drop(rows);
        if !unchanged || account_security(&conn,username).await?.mfa_secret!=verified_secret {return Ok(None);}
        conn.execute("DELETE FROM auth_session_activity WHERE token_hash IN (SELECT token_hash FROM sessions WHERE expires<=?1)",[now()]).await?;
        conn.execute("DELETE FROM sessions WHERE expires<=?1",[now()]).await?;
        conn.execute("INSERT INTO sessions VALUES (?1,?2,?3)",turso::params![digest(&token),username,now()+28800]).await?;
        conn.execute("INSERT INTO auth_session_activity VALUES (?1,?2)",turso::params![digest(&token),now()]).await?;
        conn.execute("INSERT INTO audit (created,actor,action) VALUES (?1,?2,'login')",turso::params![now(),username]).await?;
        Ok(Some(token))
        }).await
    }
    pub async fn verify_credentials(
        &self,
        username: &str,
        password: String,
        code: Option<&str>,
    ) -> Result<bool> {
        Ok(self
            .verified_credentials(username, password, code)
            .await?
            .is_some())
    }
    async fn verified_credentials(
        &self,
        username: &str,
        password: String,
        code: Option<&str>,
    ) -> Result<Option<(String, String)>> {
        if username.len() > 128 || password.len() > 1024 || code.is_some_and(|c| c.len() > 64) {
            return Ok(None);
        }
        let stored = {
            let conn = self.connection.lock().await;
            let mut rows = conn
                .query(
                    "SELECT password_hash FROM administrators WHERE username=?1",
                    [username],
                )
                .await?;
            match rows.next().await? {
                Some(row) => Some(row.get::<String>(0)?),
                None => None,
            }
        };
        let exists = stored.is_some();
        let hash = stored.unwrap_or_else(|| self.dummy_hash.clone());
        let verified_hash = hash.clone();
        let valid = tokio::task::spawn_blocking(move || {
            PasswordHash::new(&hash).is_ok_and(|hash| {
                Argon2::default()
                    .verify_password(password.as_bytes(), &hash)
                    .is_ok()
            })
        })
        .await?;
        if !exists || !valid {
            return Ok(None);
        }
        let conn = self.connection.lock().await;
        // Account deletion or password reset may have raced password verification.
        let mut rows = conn
            .query(
                "SELECT password_hash FROM administrators WHERE username=?1",
                [username],
            )
            .await?;
        let unchanged = match rows.next().await? {
            Some(row) => row.get::<String>(0)? == verified_hash,
            None => false,
        };
        drop(rows);
        if !unchanged {
            return Ok(None);
        }
        let mut security = account_security(&conn, username).await?;
        if security.mfa_secret.is_empty() {
            return Ok(Some((verified_hash, String::new())));
        }
        let Some(code) = code else {
            return Ok(None);
        };
        auth_transaction(&conn,async {
        if let Some(counter)=crate::auth::verify_totp(&security.mfa_secret,code,now(),security.last_counter) {
            security.last_counter=counter;
        } else {
            let hash=digest(&code.replace(['-',' '],"").to_ascii_lowercase());
            let Some(index)=security.recovery_hashes.iter().position(|h|h==&hash) else {return Ok(None);};
            security.recovery_hashes.remove(index);
            conn.execute("INSERT INTO audit (created,actor,action) VALUES (?1,?2,'MFA recovery code used')",turso::params![now(),username]).await?;
        }
        save_account_security(&conn,username,&security).await?;
        Ok(Some((verified_hash,security.mfa_secret)))
        }).await
    }
    #[cfg(test)]
    pub async fn user(&self, token: &str) -> Result<Option<String>> {
        Ok(self
            .session_principal(token, true)
            .await?
            .map(|p| p.username))
    }
    pub async fn session_principal(
        &self,
        token: &str,
        activity: bool,
    ) -> Result<Option<crate::auth::Principal>> {
        if token.len() != 64 {
            return Ok(None);
        }
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query(
                "SELECT sessions.username FROM sessions JOIN administrators ON administrators.username=sessions.username WHERE token_hash=?1 AND expires>?2",
                turso::params![digest(token), now()],
            )
            .await?;
        let Some(row) = rows.next().await? else {
            return Ok(None);
        };
        let username = row.get::<String>(0)?;
        drop(rows);
        let mut rows = conn
            .query(
                "SELECT last_seen FROM auth_session_activity WHERE token_hash=?1",
                [digest(token)],
            )
            .await?;
        let last_seen = rows
            .next()
            .await?
            .map(|r| r.get::<i64>(0))
            .transpose()?
            .unwrap_or(0);
        drop(rows);
        let settings = security_settings(&conn).await?;
        if last_seen == 0 || last_seen + settings.idle_timeout_secs as i64 <= now() {
            return Ok(None);
        }
        if activity {
            conn.execute(
                "UPDATE auth_session_activity SET last_seen=?2 WHERE token_hash=?1",
                turso::params![digest(token), now()],
            )
            .await?;
        }
        let role = account_security(&conn, &username).await?.role;
        Ok(Some(crate::auth::Principal {
            username,
            role,
            token_scope: None,
        }))
    }
    pub async fn logout(&self, token: &str) -> Result<()> {
        let conn = self.connection.lock().await;
        auth_transaction(&conn, async {
            conn.execute(
                "DELETE FROM auth_session_activity WHERE token_hash=?1",
                [digest(token)],
            )
            .await?;
            conn.execute("DELETE FROM sessions WHERE token_hash=?1", [digest(token)])
                .await?;
            Ok(())
        })
        .await
    }
}
impl Store {
    pub async fn audit_page(
        &self,
        query: &str,
        actor: &str,
        offset: u32,
        limit: u32,
    ) -> Result<serde_json::Value> {
        ensure!(
            query.len() <= 256
                && actor.len() <= 128
                && offset <= 1000000
                && (1..=200).contains(&limit),
            "Invalid audit search bounds"
        );
        let conn = self.connection.lock().await;
        let condition = "(instr(lower(action),lower(?1))>0 OR instr(lower(actor),lower(?1))>0) AND (?2='' OR actor=?2)";
        let mut rows = conn
            .query(
                &format!("SELECT COUNT(*) FROM audit WHERE {condition}"),
                turso::params![query, actor],
            )
            .await?;
        let total = rows.next().await?.unwrap().get::<i64>(0)?;
        drop(rows);
        let mut rows=conn.query(&format!("SELECT id,created,actor,action FROM audit WHERE {condition} ORDER BY id DESC LIMIT ?3 OFFSET ?4"),turso::params![query,actor,limit as i64,offset as i64]).await?;
        let mut entries = Vec::new();
        while let Some(row) = rows.next().await? {
            entries.push(serde_json::json!({"id":row.get::<i64>(0)?,"created":row.get::<i64>(1)?,"actor":row.get::<String>(2)?,"action":row.get::<String>(3)?}));
        }
        Ok(serde_json::json!({"entries":entries,"total":total,"offset":offset,"limit":limit}))
    }
    pub async fn audit_since(&self, after: i64, limit: u32) -> Result<Vec<serde_json::Value>> {
        ensure!((1..=200).contains(&limit), "Invalid audit page size");
        let conn = self.connection.lock().await;
        let mut rows = conn
            .query(
                "SELECT id,created,actor,action FROM audit WHERE id>?1 ORDER BY id ASC LIMIT ?2",
                turso::params![after, limit as i64],
            )
            .await?;
        let mut entries = Vec::new();
        while let Some(row) = rows.next().await? {
            entries.push(serde_json::json!({"id":row.get::<i64>(0)?,"created":row.get::<i64>(1)?,"actor":row.get::<String>(2)?,"action":row.get::<String>(3)?}));
        }
        Ok(entries)
    }
    pub async fn prune_audit(&self, retention_days: u32, max_records: u32) -> Result<u64> {
        ensure!(
            (1..=3650).contains(&retention_days) && (1000..=1000000).contains(&max_records),
            "Invalid audit retention"
        );
        let conn = self.connection.lock().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        let result=async {
            let age=conn.execute("DELETE FROM audit WHERE created<?1",[now()-i64::from(retention_days)*86400]).await?;
            let count=conn.execute("DELETE FROM audit WHERE id<(SELECT id FROM audit ORDER BY id DESC LIMIT 1 OFFSET ?1)",[i64::from(max_records)-1]).await?;
            conn.execute("COMMIT",()).await?;anyhow::Ok(age+count)
        }.await;
        if result.is_err() {
            let _ = conn.execute("ROLLBACK", ()).await;
        }
        result
    }
}

#[cfg(test)]
mod auth_release_tests {
    use super::*;
    use crate::auth::{Role, SecuritySettings, TokenScope};
    const PASSWORD: &str = "release-fixture-password-123";
    async fn fixture() -> (tempfile::TempDir, Store) {
        let directory = tempfile::tempdir().unwrap();
        let store = Store::open(&directory.path().join("auth.db"))
            .await
            .unwrap();
        store.set_admin("admin", PASSWORD.into()).await.unwrap();
        (directory, store)
    }
    #[tokio::test]
    async fn audit_cursor_survives_all_row_pruning_and_legacy_table_migration() {
        let (directory, store) = fixture().await;
        store
            .record_audit("fixture", "first forwarded event")
            .await
            .unwrap();
        let first = store.audit_since(0, 200).await.unwrap().last().unwrap()["id"]
            .as_i64()
            .unwrap();
        store
            .connection
            .lock()
            .await
            .execute("DELETE FROM audit", ())
            .await
            .unwrap();
        store
            .record_audit("fixture", "after complete pruning")
            .await
            .unwrap();
        let after = store.audit_since(first, 200).await.unwrap();
        assert_eq!(after.len(), 1);
        assert!(
            after[0]["id"].as_i64().unwrap() > first,
            "Forwarding cursors must not skip new events after pruning"
        );
        {
            let conn = store.connection.lock().await;
            conn.execute("DROP TABLE audit", ()).await.unwrap();
            conn.execute("CREATE TABLE audit (id INTEGER PRIMARY KEY, created INTEGER NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL)",()).await.unwrap();
            conn.execute(
                "INSERT INTO audit VALUES (41,1,'legacy','first'),(99,2,'legacy','last')",
                (),
            )
            .await
            .unwrap();
            conn.execute("UPDATE schema_version SET version=5", ())
                .await
                .unwrap();
        }
        drop(store);
        let store = Store::open(&directory.path().join("auth.db"))
            .await
            .unwrap();
        let legacy = store.audit_since(0, 200).await.unwrap();
        assert_eq!(
            legacy
                .iter()
                .map(|row| row["id"].as_i64().unwrap())
                .collect::<Vec<_>>(),
            vec![41, 99]
        );
        store
            .record_audit("fixture", "after audit migration")
            .await
            .unwrap();
        let new = store.audit_since(99, 200).await.unwrap();
        assert_eq!(new.len(), 1);
        let latest = new[0]["id"].as_i64().unwrap();
        assert!(latest > 99);
        store
            .connection
            .lock()
            .await
            .execute("DELETE FROM audit", ())
            .await
            .unwrap();
        store
            .record_audit("fixture", "after migrated table pruning")
            .await
            .unwrap();
        assert!(
            store.audit_since(latest, 200).await.unwrap()[0]["id"]
                .as_i64()
                .unwrap()
                > latest
        );
    }
    #[tokio::test]
    async fn roles_idle_expiration_token_hashing_and_revocation() {
        let (_directory, store) = fixture().await;
        store
            .manage_account(
                "admin",
                "reader",
                "create",
                Some(PASSWORD.into()),
                Some(Role::ReadOnly),
            )
            .await
            .unwrap();
        assert!(
            store
                .manage_account("admin", "admin", "role", None, Some(Role::ReadOnly))
                .await
                .is_err()
        );
        let reader = store
            .login("reader", PASSWORD.into())
            .await
            .unwrap()
            .unwrap();
        let principal = store
            .session_principal(&reader, false)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(principal.role, Role::ReadOnly);
        assert!(!principal.permits("PUT", "/api/v1/config"));
        assert!(
            store
                .manage_account("reader", "newadmin", "create", Some(PASSWORD.into()), None)
                .await
                .is_err()
        );
        assert!(
            store
                .create_api_token("reader", "escape", TokenScope::Configure, 3600)
                .await
                .is_err()
        );
        let token = store
            .create_api_token("admin", "monitor", TokenScope::Monitoring, 3600)
            .await
            .unwrap();
        let raw = token["token"].as_str().unwrap();
        assert!(
            store
                .token_principal(raw)
                .await
                .unwrap()
                .unwrap()
                .permits("GET", "/metrics")
        );
        assert!(
            !store
                .token_principal(raw)
                .await
                .unwrap()
                .unwrap()
                .permits("PUT", "/api/v1/config")
        );
        let inventory = store.api_tokens("admin").await.unwrap();
        assert!(!inventory.to_string().contains(raw));
        let conn = store.connection.lock().await;
        let mut rows = conn
            .query("SELECT token_hash FROM api_tokens", ())
            .await
            .unwrap();
        assert_eq!(
            rows.next()
                .await
                .unwrap()
                .unwrap()
                .get::<String>(0)
                .unwrap(),
            digest(raw)
        );
        drop(rows);
        let before = now() - 30;
        conn.execute("UPDATE auth_session_activity SET last_seen=?1", [before])
            .await
            .unwrap();
        drop(conn);
        assert!(
            store
                .session_principal(&reader, false)
                .await
                .unwrap()
                .is_some()
        );
        let conn = store.connection.lock().await;
        let mut rows = conn
            .query(
                "SELECT last_seen FROM auth_session_activity WHERE token_hash=?1",
                [digest(&reader)],
            )
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            before
        );
        drop(rows);
        drop(conn);
        store
            .set_security_settings(
                SecuritySettings {
                    idle_timeout_secs: 60,
                    ..Default::default()
                },
                "admin",
            )
            .await
            .unwrap();
        store
            .connection
            .lock()
            .await
            .execute(
                "UPDATE auth_session_activity SET last_seen=?1",
                [now() - 61],
            )
            .await
            .unwrap();
        assert!(
            store
                .session_principal(&reader, true)
                .await
                .unwrap()
                .is_none()
        );
        store
            .revoke_api_token("reader", token["id"].as_str().unwrap())
            .await
            .unwrap();
        assert!(store.token_principal(raw).await.unwrap().is_some());
        store
            .revoke_api_token("admin", token["id"].as_str().unwrap())
            .await
            .unwrap();
        assert!(store.token_principal(raw).await.unwrap().is_none());
        let token = store
            .create_api_token("admin", "expiring", TokenScope::Read, 60)
            .await
            .unwrap();
        store
            .connection
            .lock()
            .await
            .execute("UPDATE api_tokens SET expires=?1", [now() - 1])
            .await
            .unwrap();
        assert!(
            store
                .token_principal(token["token"].as_str().unwrap())
                .await
                .unwrap()
                .is_none()
        );
    }
    #[tokio::test]
    async fn mfa_confirmation_recovery_and_audit_failures_are_atomic() {
        let (_directory, store) = fixture().await;
        let session = store
            .login("admin", PASSWORD.into())
            .await
            .unwrap()
            .unwrap();
        let token = store
            .create_api_token("admin", "before-mfa", TokenScope::Read, 3600)
            .await
            .unwrap();
        let enrollment = store.enroll_mfa("admin").await.unwrap();
        let secret = enrollment["secret"].as_str().unwrap();
        let code = crate::auth::totp_at(secret, now() / 30).unwrap();
        store.connection.lock().await.execute("CREATE TRIGGER auth_audit_failure BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END",()).await.unwrap();
        assert!(store.confirm_mfa("admin", &code).await.is_err());
        assert_eq!(store.mfa_status("admin").await.unwrap()["enabled"], false);
        assert!(store.user(&session).await.unwrap().is_some());
        assert!(
            store
                .token_principal(token["token"].as_str().unwrap())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .create_api_token("admin", "must-rollback", TokenScope::Read, 3600)
                .await
                .is_err()
        );
        assert_eq!(
            store
                .api_tokens("admin")
                .await
                .unwrap()
                .as_array()
                .unwrap()
                .len(),
            1
        );
        store
            .connection
            .lock()
            .await
            .execute("DROP TRIGGER auth_audit_failure", ())
            .await
            .unwrap();
        let codes = store
            .confirm_mfa("admin", &crate::auth::totp_at(secret, now() / 30).unwrap())
            .await
            .unwrap();
        assert_eq!(codes.len(), 10);
        assert!(store.user(&session).await.unwrap().is_none());
        assert!(
            store
                .token_principal(token["token"].as_str().unwrap())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            store
                .login("admin", PASSWORD.into())
                .await
                .unwrap()
                .is_none()
        );
        assert!(
            !store
                .verify_credentials("admin", PASSWORD.into(), Some(&code))
                .await
                .unwrap()
        );
        let current = crate::auth::totp_at(secret, now() / 30 + 1).unwrap();
        let (a, b) = tokio::join!(
            store.verify_credentials("admin", PASSWORD.into(), Some(&current)),
            store.verify_credentials("admin", PASSWORD.into(), Some(&current))
        );
        assert_ne!(
            a.unwrap(),
            b.unwrap(),
            "A TOTP may be consumed only once, including concurrent attempts"
        );
        let (a, b) = tokio::join!(
            store.verify_credentials("admin", PASSWORD.into(), Some(&codes[0])),
            store.verify_credentials("admin", PASSWORD.into(), Some(&codes[0]))
        );
        assert_ne!(
            a.unwrap(),
            b.unwrap(),
            "Recovery codes are consumed atomically"
        );
        assert_eq!(
            store.mfa_status("admin").await.unwrap()["recovery_codes_remaining"],
            9
        );
        let conn = store.connection.lock().await;
        let mut rows = conn
            .query("SELECT json FROM auth_accounts WHERE username='admin'", ())
            .await
            .unwrap();
        let stored = rows
            .next()
            .await
            .unwrap()
            .unwrap()
            .get::<String>(0)
            .unwrap();
        assert!(!stored.contains(&codes[0]));
        drop(rows);
        drop(conn);
        store.disable_mfa("admin").await.unwrap();
        assert!(
            store
                .login("admin", PASSWORD.into())
                .await
                .unwrap()
                .is_some()
        );
    }
    #[tokio::test]
    async fn password_or_mfa_change_between_verification_and_issuance_cannot_create_session() {
        let (_directory, store) = fixture().await;
        let (hash, secret) = store
            .verified_credentials("admin", PASSWORD.into(), None)
            .await
            .unwrap()
            .unwrap();
        store
            .set_admin("admin", "new-fixture-password-123".into())
            .await
            .unwrap();
        assert!(
            store
                .issue_verified_session("admin", hash, secret)
                .await
                .unwrap()
                .is_none()
        );
        let (hash, secret) = store
            .verified_credentials("admin", "new-fixture-password-123".into(), None)
            .await
            .unwrap()
            .unwrap();
        let enrollment = store.enroll_mfa("admin").await.unwrap();
        let code =
            crate::auth::totp_at(enrollment["secret"].as_str().unwrap(), now() / 30).unwrap();
        store.confirm_mfa("admin", &code).await.unwrap();
        assert!(
            store
                .issue_verified_session("admin", hash, secret)
                .await
                .unwrap()
                .is_none()
        );
        store.set_admin("admin", PASSWORD.into()).await.unwrap();
        assert_eq!(store.mfa_status("admin").await.unwrap()["enabled"], false);
        assert_eq!(
            store.account_inventory().await.unwrap()[0]["role"],
            "administrator"
        );
    }
    #[tokio::test]
    async fn backups_keep_roles_and_policy_but_revoke_tokens_and_legacy_restore_resets_metadata() {
        let (directory, store) = fixture().await;
        let config = Config::load(Path::new("examples/riverlb.toml")).unwrap();
        store.save(&config, 1, "fixture").await.unwrap();
        store
            .manage_account(
                "admin",
                "reader",
                "create",
                Some(PASSWORD.into()),
                Some(Role::ReadOnly),
            )
            .await
            .unwrap();
        store
            .set_security_settings(
                SecuritySettings {
                    idle_timeout_secs: 60,
                    source_allowlist: vec!["127.0.0.1/32".into()],
                },
                "admin",
            )
            .await
            .unwrap();
        let snapshot = store.backup().await.unwrap();
        assert_eq!(snapshot.format, 3);
        let token = store
            .create_api_token("admin", "temporary", TokenScope::Monitoring, 3600)
            .await
            .unwrap();
        let session = store
            .login("reader", PASSWORD.into())
            .await
            .unwrap()
            .unwrap();
        store.restore(&snapshot).await.unwrap();
        assert!(store.user(&session).await.unwrap().is_none());
        assert!(
            store
                .token_principal(token["token"].as_str().unwrap())
                .await
                .unwrap()
                .is_none()
        );
        assert_eq!(
            store.account_inventory().await.unwrap()[1]["role"],
            "read_only"
        );
        assert_eq!(
            store.security_settings().await.unwrap().idle_timeout_secs,
            60
        );
        let mut legacy = snapshot;
        legacy.format = 2;
        legacy.tables.remove("auth_accounts");
        legacy.tables.remove("auth_settings");
        legacy.sha256 = format!(
            "{:x}",
            Sha256::digest(
                serde_json::to_vec(&(legacy.format, legacy.created, &legacy.tables)).unwrap()
            )
        );
        store.restore(&legacy).await.unwrap();
        assert_eq!(
            store.account_inventory().await.unwrap()[1]["role"],
            "administrator"
        );
        assert_eq!(
            store.security_settings().await.unwrap().idle_timeout_secs,
            1800
        );
        store
            .connection
            .lock()
            .await
            .execute("UPDATE schema_version SET version=5", ())
            .await
            .unwrap();
        drop(store);
        let reopened = Store::open(&directory.path().join("auth.db"))
            .await
            .unwrap();
        assert!(
            reopened
                .login("admin", PASSWORD.into())
                .await
                .unwrap()
                .is_some()
        );
        let conn = reopened.connection.lock().await;
        let mut rows = conn
            .query("SELECT version FROM schema_version", ())
            .await
            .unwrap();
        assert_eq!(
            rows.next().await.unwrap().unwrap().get::<i64>(0).unwrap(),
            6
        );
    }
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn traffic_retention_handles_expired_rows_and_id_gaps() {
        let folder = tempfile::tempdir().unwrap();
        let store = super::Store::open(&folder.path().join("retention.db"))
            .await
            .unwrap();
        {
            let conn = store.connection.lock().await;
            conn.execute("BEGIN IMMEDIATE", ()).await.unwrap();
            for _ in 0..20003 {
                conn.execute(
                    "INSERT INTO traffic_samples (created,revision,json) VALUES (?1,1,'{}')",
                    [super::now()],
                )
                .await
                .unwrap();
            }
            conn.execute(
                "INSERT INTO traffic_samples (created,revision,json) VALUES (?1,1,'{}')",
                [super::now() - 604801],
            )
            .await
            .unwrap();
            conn.execute("COMMIT", ()).await.unwrap();
        }
        store
            .record_traffic(1, serde_json::json!({"virtual_servers":[]}))
            .await
            .unwrap();
        let conn = store.connection.lock().await;
        let mut rows = conn
            .query("SELECT count(*),min(id),max(id) FROM traffic_samples", ())
            .await
            .unwrap();
        let row = rows.next().await.unwrap().unwrap();
        assert_eq!(row.get::<i64>(0).unwrap(), 20000);
        assert_eq!(row.get::<i64>(1).unwrap(), 5);
        assert_eq!(row.get::<i64>(2).unwrap(), 20005);
    }

    use super::*;
    #[tokio::test]
    async fn backup_restore_is_validated_atomic_and_revokes_sessions() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("restore.db"))
            .await
            .unwrap();
        let config = Config::load(Path::new("examples/riverlb.toml")).unwrap();
        store.save(&config, 1, "fixture").await.unwrap();
        store
            .set_admin("admin", "backup-test-password".into())
            .await
            .unwrap();
        let snapshot = store.backup().await.unwrap();
        snapshot.validate().unwrap();
        let token = store
            .login("admin", "backup-test-password".into())
            .await
            .unwrap()
            .unwrap();
        store.save(&config, 2, "fixture").await.unwrap();
        // Inject an actual SQL failure after deletions to verify transaction rollback.
        store.connection.lock().await.execute("CREATE TRIGGER restore_failure BEFORE INSERT ON configurations BEGIN SELECT RAISE(ABORT,'fixture failure'); END",()).await.unwrap();
        assert!(store.restore(&snapshot).await.is_err());
        assert_eq!(store.load().await.unwrap().unwrap().1, 2);
        assert!(store.user(&token).await.unwrap().is_some());
        store
            .connection
            .lock()
            .await
            .execute("DROP TRIGGER restore_failure", ())
            .await
            .unwrap();
        store.restore(&snapshot).await.unwrap();
        assert_eq!(store.load().await.unwrap().unwrap().1, 1);
        assert!(store.user(&token).await.unwrap().is_none());
        let mut corrupt = snapshot;
        corrupt.sha256 = "invalid".into();
        assert!(store.restore(&corrupt).await.is_err());
        assert_eq!(store.load().await.unwrap().unwrap().1, 1);
    }
    #[tokio::test]
    async fn transaction_failure_rolls_back_and_password_reset_revokes_sessions() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("state.db")).await.unwrap();
        let config = Config::load(Path::new("examples/riverlb.toml")).unwrap();
        store.save(&config, 1, "fixture").await.unwrap();
        assert!(store.save(&config, 1, "duplicate").await.is_err());
        // The failed transaction must not leave the connection in a transaction.
        store.save(&config, 2, "fixture").await.unwrap();
        assert_eq!(store.load().await.unwrap().unwrap().1, 2);
        assert_eq!(store.audit().await.unwrap().as_array().unwrap().len(), 2);
        store
            .set_admin("admin", "initial-test-password".into())
            .await
            .unwrap();
        let token = store
            .login("admin", "initial-test-password".into())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(store.user(&token).await.unwrap().as_deref(), Some("admin"));
        store
            .set_admin("admin", "replacement-password".into())
            .await
            .unwrap();
        assert!(store.user(&token).await.unwrap().is_none());
        let token = store
            .login("admin", "replacement-password".into())
            .await
            .unwrap()
            .unwrap();
        store
            .connection
            .lock()
            .await
            .execute("UPDATE sessions SET expires=?1", [now() - 1])
            .await
            .unwrap();
        assert!(store.user(&token).await.unwrap().is_none());
        assert!(store.user("invalid-token").await.unwrap().is_none());
        // Simulate the previous schema, preserving accounts and configurations.
        store
            .connection
            .lock()
            .await
            .execute("DROP TABLE traffic_samples", ())
            .await
            .unwrap();
        store
            .connection
            .lock()
            .await
            .execute("UPDATE schema_version SET version=1", ())
            .await
            .unwrap();
        drop(store);
        let upgraded = Store::open(&folder.path().join("state.db")).await.unwrap();
        assert_eq!(upgraded.load().await.unwrap().unwrap().1, 2);
        assert_eq!(
            upgraded.traffic_history().await.unwrap(),
            serde_json::json!([])
        );
        assert!(
            upgraded
                .login("admin", "replacement-password".into())
                .await
                .unwrap()
                .is_some()
        );
    }
    #[tokio::test]
    async fn account_mutations_preserve_access_and_roll_back_with_audit_failure() {
        let folder = tempfile::tempdir().unwrap();
        let store = Store::open(&folder.path().join("accounts.db"))
            .await
            .unwrap();
        store
            .set_admin("admin", "initial-password-123".into())
            .await
            .unwrap();
        store
            .manage_administrator(
                "admin",
                "operator",
                "create",
                Some("operator-password-123".into()),
            )
            .await
            .unwrap();
        let token = store
            .login("operator", "operator-password-123".into())
            .await
            .unwrap()
            .unwrap();
        assert!(
            store
                .manage_administrator(
                    "admin",
                    "operator",
                    "create",
                    Some("different-password-123".into())
                )
                .await
                .is_err()
        );
        assert!(store.user(&token).await.unwrap().is_some());
        assert!(
            store
                .manage_administrator("operator", "operator", "delete", None)
                .await
                .is_err()
        );
        store
            .manage_administrator("operator", "admin", "delete", None)
            .await
            .unwrap();
        assert!(
            store
                .manage_administrator("recovery", "operator", "delete", None)
                .await
                .is_err()
        );
        assert_eq!(store.administrators().await.unwrap(), vec!["operator"]);
        store.connection.lock().await.execute("CREATE TRIGGER deny_audit BEFORE INSERT ON audit BEGIN SELECT RAISE(ABORT, 'audit unavailable'); END",()).await.unwrap();
        assert!(
            store
                .manage_administrator(
                    "operator",
                    "operator",
                    "password",
                    Some("replacement-password-123".into())
                )
                .await
                .is_err()
        );
        assert!(store.user(&token).await.unwrap().is_some());
        store
            .connection
            .lock()
            .await
            .execute("DROP TRIGGER deny_audit", ())
            .await
            .unwrap();
        assert!(
            store
                .login("operator", "operator-password-123".into())
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .login("operator", "replacement-password-123".into())
                .await
                .unwrap()
                .is_none()
        );
    }
}
