//! Scheduled HTTP-01 issuance. Account secrets stay in the protected database.
use anyhow::{Context, Result, ensure};
use instant_acme::{
    Account, AuthorizationStatus, ChallengeType, Identifier, NewAccount, NewOrder, OrderStatus,
    RetryPolicy,
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::Duration,
};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    #[serde(default)]
    pub store: crate::certificates::StoreKind,
    pub name: String,
    pub domains: Vec<String>,
    pub directory: String,
    pub email: String,
    pub terms_agreed: bool,
    pub enabled: bool,
    pub challenge_listen: SocketAddr,
    pub renew_before_days: u32,
    #[serde(default)]
    pub ca_certificate: Option<String>,
}
impl Settings {
    pub fn validate(&self) -> Result<()> {
        crate::certificates::validate_name(&self.name)?;
        ensure!(
            !self.domains.is_empty() && self.domains.len() <= 100,
            "ACME requires 1..100 domains"
        );
        let mut domains = std::collections::HashSet::new();
        ensure!(
            self.domains
                .iter()
                .all(|d| crate::certificates::dns_name(d) && domains.insert(d)),
            "ACME domains must be unique lowercase DNS names; HTTP-01 does not support wildcards"
        );
        let uri: hyper::Uri = self.directory.parse()?;
        ensure!(
            uri.scheme_str() == Some("https"),
            "ACME directory requires HTTPS"
        );
        ensure!(
            uri.host().is_some() && !self.directory.contains('@') && self.directory.len() <= 2048,
            "invalid ACME directory"
        );
        ensure!(
            !self.email.is_empty()
                && self.email.len() <= 254
                && self.email.contains('@')
                && !self.email.chars().any(char::is_whitespace),
            "ACME contact email is required"
        );
        ensure!(
            self.terms_agreed || !self.enabled,
            "accept the CA terms before enabling issuance"
        );
        ensure!(
            (1..=90).contains(&self.renew_before_days) && self.challenge_listen.port() != 0,
            "invalid renewal window or challenge port"
        );
        Ok(())
    }
}
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_enabled_acme_settings_and_supported_challenges() {
        let mut settings = Settings {
            store: Default::default(),
            name: "home".into(),
            domains: vec!["app.home.test".into()],
            directory: "https://ca.home.test/directory".into(),
            email: "admin@home.test".into(),
            terms_agreed: true,
            enabled: true,
            challenge_listen: "127.0.0.1:9080".parse().unwrap(),
            renew_before_days: 30,
            ca_certificate: None,
        };
        settings.validate().unwrap();
        settings.terms_agreed = false;
        assert!(settings.validate().is_err());
        settings.enabled = false;
        settings.validate().unwrap();
        settings.domains.push(settings.domains[0].clone());
        assert!(settings.validate().is_err());
        settings.domains = vec!["*.home.test".into()];
        assert!(settings.validate().is_err());
        settings.domains = vec!["app.home.test".into()];
        settings.directory = "http://127.0.0.1/directory".into();
        assert!(settings.validate().is_err());
    }
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Job {
    pub settings: Settings,
    pub next_attempt: i64,
    pub last_success: Option<i64>,
    pub last_error: Option<String>,
    pub failures: u32,
}
pub struct Issued {
    pub store: crate::certificates::StoreKind,
    pub name: String,
    pub certificate: String,
    pub private_key: String,
}
pub(crate) type Challenges = Arc<Mutex<HashMap<String, String>>>;

async fn issue(control: &Arc<crate::control::Control>, settings: &Settings) -> Result<Issued> {
    let (challenges, integrated) = {
        let generation = control.generation.lock().await;
        let runtime = &generation.runtime;
        let integrated = runtime.config.virtual_servers.iter().any(|v| {
            v.enabled
                && v.http.is_some()
                && v.tls.is_none()
                && v.certificate.is_none()
                && v.listen.port() == settings.challenge_listen.port()
                && (v.listen.ip() == settings.challenge_listen.ip()
                    || v.listen.ip().is_unspecified()
                    || settings.challenge_listen.ip().is_unspecified())
        });
        (runtime.acme_challenges.clone(), integrated)
    };
    let mut lease = ChallengeLease {
        challenges: challenges.clone(),
        tokens: Vec::new(),
    };
    let server = if integrated {
        None
    } else {
        let listener = tokio::net::TcpListener::bind(settings.challenge_listen)
            .await
            .context("bind HTTP-01 challenge listener (public port 80 must reach this endpoint)")?;
        let state = challenges.clone();
        let router = axum::Router::new().route(
            "/.well-known/acme-challenge/{token}",
            axum::routing::get(
                move |axum::extract::Path(token): axum::extract::Path<String>| {
                    let state = state.clone();
                    async move {
                        match state.lock().unwrap().get(&token).cloned() {
                            Some(value) => (axum::http::StatusCode::OK, value),
                            None => (axum::http::StatusCode::NOT_FOUND, String::new()),
                        }
                    }
                },
            ),
        );
        Some(Abort(tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        })))
    };
    let builder = if let Some(path) = &settings.ca_certificate {
        Account::builder_with_root(path)?
    } else {
        Account::builder()?
    };
    let account_key = format!("{}|{}", settings.directory, settings.email);
    let account = if let Some(credentials) = control.store.acme_account(&account_key).await? {
        builder
            .from_credentials(serde_json::from_str(&credentials)?)
            .await?
    } else {
        let contact = format!("mailto:{}", settings.email);
        let (account, credentials) = builder
            .create(
                &NewAccount {
                    contact: &[&contact],
                    terms_of_service_agreed: settings.terms_agreed,
                    only_return_existing: false,
                },
                settings.directory.clone(),
                None,
            )
            .await?;
        control
            .store
            .save_acme_account(&account_key, &serde_json::to_string(&credentials)?)
            .await?;
        account
    };
    let ids = settings
        .domains
        .iter()
        .cloned()
        .map(Identifier::Dns)
        .collect::<Vec<_>>();
    let mut order = account.new_order(&NewOrder::new(&ids)).await?;
    let mut authorizations = order.authorizations();
    while let Some(result) = authorizations.next().await {
        let mut auth = result?;
        if auth.status == AuthorizationStatus::Valid {
            continue;
        }
        ensure!(
            auth.status == AuthorizationStatus::Pending,
            "ACME authorization is not pending"
        );
        let mut challenge = auth
            .challenge(ChallengeType::Http01)
            .context("CA did not offer HTTP-01")?;
        challenges.lock().unwrap().insert(
            challenge.token.clone(),
            challenge.key_authorization().as_str().to_owned(),
        );
        lease.tokens.push(challenge.token.clone());
        challenge.set_ready().await?;
    }
    ensure!(
        order.poll_ready(&RetryPolicy::default()).await? == OrderStatus::Ready,
        "ACME order is not ready"
    );
    let private_key = order.finalize().await?;
    let certificate = order.poll_certificate(&RetryPolicy::default()).await?;
    let metadata = crate::certificates::metadata(&settings.name, &certificate, 0)?;
    ensure!(
        metadata.valid_now && metadata.not_after > crate::storage::now() + 86400,
        "issued certificate is not valid for at least one day"
    );
    ensure!(
        settings.domains.iter().all(|d| metadata
            .dns_names
            .iter()
            .any(|p| crate::certificates::matches_dns(p, d))),
        "issued certificate does not cover requested domains"
    );
    drop(server);
    Ok(Issued {
        store: settings.store,
        name: settings.name.clone(),
        certificate,
        private_key,
    })
}
struct ChallengeLease {
    challenges: Challenges,
    tokens: Vec<String>,
}
impl Drop for ChallengeLease {
    fn drop(&mut self) {
        let mut entries = self.challenges.lock().unwrap();
        for token in &self.tokens {
            entries.remove(token);
        }
    }
}
struct Abort(tokio::task::JoinHandle<()>);
impl Drop for Abort {
    fn drop(&mut self) {
        self.0.abort();
    }
}

pub fn start(control: Arc<crate::control::Control>) {
    let tasks = control.renewals.clone();
    tasks.spawn(async move {
        let mut timer = tokio::time::interval(Duration::from_secs(30));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tokio::select! {_=control.stop.cancelled()=>break,_=timer.tick()=>{},_=control.acme_wake.notified()=>{}}
            if !control.data_plane_active(){continue;}
            let jobs = match control.store.acme_jobs().await {
                Ok(v) => v,
                Err(e) => {
                    tracing::warn!(%e,"ACME schedule unavailable");
                    continue;
                }
            };
            for mut job in jobs {
                if !control.data_plane_active(){break;}
                if !job.settings.enabled || job.next_attempt > crate::storage::now() {
                    continue;
                }
                let due = match control.store.certificate_pem_in(job.settings.store, &job.settings.name).await {
                    Ok(Some(pem)) => crate::certificates::metadata(&job.settings.name, &pem, 0)
                        .map(|m| {
                            m.not_after
                                <= crate::storage::now()
                                    + i64::from(job.settings.renew_before_days) * 86400
                        })
                        .unwrap_or(true),
                    _ => true,
                };
                if !due {
                    job.next_attempt = crate::storage::now() + 3600;
                    let _ = control.store.finish_acme_job(&job).await;
                    continue;
                }
                let ownership=control.ha_session_token();
                let result = tokio::select! {_=control.stop.cancelled()=>return,_=ownership.cancelled()=>continue,result=tokio::time::timeout(Duration::from_secs(600),issue(&control,&job.settings))=>result};
                let result = match result {
                    Ok(v) => v,
                    Err(_) => Err(anyhow::anyhow!("ACME issuance timed out")),
                };
                let result = match result {
                    Ok(cert) => {
                        if !control
                            .store
                            .acme_job_unchanged(&job.settings)
                            .await
                            .unwrap_or(false)
                        {
                            continue;
                        }
                        control.activate_certificate(cert).await.map(|_| ())
                    }
                    Err(e) => Err(e),
                };
                match result {
                    Ok(()) => {
                        job.last_success = Some(crate::storage::now());
                        job.last_error = None;
                        job.failures = 0;
                        job.next_attempt = crate::storage::now() + 3600;
                    }
                    Err(e) => {
                        job.failures = job.failures.saturating_add(1);
                        job.last_error = Some(e.to_string().chars().take(1024).collect());
                        job.next_attempt =
                            crate::storage::now() + 300 * (1i64 << job.failures.min(8));
                    }
                }
                let _ = control.store.finish_acme_job(&job).await;
            }
        }
    });
}
