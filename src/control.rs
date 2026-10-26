//! Serialized configuration transactions and runtime generation ownership.
use crate::network::{Network, Transaction};
use crate::{config::Config, management, runtime::Runtime};
use anyhow::{Context, Result, ensure};
use std::{
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
};
use tokio::{net::TcpListener, sync::Mutex};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub struct Generation {
    pub runtime: Arc<Runtime>,
    pub revision: u64,
    listeners: Vec<Option<crate::runtime::Listener>>,
    pub firewall_rules: crate::firewall::Rules,
    stop: CancellationToken,
    tasks: TaskTracker,
    admin_stop: CancellationToken,
    admin_connections_stop: CancellationToken,
}
pub struct Control {
    pub generation: Mutex<Generation>,
    pub change_gate: Mutex<()>,
    pub pending_configuration: Mutex<Option<crate::confirmation::Pending>>,
    pub confirmation_path: PathBuf,
    pub operations: crate::operations::Operations,
    pub updates: crate::updates::Updates,
    local_control: Mutex<Option<crate::local_control::Server>>,
    pub ha: Option<Arc<crate::ha::State>>,
    pub ha_config_path: PathBuf,
    pub store: crate::storage::Store,
    pub login_budget: Mutex<management::LoginBudget>,
    pub login_slots: Arc<tokio::sync::Semaphore>,
    admin_slots: Arc<tokio::sync::Semaphore>,
    pub admin_body_slots: Arc<tokio::sync::Semaphore>,
    pub administrator_budget: Mutex<(std::time::Instant, u32)>,
    pub sessions: TaskTracker,
    statistics_write: Mutex<()>,
    pub renewals: TaskTracker,
    active: Arc<AtomicUsize>,
    pub stop: CancellationToken,
    pub manage_network: bool,
    pub manage_firewall: bool,
    pub acme_wake: tokio::sync::Notify,
    network_recovery_required: AtomicBool,
}
impl Control {
    pub async fn new(
        path: PathBuf,
        manage_network: bool,
        database: Option<PathBuf>,
        ha_config: Option<PathBuf>,
    ) -> Result<Arc<Self>> {
        let ha_config_path = ha_config
            .clone()
            .unwrap_or_else(|| PathBuf::from("/etc/riverlb/ha.json"));
        let ha_config =
            ha_config.or_else(|| ha_config_path.exists().then(|| ha_config_path.clone()));
        let ha = ha_config
            .map(|p| crate::ha::Settings::load(&p).and_then(crate::ha::State::new))
            .transpose()?;
        ensure!(
            ha.is_none() || manage_network,
            "HA requires managed Linux networking"
        );
        let path = std::fs::canonicalize(path)?;
        let database = database.unwrap_or_else(|| path.with_extension("db"));
        let store = crate::storage::Store::open(&database).await?;
        let confirmation_path = crate::confirmation::path(&database);
        crate::confirmation::recover(&store, &confirmation_path, manage_network, ha.as_deref())
            .await?;
        let operations = crate::operations::Operations::open(&database)?;
        let updates = crate::updates::Updates::new(&database);
        let (config, revision) = match store.load().await? {
            Some(saved) => saved,
            None => {
                let config = Config::load(&path)?;
                store.resolve_certificates(&config).await?;
                store.save(&config, 1, "initial import").await?;
                (config, 1)
            }
        };
        let config = config.expand_domain_tls()?;
        config.validate()?;
        Self::validate_ha(&config, ha.as_deref())?;
        let data_active = ha.is_none();
        let runtime = Runtime::with_certificates(
            config.clone(),
            &store.resolve_certificates(&config).await?,
            Default::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        )?;
        if let Some(state) = &ha {
            for replica in state.persistence.lock().unwrap().iter() {
                if let Some(pool) = runtime
                    .pools
                    .iter()
                    .find(|p| p.config.name == replica.virtual_server)
                {
                    pool.import_persistence(replica)?;
                }
            }
        }
        if let Some(saved) = store.latest_traffic().await? {
            crate::traffic::restore_runtime(&runtime, &saved)?;
        }
        let manage_firewall = crate::firewall::active(manage_network).await?;
        tracing::debug!(
            enabled = manage_firewall,
            "automatic firewall provisioning initialized"
        );
        if let Some(state) = &ha {
            // Remove stale floating ownership before exposing a standby controller.
            // Never put these addresses back if later management startup fails.
            Transaction::reconcile(state.recovery_steps(manage_firewall)?).await?;
            let full = crate::network::provisioned(&runtime.config)?;
            let standby = crate::ha::network(&runtime.config, Some(state), false)?;
            // A clean standalone stop or a reboot can leave no VLAN devices.
            // Withdraw ownership only; prepare below creates the standby links
            // before adding their local addresses, routes and source rules.
            let mut steps = crate::network::withdrawal_plan(&full, &standby)?;
            let owned = crate::firewall::desired(&runtime.config, manage_firewall).await?;
            let local = crate::firewall::desired(
                &crate::ha::effective(&runtime.config, Some(state), false),
                manage_firewall,
            )
            .await?;
            steps.extend(crate::firewall::plan(&owned, &local));
            Transaction::reconcile(steps).await?;
        }
        let mut network_tx = Transaction::prepare(
            &Network::default(),
            &crate::ha::network(&runtime.config, ha.as_deref(), data_active)?,
            manage_network,
        )
        .await?;
        let prepared = async {
            let listeners = if data_active {
                runtime.bind().await?
            } else {
                vec![None; runtime.pools.len()]
            };
            let admin = TcpListener::bind(runtime.config.management).await?;
            let firewall_rules = crate::firewall::desired(
                &crate::ha::effective(&runtime.config, ha.as_deref(), data_active),
                manage_firewall,
            )
            .await?;
            network_tx
                .apply_steps(crate::firewall::plan(&Default::default(), &firewall_rules))
                .await?;
            anyhow::Ok((listeners, admin, firewall_rules))
        }
        .await;
        let (listeners, admin, firewall_rules) = match prepared {
            Ok(value) => value,
            Err(error) => {
                network_tx
                    .rollback()
                    .await
                    .context("startup networking rollback failed")?;
                return Err(error);
            }
        };
        runtime.probe().await;
        let control = Arc::new(Self {
            change_gate: Mutex::new(()),
            pending_configuration: Mutex::new(None),
            confirmation_path,
            operations,
            updates,
            local_control: Mutex::new(None),
            ha,
            ha_config_path,
            generation: Mutex::new(Generation {
                runtime,
                revision,
                listeners,
                firewall_rules,
                stop: CancellationToken::new(),
                tasks: TaskTracker::new(),
                admin_stop: CancellationToken::new(),
                admin_connections_stop: CancellationToken::new(),
            }),
            store,
            login_budget: Mutex::new(Default::default()),
            login_slots: Arc::new(tokio::sync::Semaphore::new(4)),
            admin_slots: Arc::new(tokio::sync::Semaphore::new(64)),
            admin_body_slots: Arc::new(tokio::sync::Semaphore::new(256)),
            administrator_budget: Mutex::new((std::time::Instant::now(), 0)),
            sessions: TaskTracker::new(),
            statistics_write: Mutex::new(()),
            renewals: TaskTracker::new(),
            active: Arc::new(AtomicUsize::new(0)),
            stop: CancellationToken::new(),
            manage_network,
            manage_firewall,
            acme_wake: tokio::sync::Notify::new(),
            network_recovery_required: AtomicBool::new(false),
        });
        match crate::local_control::start(control.clone(), &database).await {
            Ok(server) => *control.local_control.lock().await = server,
            Err(error) => {
                control.shutdown().await;
                network_tx.rollback().await?;
                return Err(error);
            }
        }
        {
            let generation = control.generation.lock().await;
            generation.runtime.start(
                generation.listeners.clone(),
                generation.stop.clone(),
                &generation.tasks,
                (&control.sessions, control.ha_session_token()),
                control.active.clone(),
            );
            control.start_admin(admin, generation.admin_stop.clone());
        }
        if control.ha.is_some()
            && let Err(error) = crate::ha::start(control.clone()).await
        {
            control.shutdown().await;
            network_tx.rollback().await?;
            return Err(error);
        }
        let sampler = control.clone();
        crate::acme::start(control.clone());
        crate::operations::start(control.clone());
        crate::inspection::start(control.clone()).await;
        tokio::spawn(async move {
            let mut timer = tokio::time::interval(std::time::Duration::from_secs(5));
            timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                tokio::select! { _ = sampler.stop.cancelled() => break, _ = timer.tick() => {} }
                if let Err(error) = sampler.save_statistics().await {
                    tracing::warn!(%error,"statistics checkpoint write failed");
                }
            }
        });
        Ok(control)
    }
    fn start_admin(self: &Arc<Self>, listener: TcpListener, stop: CancellationToken) {
        let control = self.clone();
        let address = listener.local_addr().expect("bound address");
        tokio::spawn(async move {
            tracing::info!(%address, "management portal ready");
            loop {
                let accepted = tokio::select! { _ = stop.cancelled() => break, accepted = listener.accept() => accepted };
                let (stream, peer) = match accepted {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::error!(%error,"management accept failed");
                        control.stop.cancel();
                        break;
                    }
                };
                // Admission precedes TLS and survives runtime/listener replacement.
                let Ok(permit) = control.admin_slots.clone().try_acquire_owned() else {
                    drop(stream);
                    continue;
                };
                if !control
                    .store
                    .security_settings()
                    .await
                    .is_ok_and(|s| s.allows_source(peer.ip()))
                {
                    continue;
                }
                let (tls, drain) = {
                    let generation = control.generation.lock().await;
                    (
                        generation.runtime.management_tls.clone(),
                        generation.admin_connections_stop.clone(),
                    )
                };
                if stop.is_cancelled() {
                    break;
                }
                let router = management::router(control.clone(), address, tls.is_some())
                    .layer(axum::Extension(peer));
                tokio::spawn(async move {
                    let _permit = permit;
                    if let Some(tls) = tls {
                        let handshake = tokio_rustls::TlsAcceptor::from(tls).accept(stream);
                        let accepted = tokio::select! { _ = drain.cancelled() => return, result = tokio::time::timeout(std::time::Duration::from_secs(10), handshake) => result };
                        if let Ok(Ok(stream)) = accepted {
                            serve_admin_connection(stream, router, drain).await;
                        }
                    } else {
                        serve_admin_connection(stream, router, drain).await;
                    }
                });
            }
        });
    }
    pub async fn apply(
        self: &Arc<Self>,
        config: Config,
        revision: u64,
        actor: String,
    ) -> Result<u64> {
        let _gate = self.change_gate.lock().await;
        ensure!(
            !crate::interfaces::has_pending().await,
            "Confirm or revert the pending interface change before applying configuration"
        );
        ensure!(
            self.pending_configuration.lock().await.is_none(),
            "Confirm or revert the pending configuration before applying another change"
        );
        let config = config.expand_domain_tls()?;
        config.validate()?;
        let (old, old_firewall) = {
            let current = self.generation.lock().await;
            ensure!(
                current.revision == revision,
                "configuration changed; reload before applying"
            );
            (
                current.runtime.config.clone(),
                current.firewall_rules.clone(),
            )
        };
        let mut comparison = old.clone();
        if !self.manage_network {
            comparison.network = config.network.clone();
        }
        let pending = crate::confirmation::required(&comparison, &config).then(|| {
            crate::confirmation::Pending::new(
                old,
                config.clone(),
                old_firewall,
                revision,
                actor.clone(),
            )
        });
        if let Some(journal) = &pending {
            journal.save(&self.confirmation_path)?;
            *self.pending_configuration.lock().await = Some(journal.clone());
        }
        let result = self.apply_inner(config, revision, actor, None, None).await;
        if result.is_err() && !self.network_recovery_required.load(Ordering::SeqCst) {
            crate::confirmation::clear(&self.confirmation_path)?;
            *self.pending_configuration.lock().await = None;
        } else if let Some(journal) = pending {
            let control = self.clone();
            tokio::spawn(async move {
                tokio::select! {
                    _ = control.stop.cancelled() => {},
                    _ = tokio::time::sleep(std::time::Duration::from_secs((journal.deadline - crate::storage::now()).max(0) as u64)) => {
                        let still_pending = control.pending_configuration.lock().await.as_ref().is_some_and(|p| p.revision == journal.revision);
                        if still_pending && let Err(error) = control.revert_configuration(journal.revision,"confirmation timeout").await {
                            tracing::error!(%error,"automatic configuration revert failed; stopping for recovery");
                            control.stop.cancel();
                        }
                    }
                }
            });
        }
        result
    }
    pub async fn confirm_configuration(
        self: &Arc<Self>,
        revision: u64,
        actor: &str,
        endpoint: crate::confirmation::Endpoint,
    ) -> Result<u64> {
        let _gate = self.change_gate.lock().await;
        let mut pending = self.pending_configuration.lock().await;
        let journal = pending
            .as_ref()
            .context("No configuration is waiting for confirmation")?;
        ensure!(
            journal.revision == revision && crate::storage::now() < journal.deadline,
            "Confirmation expired or revision changed"
        );
        let current = self.generation.lock().await;
        ensure!(
            current.revision == revision
                && endpoint.address == current.runtime.config.management
                && endpoint.secure == current.runtime.management_tls.is_some(),
            "Confirm through the new management endpoint"
        );
        self.store
            .record_audit(actor, "management/network configuration confirmed")
            .await?;
        crate::confirmation::clear(&self.confirmation_path)?;
        *pending = None;
        Ok(revision)
    }
    pub async fn revert_configuration(self: &Arc<Self>, revision: u64, actor: &str) -> Result<u64> {
        let _gate = self.change_gate.lock().await;
        let journal = self
            .pending_configuration
            .lock()
            .await
            .clone()
            .context("No configuration is waiting for confirmation")?;
        ensure!(journal.revision == revision, "Pending revision changed");
        let next = self
            .apply_inner(
                journal.old_config,
                revision,
                format!("{actor}: reverted unconfirmed configuration"),
                None,
                None,
            )
            .await?;
        crate::confirmation::clear(&self.confirmation_path)?;
        *self.pending_configuration.lock().await = None;
        Ok(next)
    }
    pub async fn activate_certificate(self: &Arc<Self>, cert: crate::acme::Issued) -> Result<u64> {
        let _gate = self.change_gate.lock().await;
        ensure!(
            self.pending_configuration.lock().await.is_none(),
            "Certificate activation waits for configuration confirmation"
        );
        crate::certificates::server_config(&cert.certificate, &cert.private_key)?;
        let (config, revision) = {
            let old = self.generation.lock().await;
            (old.runtime.config.clone(), old.revision)
        };
        for vs in &config.virtual_servers {
            for (host, name) in &vs.sni_certificates {
                if name == &cert.name {
                    let metadata = crate::certificates::metadata(name, &cert.certificate, 0)?;
                    ensure!(
                        metadata
                            .dns_names
                            .iter()
                            .any(|p| crate::certificates::matches_dns(p, host)),
                        "renewed certificate does not cover SNI hostname"
                    );
                }
            }
        }
        self.apply_inner(config, revision, "ACME renewal".into(), Some(cert), None)
            .await
    }
    async fn apply_inner(
        self: &Arc<Self>,
        config: Config,
        revision: u64,
        actor: String,
        certificate: Option<crate::acme::Issued>,
        ha_bundle: Option<&crate::ha::Bundle>,
    ) -> Result<u64> {
        ensure!(
            !crate::interfaces::has_pending().await,
            "Confirm or revert the pending interface change before activating configuration"
        );
        let began = std::time::Instant::now();
        let mut phase = began;
        let mut timing = |stage: &'static str| {
            let now = std::time::Instant::now();
            tracing::debug!(
                revision,
                stage,
                elapsed_ms = now.duration_since(phase).as_millis() as u64,
                total_ms = now.duration_since(began).as_millis() as u64,
                "configuration apply timing"
            );
            phase = now;
        };
        let config = config.expand_domain_tls()?;
        config.validate()?;
        timing("validation");
        let mut old = self.generation.lock().await;
        timing("transaction_lock");
        let data_active = self.data_plane_active();
        ensure!(
            self.ha.is_none() || data_active || ha_bundle.is_some(),
            "standby traffic configuration is read-only"
        );
        ensure!(
            ha_bundle.is_none() || !data_active,
            "active owner rejects peer synchronization"
        );
        Self::validate_ha(&config, self.ha.as_deref())?;
        ensure!(!self.stop.is_cancelled(), "daemon is shutting down");
        ensure!(
            old.revision == revision,
            "configuration changed; reload before applying"
        );
        for vs in config.virtual_servers.iter().filter(|v| v.enabled) {
            if let Some(previous) = old.runtime.config.virtual_servers.iter().find(|v| {
                v.enabled
                    && v.listen == vs.listen
                    && v.server_type.is_udp() == vs.server_type.is_udp()
            }) {
                let device = |n: &Network, v: &crate::config::VirtualServer| {
                    v.ingress_vlan.as_ref().map(|name| {
                        let vlan = n
                            .vlans
                            .iter()
                            .find(|vlan| &vlan.name == name)
                            .expect("validated VLAN");
                        (n.device(name).to_owned(), vlan.interface.clone(), vlan.tag)
                    })
                };
                ensure!(
                    device(&config.network, vs) == device(&old.runtime.config.network, previous),
                    "changing ingress device on an active listener requires disabling and applying the virtual server first, or choosing a new listen address"
                );
            }
        }
        if let Some(state) = &self.ha
            && data_active
        {
            state.record_ownership(
                vec![old.runtime.config.clone(), config.clone()],
                old.firewall_rules.clone(),
            )?;
        }
        let network_result = Transaction::prepare(
            &crate::ha::network(&old.runtime.config, self.ha.as_deref(), data_active)?,
            &crate::ha::network(&config, self.ha.as_deref(), data_active)?,
            self.manage_network,
        )
        .await;
        let mut network_tx = match network_result {
            Ok(tx) => tx,
            Err(error) => {
                if error
                    .downcast_ref::<crate::network::RollbackFailure>()
                    .is_some()
                {
                    self.network_recovery_required.store(true, Ordering::SeqCst);
                    self.stop.cancel();
                }
                return Err(error);
            }
        };
        timing("network_provisioning");
        let prepared = async {
            let mut certificates = if let Some(bundle) = ha_bundle {
                Self::ha_resolved(&self.store, &config, bundle).await?
            } else {
                self.store.resolve_certificates(&config).await?
            };
            if let Some(cert) = &certificate {
                certificates.insert(
                    cert.store.key(&cert.name),
                    crate::certificates::server_config(&cert.certificate, &cert.private_key)?,
                );
            }
            timing("certificate_resolution");
            let runtime = Runtime::with_certificates(
                config.clone(),
                &certificates,
                old.runtime.admission_registry.clone(),
                old.runtime.stats_registry.clone(),
                old.runtime.acme_challenges.clone(),
                old.runtime.inspection.clone(),
            )?;
            timing("runtime_construction");
            crate::network::validate_runtime_devices(&config)?;
            let mut listeners = Vec::new();
            for vs in &runtime.config.virtual_servers {
                if !vs.enabled || !data_active {
                    listeners.push(None);
                    continue;
                }
                if let Some(index) = old.runtime.config.virtual_servers.iter().position(|v| {
                    v.enabled
                        && v.listen == vs.listen
                        && v.server_type.is_udp() == vs.server_type.is_udp()
                        && v.ingress_vlan == vs.ingress_vlan
                }) {
                    listeners.push(old.listeners[index].clone());
                } else {
                    listeners.push(Some(
                        crate::runtime::bind_listener(&runtime.config, vs)
                            .await
                            .context("bind new virtual server; configuration unchanged")?,
                    ));
                }
            }
            let admin = if runtime.config.management != old.runtime.config.management {
                Some(
                    TcpListener::bind(runtime.config.management)
                        .await
                        .context("bind management listener; configuration unchanged")?,
                )
            } else {
                None
            };
            runtime.inherit_health(&old.runtime);
            timing("listeners_and_health_transfer");
            let firewall_rules = crate::firewall::desired(
                &crate::ha::effective(&runtime.config, self.ha.as_deref(), data_active),
                self.manage_firewall,
            )
            .await?;
            if let Some(journal) = self.pending_configuration.lock().await.as_mut() {
                // Persist exact zones and rules before any firewall mutation.
                // Keep both trial and rollback rules if a revert is interrupted.
                journal
                    .new_firewall
                    .extend(old.firewall_rules.iter().cloned());
                journal.new_firewall.extend(firewall_rules.iter().cloned());
                journal.save(&self.confirmation_path)?;
            }
            if let Some(state) = &self.ha
                && data_active
            {
                let mut owned = old.firewall_rules.clone();
                owned.extend(firewall_rules.iter().cloned());
                state.record_ownership(vec![old.runtime.config.clone(), config.clone()], owned)?;
            }
            network_tx
                .apply_steps(crate::firewall::plan(&old.firewall_rules, &firewall_rules))
                .await?;
            if let Some(state) = &self.ha
                && data_active
            {
                crate::ha_network::announce(
                    &crate::ha::network(&config, Some(state), true)?,
                    &crate::ha::network(&old.runtime.config, Some(state), true)?,
                )
                .await?;
                ensure!(
                    crate::ha::authority(state).await?.as_deref() == Some(&state.settings.node_id),
                    "HA owner changed during configuration apply"
                );
            }
            timing("firewall_and_ha");
            if let Some(bundle) = ha_bundle {
                for replica in &bundle.persistence {
                    let pool = runtime
                        .pools
                        .iter()
                        .find(|p| p.config.name == replica.virtual_server)
                        .context("unknown replicated persistence object")?;
                    pool.import_persistence(replica)?;
                }
                self.store
                    .save_ha_configuration(
                        &runtime.config,
                        old.revision + 1,
                        &bundle.certificates,
                        &bundle.material,
                    )
                    .await?;
            } else {
                self.store
                    .save_with_certificate(
                        &runtime.config,
                        old.revision + 1,
                        &actor,
                        certificate.as_ref(),
                    )
                    .await
                    .context("commit configuration database")?;
            }
            timing("database_commit");
            anyhow::Ok((runtime, listeners, admin, firewall_rules))
        }
        .await;
        let (runtime, listeners, admin, firewall_rules) = match prepared {
            Ok(value) => value,
            Err(error) => {
                if let Err(rollback) = network_tx.rollback().await {
                    self.network_recovery_required.store(true, Ordering::SeqCst);
                    self.stop.cancel();
                    return Err(rollback.context(
                        "network rollback failed; daemon stopping; operator recovery required",
                    ));
                }
                return Err(error);
            }
        };
        old.stop.cancel();
        old.tasks.close();
        old.tasks.wait().await;
        timing("old_task_drain");
        let admin_stop = if admin.is_some() {
            old.admin_stop.cancel();
            CancellationToken::new()
        } else {
            old.admin_stop.clone()
        };
        let admin_connections_stop = if admin.is_some()
            || runtime.management_tls.is_some() != old.runtime.management_tls.is_some()
        {
            let previous = old.admin_connections_stop.clone();
            tokio::spawn(async move {
                tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                previous.cancel();
            });
            CancellationToken::new()
        } else {
            old.admin_connections_stop.clone()
        };
        let revision = old.revision + 1;
        let next = Generation {
            runtime,
            listeners,
            firewall_rules,
            revision,
            stop: CancellationToken::new(),
            tasks: TaskTracker::new(),
            admin_stop,
            admin_connections_stop,
        };
        next.runtime.start(
            next.listeners.clone(),
            next.stop.clone(),
            &next.tasks,
            (&self.sessions, self.ha_session_token()),
            self.active.clone(),
        );
        if let Some(listener) = admin {
            self.start_admin(listener, next.admin_stop.clone());
        }
        *old = next;
        timing("activation");
        tracing::info!(revision, "configuration saved and applied");
        Ok(revision)
    }
    pub async fn ha_status(&self) -> serde_json::Value {
        let Some(state) = &self.ha else {
            return serde_json::json!({"role":"standalone","hostname":std::fs::read_to_string("/proc/sys/kernel/hostname").unwrap_or_else(|_|"RiverLB".into()).trim(),"configuration_sync":"standalone","local_configuration_acknowledged":false});
        };
        let generation = self.generation.lock().await;
        let mut status = serde_json::to_value(state.status()).unwrap_or_default();
        if self.network_recovery_required.load(Ordering::SeqCst) || self.stop.is_cancelled() {
            status["role"] = "fault".into();
        }
        let local_config = generation.runtime.config.clone();
        let local_revision = generation.revision;
        let data_ready = state.active.load(Ordering::SeqCst)
            && !generation.stop.is_cancelled()
            && generation.listeners.iter().flatten().count()
                == local_config
                    .virtual_servers
                    .iter()
                    .filter(|v| v.enabled)
                    .count();
        // Database reads and snapshot hashing must not block configuration/probe/status requests.
        drop(generation);
        let checkpoint = state.status();
        let certificates = self.store.ha_certificates().await;
        let material = self.store.ha_material().await;
        let readable = certificates.is_ok() && material.is_ok();
        let bundle = crate::ha::Bundle {
            format: 1,
            cluster_id: state.settings.cluster_id.clone(),
            source_id: state.settings.node_id.clone(),
            created: crate::storage::now(),
            revision: local_revision,
            floating_self_ips: state.settings.floating_self_ips.clone(),
            config: local_config,
            certificates: certificates.unwrap_or_default(),
            material: material.unwrap_or_default(),
            persistence: vec![],
        };
        let matched = readable
            && bundle
                .fingerprint()
                .ok()
                .is_some_and(|fp| checkpoint.fingerprint.as_deref() == Some(&fp));
        let sync = if !readable {
            "unknown"
        } else if status["role"] == "fault" || checkpoint.sync_error.is_some() {
            "error"
        } else if checkpoint.fingerprint.is_none() {
            "not synchronized"
        } else if !matched {
            "pending changes"
        } else if checkpoint
            .checkpoint_time
            .is_none_or(|t| crate::storage::now() - t > state.settings.max_sync_age_secs as i64)
        {
            "stale"
        } else {
            "synchronized"
        };
        status["hostname"] = std::fs::read_to_string("/proc/sys/kernel/hostname")
            .unwrap_or_else(|_| state.settings.node_id.clone())
            .trim()
            .into();
        status["configuration_sync"] = sync.into();
        status["local_configuration_acknowledged"] = matched.into();
        status["automatic_sync"] = state.automatic_sync.load(Ordering::SeqCst).into();
        status["local_revision"] = local_revision.into();
        status["node_id"] = state.settings.node_id.clone().into();
        status["peer_id"] = state.settings.peer_id.clone().into();
        status["data_ready"] = data_ready.into();
        status
    }
    pub fn data_plane_active(&self) -> bool {
        self.ha
            .as_ref()
            .is_none_or(|h| h.active.load(Ordering::SeqCst))
    }
    pub(crate) fn ha_session_token(&self) -> CancellationToken {
        self.ha
            .as_ref()
            .map(|h| h.sessions.lock().unwrap().clone())
            .unwrap_or_default()
    }
    fn validate_ha(config: &Config, state: Option<&crate::ha::State>) -> Result<()> {
        if let Some(state) = state {
            for name in &state.settings.floating_self_ips {
                ensure!(
                    config.network.self_ips.iter().any(|ip| &ip.name == name),
                    "unknown floating self IP {name}"
                );
            }
            for vs in config.virtual_servers.iter().filter(|v| v.enabled) {
                ensure!(
                    !vs.listen.ip().is_unspecified() && !vs.listen.ip().is_loopback(),
                    "HA virtual servers require explicit floating IPs"
                );
                ensure!(
                    vs.tls.is_none(),
                    "HA virtual-server TLS requires managed certificates"
                );
                ensure!(
                    !config.network.self_ips.iter().any(|ip| !state
                        .settings
                        .floating_self_ips
                        .contains(&ip.name)
                        && crate::network::cidr(&ip.address)
                            .is_ok_and(|(address, _)| address == vs.listen.ip())),
                    "HA VIP cannot use a non-floating self IP"
                );
            }
        }
        Ok(())
    }
    async fn ha_resolved(
        store: &crate::storage::Store,
        config: &Config,
        bundle: &crate::ha::Bundle,
    ) -> Result<crate::certificates::Resolved> {
        ensure!(
            bundle.certificates.len() <= 1000,
            "HA certificate inventory too large"
        );
        let mut local = config.clone();
        local.virtual_servers.clear();
        local.domain_routes.clear();
        let mut resolved = store.resolve_certificates(&local).await?;
        let mut metadata = std::collections::HashMap::new();
        for cert in &bundle.certificates {
            ensure!(
                !cert.name.is_empty()
                    && cert.name.len() <= 128
                    && !cert.name.starts_with("device:"),
                "invalid replicated certificate name"
            );
            ensure!(
                metadata
                    .insert(
                        cert.name.clone(),
                        crate::certificates::metadata(&cert.name, &cert.certificate, 0)?
                    )
                    .is_none(),
                "duplicate replicated certificate"
            );
            resolved.insert(
                cert.name.clone(),
                crate::certificates::server_config(&cert.certificate, &cert.private_key)?,
            );
        }
        for vs in &config.virtual_servers {
            for (host, name) in &vs.sni_certificates {
                ensure!(
                    metadata.get(name).is_some_and(|m| m
                        .dns_names
                        .iter()
                        .any(|p| crate::certificates::matches_dns(p, host))),
                    "replicated SNI certificate mismatch"
                );
            }
        }
        for route in &config.domain_routes {
            if let Some(name) = &route.certificate {
                ensure!(
                    metadata.get(name).is_some_and(|m| m
                        .dns_names
                        .iter()
                        .any(|p| crate::certificates::matches_dns(p, &route.hostname))),
                    "replicated domain certificate mismatch"
                );
            }
        }
        Ok(resolved)
    }
    pub async fn receive_ha_bundle(self: &Arc<Self>, bundle: crate::ha::Bundle) -> Result<()> {
        let _gate = self.change_gate.lock().await;
        ensure!(
            self.pending_configuration.lock().await.is_none(),
            "Confirm or revert the pending configuration before accepting HA synchronization"
        );
        let state = self.ha.as_ref().context("HA disabled")?;
        ensure!(
            bundle.material.requests.len() <= 1000
                && bundle.material.renewals.len() <= 1000
                && bundle.material.accounts.len() <= 1000,
            "HA certificate material inventory too large"
        );
        for (name, csr, key, names, _) in &bundle.material.requests {
            crate::certificates::validate_name(name)?;
            crate::certificates::validate_request(csr, key, names)?;
        }
        for job in &bundle.material.renewals {
            ensure!(
                job.settings.store == crate::certificates::StoreKind::VirtualServer,
                "device renewal cannot be replicated"
            );
            job.settings.validate()?;
        }
        for (_, credentials) in &bundle.material.accounts {
            let _: instant_acme::AccountCredentials = serde_json::from_str(credentials)?;
        }
        let fingerprint = bundle.fingerprint()?;
        let (config, revision, same) = {
            let old = self.generation.lock().await;
            ensure!(
                !self.data_plane_active(),
                "active owner rejects peer synchronization"
            );
            let status = state.status();
            ensure!(
                status.last_source_time.is_none_or(|t| bundle.created >= t),
                "out-of-order HA snapshot"
            );
            let current = crate::ha::Bundle {
                config: old.runtime.config.clone(),
                certificates: self.store.ha_certificates().await?,
                material: self.store.ha_material().await?,
                ..bundle.clone()
            };
            (
                bundle.overlay(&old.runtime.config),
                old.revision,
                current.fingerprint()? == fingerprint,
            )
        };
        if same {
            let generation = self.generation.lock().await;
            ensure!(
                !self.data_plane_active(),
                "active owner rejects synchronization"
            );
            for replica in &bundle.persistence {
                let pool = generation
                    .runtime
                    .pools
                    .iter()
                    .find(|p| p.config.name == replica.virtual_server)
                    .context("unknown replicated persistence object")?;
                pool.import_persistence(replica)?;
            }
        } else {
            self.apply_inner(config, revision, "HA peer".into(), None, Some(&bundle))
                .await?;
        }
        {
            let mut status = state.status.lock().unwrap();
            status.peer_revision = Some(bundle.revision);
            status.last_received = Some(crate::storage::now());
            status.checkpoint_time = status.last_received;
            status.last_source_time = Some(bundle.created);
            status.fingerprint = Some(fingerprint);
            status.seed = false;
            status.sync_error = None;
        }
        *state.persistence.lock().unwrap() = bundle.persistence.clone();
        state.save()?;
        Ok(())
    }
    pub async fn set_ha_active(self: &Arc<Self>, active: bool) -> Result<()> {
        let state = self.ha.as_ref().context("HA disabled")?;
        let mut generation = self.generation.lock().await;
        ensure!(
            !self.stop.is_cancelled() && !self.network_recovery_required.load(Ordering::SeqCst),
            "HA withdrawal uncertain; cluster fencing required"
        );
        let was = self.data_plane_active();
        if was == active {
            return Ok(());
        }
        if active {
            let owner = crate::ha::authority(state).await?;
            ensure!(
                owner.is_none() || owner.as_deref() == Some(&state.settings.node_id),
                "another cluster owner is active"
            );
            let status = state.status();
            if !status.seed {
                ensure!(
                    status
                        .checkpoint_time
                        .is_some_and(|t| crate::storage::now() - t
                            <= state.settings.max_sync_age_secs as i64),
                    "standby has no recent synchronized checkpoint; seed only the initial primary"
                );
                let bundle = crate::ha::Bundle {
                    format: 1,
                    cluster_id: state.settings.cluster_id.clone(),
                    source_id: state.settings.node_id.clone(),
                    created: crate::storage::now(),
                    revision: generation.revision,
                    floating_self_ips: state.settings.floating_self_ips.clone(),
                    config: generation.runtime.config.clone(),
                    certificates: self.store.ha_certificates().await?,
                    persistence: vec![],
                    material: self.store.ha_material().await?,
                };
                ensure!(
                    status.fingerprint.as_deref() == Some(bundle.fingerprint()?.as_str()),
                    "local traffic configuration differs from synchronized checkpoint"
                );
            }
        } else {
            state.sessions.lock().unwrap().cancel();
        }
        ensure!(
            !self.stop.is_cancelled() && !self.network_recovery_required.load(Ordering::SeqCst),
            "HA withdrawal uncertain; cluster fencing required"
        );
        state.record_ownership(
            vec![generation.runtime.config.clone()],
            generation.firewall_rules.clone(),
        )?;
        let before = crate::ha::network(&generation.runtime.config, Some(state), was)?;
        let after = crate::ha::network(&generation.runtime.config, Some(state), active)?;
        if !active {
            generation.stop.cancel();
            generation.tasks.close();
            generation.tasks.wait().await;
            generation.listeners.clear();
            self.sessions.close();
            if tokio::time::timeout(std::time::Duration::from_secs(5), self.sessions.wait())
                .await
                .is_err()
            {
                self.network_recovery_required.store(true, Ordering::SeqCst);
                self.stop.cancel();
                anyhow::bail!("HA session withdrawal timed out; cluster fencing required");
            }
        }
        let mut tx = match Transaction::prepare(&before, &after, self.manage_network).await {
            Ok(tx) => tx,
            Err(error) => {
                if !active
                    || error
                        .downcast_ref::<crate::network::RollbackFailure>()
                        .is_some()
                {
                    self.network_recovery_required.store(true, Ordering::SeqCst);
                    self.stop.cancel();
                }
                return Err(error);
            }
        };
        let prepared = async {
            let listeners = if active {
                generation.runtime.bind().await?
            } else {
                vec![None; generation.runtime.pools.len()]
            };
            let firewall_rules = crate::firewall::desired(
                &crate::ha::effective(&generation.runtime.config, Some(state), active),
                self.manage_firewall,
            )
            .await?;
            let mut owned = generation.firewall_rules.clone();
            owned.extend(firewall_rules.iter().cloned());
            state.record_ownership(vec![generation.runtime.config.clone()], owned)?;
            tx.apply_steps(crate::firewall::plan(
                &generation.firewall_rules,
                &firewall_rules,
            ))
            .await?;
            if active {
                crate::ha_network::announce(&after, &before).await?;
                generation.runtime.probe().await;
                let owner = crate::ha::authority(state).await?;
                ensure!(
                    owner.is_none() || owner.as_deref() == Some(&state.settings.node_id),
                    "HA ownership changed during activation"
                );
            }
            anyhow::Ok((listeners, firewall_rules))
        }
        .await;
        let (listeners, firewall_rules) = match prepared {
            Ok(v) => v,
            Err(e) => {
                if active {
                    if let Err(rollback) = tx.rollback().await {
                        self.network_recovery_required.store(true, Ordering::SeqCst);
                        self.stop.cancel();
                        return Err(rollback);
                    }
                } else {
                    self.network_recovery_required.store(true, Ordering::SeqCst);
                    self.stop.cancel();
                }
                return Err(e);
            }
        };
        if active {
            generation.stop.cancel();
            generation.tasks.close();
            generation.tasks.wait().await;
            *state.sessions.lock().unwrap() = CancellationToken::new();
            self.sessions.reopen();
        }
        generation.listeners = listeners;
        generation.firewall_rules = firewall_rules;
        generation.stop = CancellationToken::new();
        generation.tasks = TaskTracker::new();
        state.active.store(active, Ordering::SeqCst);
        {
            let mut status = state.status.lock().unwrap();
            status.role = if active { "active" } else { "standby" }.into();
            status.seed = false;
            status.activated_at = if active {
                Some(crate::storage::now())
            } else {
                None
            };
        }
        generation.runtime.start(
            generation.listeners.clone(),
            generation.stop.clone(),
            &generation.tasks,
            (&self.sessions, self.ha_session_token()),
            self.active.clone(),
        );
        self.store
            .record_audit(
                "Pacemaker controller",
                if active {
                    "HA activated"
                } else {
                    "HA deactivated"
                },
            )
            .await?;
        self.acme_wake.notify_one();
        Ok(())
    }
    pub async fn save_statistics(&self) -> Result<()> {
        // Checkpoints and resets share ordering, without holding generation during disk I/O.
        let _write = self.statistics_write.lock().await;
        let (revision, snapshot) = {
            let generation = self.generation.lock().await;
            (
                generation.revision,
                management::traffic_snapshot(&generation.runtime, generation.revision),
            )
        };
        self.store.record_traffic(revision, snapshot).await
    }
    pub async fn reset_statistics(&self, actor: &str) -> Result<()> {
        let _write = self.statistics_write.lock().await;
        let generation = self.generation.lock().await;
        let mut snapshot = management::traffic_snapshot(&generation.runtime, generation.revision);
        crate::traffic::zero_snapshot(&mut snapshot);
        snapshot["epoch"] = format!("{:016x}", rand::random::<u64>()).into();
        self.store
            .reset_traffic(generation.revision, snapshot.clone(), actor)
            .await?;
        for stats in generation.runtime.stats_registry.lock().unwrap().values() {
            if let Some(stats) = stats.upgrade() {
                stats.reset();
            }
        }
        // A new rate epoch prevents throughput calculation across a reset.
        *generation.runtime.epoch.lock().unwrap() = snapshot["epoch"].as_str().unwrap().to_owned();
        Ok(())
    }
    pub async fn shutdown(&self) {
        self.stop.cancel();
        if let Some(server) = self.local_control.lock().await.take() {
            server.shutdown().await;
        }
        self.renewals.close();
        self.renewals.wait().await;
        let generation = self.generation.lock().await;
        generation.stop.cancel();
        generation.admin_stop.cancel();
        generation.admin_connections_stop.cancel();
        generation.tasks.close();
        generation.tasks.wait().await;
        self.sessions.close();
    }
    pub async fn cleanup_network(&self) -> Result<()> {
        ensure!(
            !self.network_recovery_required.load(Ordering::SeqCst),
            "network rollback failed; automatic cleanup skipped; inspect kernel state before operator recovery"
        );
        let generation = self.generation.lock().await;
        if self.manage_network {
            let mut steps = crate::firewall::plan(&generation.firewall_rules, &Default::default());
            steps.extend(crate::network::plan(
                &crate::ha::network(
                    &generation.runtime.config,
                    self.ha.as_deref(),
                    self.data_plane_active(),
                )?,
                &Network::default(),
            )?);
            Transaction::prepare_plan(steps).await?;
        }
        Ok(())
    }
}

async fn serve_admin_connection<S>(stream: S, router: axum::Router, drain: CancellationToken)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let service = hyper_util::service::TowerToHyperService::new(router);
    let mut connection = Box::pin(
        hyper::server::conn::http1::Builder::new()
            .timer(hyper_util::rt::TokioTimer::new())
            .header_read_timeout(std::time::Duration::from_secs(10))
            .serve_connection(hyper_util::rt::TokioIo::new(stream), service),
    );
    tokio::select! {
        _ = &mut connection => {},
        // Recycle idle keep-alive connections even when no body is being read.
        _ = tokio::time::sleep(std::time::Duration::from_secs(180)) => {},
        _ = drain.cancelled() => {
            connection.as_mut().graceful_shutdown();
            let _ = tokio::time::timeout(std::time::Duration::from_secs(10),connection).await;
        },
    }
}
