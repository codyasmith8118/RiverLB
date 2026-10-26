//! RiverLB daemon and local CLI. See docs/architecture.md before extending.
mod acme;
mod admission;
mod auth;
mod backup;
mod certificates;
mod config;
mod confirmation;
mod control;
mod firewall;
mod ha;
mod ha_deploy;
mod ha_group;
mod ha_network;
mod http_proxy;
mod inspection;
mod interfaces;
mod local_control;
mod management;
mod management_cli;
mod monitor;
mod nat;
mod network;
mod operations;
mod runtime;
mod server_tls;
mod storage;
mod tls;
mod traffic;
mod updates;

use anyhow::Result;
use clap::{Parser, Subcommand};
use config::Config;
use std::{path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

#[derive(Parser)]
#[command(version, about = "RiverLB traffic management appliance")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}
#[derive(Subcommand)]
enum Command {
    /// Manage live configuration and status over verified HTTPS.
    Manage(management_cli::Options),
    /// Verify a signed offline bundle against root-owned publisher trust. Does not install.
    UpdateVerify {
        #[arg(long)]
        bundle: PathBuf,
        #[arg(long,default_value=updates::TRUST)]
        trust: PathBuf,
        #[arg(long, default_value = "0")]
        sequence: u64,
    },
    /// Save a consistent private logical backup. Stop the daemon for local DB access.
    Backup {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    /// Restore a validated snapshot while stopped. --staged uses the portal upload.
    Restore {
        #[arg(long)]
        database: PathBuf,
        #[arg(long, conflicts_with = "staged", required_unless_present = "staged")]
        input: Option<PathBuf>,
        #[arg(long)]
        staged: bool,
        #[arg(long)]
        replace: bool,
    },
    /// Configure an ACME schedule from JSON while stopped; issuance runs in serve.
    Renewal {
        #[arg(long)]
        database: PathBuf,
        #[arg(long)]
        settings: PathBuf,
    },
    /// Manage certificate inventory offline; stop the daemon before local DB commands.
    Certificate {
        #[command(subcommand)]
        command: CertificateCommand,
    },
    /// Export saved configuration JSON. Stop the daemon before local database commands.
    Export {
        #[arg(long)]
        database: PathBuf,
    },
    /// Replace saved configuration from validated TOML while the daemon is stopped.
    Import {
        #[arg(long)]
        database: PathBuf,
        #[arg(short, long)]
        config: PathBuf,
    },
    /// Run the TCP data plane and authenticated web dashboard.
    Serve {
        #[arg(short, long, default_value = "examples/riverlb.toml")]
        config: PathBuf,
        /// Local node settings; starts in standby and delegates ownership to Pacemaker.
        #[arg(long)]
        ha_config: Option<PathBuf>,
        /// Compatibility flag: Linux network provisioning is enabled by default.
        #[arg(long, conflicts_with = "external_network")]
        manage_network: bool,
        /// Save network objects without changing Linux; provision them with OS tooling.
        #[arg(long)]
        external_network: bool,
        #[arg(long)]
        database: Option<PathBuf>,
    },
    /// Root-only local HA controller and restricted SSH synchronization entry point.
    Ha {
        #[arg(long)]
        socket: PathBuf,
        #[arg(value_parser=["status","seed","activate","deactivate","export","receive","sync"])]
        action: String,
    },
    /// Create or reset an administrator. Password is read from stdin, never arguments.
    Admin {
        #[arg(long)]
        database: PathBuf,
        #[arg(long, default_value = "admin")]
        username: String,
    },
    /// Validate the configuration without binding sockets.
    Validate {
        #[arg(short, long, default_value = "examples/riverlb.toml")]
        config: PathBuf,
        #[arg(long)]
        database: Option<PathBuf>,
    },
    /// Show live status from a local daemon.
    Status {
        #[arg(long, default_value = "127.0.0.1:18090")]
        address: std::net::SocketAddr,
        /// Read the management session token from stdin (HTTP loopback CLI only).
        #[arg(long)]
        session_stdin: bool,
    },
}
#[derive(Subcommand)]
enum CertificateCommand {
    List {
        #[arg(long)]
        database: PathBuf,
        #[arg(long, value_enum, default_value = "virtual-server")]
        store: certificates::StoreKind,
    },
    Import {
        #[arg(long)]
        database: PathBuf,
        #[arg(long, value_enum, default_value = "virtual-server")]
        store: certificates::StoreKind,
        #[arg(long)]
        name: String,
        #[arg(long)]
        certificate: PathBuf,
        #[arg(long)]
        private_key: PathBuf,
    },
    Delete {
        #[arg(long)]
        database: PathBuf,
        #[arg(long, value_enum, default_value = "virtual-server")]
        store: certificates::StoreKind,
        #[arg(long)]
        name: String,
    },
}
async fn shutdown() {
    let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .expect("install SIGTERM handler");
    tokio::select! { _ = tokio::signal::ctrl_c() => {}, _ = term.recv() => {} }
}
#[tokio::main]
async fn main() -> Result<()> {
    // Restrict database journals and other files created by dependencies.
    // SAFETY: setting process umask has no pointer arguments; this runs before
    // any application file creation, and is never changed again.
    unsafe {
        libc::umask(0o077);
    }
    let command = Cli::parse().command;
    if !matches!(&command, Command::Manage(_)) {
        tracing_subscriber::fmt()
            .with_env_filter(
                tracing_subscriber::EnvFilter::try_from_default_env()
                    .unwrap_or_else(|_| "riverlb=info".into()),
            )
            .init();
    }
    // Database WAL files and generated secrets inherit private permissions.
    match command {
        Command::Manage(options) => {
            let code = management_cli::run(options).await;
            if code != 0 {
                std::process::exit(code);
            }
        }
        Command::UpdateVerify {
            bundle,
            trust,
            sequence,
        } => {
            println!(
                "{}",
                serde_json::to_string(&updates::verify_file(&bundle, &trust, sequence)?)?
            );
        }
        Command::Backup { database, output } => {
            let store = storage::Store::open(&database).await?;
            let snapshot = store.backup().await?;
            use std::io::Write;
            let mut options = std::fs::OpenOptions::new();
            options.write(true).create_new(true);
            #[cfg(unix)]
            {
                use std::os::unix::fs::OpenOptionsExt;
                options.mode(0o600);
            }
            let mut file = options.open(output)?;
            file.write_all(&serde_json::to_vec(&snapshot)?)?;
            file.sync_all()?;
            println!(
                "Private backup saved (includes keys and password hashes; sessions excluded)."
            );
        }
        Command::Restore {
            database,
            input,
            staged,
            replace,
        } => {
            let store = storage::Store::open(&database).await?;
            anyhow::ensure!(
                replace || store.load().await?.is_none(),
                "target contains configuration; use --replace to overwrite it"
            );
            let snapshot = if staged {
                store
                    .staged_restore()
                    .await?
                    .ok_or_else(|| anyhow::anyhow!("no staged restore"))?
            } else {
                let path = input.unwrap();
                anyhow::ensure!(
                    std::fs::metadata(&path)?.len() <= backup::MAX_BYTES as u64,
                    "backup exceeds size limit"
                );
                serde_json::from_slice(&std::fs::read(path)?)?
            };
            store.restore(&snapshot).await?;
            confirmation::clear(&confirmation::path(&database))?;
            println!(
                "Backup restored; sessions revoked. Start RiverLB and sign in using restored credentials."
            );
        }
        Command::Renewal { database, settings } => {
            let settings = serde_json::from_str(&std::fs::read_to_string(settings)?)?;
            storage::Store::open(&database)
                .await?
                .set_acme_job(settings, "local CLI")
                .await?;
            println!("ACME schedule saved; start RiverLB to issue/renew.");
        }
        Command::Export { database } => {
            let store = storage::Store::open(&database).await?;
            let (config, _) = store
                .load()
                .await?
                .ok_or_else(|| anyhow::anyhow!("database has no saved configuration"))?;
            println!("{}", serde_json::to_string_pretty(&config)?);
        }
        Command::Import { database, config } => {
            let config = Config::load(&config)?;
            let store = storage::Store::open(&database).await?;
            store.resolve_certificates(&config).await?;
            let revision = store.load().await?.map_or(1, |(_, revision)| revision + 1);
            store.save(&config, revision, "local import").await?;
            println!("Configuration imported as revision {revision}");
        }
        Command::Admin { database, username } => {
            use std::io::IsTerminal;
            let password = if std::io::stdin().is_terminal() {
                rpassword::prompt_password("New administrator password: ")?
            } else {
                let mut password = String::new();
                std::io::stdin().read_line(&mut password)?;
                password.trim_end_matches(['\r', '\n']).to_owned()
            };
            storage::Store::open(&database)
                .await?
                .set_admin(&username, password)
                .await?;
            println!("Administrator saved; existing sessions revoked.");
        }
        Command::Validate { config, database } => {
            let parsed = Config::load(&config)?;
            if parsed.management_certificate.is_some()
                || parsed
                    .virtual_servers
                    .iter()
                    .any(|v| v.certificate.is_some())
            {
                storage::Store::open(&database.unwrap_or_else(|| config.with_extension("db")))
                    .await?
                    .resolve_certificates(&parsed)
                    .await?;
            }
            println!("Configuration valid");
        }
        Command::Certificate { command } => match command {
            CertificateCommand::List { database, store } => {
                println!(
                    "{}",
                    serde_json::to_string_pretty(
                        &storage::Store::open(&database)
                            .await?
                            .certificates_in(store)
                            .await?
                    )?
                );
            }
            CertificateCommand::Import {
                database,
                store,
                name,
                certificate,
                private_key,
            } => {
                storage::Store::open(&database)
                    .await?
                    .import_certificate_in(
                        store,
                        &name,
                        &std::fs::read_to_string(certificate)?,
                        &std::fs::read_to_string(private_key)?,
                        "local CLI",
                    )
                    .await?;
                println!("Certificate imported: {name}");
            }
            CertificateCommand::Delete {
                database,
                name,
                store,
            } => {
                let database_store = storage::Store::open(&database).await?;
                if let Some((config, _)) = database_store.load().await? {
                    anyhow::ensure!(
                        match store {
                            certificates::StoreKind::Device =>
                                config.management_certificate.as_deref() != Some(&name),
                            certificates::StoreKind::VirtualServer =>
                                !config
                                    .domain_routes
                                    .iter()
                                    .any(|r| r.certificate.as_deref() == Some(&name))
                                    && !config.virtual_servers.iter().any(|v| v
                                        .certificate
                                        .as_deref()
                                        == Some(&name)
                                        || v.sni_certificates.values().any(|c| c == &name)),
                        },
                        "certificate is assigned; remove assignments first"
                    );
                }
                anyhow::ensure!(
                    database_store
                        .delete_certificate_in(store, &name, "local CLI")
                        .await?,
                    "unknown certificate"
                );
                println!("Certificate deleted: {name}");
            }
        },
        Command::Status {
            address,
            session_stdin,
        } => {
            let mut token = String::new();
            if session_stdin {
                std::io::stdin().read_line(&mut token)?;
            }
            let token = token.trim();
            anyhow::ensure!(
                token.len() == 64 && token.chars().all(|c| c.is_ascii_hexdigit()),
                "status requires --session-stdin with a signed-in management session token"
            );
            anyhow::ensure!(
                address.ip().is_loopback(),
                "status requires a loopback address"
            );
            let response = tokio::time::timeout(Duration::from_secs(5), async {
                let mut socket = TcpStream::connect(address).await?;
                socket.write_all(format!("GET /api/v1/status HTTP/1.0\r\nHost: {address}\r\nCookie: riverlb_session={token}\r\nConnection: close\r\n\r\n").as_bytes()).await?;
                let mut response = String::new();
                socket.take(4 * 1024 * 1024).read_to_string(&mut response).await?;
                anyhow::Ok(response)
            }).await??;
            anyhow::ensure!(
                response.starts_with("HTTP/1.0 200") || response.starts_with("HTTP/1.1 200"),
                "management returned an error"
            );
            let body = response
                .split_once("\r\n\r\n")
                .ok_or_else(|| anyhow::anyhow!("invalid HTTP response"))?
                .1;
            println!(
                "{}",
                serde_json::to_string_pretty(&serde_json::from_str::<serde_json::Value>(body)?)?
            );
        }
        Command::Ha { socket, action } => {
            let bundle = if action == "receive" {
                let mut bytes = Vec::new();
                tokio::io::stdin()
                    .take((ha::MAX_BYTES + 1) as u64)
                    .read_to_end(&mut bytes)
                    .await?;
                anyhow::ensure!(bytes.len() <= ha::MAX_BYTES, "HA input too large");
                Some(serde_json::from_slice(&bytes)?)
            } else {
                None
            };
            let result = ha::call(&socket, &ha::Request { action, bundle }).await?;
            println!("{}", serde_json::to_string(&result)?);
        }
        Command::Serve {
            config,
            ha_config,
            manage_network,
            external_network,
            database,
        } => {
            let manage_network = manage_network || !external_network;
            let control =
                control::Control::new(config, manage_network, database, ha_config).await?;
            tokio::select! { _ = shutdown() => {}, _ = control.stop.cancelled() => {} }
            control.shutdown().await;
            if tokio::time::timeout(Duration::from_secs(10), control.sessions.wait())
                .await
                .is_err()
            {
                tracing::warn!("drain deadline exceeded; remaining sessions will close");
            }
            let statistics = control.save_statistics().await;
            control.cleanup_network().await?;
            statistics?;
        }
    }
    Ok(())
}
