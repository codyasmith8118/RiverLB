//! Root-only, read-only readiness IPC for installed appliance lifecycle helpers.
use crate::control::Control;
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{
    os::unix::fs::{DirBuilderExt, FileTypeExt, MetadataExt, PermissionsExt},
    path::{Path, PathBuf},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{UnixListener, UnixStream},
    task::{JoinHandle, JoinSet},
    time::timeout,
};
use tokio_util::sync::CancellationToken;

pub const SOCKET: &str = "/run/riverlb/operations.sock";
const DATABASE: &str = "/var/lib/riverlb/riverlb.db";
const DEADLINE: Duration = Duration::from_secs(1);
const MAX_REQUEST: usize = 256;
const MAX_RESPONSE: usize = 2 * 1024 * 1024;
const MAX_CLIENTS: usize = 16;

#[derive(Serialize)]
struct VirtualServerStatus {
    name: String,
    enabled: bool,
    state: &'static str,
    healthy_members: usize,
}
#[derive(Serialize)]
struct Status {
    version: &'static str,
    revision: u64,
    management: String,
    management_secure: bool,
    confirmation_pending: bool,
    ha_role: &'static str,
    virtual_servers: Vec<VirtualServerStatus>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Request {
    action: String,
}

/// Separate ownership from traffic sessions: dropping this handle requests local
/// server shutdown without stopping the management or traffic listeners.
pub struct Server {
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}
impl Server {
    pub async fn shutdown(mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

struct SocketGuard {
    path: PathBuf,
    device: u64,
    inode: u64,
    owner: u32,
}
impl Drop for SocketGuard {
    fn drop(&mut self) {
        // An administrator might have replaced the pathname while this listener
        // was running. Never delete a replacement file, link, or another socket.
        if std::fs::symlink_metadata(&self.path).is_ok_and(|metadata| {
            metadata.file_type().is_socket()
                && metadata.uid() == self.owner
                && metadata.dev() == self.device
                && metadata.ino() == self.inode
        }) {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

async fn bind_private(path: &Path, owner: u32) -> Result<(UnixListener, SocketGuard)> {
    let parent = path
        .parent()
        .context("Local control socket directory missing")?;
    let metadata = std::fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == owner
            && metadata.permissions().mode() & 0o077 == 0,
        "Local control socket directory must be private and owned by the service"
    );
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            ensure!(
                metadata.file_type().is_socket()
                    && metadata.uid() == owner
                    && metadata.permissions().mode() & 0o077 == 0,
                "Local control socket path is not a private owned socket"
            );
            match timeout(DEADLINE, UnixStream::connect(path)).await {
                Ok(Err(error)) if error.raw_os_error() == Some(libc::ECONNREFUSED) => {
                    let current = std::fs::symlink_metadata(path)?;
                    ensure!(
                        current.file_type().is_socket()
                            && current.uid() == owner
                            && current.dev() == metadata.dev()
                            && current.ino() == metadata.ino(),
                        "Local control socket changed during stale-socket inspection"
                    );
                    std::fs::remove_file(path)?;
                }
                _ => anyhow::bail!(
                    "Local control socket is already active or cannot be safely reconciled"
                ),
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error.into()),
    }
    let listener = UnixListener::bind(path)?;
    let metadata = std::fs::symlink_metadata(path)?;
    let guard = SocketGuard {
        path: path.to_owned(),
        device: metadata.dev(),
        inode: metadata.ino(),
        owner,
    };
    ensure!(
        metadata.file_type().is_socket() && metadata.uid() == owner,
        "Local control socket ownership changed"
    );
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    Ok((listener, guard))
}

fn ensure_runtime_directory(path: &Path, owner: u32) -> Result<()> {
    let directory = path
        .parent()
        .context("Local control socket directory missing")?;
    match std::fs::symlink_metadata(directory) {
        Ok(_) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            // Direct installed CLI startup has no systemd RuntimeDirectory.
            // Create only this fixed child of a trusted parent, never an entire
            // path or an adopted directory whose ownership/mode is unknown.
            let parent = directory.parent().context("Local runtime parent missing")?;
            let metadata = std::fs::symlink_metadata(parent)?;
            ensure!(
                metadata.is_dir()
                    && !metadata.file_type().is_symlink()
                    && metadata.uid() == owner
                    && metadata.permissions().mode() & 0o022 == 0,
                "Local runtime parent must be an owned directory without group or public writes"
            );
            match std::fs::DirBuilder::new().mode(0o700).create(directory) {
                Ok(()) => {}
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error.into()),
            }
        }
        Err(error) => return Err(error.into()),
    }
    let metadata = std::fs::symlink_metadata(directory)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == owner
            && metadata.permissions().mode() & 0o077 == 0,
        "Local control socket directory must be private and owned by the service"
    );
    Ok(())
}

async fn snapshot(control: &Control) -> Result<Status> {
    let _gate = control.change_gate.lock().await;
    let confirmation_pending = control.pending_configuration.lock().await.is_some();
    let ha_role = if control.ha.is_none() {
        "standalone"
    } else if control.data_plane_active() {
        "active"
    } else {
        "standby"
    };
    let generation = control.generation.lock().await;
    let runtime = &generation.runtime;
    let virtual_servers = runtime
        .pools
        .iter()
        .map(|pool| {
            let members = pool
                .members
                .lock()
                .map_err(|_| anyhow::anyhow!("Local readiness member state unavailable"))?;
            let healthy_members = members
                .iter()
                .filter(|member| member.healthy && !member.draining)
                .count();
            let state = if !pool.config.enabled {
                "disabled"
            } else if healthy_members > 0 {
                "up"
            } else if members.iter().any(|member| member.healthy) {
                "unavailable"
            } else if members.is_empty() || members.iter().any(|member| member.last_probe.is_none())
            {
                "unknown"
            } else {
                "down"
            };
            Ok(VirtualServerStatus {
                name: pool.config.name.clone(),
                enabled: pool.config.enabled,
                state,
                healthy_members,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(Status {
        version: env!("CARGO_PKG_VERSION"),
        revision: generation.revision,
        management: runtime.config.management.to_string(),
        management_secure: runtime.management_tls.is_some(),
        confirmation_pending,
        ha_role,
        virtual_servers,
    })
}

async fn read_request(stream: &mut UnixStream) -> Result<Request> {
    let mut bytes = Vec::with_capacity(32);
    loop {
        let byte = stream.read_u8().await?;
        ensure!(
            bytes.len() < MAX_REQUEST,
            "Local request exceeds size limit"
        );
        if byte == b'\n' {
            break;
        }
        bytes.push(byte);
    }
    let request: Request = serde_json::from_slice(&bytes)?;
    ensure!(request.action == "status", "Only local status is supported");
    Ok(request)
}

async fn reply(stream: &mut UnixStream, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= MAX_RESPONSE,
        "Local response exceeds size limit"
    );
    stream.write_all(bytes).await?;
    stream.write_all(b"\n").await?;
    stream.shutdown().await?;
    Ok(())
}

async fn handle(control: Arc<Control>, mut stream: UnixStream) {
    // Authenticate kernel credentials before reading any request. No headers,
    // claimed username, or management source allowlist participate in this IPC.
    let allowed = stream
        .peer_cred()
        .is_ok_and(|credentials| credentials.uid() == 0);
    let _ = timeout(DEADLINE, async {
        if !allowed {
            return reply(&mut stream, br#"{"error":"Root credentials required"}"#).await;
        }
        if read_request(&mut stream).await.is_err() {
            return reply(
                &mut stream,
                br#"{"error":"Expected bounded status JSON line"}"#,
            )
            .await;
        }
        match snapshot(&control)
            .await
            .and_then(|status| serde_json::to_vec(&status).map_err(Into::into))
        {
            Ok(bytes) => reply(&mut stream, &bytes).await,
            Err(_) => reply(&mut stream, br#"{"error":"Local readiness unavailable"}"#).await,
        }
    })
    .await;
}

/// Repository instances never expose this socket. The installed service's private
/// runtime directory comes from systemd or a private child of the trusted /run
/// parent for direct CLI startup. Existing directories are never adopted.
pub async fn start(control: Arc<Control>, database: &Path) -> Result<Option<Server>> {
    if database != Path::new(DATABASE) || unsafe { libc::geteuid() } != 0 {
        return Ok(None);
    }
    ensure_runtime_directory(Path::new(SOCKET), 0)?;
    let (listener, guard) = bind_private(Path::new(SOCKET), 0).await?;
    let stop = CancellationToken::new();
    let server_stop = stop.clone();
    let task = tokio::spawn(async move {
        let _guard = guard;
        let mut clients = JoinSet::new();
        loop {
            tokio::select! {
                _ = server_stop.cancelled() => break,
                _ = control.stop.cancelled() => break,
                Some(_) = clients.join_next(), if !clients.is_empty() => {},
                accepted = listener.accept() => {
                    let Ok((stream, _)) = accepted else { break; };
                    if clients.len() < MAX_CLIENTS { clients.spawn(handle(control.clone(), stream)); }
                }
            }
        }
        clients.shutdown().await;
    });
    Ok(Some(Server {
        stop,
        task: Some(task),
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    fn private_directory() -> tempfile::TempDir {
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        directory
    }
    #[test]
    fn runtime_directory_bootstrap_never_adopts_untrusted_paths() {
        let directory = private_directory();
        let owner = unsafe { libc::geteuid() };
        let path = directory.path().join("runtime").join("operations.sock");
        ensure_runtime_directory(&path, owner).unwrap();
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        std::fs::set_permissions(
            path.parent().unwrap(),
            std::fs::Permissions::from_mode(0o755),
        )
        .unwrap();
        assert!(ensure_runtime_directory(&path, owner).is_err());
        assert_eq!(
            std::fs::metadata(path.parent().unwrap())
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o755
        );
        std::fs::remove_dir(path.parent().unwrap()).unwrap();
        std::os::unix::fs::symlink(directory.path(), path.parent().unwrap()).unwrap();
        assert!(ensure_runtime_directory(&path, owner).is_err());
        std::fs::remove_file(path.parent().unwrap()).unwrap();
        assert!(ensure_runtime_directory(&path, owner.wrapping_add(1)).is_err());
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o777)).unwrap();
        assert!(ensure_runtime_directory(&path, owner).is_err());
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let linked = directory.path().join("linked-parent");
        std::os::unix::fs::symlink(directory.path(), &linked).unwrap();
        assert!(
            ensure_runtime_directory(&linked.join("runtime").join("operations.sock"), owner)
                .is_err()
        );
        assert!(!path.parent().unwrap().exists());
    }
    #[tokio::test]
    async fn owned_socket_lifecycle_rejects_links_files_live_and_public_paths() {
        let directory = private_directory();
        let path = directory.path().join("operations.sock");
        let owner = unsafe { libc::geteuid() };
        std::fs::write(&path, "file must not be removed").unwrap();
        assert!(bind_private(&path, owner).await.is_err());
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "file must not be removed"
        );
        std::fs::remove_file(&path).unwrap();
        std::os::unix::fs::symlink("missing-target", &path).unwrap();
        assert!(bind_private(&path, owner).await.is_err());
        assert!(
            std::fs::symlink_metadata(&path)
                .unwrap()
                .file_type()
                .is_symlink()
        );
        std::fs::remove_file(&path).unwrap();
        let (listener, guard) = bind_private(&path, owner).await.unwrap();
        assert!(bind_private(&path, owner).await.is_err());
        assert_eq!(
            std::fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        drop(listener);
        drop(guard);
        assert!(!path.exists());
        let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
        drop(listener);
        let (listener, guard) = bind_private(&path, owner).await.unwrap();
        drop(listener);
        std::fs::remove_file(&path).unwrap();
        std::fs::write(&path, "replacement survives").unwrap();
        drop(guard);
        assert_eq!(
            std::fs::read_to_string(&path).unwrap(),
            "replacement survives"
        );
        std::fs::remove_file(&path).unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
        assert!(bind_private(&path, owner).await.is_err());
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let link = directory.path().join("linked-parent");
        std::os::unix::fs::symlink(directory.path(), &link).unwrap();
        assert!(
            bind_private(&link.join("operations.sock"), owner)
                .await
                .is_err()
        );
        assert!(bind_private(&path, owner.wrapping_add(1)).await.is_err());
    }
    #[tokio::test]
    async fn json_lines_are_bounded_and_only_status_is_admitted() {
        for (bytes, accepted) in [
            (br#"{"action":"status"}"#.as_slice(), true),
            (br#"{"action":"activate"}"#.as_slice(), false),
            (
                br#"{"action":"status","token":"claimed"}"#.as_slice(),
                false,
            ),
            (b"invalid".as_slice(), false),
        ] {
            let (mut sender, mut receiver) = UnixStream::pair().unwrap();
            sender.write_all(bytes).await.unwrap();
            sender.write_all(b"\n").await.unwrap();
            assert_eq!(read_request(&mut receiver).await.is_ok(), accepted);
        }
        let (mut sender, mut receiver) = UnixStream::pair().unwrap();
        sender
            .write_all(&vec![b'x'; MAX_REQUEST + 1])
            .await
            .unwrap();
        assert!(read_request(&mut receiver).await.is_err());
        let (_sender, mut receiver) = UnixStream::pair().unwrap();
        assert!(
            timeout(Duration::from_millis(20), read_request(&mut receiver))
                .await
                .is_err()
        );
        let (sender, receiver) = UnixStream::pair().unwrap();
        assert_eq!(receiver.peer_cred().unwrap().uid(), unsafe {
            libc::geteuid()
        });
        drop(sender);
    }
    #[test]
    fn serialized_readiness_has_only_explicit_nonsecret_fields() {
        let status = Status {
            version: "fixture",
            revision: 2,
            management: "192.0.2.1:18090".into(),
            management_secure: true,
            confirmation_pending: false,
            ha_role: "standalone",
            virtual_servers: vec![VirtualServerStatus {
                name: "web".into(),
                enabled: true,
                state: "up",
                healthy_members: 2,
            }],
        };
        let value = serde_json::to_value(status).unwrap();
        assert_eq!(
            value
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            [
                "version",
                "revision",
                "management",
                "management_secure",
                "confirmation_pending",
                "ha_role",
                "virtual_servers"
            ]
            .into_iter()
            .collect()
        );
        assert_eq!(
            value["virtual_servers"][0]
                .as_object()
                .unwrap()
                .keys()
                .map(String::as_str)
                .collect::<std::collections::BTreeSet<_>>(),
            ["name", "enabled", "state", "healthy_members"]
                .into_iter()
                .collect()
        );
    }
    #[tokio::test]
    async fn runtime_readiness_and_kernel_credentials_use_disposable_state() {
        fn free_port() -> u16 {
            let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
            listener.local_addr().unwrap().port()
        }
        let directory = private_directory();
        let config = directory.path().join("fixture.toml");
        let management = free_port();
        let mut virtual_port = free_port();
        while virtual_port == management {
            virtual_port = free_port();
        }
        std::fs::write(&config,format!("management = \"127.0.0.1:{management}\"\nconnect_timeout_ms = 1000\nsession_timeout_secs = 10\nhealth_interval_secs = 1\nmax_connections = 64\n[[virtual_servers]]\nname = \"readiness-only\"\nlisten = \"127.0.0.1:{virtual_port}\"\nenabled = false\nmembers = [\"127.0.0.1:9\"]\n")).unwrap();
        let database = config.with_extension("db");
        let control = Control::new(config, false, Some(database.clone()), None)
            .await
            .unwrap();
        assert!(
            start(control.clone(), &database).await.unwrap().is_none(),
            "Repository databases never create the installed socket"
        );
        let status = snapshot(&control).await.unwrap();
        assert_eq!(status.revision, 1);
        assert_eq!(status.management, format!("127.0.0.1:{management}"));
        assert!(!status.management_secure);
        assert_eq!(status.ha_role, "standalone");
        assert_eq!(status.virtual_servers[0].name, "readiness-only");
        assert_eq!(status.virtual_servers[0].state, "disabled");
        let gate = control.change_gate.lock().await;
        assert!(
            timeout(Duration::from_millis(20), snapshot(&control))
                .await
                .is_err(),
            "Readiness cannot observe a partial configuration transaction"
        );
        drop(gate);
        let (mut client, server) = UnixStream::pair().unwrap();
        let task = tokio::spawn(handle(control.clone(), server));
        // Non-root clients are rejected from kernel credentials before any input
        // is read, so they need not send even a syntactically valid request.
        if unsafe { libc::geteuid() } == 0 {
            client
                .write_all(b"{\"action\":\"status\"}\n")
                .await
                .unwrap();
        }
        let mut response = Vec::new();
        timeout(DEADLINE, client.read_to_end(&mut response))
            .await
            .unwrap()
            .unwrap();
        task.await.unwrap();
        let response: serde_json::Value = serde_json::from_slice(&response).unwrap();
        if unsafe { libc::geteuid() } == 0 {
            assert_eq!(response["revision"], 1);
            assert_eq!(response["virtual_servers"][0]["name"], "readiness-only");
        } else {
            assert_eq!(
                response,
                serde_json::json!({"error":"Root credentials required"})
            );
        }
        control.shutdown().await;
    }
}
