//! Installed daemon client for the fixed root broker. No privileged fallback.
use anyhow::{Context, Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use std::{
    io::{Read, Write},
    os::{
        fd::AsRawFd,
        unix::{
            fs::{FileTypeExt, MetadataExt},
            net::UnixStream,
            process::ExitStatusExt,
        },
    },
    path::{Path, PathBuf},
    process::{ExitStatus, Output},
    sync::OnceLock,
    time::Duration,
};

pub const SOCKET: &str = "/run/riverlb-privileged/control.sock";
static ENDPOINT: OnceLock<PathBuf> = OnceLock::new();
const MAX_RESPONSE: usize = 2 * 1024 * 1024;
const MAX_REQUEST: usize = 65536;

pub fn configure(path: PathBuf) -> Result<()> {
    ensure!(
        path.is_absolute()
            && !path
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir)),
        "Privileged socket must be an absolute path without parent traversal"
    );
    ensure!(
        ENDPOINT.set(path).is_ok(),
        "Privileged client already configured"
    );
    Ok(())
}
pub fn enabled() -> bool {
    ENDPOINT.get().is_some()
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Challenge {
    version: u32,
    nonce: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Response {
    version: u32,
    ok: bool,
    #[serde(default)]
    result: Value,
    error: Option<String>,
}
fn read(stream: &mut UnixStream) -> Result<Vec<u8>> {
    let mut header = [0; 4];
    stream.read_exact(&mut header)?;
    let length = u32::from_be_bytes(header) as usize;
    ensure!(
        length > 0 && length <= MAX_RESPONSE,
        "Privileged response exceeds its bound"
    );
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes)?;
    Ok(bytes)
}
fn exchange(path: &Path, action: &str, parameters: Value) -> Result<Value> {
    let parent =
        std::fs::symlink_metadata(path.parent().context("Privileged socket parent missing")?)?;
    let endpoint = std::fs::symlink_metadata(path)?;
    ensure!(
        parent.is_dir()
            && parent.uid() == 0
            && parent.mode() & 0o022 == 0
            && endpoint.file_type().is_socket()
            && endpoint.uid() == 0
            && endpoint.mode() & 0o007 == 0,
        "Privileged endpoint must have trusted root ownership and permissions"
    );
    let mut stream = UnixStream::connect(path)?;
    stream.set_read_timeout(Some(Duration::from_secs(180)))?;
    stream.set_write_timeout(Some(Duration::from_secs(5)))?;
    let mut credentials: libc::ucred = unsafe { std::mem::zeroed() };
    let mut length = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SO_PEERCRED is supplied by the kernel, not the peer's JSON or pathname.
    let status = unsafe {
        libc::getsockopt(
            stream.as_raw_fd(),
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&mut credentials as *mut libc::ucred).cast(),
            &mut length,
        )
    };
    ensure!(
        status == 0
            && length as usize == std::mem::size_of::<libc::ucred>()
            && credentials.uid == 0,
        "Privileged peer is not root"
    );
    let hello: Challenge = serde_json::from_slice(&read(&mut stream)?)?;
    ensure!(
        hello.version == 1
            && hello.nonce.len() == 64
            && hello.nonce.bytes().all(|b| b.is_ascii_hexdigit()),
        "Unsupported privileged challenge"
    );
    let bytes = serde_json::to_vec(
        &json!({"version":1,"nonce":hello.nonce,"action":action,"parameters":parameters}),
    )?;
    ensure!(
        bytes.len() <= MAX_REQUEST,
        "Privileged request exceeds its bound"
    );
    stream.write_all(&(bytes.len() as u32).to_be_bytes())?;
    stream.write_all(&bytes)?;
    let response: Response = serde_json::from_slice(&read(&mut stream)?)?;
    ensure!(
        response.version == 1 && response.ok && response.error.is_none(),
        "Privileged operation rejected"
    );
    Ok(response.result)
}
pub async fn call(action: &str, parameters: Value) -> Result<Value> {
    let path = ENDPOINT
        .get()
        .context("Installed privileged broker is not configured")?
        .clone();
    let action = action.to_owned();
    tokio::task::spawn_blocking(move || exchange(&path, &action, parameters))
        .await?
        .context("Privileged broker unavailable or rejected the operation")
}
pub async fn ready() -> Result<()> {
    let mut last = None;
    for _ in 0..50 {
        match call("status", json!({})).await {
            Ok(status) => {
                ensure!(
                    status["protocol"].as_u64() == Some(1)
                        && status["uid"].as_u64() == Some(unsafe { libc::geteuid() } as u64),
                    "Privileged service protocol or application identity mismatch"
                );
                return Ok(());
            }
            Err(error) => last = Some(error),
        }
        tokio::time::sleep(std::time::Duration::from_millis(100)).await;
    }
    Err(last.context("Privileged service did not become ready")?)
}
pub async fn command(action: &str, parameters: Value) -> Result<Output> {
    let result = call(action, parameters).await?;
    let code = result["code"]
        .as_i64()
        .filter(|code| (0..=255).contains(code))
        .context("Invalid privileged status")?;
    let stdout = result["stdout"]
        .as_str()
        .context("Invalid privileged output")?
        .as_bytes()
        .to_vec();
    let stderr = result["stderr"]
        .as_str()
        .context("Invalid privileged diagnostic")?
        .as_bytes()
        .to_vec();
    Ok(Output {
        status: ExitStatus::from_raw((code as i32) << 8),
        stdout,
        stderr,
    })
}
pub async fn network(arguments: &[String]) -> Result<bool> {
    let result = call("network", json!({"argv":arguments})).await?;
    ensure!(
        result["code"].as_i64() == Some(0),
        "Privileged network operation failed"
    );
    Ok(result["changed"].as_bool().unwrap_or(true))
}
pub async fn firewall(arguments: &[String]) -> Result<bool> {
    let result = call("firewall", json!({"argv":arguments})).await?;
    ensure!(
        result["code"].as_i64() == Some(0),
        "Privileged firewall operation failed"
    );
    Ok(result["changed"].as_bool().unwrap_or(true))
}
