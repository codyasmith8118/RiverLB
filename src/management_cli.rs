//! Online, revision-preserving management client. No local database access.
use clap::{Args, Subcommand, ValueEnum};
use http_body_util::{BodyExt, Full, Limited};
use hyper::{Request, body::Bytes};
use hyper_util::rt::TokioIo;
use serde_json::{Value, json};
use std::{
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::net::TcpStream;

const MAX: usize = 2 * 1024 * 1024;
#[derive(Args)]
pub struct Options {
    /// Management HTTPS origin, without a path or credentials.
    #[arg(long, default_value = "https://127.0.0.1:18090")]
    url: String,
    /// Trusted CA PEM file; defaults to the system CA bundle.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Owner-only credential file containing a scoped bearer token.
    #[arg(long, conflicts_with = "session_file")]
    token_file: Option<PathBuf>,
    /// Owner-only file containing an existing management session.
    #[arg(long)]
    session_file: Option<PathBuf>,
    #[command(subcommand)]
    command: Action,
}
#[derive(Subcommand)]
enum Action {
    /// Login with a JSON {username,password,code?} document on stdin; save a private session file.
    Login {
        #[arg(long)]
        output: PathBuf,
    },
    Logout,
    Status,
    /// Read the complete revisioned configuration.
    Get,
    /// Validate a complete configuration JSON file without activating it.
    Validate {
        #[arg(long)]
        input: PathBuf,
    },
    /// Review the server's diff and connectivity-confirmation requirements.
    Diff {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        revision: u64,
    },
    /// Apply a complete configuration at the reviewed revision. Never auto-confirms.
    Apply {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        revision: u64,
    },
    Confirmation,
    Confirm {
        #[arg(long)]
        revision: u64,
    },
    Revert {
        #[arg(long)]
        revision: u64,
    },
    History,
    /// Apply a historical configuration as a new revision; never rewinds the revision counter.
    Rollback {
        #[arg(long)]
        target: u64,
        #[arg(long)]
        revision: u64,
    },
    /// CRUD for named objects in the shared configuration model.
    Object {
        #[arg(value_enum)]
        kind: Kind,
        #[command(subcommand)]
        action: ObjectAction,
    },
    /// Print static shell completion, which never reads credentials.
    Completion {
        #[arg(long, value_enum)]
        shell: Shell,
    },
}
#[derive(Clone, Copy, ValueEnum)]
enum Shell {
    Bash,
    Zsh,
}
#[derive(Clone, Copy, ValueEnum)]
enum Kind {
    VirtualServers,
    Pools,
    Nodes,
    DomainRoutes,
    HealthMonitors,
    PersistenceProfiles,
    ServerTlsProfiles,
    RiverRules,
    CookieProfiles,
    HttpProfiles,
    Vlans,
    SelfIps,
    Routes,
}
impl Kind {
    fn path(self) -> &'static str {
        match self {
            Self::VirtualServers => "/virtual_servers",
            Self::Pools => "/pools",
            Self::Nodes => "/nodes",
            Self::DomainRoutes => "/domain_routes",
            Self::HealthMonitors => "/health_monitors",
            Self::PersistenceProfiles => "/persistence_profiles",
            Self::ServerTlsProfiles => "/server_tls_profiles",
            Self::RiverRules => "/river_rules",
            Self::CookieProfiles => "/cookie_profiles",
            Self::HttpProfiles => "/http_profiles",
            Self::Vlans => "/network/vlans",
            Self::SelfIps => "/network/self_ips",
            Self::Routes => "/network/routes",
        }
    }
}
#[derive(Subcommand)]
enum ObjectAction {
    List,
    Get {
        name: String,
    },
    Create {
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        revision: u64,
    },
    /// Replace the entire named object. Renaming requires an explicit whole-config apply.
    Update {
        name: String,
        #[arg(long)]
        input: PathBuf,
        #[arg(long)]
        revision: u64,
    },
    Delete {
        name: String,
        #[arg(long)]
        revision: u64,
    },
}
struct Failure {
    kind: &'static str,
    code: i32,
    status: Option<u16>,
}
type Result<T> = std::result::Result<T, Failure>;
fn fail(kind: &'static str, code: i32) -> Failure {
    Failure {
        kind,
        code,
        status: None,
    }
}
fn input(path: &Path) -> Result<Value> {
    let mut bytes = Vec::new();
    std::fs::File::open(path)
        .map_err(|_| fail("input", 2))?
        .take((MAX + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| fail("input", 2))?;
    if bytes.len() > MAX {
        return Err(fail("input", 2));
    }
    serde_json::from_slice(&bytes).map_err(|_| fail("input", 2))
}
fn credential(path: &Path) -> Result<String> {
    let file = std::fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| fail("credential_file", 2))?;
    let meta = file.metadata().map_err(|_| fail("credential_file", 2))?;
    if !meta.is_file()
        || meta.mode() & 0o077 != 0
        || meta.uid() != unsafe { libc::geteuid() }
        || meta.len() > 4096
    {
        return Err(fail("credential_file", 2));
    }
    let mut text = String::new();
    file.take(4097)
        .read_to_string(&mut text)
        .map_err(|_| fail("credential_file", 2))?;
    let text = text.trim();
    // Scoped tokens add the server-defined prefix to the random hex secret.
    let secret = text.strip_prefix("rlb_").unwrap_or(text);
    if secret.len() != 64 || !secret.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(fail("credential_file", 2));
    }
    Ok(text.to_owned())
}
struct Client {
    host: String,
    authority: String,
    port: u16,
    tls: tokio_rustls::TlsConnector,
    auth: Option<String>,
}
impl Client {
    fn new(options: &Options) -> Result<Self> {
        let uri: hyper::Uri = options.url.parse().map_err(|_| fail("https_origin", 2))?;
        let authority = uri
            .authority()
            .ok_or_else(|| fail("https_origin", 2))?
            .as_str()
            .to_owned();
        if uri.scheme_str() != Some("https")
            || authority.contains('@')
            || uri.path() != "/"
            || uri.query().is_some()
        {
            return Err(fail("https_origin", 2));
        }
        let host = uri
            .host()
            .ok_or_else(|| fail("https_origin", 2))?
            .trim_matches(['[', ']'])
            .to_owned();
        let tls = crate::server_tls::Profile {
            name: "management_cli".into(),
            server_name: host.clone(),
            ca_certificate: options
                .ca
                .as_ref()
                .map(|p| p.to_string_lossy().into_owned())
                .unwrap_or_else(|| "system".into()),
        }
        .connector()
        .map_err(|_| fail("tls_trust", 7))?;
        let auth = if let Some(path) = &options.token_file {
            Some(format!("Bearer {}", credential(path)?))
        } else if let Some(path) = &options.session_file {
            Some(format!("riverlb_session={}", credential(path)?))
        } else {
            None
        };
        Ok(Self {
            host,
            authority,
            port: uri.port_u16().unwrap_or(443),
            tls,
            auth,
        })
    }
    async fn request(
        &self,
        method: &str,
        path: &str,
        body: Option<Value>,
    ) -> Result<(Value, Option<String>)> {
        let bytes = body
            .map(|b| serde_json::to_vec(&b).map_err(|_| fail("input", 2)))
            .transpose()?
            .unwrap_or_default();
        if bytes.len() > MAX {
            return Err(fail("input", 2));
        }
        let exchange = async {
            let tcp = TcpStream::connect((self.host.as_str(), self.port))
                .await
                .map_err(|_| fail("transport", 7))?;
            let name = tokio_rustls::rustls::pki_types::ServerName::try_from(self.host.clone())
                .map_err(|_| fail("https_origin", 2))?;
            let stream = self
                .tls
                .connect(name, tcp)
                .await
                .map_err(|_| fail("tls_verification", 7))?;
            let (mut sender, connection) =
                hyper::client::conn::http1::handshake(TokioIo::new(stream))
                    .await
                    .map_err(|_| fail("transport", 7))?;
            // Always stop the driver, including on body limits or interrupted callers.
            struct Driver(tokio::task::JoinHandle<()>);
            impl Drop for Driver {
                fn drop(&mut self) {
                    self.0.abort();
                }
            }
            let _driver = Driver(tokio::spawn(async move {
                let _ = connection.await;
            }));
            let mut request = Request::builder()
                .method(method)
                .uri(path)
                .header("Host", &self.authority)
                .header("Connection", "close")
                .header("Content-Type", "application/json")
                .header("X-RiverLB-Request", "configure");
            if let Some(auth) = &self.auth {
                request = request.header(
                    if auth.starts_with("Bearer ") {
                        "Authorization"
                    } else {
                        "Cookie"
                    },
                    auth,
                );
            }
            let response = sender
                .send_request(
                    request
                        .body(Full::new(Bytes::from(bytes)))
                        .map_err(|_| fail("input", 2))?,
                )
                .await
                .map_err(|_| fail("transport", 7))?;
            let status = response.status().as_u16();
            if !(200..300).contains(&status) {
                return Err(Failure {
                    kind: "http",
                    code: match status {
                        401 | 403 => 3,
                        400 | 404 | 413 | 422 => 4,
                        409 => 5,
                        _ => 6,
                    },
                    status: Some(status),
                });
            }
            let cookie = response
                .headers()
                .get("set-cookie")
                .and_then(|v| v.to_str().ok())
                .and_then(|s| s.split(';').next())
                .and_then(|s| s.strip_prefix("riverlb_session="))
                .map(str::to_owned);
            let bytes = Limited::new(response.into_body(), 4 * MAX)
                .collect()
                .await
                .map_err(|_| fail("response", 6))?
                .to_bytes();
            let value = serde_json::from_slice(&bytes).map_err(|_| fail("response", 6))?;
            Ok((value, cookie))
        };
        tokio::time::timeout(Duration::from_secs(15), exchange)
            .await
            .map_err(|_| fail("transport", 7))?
    }
    async fn call(&self, method: &str, path: &str, body: Option<Value>) -> Result<Value> {
        self.request(method, path, body).await.map(|r| r.0)
    }
}
fn objects(config: &mut Value, kind: Kind) -> Result<&mut Vec<Value>> {
    let path = kind.path();
    let (parent, key) = path
        .rsplit_once('/')
        .ok_or_else(|| fail("object_kind", 2))?;
    let root = config.as_object_mut().ok_or_else(|| fail("response", 6))?;
    let map = if parent.is_empty() {
        root
    } else {
        root.entry("network")
            .or_insert_with(|| json!({}))
            .as_object_mut()
            .ok_or_else(|| fail("response", 6))?
    };
    map.entry(key)
        .or_insert_with(|| json!([]))
        .as_array_mut()
        .ok_or_else(|| fail("response", 6))
}
async fn execute(options: Options) -> Result<Value> {
    if let Action::Completion { shell } = options.command {
        let commands = "manage login logout status get validate diff apply confirmation confirm revert history rollback object completion list create update delete --url --ca --session-file --token-file --input --revision --target --output --shell --help";
        let kinds = Kind::value_variants()
            .iter()
            .map(|k| k.to_possible_value().unwrap().get_name().to_owned())
            .collect::<Vec<_>>()
            .join(" ");
        let commands = format!("{commands} {kinds}");
        match shell {
            Shell::Bash => println!("complete -W '{commands}' riverlb"),
            Shell::Zsh => println!("#compdef riverlb\n_arguments '*:command:({commands})'"),
        }
        return Ok(Value::Null);
    }
    let client = Client::new(&options)?;
    if !matches!(options.command, Action::Login { .. }) && client.auth.is_none() {
        return Err(fail("authentication_required", 3));
    }
    let preview = matches!(&options.command, Action::Diff { .. });
    match options.command {
        Action::Completion { .. } => unreachable!(),
        Action::Login { output } => {
            if client.auth.is_some() {
                return Err(fail("login_auth_options", 2));
            }
            let mut bytes = Vec::new();
            std::io::stdin()
                .take(4097)
                .read_to_end(&mut bytes)
                .map_err(|_| fail("input", 2))?;
            if bytes.len() > 4096 {
                return Err(fail("input", 2));
            }
            let credentials: Value =
                serde_json::from_slice(&bytes).map_err(|_| fail("input", 2))?;
            let (_, cookie) = client
                .request("POST", "/api/v1/auth/login", Some(credentials))
                .await?;
            let token = cookie.ok_or_else(|| fail("response", 6))?;
            if token.len() != 64 || !token.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(fail("response", 6));
            }
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(output)
                .map_err(|_| fail("session_output", 2))?;
            use std::io::Write;
            file.write_all(token.as_bytes())
                .and_then(|_| file.sync_all())
                .map_err(|_| fail("session_output", 2))?;
            Ok(json!({"authenticated":true}))
        }
        Action::Logout => {
            client
                .call("POST", "/api/v1/auth/logout", Some(json!({})))
                .await
        }
        Action::Status => client.call("GET", "/api/v1/status", None).await,
        Action::Get => client.call("GET", "/api/v1/config", None).await,
        Action::Validate { input: path } => {
            client
                .call("POST", "/api/v1/config/validate", Some(input(&path)?))
                .await
        }
        Action::Diff {
            input: path,
            revision,
        }
        | Action::Apply {
            input: path,
            revision,
        } => {
            client
                .call(
                    if preview { "POST" } else { "PUT" },
                    if preview {
                        "/api/v1/config/preview"
                    } else {
                        "/api/v1/config"
                    },
                    Some(json!({"revision":revision,"config":input(&path)?})),
                )
                .await
        }
        Action::Confirmation => {
            client
                .call("GET", "/api/v1/config/confirmation", None)
                .await
        }
        Action::Confirm { revision } => {
            client
                .call(
                    "POST",
                    "/api/v1/config/confirm",
                    Some(json!({"revision":revision})),
                )
                .await
        }
        Action::Revert { revision } => {
            client
                .call(
                    "POST",
                    "/api/v1/config/revert",
                    Some(json!({"revision":revision})),
                )
                .await
        }
        Action::History => client.call("GET", "/api/v1/config/history", None).await,
        Action::Rollback { target, revision } => {
            let saved = client
                .call("GET", &format!("/api/v1/config/history/{target}"), None)
                .await?;
            let config = saved;
            client
                .call(
                    "PUT",
                    "/api/v1/config",
                    Some(json!({"revision":revision,"config":config})),
                )
                .await
        }
        Action::Object { kind, action } => {
            let current = client.call("GET", "/api/v1/config", None).await?;
            let actual = current["revision"]
                .as_u64()
                .ok_or_else(|| fail("response", 6))?;
            let mut config = current
                .get("config")
                .cloned()
                .ok_or_else(|| fail("response", 6))?;
            let list = objects(&mut config, kind)?;
            let revision = match action {
                ObjectAction::List => return Ok(json!({"revision":actual,"objects":list})),
                ObjectAction::Get { name } => {
                    return Ok(
                        json!({"revision":actual,"object":list.iter().find(|o|o["name"]==name).ok_or_else(||fail("not_found",4))?}),
                    );
                }
                ObjectAction::Create {
                    input: path,
                    revision,
                } => {
                    let value = input(&path)?;
                    let name = value["name"]
                        .as_str()
                        .filter(|n| !n.is_empty())
                        .ok_or_else(|| fail("input", 2))?;
                    if list.iter().any(|o| o["name"] == name) {
                        return Err(fail("already_exists", 5));
                    }
                    list.push(value);
                    revision
                }
                ObjectAction::Update {
                    name,
                    input: path,
                    revision,
                } => {
                    let value = input(&path)?;
                    if value["name"] != name {
                        return Err(fail("object_name", 2));
                    }
                    let old = list
                        .iter_mut()
                        .find(|o| o["name"] == name)
                        .ok_or_else(|| fail("not_found", 4))?;
                    *old = value;
                    revision
                }
                ObjectAction::Delete { name, revision } => {
                    let index = list
                        .iter()
                        .position(|o| o["name"] == name)
                        .ok_or_else(|| fail("not_found", 4))?;
                    list.remove(index);
                    revision
                }
            };
            if revision != actual {
                return Err(fail("stale_revision", 5));
            }
            client
                .call(
                    "PUT",
                    "/api/v1/config",
                    Some(json!({"revision":revision,"config":config})),
                )
                .await
        }
    }
}
pub async fn run(options: Options) -> i32 {
    let completion = matches!(&options.command, Action::Completion { .. });
    match execute(options).await {
        Ok(result) => {
            if !completion {
                println!("{}", json!({"schema":1,"result":result}));
            }
            0
        }
        Err(e) => {
            eprintln!(
                "{}",
                json!({"schema":1,"error":{"kind":e.kind,"http_status":e.status}})
            );
            e.code
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn malformed_configuration_responses_return_a_protocol_error() {
        for mut value in [
            json!(null),
            json!("unexpected"),
            json!({"network":false}),
            json!({"network":{"vlans":{}}}),
        ] {
            assert!(matches!(
                objects(&mut value, Kind::Vlans),
                Err(Failure { code: 6, .. })
            ));
        }
    }
}
