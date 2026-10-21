//! Readiness checks over the same source-bound connection used by the data plane.
use anyhow::{Context, Result, ensure};
use http_body_util::{BodyExt, Empty};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use std::{io::BufReader, sync::Arc};
use tokio::{
    io::AsyncWriteExt,
    net::{TcpStream, UdpSocket},
};
use tokio_rustls::{TlsConnector, rustls};

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct Monitor {
    pub name: String,
    pub interval_secs: u64,
    pub timeout_ms: u64,
    pub rise: u32,
    pub fall: u32,
    #[serde(flatten)]
    pub check: Check,
}
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Check {
    Tcp {},
    Icmp {},
    Udp {
        send: String,
        receive: String,
    },
    Dns {
        query: String,
        #[serde(default = "default_record_type")]
        record_type: String,
    },
    Tls {
        host: String,
        ca_certificate: String,
    },
    Http {
        path: String,
        host: String,
        expected_status: u16,
        #[serde(default)]
        body_contains: String,
    },
    Https {
        path: String,
        host: String,
        expected_status: u16,
        #[serde(default)]
        body_contains: String,
        ca_certificate: String,
    },
}

impl Monitor {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.name.trim().is_empty() && self.name.len() <= 128,
            "monitor name must contain 1..128 bytes"
        );
        ensure!(
            (1..=3600).contains(&self.interval_secs) && (1..=60000).contains(&self.timeout_ms),
            "monitor interval must be 1..3600 seconds and timeout 1..60000 ms"
        );
        ensure!(
            (1..=1000).contains(&self.rise) && (1..=1000).contains(&self.fall),
            "monitor rise/fall must be 1..1000"
        );
        match &self.check {
            Check::Tcp {} | Check::Icmp {} => {}
            Check::Udp { send, receive } => ensure!(
                !send.is_empty()
                    && send.len() <= 4096
                    && !receive.is_empty()
                    && receive.len() <= 4096,
                "UDP requires send and receive text of 1..4096 bytes"
            ),
            Check::Dns { query, record_type } => {
                dns_question(query, record_type)?;
            }
            Check::Tls { host, .. } => {
                rustls::pki_types::ServerName::try_from(host.clone())
                    .context("TLS monitor requires a server name without a port")?;
            }
            Check::Http {
                path,
                host,
                expected_status,
                body_contains,
            }
            | Check::Https {
                path,
                host,
                expected_status,
                body_contains,
                ..
            } => {
                ensure!(
                    path.starts_with('/')
                        && path.len() <= 2048
                        && path.bytes().all(|b| b > 32 && b < 127),
                    "monitor path must be an ASCII origin path without spaces/control characters"
                );
                ensure!(
                    !host.is_empty()
                        && host.len() <= 253
                        && host
                            .bytes()
                            .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b)),
                    "monitor host must be a hostname or IPv4 address, optionally with port"
                );
                ensure!(
                    (100..=599).contains(expected_status) && body_contains.len() <= 4096,
                    "monitor status must be 100..599 and body match <=4096 bytes"
                );
            }
        }
        if let Check::Https { host, .. } | Check::Tls { host, .. } = &self.check {
            rustls::pki_types::ServerName::try_from(host.clone())
                .context("HTTPS monitor host must be a TLS server name without a port")?;
            self.connector()?;
        }
        Ok(())
    }
    pub fn connector(&self) -> Result<Option<TlsConnector>> {
        let (Check::Https { ca_certificate, .. } | Check::Tls { ca_certificate, .. }) = &self.check
        else {
            return Ok(None);
        };
        let mut roots = rustls::RootCertStore::empty();
        let mut pem = BufReader::new(
            std::fs::File::open(ca_certificate).context("read monitor CA certificate")?,
        );
        for cert in rustls_pemfile::certs(&mut pem) {
            roots.add(cert?)?;
        }
        ensure!(
            !roots.is_empty(),
            "monitor CA file contains no certificates"
        );
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = rustls::ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Some(TlsConnector::from(Arc::new(config))))
    }
    pub fn is_datagram(&self) -> bool {
        matches!(
            self.check,
            Check::Icmp {} | Check::Udp { .. } | Check::Dns { .. }
        )
    }
    pub async fn probe_datagram(
        &self,
        address: SocketAddr,
        source: Option<IpAddr>,
        device: Option<&str>,
    ) -> Result<()> {
        if matches!(self.check, Check::Icmp {}) {
            let mut command = tokio::process::Command::new("/usr/bin/ping");
            command.kill_on_drop(true).env("LC_ALL", "C").args([
                "-n",
                "-c",
                "1",
                "-W",
                &format!("{:.3}", self.timeout_ms as f64 / 1000.0),
            ]);
            command.arg(if address.is_ipv4() { "-4" } else { "-6" });
            if let Some(device) = device {
                command.args(["-I", device]);
            }
            if let Some(source) = source {
                command.args(["-I", &source.to_string()]);
            }
            let result = command
                .arg(address.ip().to_string())
                .output()
                .await
                .context(
                    "ICMP requires /usr/bin/ping from iputils and permission to send echo requests",
                )?;
            if !result.status.success() {
                let detail = String::from_utf8_lossy(&result.stderr);
                anyhow::bail!(
                    "ICMP echo failed: {}",
                    if detail.trim().is_empty() {
                        "no echo reply"
                    } else {
                        detail.trim()
                    }
                );
            }
            return Ok(());
        }
        let local = source.unwrap_or_else(|| {
            if address.is_ipv4() {
                IpAddr::from([0, 0, 0, 0])
            } else {
                IpAddr::from([0u16; 8])
            }
        });
        let socket = UdpSocket::bind(SocketAddr::new(local, 0)).await?;
        if let Some(device) = device {
            crate::network::bind_device(&socket, device)?;
        }
        socket.connect(address).await?;
        let (payload, question) = match &self.check {
            Check::Udp { send, .. } => (send.as_bytes().to_vec(), None),
            Check::Dns { query, record_type } => {
                let question = dns_question(query, record_type)?;
                let id: u16 = rand::random();
                let mut payload = vec![(id >> 8) as u8, id as u8, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0];
                payload.extend_from_slice(&question);
                (payload, Some(question))
            }
            _ => anyhow::bail!("not a datagram monitor"),
        };
        socket.send(&payload).await?;
        let mut response = vec![0u8; 65536];
        let length = socket.recv(&mut response).await?;
        response.truncate(length);
        if let Some(question) = question {
            validate_dns_response(&response, &payload[..2], &question)?;
        } else if let Check::Udp { receive, .. } = &self.check {
            ensure!(
                response
                    .windows(receive.len())
                    .any(|w| w == receive.as_bytes()),
                "expected UDP response text was not found"
            );
        }
        Ok(())
    }
    pub async fn probe(&self, stream: TcpStream, connector: Option<&TlsConnector>) -> Result<()> {
        match &self.check {
            Check::Tcp {} => Ok(()),
            Check::Icmp {} | Check::Udp { .. } | Check::Dns { .. } => {
                anyhow::bail!("datagram monitor requires datagram transport")
            }
            Check::Tls { host, .. } => {
                let name = rustls::pki_types::ServerName::try_from(host.clone())?;
                let mut stream = connector
                    .context("missing monitor TLS configuration")?
                    .connect(name, stream)
                    .await
                    .context("monitor TLS verification/handshake failed")?;
                stream.shutdown().await?;
                Ok(())
            }
            Check::Http {
                path,
                host,
                expected_status,
                body_contains,
            } => http(stream, path, host, *expected_status, body_contains).await,
            Check::Https {
                path,
                host,
                expected_status,
                body_contains,
                ..
            } => {
                let name = rustls::pki_types::ServerName::try_from(host.clone())?;
                let stream = connector
                    .context("missing monitor TLS configuration")?
                    .connect(name, stream)
                    .await
                    .context("monitor TLS verification/handshake failed")?;
                http(stream, path, host, *expected_status, body_contains).await
            }
        }
    }
}
fn default_record_type() -> String {
    "A".into()
}
fn dns_question(query: &str, record_type: &str) -> Result<Vec<u8>> {
    let name = query.strip_suffix('.').unwrap_or(query);
    ensure!(
        !name.is_empty() && name.len() <= 253,
        "DNS query name must contain 1..253 bytes"
    );
    let mut question = Vec::new();
    for label in name.split('.') {
        ensure!(
            !label.is_empty()
                && label.len() <= 63
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b"-_".contains(&b)),
            "invalid DNS query label"
        );
        question.push(label.len() as u8);
        question.extend_from_slice(label.as_bytes());
    }
    question.push(0);
    let kind: u16 = match record_type {
        "A" => 1,
        "AAAA" => 28,
        "CNAME" => 5,
        "MX" => 15,
        "NS" => 2,
        "TXT" => 16,
        "SOA" => 6,
        "SRV" => 33,
        _ => anyhow::bail!("unsupported DNS record type"),
    };
    question.extend_from_slice(&kind.to_be_bytes());
    question.extend_from_slice(&[0, 1]);
    Ok(question)
}
fn validate_dns_response(response: &[u8], id: &[u8], question: &[u8]) -> Result<()> {
    ensure!(
        response.len() >= 12 && &response[..2] == id,
        "invalid DNS response or transaction ID"
    );
    ensure!(
        response[2] & 0xf8 == 0x80,
        "DNS response must be a standard query response"
    );
    ensure!(
        response[2] & 2 == 0,
        "DNS response truncated; use a smaller query (TCP fallback is not supported)"
    );
    ensure!(
        response[3] & 15 == 0,
        "DNS response code {}",
        response[3] & 15
    );
    ensure!(
        response[4..6] == [0, 1],
        "DNS response must echo one question"
    );
    // Compare the echoed name and type/class without trusting remote length fields.
    let end = 12 + question.len();
    ensure!(
        response.len() >= end && response[12..end].eq_ignore_ascii_case(question),
        "DNS response question mismatch"
    );
    let answers = u16::from_be_bytes([response[6], response[7]]);
    ensure!(answers > 0, "DNS response contains no answers");
    let mut offset = end;
    let expected_type = &question[question.len() - 4..question.len() - 2];
    let mut matching = false;
    for _ in 0..answers {
        loop {
            ensure!(offset < response.len(), "incomplete DNS answer name");
            let label = response[offset];
            offset += 1;
            if label == 0 {
                break;
            }
            if label & 0xc0 == 0xc0 {
                ensure!(
                    offset < response.len()
                        && ((((label & 63) as usize) << 8) | response[offset] as usize)
                            < response.len(),
                    "invalid DNS name pointer"
                );
                offset += 1;
                break;
            }
            ensure!(
                label <= 63 && offset + label as usize <= response.len(),
                "invalid DNS answer label"
            );
            offset += label as usize;
        }
        ensure!(offset + 10 <= response.len(), "incomplete DNS answer");
        let kind = &response[offset..offset + 2];
        let class = &response[offset + 2..offset + 4];
        let length = u16::from_be_bytes([response[offset + 8], response[offset + 9]]) as usize;
        if kind == expected_type && class == [0, 1] {
            ensure!(
                length > 0 && (kind != [0, 1] || length == 4) && (kind != [0, 28] || length == 16),
                "invalid DNS answer data length"
            );
            matching = true;
        }
        offset += 10;
        ensure!(
            offset + length <= response.len(),
            "incomplete DNS answer data"
        );
        offset += length;
    }
    ensure!(
        matching,
        "DNS response contains no answer of the requested type"
    );
    Ok(())
}
// Abort the HTTP driver on success, error, cancellation and timeout alike.
struct Driver(tokio::task::JoinHandle<()>);
impl Drop for Driver {
    fn drop(&mut self) {
        self.0.abort();
    }
}
async fn http<S>(stream: S, path: &str, host: &str, status: u16, body: &str) -> Result<()>
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
{
    let (mut sender, connection) = hyper::client::conn::http1::Builder::new()
        .max_buf_size(16384)
        .handshake(hyper_util::rt::TokioIo::new(stream))
        .await?;
    let _driver = Driver(tokio::spawn(async move {
        let _ = connection.await;
    }));
    let request = hyper::Request::builder()
        .uri(path)
        .header("host", host)
        .header("connection", "close")
        .body(Empty::<hyper::body::Bytes>::new())?;
    let response = sender
        .send_request(request)
        .await
        .context("monitor HTTP request failed")?;
    ensure!(
        response.status().as_u16() == status,
        "HTTP status {} (expected {})",
        response.status().as_u16(),
        status
    );
    if body.is_empty() {
        return Ok(());
    }
    let mut incoming = response.into_body();
    let mut bytes = Vec::new();
    while let Some(frame) = incoming.frame().await {
        if let Ok(data) = frame?.into_data() {
            let remaining = 65536 - bytes.len();
            bytes.extend_from_slice(&data[..data.len().min(remaining)]);
            if bytes.windows(body.len()).any(|w| w == body.as_bytes()) {
                return Ok(());
            }
            ensure!(
                bytes.len() < 65536,
                "monitor response text not found within 64 KiB"
            );
        }
    }
    anyhow::bail!("expected response text was not found")
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn validates_profiles_and_rejects_injection_and_unknown_fields() {
        let json = serde_json::json!({"name":"ready","interval_secs":1,"timeout_ms":200,"rise":2,"fall":2,"kind":"http","path":"/health","host":"localhost","expected_status":200,"body_contains":"ready"});
        let monitor: Monitor = serde_json::from_value(json.clone()).unwrap();
        monitor.validate().unwrap();
        let mut bad = json.clone();
        bad["host"] = "localhost\r\nX: y".into();
        assert!(
            serde_json::from_value::<Monitor>(bad)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut bad = json.clone();
        bad["path"] = "/health extra".into();
        assert!(
            serde_json::from_value::<Monitor>(bad)
                .unwrap()
                .validate()
                .is_err()
        );
        let mut bad = json;
        bad["unexpected"] = true.into();
        assert!(serde_json::from_value::<Monitor>(bad).is_err());
        let bad = serde_json::json!({"name":"tcp","kind":"tcp","interval_secs":1,"timeout_ms":200,"rise":1,"fall":1,"unexpected":true});
        assert!(serde_json::from_value::<Monitor>(bad).is_err());
    }
    fn datagram(check: Check) -> Monitor {
        Monitor {
            name: "test".into(),
            interval_secs: 1,
            timeout_ms: 500,
            rise: 1,
            fall: 1,
            check,
        }
    }
    #[tokio::test]
    async fn udp_requires_matching_response_and_honors_source_address() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut buf = [0; 64];
            for reply in [b"pong".as_slice(), b"wrong".as_slice()] {
                let (n, source) = server.recv_from(&mut buf).await.unwrap();
                assert_eq!(&buf[..n], b"ping");
                assert_eq!(source.ip(), IpAddr::from([127, 0, 0, 2]));
                server.send_to(reply, source).await.unwrap();
            }
        });
        let monitor = datagram(Check::Udp {
            send: "ping".into(),
            receive: "pong".into(),
        });
        monitor.validate().unwrap();
        monitor
            .probe_datagram(address, Some(IpAddr::from([127, 0, 0, 2])), None)
            .await
            .unwrap();
        assert!(
            monitor
                .probe_datagram(address, Some(IpAddr::from([127, 0, 0, 2])), None)
                .await
                .unwrap_err()
                .to_string()
                .contains("response text")
        );
        responder.await.unwrap();
        let silent = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        assert!(
            tokio::time::timeout(
                std::time::Duration::from_millis(20),
                monitor.probe_datagram(silent.local_addr().unwrap(), None, None)
            )
            .await
            .is_err()
        );
        assert!(
            datagram(Check::Udp {
                send: "".into(),
                receive: "".into()
            })
            .validate()
            .is_err()
        );
    }
    #[tokio::test]
    async fn dns_checks_real_udp_responses_and_rejects_errors() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let responder = tokio::spawn(async move {
            let mut buf = [0; 512];
            for code in [0, 3] {
                let (n, source) = server.recv_from(&mut buf).await.unwrap();
                let mut reply = buf[..n].to_vec();
                reply[2] = 0x81;
                reply[3] = 0x80 | code;
                reply[7] = 1;
                reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1]);
                server.send_to(&reply, source).await.unwrap();
            }
        });
        let monitor = datagram(Check::Dns {
            query: "health.example.".into(),
            record_type: "A".into(),
        });
        monitor.validate().unwrap();
        monitor.probe_datagram(address, None, None).await.unwrap();
        assert!(
            monitor
                .probe_datagram(address, None, None)
                .await
                .unwrap_err()
                .to_string()
                .contains("code 3")
        );
        responder.await.unwrap();
        let question = dns_question("health.example", "A").unwrap();
        let mut reply = vec![1, 2, 0x81, 0x80, 0, 1, 0, 1, 0, 0, 0, 0];
        reply.extend_from_slice(&question);
        reply.extend_from_slice(&[0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 30, 0, 4, 127, 0, 0, 1]);
        validate_dns_response(&reply, &[1, 2], &question).unwrap();
        assert!(validate_dns_response(&reply, &[1, 3], &question).is_err());
        reply.pop();
        assert!(validate_dns_response(&reply, &[1, 2], &question).is_err());
        reply[2] |= 2;
        assert!(validate_dns_response(&reply, &[1, 2], &question).is_err());
        assert!(dns_question("bad..name", "A").is_err());
        assert!(dns_question("example.com", "BOGUS").is_err());
    }
    #[tokio::test]
    async fn icmp_checks_loopback_without_a_tcp_listener() {
        let monitor = datagram(Check::Icmp {});
        monitor.validate().unwrap();
        tokio::time::timeout(
            std::time::Duration::from_secs(2),
            monitor.probe_datagram(
                "127.0.0.1:1".parse().unwrap(),
                Some("127.0.0.1".parse().unwrap()),
                Some("lo"),
            ),
        )
        .await
        .unwrap()
        .unwrap();
    }
}
