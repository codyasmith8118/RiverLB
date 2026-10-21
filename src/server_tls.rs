//! Verified server-side TLS profiles; trust is explicit and loaded per runtime generation.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use std::{io::BufReader, sync::Arc};
use tokio_rustls::{TlsConnector, rustls};

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    pub name: String,
    pub server_name: String,
    pub ca_certificate: String,
}
impl Default for Profile {
    fn default() -> Self {
        Self {
            name: "server_tls".into(),
            server_name: String::new(),
            ca_certificate: "system".into(),
        }
    }
}
impl Profile {
    pub fn connector(&self) -> Result<TlsConnector> {
        ensure!(
            !self.name.trim().is_empty() && self.name.len() <= 128,
            "server TLS profile name must contain 1..128 bytes"
        );
        self.server_name()?;
        let mut roots = rustls::RootCertStore::empty();
        let ca_path = if self.ca_certificate == "system" {
            ["/etc/ssl/certs/ca-certificates.crt", "/etc/pki/tls/certs/ca-bundle.crt", "/etc/ssl/certs/ca-bundle.crt"]
                .into_iter().find(|path| std::path::Path::new(path).is_file())
                .ok_or_else(|| anyhow::anyhow!("system CA bundle not found; install ca-certificates or configure a trusted CA PEM path"))?
        } else {
            &self.ca_certificate
        };
        let mut pem =
            BufReader::new(std::fs::File::open(ca_path).context("open server TLS trusted CA PEM")?);
        for cert in rustls_pemfile::certs(&mut pem) {
            roots.add(cert?)?;
        }
        ensure!(
            !roots.is_empty(),
            "server TLS trust file contains no certificates"
        );
        let config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
        Ok(TlsConnector::from(Arc::new(config)))
    }
    pub fn server_name(&self) -> Result<Option<rustls::pki_types::ServerName<'static>>> {
        if self.server_name.is_empty() {
            return Ok(None);
        }
        rustls::pki_types::ServerName::try_from(self.server_name.clone())
            .map(Some)
            .context("server TLS name must be a valid DNS name or IP, without a port")
    }
}
