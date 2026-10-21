//! PEM file loading and explicit TLS termination; keys never enter API responses.
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::{io::BufReader, sync::Arc};
use tokio_rustls::{TlsAcceptor, rustls};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Tls {
    pub certificate: String,
    pub private_key: String,
}
impl Tls {
    pub fn server_config(&self) -> Result<Arc<rustls::ServerConfig>> {
        let certs = rustls_pemfile::certs(&mut BufReader::new(
            std::fs::File::open(&self.certificate).context("open TLS certificate")?,
        ))
        .collect::<std::io::Result<Vec<_>>>()?;
        let key = rustls_pemfile::private_key(&mut BufReader::new(
            std::fs::File::open(&self.private_key).context("open TLS private key")?,
        ))?
        .ok_or_else(|| anyhow::anyhow!("PEM contains no private key"))?;
        Ok(Arc::new(
            rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()?
            .with_no_client_auth()
            .with_single_cert(certs, key)?,
        ))
    }
    pub fn acceptor(&self) -> Result<TlsAcceptor> {
        Ok(TlsAcceptor::from(self.server_config()?))
    }
}
