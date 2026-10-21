//! Managed key material remains private to storage and runtime, never configuration JSON.
use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{io::BufReader, sync::Arc};
use tokio_rustls::rustls;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub enum StoreKind {
    Device,
    #[default]
    VirtualServer,
}
impl StoreKind {
    pub fn table(self) -> &'static str {
        match self {
            Self::Device => "device_certificates",
            Self::VirtualServer => "certificates",
        }
    }
    pub fn key(self, name: &str) -> String {
        match self {
            Self::Device => format!("device:{name}"),
            Self::VirtualServer => name.to_owned(),
        }
    }
    pub fn request_key(self, name: &str) -> String {
        format!(
            "{}:{name}",
            match self {
                Self::Device => "device",
                Self::VirtualServer => "virtual_server",
            }
        )
    }
}
#[derive(Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Subject {
    #[serde(default)]
    pub organization: String,
    #[serde(default)]
    pub organizational_unit: String,
    #[serde(default)]
    pub country: String,
    #[serde(default)]
    pub state: String,
    #[serde(default)]
    pub locality: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Generate {
    pub name: String,
    #[serde(default)]
    pub hostname: Option<String>,
    #[serde(default)]
    pub names: Vec<String>,
    #[serde(default)]
    pub subject: Subject,
    #[serde(default = "default_days")]
    pub days: u16,
}
fn default_days() -> u16 {
    365
}
impl Generate {
    pub fn names(&self) -> Result<Vec<String>> {
        let names = if self.names.is_empty() {
            self.hostname.iter().cloned().collect()
        } else {
            self.names.clone()
        };
        ensure!(
            !names.is_empty() && names.len() <= 100,
            "provide 1..100 DNS names or IP addresses"
        );
        let mut seen = std::collections::HashSet::new();
        for name in &names {
            ensure!(
                name.parse::<std::net::IpAddr>().is_ok()
                    || dns_name(name.strip_prefix("*.").unwrap_or(name)),
                "invalid certificate DNS name or IP address: {name}"
            );
            ensure!(seen.insert(name), "duplicate certificate name");
        }
        Ok(names)
    }
    fn params(&self) -> Result<rcgen::CertificateParams> {
        let names = self.names()?;
        let mut params = rcgen::CertificateParams::new(names.clone())?;
        params.distinguished_name = rcgen::DistinguishedName::new();
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, &names[0]);
        for (kind, value) in [
            (rcgen::DnType::OrganizationName, &self.subject.organization),
            (
                rcgen::DnType::OrganizationalUnitName,
                &self.subject.organizational_unit,
            ),
            (rcgen::DnType::CountryName, &self.subject.country),
            (rcgen::DnType::StateOrProvinceName, &self.subject.state),
            (rcgen::DnType::LocalityName, &self.subject.locality),
        ] {
            ensure!(
                value.len() <= 128 && !value.chars().any(char::is_control),
                "invalid certificate subject field"
            );
            if !value.is_empty() {
                params.distinguished_name.push(kind, value);
            }
        }
        ensure!(
            self.subject.country.is_empty()
                || self.subject.country.len() == 2
                    && self.subject.country.bytes().all(|c| c.is_ascii_uppercase()),
            "country must be a two-letter uppercase code"
        );
        Ok(params)
    }
    pub fn self_signed(&self) -> Result<(String, String)> {
        ensure!(
            (1..=825).contains(&self.days),
            "certificate lifetime must be 1..825 days"
        );
        let mut params = self.params()?;
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now - time::Duration::minutes(5);
        params.not_after = now + time::Duration::days(i64::from(self.days));
        let key = rcgen::KeyPair::generate()?;
        let cert = params.self_signed(&key)?.pem();
        let pem = key.serialize_pem();
        server_config(&cert, &pem)?;
        Ok((cert, pem))
    }
    pub fn csr(&self) -> Result<(String, String)> {
        let key = rcgen::KeyPair::generate()?;
        Ok((
            self.params()?.serialize_request(&key)?.pem()?,
            key.serialize_pem(),
        ))
    }
}
pub fn covers_names(pem: &str, names: &[String]) -> Result<()> {
    let metadata = metadata("coverage", pem, 0)?;
    for name in names {
        ensure!(
            metadata.dns_names.iter().any(|p| matches_dns(p, name))
                || metadata.ip_addresses.iter().any(|p| name
                    .parse::<std::net::IpAddr>()
                    .is_ok_and(|ip| ip.to_string() == *p)),
            "signed certificate does not cover requested name {name}"
        );
    }
    Ok(())
}
pub type Resolved = std::collections::HashMap<String, Arc<rustls::ServerConfig>>;
pub fn dns_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 253
        && name == name.to_ascii_lowercase()
        && name.split('.').all(|label| {
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || c == b'-')
        })
}
pub fn matches_dns(pattern: &str, host: &str) -> bool {
    pattern.eq_ignore_ascii_case(host)
        || pattern.strip_prefix("*.").is_some_and(|suffix| {
            host.split_once('.')
                .is_some_and(|(_, rest)| rest.eq_ignore_ascii_case(suffix))
        })
}
#[derive(Debug)]
struct SniResolver {
    default: Arc<rustls::ServerConfig>,
    names: std::collections::BTreeMap<String, Arc<rustls::ServerConfig>>,
}
impl rustls::server::ResolvesServerCert for SniResolver {
    fn resolve(
        &self,
        hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        let config = hello
            .server_name()
            .and_then(|name| self.names.get(&name.to_ascii_lowercase()))
            .unwrap_or(&self.default);
        config.cert_resolver.resolve(hello)
    }
}
pub fn sni_config(
    default: Arc<rustls::ServerConfig>,
    names: &std::collections::BTreeMap<String, String>,
    resolved: &Resolved,
) -> Result<Arc<rustls::ServerConfig>> {
    let names = names
        .iter()
        .map(|(host, cert)| {
            Ok((
                host.clone(),
                resolved
                    .get(cert)
                    .context("unknown SNI certificate")?
                    .clone(),
            ))
        })
        .collect::<Result<_>>()?;
    let mut config = (*default).clone();
    config.cert_resolver = Arc::new(SniResolver { default, names });
    Ok(Arc::new(config))
}
pub fn validate_name(name: &str) -> Result<()> {
    ensure!(
        (1..=128).contains(&name.len())
            && name
                .bytes()
                .all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c)),
        "certificate name must contain 1..128 letters, digits, dots, underscores or hyphens"
    );
    Ok(())
}
#[derive(Serialize)]
pub struct Metadata {
    pub name: String,
    pub subject: String,
    pub issuer: String,
    pub serial: String,
    pub dns_names: Vec<String>,
    pub ip_addresses: Vec<String>,
    pub fingerprint_sha256: String,
    pub not_before: i64,
    pub not_after: i64,
    pub valid_now: bool,
    pub days_remaining: i64,
    pub chain_length: usize,
    pub created: i64,
}
pub fn metadata(name: &str, pem: &str, created: i64) -> Result<Metadata> {
    let certs = rustls_pemfile::certs(&mut BufReader::new(pem.as_bytes()))
        .collect::<std::io::Result<Vec<_>>>()?;
    let first = certs
        .first()
        .context("certificate PEM contains no certificates")?;
    for der in &certs {
        let (remaining, _) = x509_parser::parse_x509_certificate(der.as_ref())
            .map_err(|_| anyhow::anyhow!("invalid X.509 certificate in chain"))?;
        ensure!(remaining.is_empty(), "trailing data in X.509 certificate");
    }
    let (_, cert) = x509_parser::parse_x509_certificate(first.as_ref())
        .map_err(|_| anyhow::anyhow!("invalid X.509 certificate"))?;
    let now = crate::storage::now();
    let before = cert.validity().not_before.timestamp();
    let after = cert.validity().not_after.timestamp();
    let dns_names = cert
        .subject_alternative_name()
        .map_err(|_| anyhow::anyhow!("invalid certificate names"))?
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    x509_parser::extensions::GeneralName::DNSName(s) => Some((*s).to_owned()),
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    let ip_addresses = cert
        .subject_alternative_name()?
        .map(|san| {
            san.value
                .general_names
                .iter()
                .filter_map(|n| match n {
                    x509_parser::extensions::GeneralName::IPAddress(bytes) if bytes.len() == 4 => {
                        Some(
                            std::net::Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3])
                                .to_string(),
                        )
                    }
                    x509_parser::extensions::GeneralName::IPAddress(bytes) if bytes.len() == 16 => {
                        Some(
                            std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*bytes).unwrap())
                                .to_string(),
                        )
                    }
                    _ => None,
                })
                .collect()
        })
        .unwrap_or_default();
    Ok(Metadata {
        name: name.into(),
        subject: cert.subject().to_string(),
        issuer: cert.issuer().to_string(),
        serial: cert.raw_serial_as_string(),
        dns_names,
        ip_addresses,
        fingerprint_sha256: format!("{:x}", Sha256::digest(first.as_ref())),
        not_before: before,
        not_after: after,
        valid_now: before <= now && now <= after,
        days_remaining: (after - now).div_euclid(86400),
        chain_length: certs.len(),
        created,
    })
}
pub fn server_config(certificate: &str, private_key: &str) -> Result<Arc<rustls::ServerConfig>> {
    ensure!(
        certificate.len() <= 262144 && private_key.len() <= 65536,
        "certificate/key PEM exceeds size limit"
    );
    let certs = rustls_pemfile::certs(&mut BufReader::new(certificate.as_bytes()))
        .collect::<std::io::Result<Vec<_>>>()?;
    let key = rustls_pemfile::private_key(&mut BufReader::new(private_key.as_bytes()))?
        .context("PEM contains no private key (encrypted keys are unsupported)")?;
    Ok(Arc::new(
        rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .context("certificate and private key must match")?,
    ))
}

#[cfg(test)]
pub fn self_signed(hostname: &str, days: u16) -> Result<(String, String)> {
    Generate {
        name: String::new(),
        hostname: Some(hostname.into()),
        names: vec![],
        subject: Subject::default(),
        days,
    }
    .self_signed()
}

pub fn validate_request(csr: &str, private_key: &str, names: &[String]) -> Result<()> {
    use rcgen::PublicKeyData;
    use x509_parser::prelude::FromDer;
    ensure!(
        csr.len() <= 65536 && private_key.len() <= 65536,
        "CSR/key exceeds size limit"
    );
    let (_, pem) = x509_parser::pem::parse_x509_pem(csr.as_bytes())
        .map_err(|_| anyhow::anyhow!("invalid CSR PEM"))?;
    let (_, request) =
        x509_parser::certification_request::X509CertificationRequest::from_der(&pem.contents)?;
    request
        .verify_signature()
        .map_err(|_| anyhow::anyhow!("invalid CSR signature"))?;
    let key = rcgen::KeyPair::from_pem(private_key)?;
    ensure!(
        request.certification_request_info.subject_pki.raw == key.subject_public_key_info(),
        "CSR private key mismatch"
    );
    let expected = Generate {
        name: String::new(),
        hostname: None,
        names: names.to_vec(),
        subject: Subject::default(),
        days: 365,
    }
    .params()?
    .subject_alt_names;
    let mut actual = Vec::new();
    if let Some(extensions) = request.requested_extensions() {
        for extension in extensions {
            if let x509_parser::extensions::ParsedExtension::SubjectAlternativeName(san) = extension
            {
                for name in &san.general_names {
                    match name {
                        x509_parser::extensions::GeneralName::DNSName(name) => {
                            actual.push(rcgen::SanType::DnsName((*name).try_into()?))
                        }
                        x509_parser::extensions::GeneralName::IPAddress(ip) if ip.len() == 4 => {
                            actual.push(rcgen::SanType::IpAddress(
                                std::net::Ipv4Addr::new(ip[0], ip[1], ip[2], ip[3]).into(),
                            ))
                        }
                        x509_parser::extensions::GeneralName::IPAddress(ip) if ip.len() == 16 => {
                            actual.push(rcgen::SanType::IpAddress(
                                std::net::Ipv6Addr::from(<[u8; 16]>::try_from(*ip)?).into(),
                            ))
                        }
                        _ => anyhow::bail!("unsupported CSR name"),
                    }
                }
            }
        }
    }
    ensure!(actual == expected, "CSR requested names mismatch");
    Ok(())
}

#[cfg(test)]
mod self_signed_tests {
    #[test]
    fn generated_certificate_has_matching_key_names_and_lifetime() {
        let (certificate, key) = super::self_signed("test.example.com", 30).unwrap();
        super::server_config(&certificate, &key).unwrap();
        let metadata = super::metadata("test-tls", &certificate, 0).unwrap();
        assert_eq!(metadata.dns_names, vec!["test.example.com"]);
        assert!(metadata.valid_now);
        assert!((29..=30).contains(&metadata.days_remaining));
        assert_eq!(metadata.subject, metadata.issuer);
        assert!(super::self_signed("https://test.example.com", 30).is_err());
        assert!(super::self_signed("test.example.com", 0).is_err());
        assert!(super::self_signed("test.example.com", 826).is_err());
    }
    #[test]
    fn csr_signature_key_and_requested_names_are_validated() {
        let request = super::Generate {
            name: "test".into(),
            hostname: None,
            names: vec!["test.example.com".into(), "2001:0db8::1".into()],
            subject: super::Subject::default(),
            days: 30,
        };
        let (csr, key) = request.csr().unwrap();
        super::validate_request(&csr, &key, &request.names).unwrap();
        let (_, other_key) = request.csr().unwrap();
        assert!(super::validate_request(&csr, &other_key, &request.names).is_err());
        assert!(super::validate_request(&csr, &key, &["wrong.example.com".into()]).is_err());
        let (cert, _) = request.self_signed().unwrap();
        super::covers_names(&cert, &request.names).unwrap();
    }
}
