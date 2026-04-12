use serde::Deserialize;
use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::error::{Error, Result};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub acme: AcmeConfig,
    pub dns: DnsConfig,
    #[serde(rename = "certificate")]
    pub certificates: Vec<CertificateConfig>,
}

#[derive(Debug, Deserialize)]
pub struct AcmeConfig {
    #[serde(default = "default_directory_url")]
    pub directory_url: String,

    /// Full path to encrypted credential file for the ACME account key
    pub account_key_credential: Option<PathBuf>,
    /// Plain file path for the ACME account key (fallback)
    pub account_key_path: Option<PathBuf>,

    pub contact: Vec<String>,
}

fn default_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

#[derive(Debug, Deserialize)]
pub struct DnsConfig {
    pub defaults: DnsServerConfig,
    #[serde(default)]
    pub zones: HashMap<String, DnsZoneOverride>,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsServerConfig {
    pub server: String,

    /// Full path to encrypted credential file for the TSIG key
    pub tsig_key_credential: Option<PathBuf>,
    /// Plain file path for the TSIG key (fallback)
    pub tsig_key_path: Option<PathBuf>,

    pub tsig_key_name: String,
    #[serde(default = "default_tsig_algorithm")]
    pub tsig_algorithm: TsigAlgorithm,
    #[serde(default = "default_dns_port")]
    pub port: u16,
    #[serde(default = "default_dns_protocol")]
    pub protocol: DnsProtocol,
}

#[derive(Debug, Clone, Deserialize)]
pub struct DnsZoneOverride {
    pub server: Option<String>,
    pub tsig_key_credential: Option<PathBuf>,
    pub tsig_key_path: Option<PathBuf>,
    pub tsig_key_name: Option<String>,
    pub tsig_algorithm: Option<TsigAlgorithm>,
    pub port: Option<u16>,
    pub protocol: Option<DnsProtocol>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TsigAlgorithm {
    HmacSha256,
    HmacSha512,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DnsProtocol {
    Tcp,
    Udp,
}

fn default_tsig_algorithm() -> TsigAlgorithm {
    TsigAlgorithm::HmacSha256
}

fn default_dns_port() -> u16 {
    53
}

fn default_dns_protocol() -> DnsProtocol {
    DnsProtocol::Tcp
}

#[derive(Debug, Deserialize)]
pub struct CertificateConfig {
    pub name: String,
    pub domains: Vec<String>,

    #[serde(default = "default_key_type")]
    pub key_type: KeyType,

    /// Full path to encrypted credential file for the private key.
    /// Services access the same file via LoadCredentialEncrypted= in their units.
    pub key_credential: Option<PathBuf>,
    /// Plain file path for the private key (fallback for services that can't use credentials)
    pub key_path: Option<PathBuf>,

    pub cert_path: PathBuf,

    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,

    #[serde(default)]
    pub rotate_key: bool,

    #[serde(default)]
    pub dane: Vec<DaneConfig>,

    #[serde(default, rename = "hook")]
    pub hooks: Vec<HookConfig>,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum KeyType {
    EcdsaP256,
    EcdsaP384,
    Rsa2048,
    Rsa4096,
}

fn default_key_type() -> KeyType {
    KeyType::EcdsaP256
}

fn default_renew_before_days() -> u32 {
    30
}

#[derive(Debug, Deserialize)]
pub struct DaneConfig {
    #[serde(default = "default_dane_usage")]
    pub usage: DaneUsage,
    #[serde(default = "default_dane_selector")]
    pub selector: DaneSelector,
    #[serde(default = "default_dane_matching")]
    pub matching: DaneMatching,

    /// TLSA record DNS names (e.g., _25._tcp.mx1.example.com)
    pub names: Vec<String>,

    #[serde(default = "default_dane_ttl")]
    pub ttl: u32,

    /// Pre-publish new TLSA before key rotation to avoid DANE breakage
    #[serde(default)]
    pub pre_publish: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DaneUsage {
    /// PKIX-TA (0)
    #[serde(rename = "pkix-ta")]
    PkixTa,
    /// PKIX-EE (1)
    #[serde(rename = "pkix-ee")]
    PkixEe,
    /// DANE-TA (2)
    #[serde(rename = "ta")]
    Ta,
    /// DANE-EE (3)
    #[serde(rename = "ee")]
    Ee,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DaneSelector {
    /// Full certificate (0)
    Full,
    /// SubjectPublicKeyInfo (1)
    Spki,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DaneMatching {
    /// Exact match (0)
    Full,
    /// SHA-256 (1)
    Sha256,
    /// SHA-512 (2)
    Sha512,
}

fn default_dane_usage() -> DaneUsage {
    DaneUsage::Ee
}

fn default_dane_selector() -> DaneSelector {
    DaneSelector::Spki
}

fn default_dane_matching() -> DaneMatching {
    DaneMatching::Sha256
}

fn default_dane_ttl() -> u32 {
    300
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "kebab-case")]
pub enum HookConfig {
    SystemdReload { unit: String },
    SystemdRestart { unit: String },
    Command { command: Vec<String> },
}

impl DnsConfig {
    /// Resolve DNS server config for a given zone, applying overrides on top of defaults.
    pub fn resolve_for_zone(&self, zone: &str) -> DnsServerConfig {
        let Some(ovr) = self.zones.get(zone) else {
            return self.defaults.clone();
        };

        DnsServerConfig {
            server: ovr.server.clone().unwrap_or_else(|| self.defaults.server.clone()),
            tsig_key_credential: ovr
                .tsig_key_credential
                .clone()
                .or_else(|| self.defaults.tsig_key_credential.clone()),
            tsig_key_path: ovr
                .tsig_key_path
                .clone()
                .or_else(|| self.defaults.tsig_key_path.clone()),
            tsig_key_name: ovr
                .tsig_key_name
                .clone()
                .unwrap_or_else(|| self.defaults.tsig_key_name.clone()),
            tsig_algorithm: ovr
                .tsig_algorithm
                .clone()
                .unwrap_or_else(|| self.defaults.tsig_algorithm.clone()),
            port: ovr.port.unwrap_or(self.defaults.port),
            protocol: ovr.protocol.clone().unwrap_or_else(|| self.defaults.protocol.clone()),
        }
    }
}

impl Config {
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path).map_err(|e| {
            Error::Config(format!("failed to read config file {}: {e}", path.display()))
        })?;
        let config: Config = toml::from_str(&content)
            .map_err(|e| Error::Config(format!("failed to parse config: {e}")))?;
        config.validate()?;
        Ok(config)
    }

    fn validate(&self) -> Result<()> {
        if self.acme.account_key_credential.is_none() && self.acme.account_key_path.is_none() {
            return Err(Error::Config(
                "acme: either account_key_credential or account_key_path must be set".into(),
            ));
        }

        if self.acme.contact.is_empty() {
            return Err(Error::Config("acme: contact must not be empty".into()));
        }

        if self.dns.defaults.tsig_key_credential.is_none()
            && self.dns.defaults.tsig_key_path.is_none()
        {
            return Err(Error::Config(
                "dns.defaults: either tsig_key_credential or tsig_key_path must be set".into(),
            ));
        }

        for cert in &self.certificates {
            if cert.name.is_empty() {
                return Err(Error::Config("certificate: name must not be empty".into()));
            }
            if cert.domains.is_empty() {
                return Err(Error::Config(format!(
                    "certificate {}: domains must not be empty",
                    cert.name
                )));
            }
            if cert.key_credential.is_none() && cert.key_path.is_none() {
                return Err(Error::Config(format!(
                    "certificate {}: either key_credential or key_path must be set",
                    cert.name
                )));
            }

            for dane in &cert.dane {
                if dane.names.is_empty() {
                    return Err(Error::Config(format!(
                        "certificate {}: dane block has empty names",
                        cert.name
                    )));
                }
            }

            for hook in &cert.hooks {
                match hook {
                    HookConfig::Command { command } if command.is_empty() => {
                        return Err(Error::Config(format!(
                            "certificate {}: command hook has empty command",
                            cert.name
                        )));
                    }
                    _ => {}
                }
            }
        }

        Ok(())
    }

    /// Find a certificate config by name.
    #[allow(dead_code)]
    pub fn find_certificate(&self, name: &str) -> Option<&CertificateConfig> {
        self.certificates.iter().find(|c| c.name == name)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_config() {
        let toml = r#"
[acme]
directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
account_key_credential = "/etc/credstore.encrypted/acme-account-key"
contact = ["mailto:admin@example.com"]

[dns.defaults]
server = "ns1.example.com"
tsig_key_credential = "/etc/credstore.encrypted/dns-tsig-key"
tsig_key_name = "certforge-update."
tsig_algorithm = "hmac-sha256"
port = 53
protocol = "tcp"

[dns.zones."example.org"]
server = "ns2.example.org"
tsig_key_credential = "/etc/credstore.encrypted/dns-tsig-org"

[[certificate]]
name = "mail"
domains = ["mail.example.com", "mail.example.org"]
key_type = "ecdsa-p256"
key_credential = "/etc/credstore.encrypted/mail-tls-key"
cert_path = "/etc/certforge/certs/mail.pem"
renew_before_days = 30
rotate_key = false

  [[certificate.dane]]
  usage = "ee"
  selector = "spki"
  matching = "sha256"
  names = ["_25._tcp.mx1.example.com", "_25._tcp.mx2.example.com"]
  ttl = 300
  pre_publish = true

  [[certificate.hook]]
  type = "systemd-reload"
  unit = "postfix.service"

  [[certificate.hook]]
  type = "command"
  command = ["/usr/local/bin/deploy-cert.sh", "--cert", "mail"]
"#;

        let config: Config = toml::from_str(toml).unwrap();
        assert_eq!(config.certificates.len(), 1);
        let cert = &config.certificates[0];
        assert_eq!(cert.name, "mail");
        assert_eq!(cert.domains, vec!["mail.example.com", "mail.example.org"]);
        assert_eq!(cert.key_type, KeyType::EcdsaP256);
        assert_eq!(
            cert.key_credential.as_deref(),
            Some(Path::new("/etc/credstore.encrypted/mail-tls-key"))
        );
        assert!(!cert.rotate_key);
        assert_eq!(cert.dane.len(), 1);
        assert_eq!(cert.dane[0].usage, DaneUsage::Ee);
        assert_eq!(cert.dane[0].selector, DaneSelector::Spki);
        assert_eq!(cert.dane[0].names.len(), 2);
        assert!(cert.dane[0].pre_publish);
        assert_eq!(cert.hooks.len(), 2);

        // Test zone override resolution
        let resolved = config.dns.resolve_for_zone("example.org");
        assert_eq!(resolved.server, "ns2.example.org");
        assert_eq!(
            resolved.tsig_key_credential.as_deref(),
            Some(Path::new("/etc/credstore.encrypted/dns-tsig-org"))
        );
        assert_eq!(resolved.tsig_key_name, "certforge-update.");

        // Test default zone resolution
        let default_resolved = config.dns.resolve_for_zone("example.com");
        assert_eq!(default_resolved.server, "ns1.example.com");
    }

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[acme]
account_key_path = "/etc/certforge/account.key"
contact = ["mailto:admin@example.com"]

[dns.defaults]
server = "ns1.example.com"
tsig_key_path = "/etc/certforge/tsig.key"
tsig_key_name = "certforge."

[[certificate]]
name = "web"
domains = ["example.com"]
key_path = "/etc/certforge/keys/web.key"
cert_path = "/etc/certforge/certs/web.pem"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.certificates[0].key_type, KeyType::EcdsaP256);
        assert_eq!(config.certificates[0].renew_before_days, 30);
        assert!(config.certificates[0].dane.is_empty());
        assert!(config.certificates[0].hooks.is_empty());
    }

    #[test]
    fn validation_rejects_missing_key() {
        let toml = r#"
[acme]
account_key_path = "/etc/certforge/account.key"
contact = ["mailto:admin@example.com"]

[dns.defaults]
server = "ns1.example.com"
tsig_key_path = "/etc/certforge/tsig.key"
tsig_key_name = "certforge."

[[certificate]]
name = "web"
domains = ["example.com"]
cert_path = "/etc/certforge/certs/web.pem"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("key_credential or key_path"));
    }
}
