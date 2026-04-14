use std::collections::HashMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::error::{Error, Result};

#[derive(Debug, Deserialize)]
pub struct Config {
    pub acme: AcmeConfig,

    /// Global default solver name for certificates that don't specify one.
    pub default_solver: Option<String>,

    /// Named DNS client connections, referenced by solvers and DANE blocks.
    #[serde(default)]
    pub dns: HashMap<String, DnsClientConfig>,

    /// Named challenge solvers.
    #[serde(default)]
    pub solver: HashMap<String, SolverConfig>,

    /// Named hooks, run after all renewals in definition order.
    #[serde(default)]
    pub hook: Vec<NamedHookConfig>,

    #[serde(rename = "certificate", default)]
    pub certificates: Vec<CertificateConfig>,
}

#[derive(Debug, Deserialize)]
pub struct AcmeConfig {
    #[serde(default = "default_directory_url")]
    pub directory_url: String,

    pub account_key_credential: Option<PathBuf>,
    pub account_key_path: Option<PathBuf>,

    pub contact: Vec<String>,
}

fn default_directory_url() -> String {
    "https://acme-v02.api.letsencrypt.org/directory".to_string()
}

/// DNS client connection config, used for both RFC 2136 updates (solvers) and DANE TLSA publication.
#[derive(Debug, Clone, Deserialize)]
pub struct DnsClientConfig {
    pub server: String,

    /// Single zone (convenience shorthand).
    #[serde(default)]
    pub zone: Option<String>,
    /// Multiple zones served by this DNS client.
    #[serde(default)]
    pub zones: Option<Vec<String>>,

    pub tsig_key_credential: Option<PathBuf>,
    pub tsig_key_path: Option<PathBuf>,

    pub tsig_key_name: String,
    #[serde(default = "default_tsig_algorithm")]
    pub tsig_algorithm: TsigAlgorithm,
    #[serde(default = "default_dns_port")]
    pub port: u16,
    #[serde(default = "default_dns_protocol")]
    pub protocol: DnsProtocol,
}

impl DnsClientConfig {
    /// Get all configured zones.
    pub fn all_zones(&self) -> Vec<&str> {
        let mut result = Vec::new();
        if let Some(zones) = &self.zones {
            result.extend(zones.iter().map(|s| s.as_str()));
        }
        if let Some(zone) = &self.zone
            && !result.iter().any(|z| z == &zone.as_str()) {
                result.push(zone.as_str());
            }
        result
    }

    /// Find the best matching zone for a DNS name.
    /// Matches if `name == zone` or `name` ends with `.<zone>`.
    /// Returns the longest (most specific) match.
    pub fn find_zone(&self, name: &str) -> Option<&str> {
        let name_lower = name.to_ascii_lowercase();
        let name_lower = name_lower.trim_end_matches('.');

        self.all_zones()
            .into_iter()
            .filter(|zone| {
                let zone_lower = zone.to_ascii_lowercase();
                let zone_lower = zone_lower.trim_end_matches('.');
                name_lower == zone_lower || name_lower.ends_with(&format!(".{zone_lower}"))
            })
            .max_by_key(|zone| zone.len())
    }
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum TsigAlgorithm {
    HmacSha256,
    HmacSha384,
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

/// Challenge solver configuration, tagged by type.
#[derive(Debug, Deserialize)]
#[serde(tag = "type")]
#[allow(dead_code)]
pub enum SolverConfig {
    #[serde(rename = "dns-01")]
    Dns01 {
        /// Reference to a [dns.*] client config by name.
        dns: String,
    },
    #[serde(rename = "http-01")]
    Http01 {
        /// Address to listen on for standalone HTTP server.
        listen: Option<SocketAddr>,
        /// Directory to write challenge tokens for an existing web server.
        webroot: Option<PathBuf>,
    },
    #[serde(rename = "tls-alpn-01")]
    TlsAlpn01 {
        /// Address to listen on for the TLS-ALPN server.
        listen: SocketAddr,
    },
}

#[derive(Debug, Deserialize)]
pub struct CertificateConfig {
    pub name: String,
    /// Domain names and/or IP addresses for the certificate SANs.
    pub domains: Vec<String>,

    #[serde(default = "default_key_type")]
    pub key_type: KeyType,

    pub key_credential: Option<PathBuf>,
    pub key_path: Option<PathBuf>,

    pub cert_path: PathBuf,

    /// ACME profile to use for the order.
    /// Some providers require a specific profile for certain certificate types
    /// (e.g., Let's Encrypt requires "shortlived" for IP address certificates).
    pub profile: Option<String>,

    #[serde(default = "default_renew_before_days")]
    pub renew_before_days: u32,

    #[serde(default)]
    pub rotate_key: bool,

    /// Single solver name for all domains.
    pub solver: Option<String>,
    /// Per-domain solver names (must match domains length).
    pub solvers: Option<Vec<String>>,

    #[serde(default)]
    pub dane: Vec<DaneConfig>,

    /// Named hooks to run after renewal (references [[hook]] entries by name).
    #[serde(default)]
    pub hooks: Vec<String>,

    /// Inline hooks, run per-certificate immediately after renewal.
    #[serde(default, rename = "hook")]
    pub inline_hooks: Vec<HookConfig>,
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
    /// Reference to a [dns.*] client config for TLSA record updates.
    pub dns: String,

    #[serde(default = "default_dane_usage")]
    pub usage: DaneUsage,
    #[serde(default = "default_dane_selector")]
    pub selector: DaneSelector,
    #[serde(default = "default_dane_matching")]
    pub matching: DaneMatching,

    pub names: Vec<String>,

    #[serde(default = "default_dane_ttl")]
    pub ttl: u32,

    #[serde(default)]
    pub pre_publish: bool,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DaneUsage {
    #[serde(rename = "pkix-ta")]
    PkixTa,
    #[serde(rename = "pkix-ee")]
    PkixEe,
    #[serde(rename = "ta")]
    Ta,
    #[serde(rename = "ee")]
    Ee,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DaneSelector {
    Full,
    Spki,
}

#[derive(Debug, Clone, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum DaneMatching {
    Full,
    Sha256,
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

/// A named hook that can be referenced by certificates.
#[derive(Debug, Deserialize)]
pub struct NamedHookConfig {
    pub name: String,
    #[serde(flatten)]
    pub hook: HookConfig,
}

impl CertificateConfig {
    /// Resolve the solver name for the i-th domain.
    /// Priority: solvers[i] > solver > default_solver.
    pub fn solver_for_domain<'a>(&'a self, index: usize, default: Option<&'a str>) -> Option<&'a str> {
        if let Some(solvers) = &self.solvers {
            solvers.get(index).map(|s| s.as_str())
        } else if let Some(solver) = &self.solver {
            Some(solver.as_str())
        } else {
            default
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

    /// Look up a DNS client config by name.
    pub fn dns_client(&self, name: &str) -> Result<&DnsClientConfig> {
        self.dns.get(name).ok_or_else(|| {
            Error::Config(format!("dns client '{name}' not found"))
        })
    }

    /// Look up a solver config by name.
    pub fn solver_config(&self, name: &str) -> Result<&SolverConfig> {
        self.solver.get(name).ok_or_else(|| {
            Error::Config(format!("solver '{name}' not found"))
        })
    }

    #[allow(dead_code)]
    pub fn find_certificate(&self, name: &str) -> Option<&CertificateConfig> {
        self.certificates.iter().find(|c| c.name == name)
    }

    fn validate(&self) -> Result<()> {
        // ACME config
        if self.acme.account_key_credential.is_none() && self.acme.account_key_path.is_none() {
            return Err(Error::Config(
                "acme: either account_key_credential or account_key_path must be set".into(),
            ));
        }
        if self.acme.contact.is_empty() {
            return Err(Error::Config("acme: contact must not be empty".into()));
        }

        // Validate default_solver reference
        if let Some(default) = &self.default_solver
            && !self.solver.contains_key(default) {
                return Err(Error::Config(format!(
                    "default_solver '{default}' not found in [solver.*]"
                )));
            }

        // Validate DNS client configs
        for (name, dns) in &self.dns {
            if dns.tsig_key_credential.is_none() && dns.tsig_key_path.is_none() {
                return Err(Error::Config(format!(
                    "dns.{name}: either tsig_key_credential or tsig_key_path must be set"
                )));
            }
            if dns.all_zones().is_empty() {
                return Err(Error::Config(format!(
                    "dns.{name}: either zone or zones must be set"
                )));
            }
        }

        // Validate named hook definitions
        for named_hook in &self.hook {
            if let HookConfig::Command { command } = &named_hook.hook
                && command.is_empty()
            {
                return Err(Error::Config(format!(
                    "hook '{}': command hook has empty command",
                    named_hook.name
                )));
            }
        }

        // Validate solver configs
        for (name, solver) in &self.solver {
            match solver {
                SolverConfig::Dns01 { dns } => {
                    if !self.dns.contains_key(dns) {
                        return Err(Error::Config(format!(
                            "solver.{name}: dns client '{dns}' not found in [dns.*]"
                        )));
                    }
                }
                SolverConfig::Http01 { listen, webroot } => {
                    if listen.is_none() && webroot.is_none() {
                        return Err(Error::Config(format!(
                            "solver.{name}: either listen or webroot must be set"
                        )));
                    }
                    if listen.is_some() && webroot.is_some() {
                        return Err(Error::Config(format!(
                            "solver.{name}: listen and webroot are mutually exclusive"
                        )));
                    }
                }
                SolverConfig::TlsAlpn01 { .. } => {}
            }
        }

        // Validate certificates
        let is_ip = |s: &str| s.parse::<std::net::IpAddr>().is_ok();

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

            // solver and solvers are mutually exclusive
            if cert.solver.is_some() && cert.solvers.is_some() {
                return Err(Error::Config(format!(
                    "certificate {}: solver and solvers are mutually exclusive",
                    cert.name
                )));
            }

            // solvers length must match domains
            if let Some(solvers) = &cert.solvers
                && solvers.len() != cert.domains.len() {
                    return Err(Error::Config(format!(
                        "certificate {}: solvers length ({}) must match domains length ({})",
                        cert.name,
                        solvers.len(),
                        cert.domains.len()
                    )));
                }

            // Validate each domain's solver reference and check DNS-01 not used with IPs
            for (i, domain) in cert.domains.iter().enumerate() {
                let solver_name = cert.solver_for_domain(i, self.default_solver.as_deref());
                if let Some(name) = solver_name {
                    if !self.solver.contains_key(name) {
                        return Err(Error::Config(format!(
                            "certificate {}: solver '{name}' not found in [solver.*]",
                            cert.name
                        )));
                    }
                    // DNS-01 cannot be used with IP addresses
                    if is_ip(domain) && matches!(self.solver.get(name), Some(SolverConfig::Dns01 { .. })) {
                        return Err(Error::Config(format!(
                            "certificate {}: DNS-01 solver cannot be used with IP address {domain}",
                            cert.name
                        )));
                    }
                    // DNS-01: verify domain matches a zone in the DNS client
                    if let Some(SolverConfig::Dns01 { dns: dns_name }) = self.solver.get(name)
                        && let Some(dns_config) = self.dns.get(dns_name.as_str()) {
                            let base = domain.strip_prefix("*.").unwrap_or(domain);
                            let challenge_name = format!("_acme-challenge.{base}");
                            if dns_config.find_zone(&challenge_name).is_none() {
                                return Err(Error::Config(format!(
                                    "certificate {}: domain '{domain}' does not match any zone in dns.{dns_name} ({:?})",
                                    cert.name,
                                    dns_config.all_zones()
                                )));
                            }
                        }
                }
            }

            // Validate DANE blocks
            for dane in &cert.dane {
                if dane.names.is_empty() {
                    return Err(Error::Config(format!(
                        "certificate {}: dane block has empty names",
                        cert.name
                    )));
                }
                if !self.dns.contains_key(&dane.dns) {
                    return Err(Error::Config(format!(
                        "certificate {}: dane dns client '{}' not found in [dns.*]",
                        cert.name, dane.dns
                    )));
                }
                // Verify each DANE name matches a zone in the DNS client
                if let Some(dns_config) = self.dns.get(&dane.dns) {
                    for tlsa_name in &dane.names {
                        if dns_config.find_zone(tlsa_name).is_none() {
                            return Err(Error::Config(format!(
                                "certificate {}: DANE name '{tlsa_name}' does not match any zone in dns.{} ({:?})",
                                cert.name, dane.dns, dns_config.all_zones()
                            )));
                        }
                    }
                }
            }

            // Validate named hook references
            for hook_name in &cert.hooks {
                if !self.hook.iter().any(|h| h.name == *hook_name) {
                    return Err(Error::Config(format!(
                        "certificate {}: hook '{hook_name}' not found in [[hook]]",
                        cert.name
                    )));
                }
            }

            for hook in &cert.inline_hooks {
                if let HookConfig::Command { command } = hook
                    && command.is_empty()
                {
                    return Err(Error::Config(format!(
                        "certificate {}: command hook has empty command",
                        cert.name
                    )));
                }
            }
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_full_config() {
        let toml = r#"
default_solver = "dns"

[acme]
directory_url = "https://acme-staging-v02.api.letsencrypt.org/directory"
account_key_credential = "/etc/credstore.encrypted/acme-account-key"
contact = ["mailto:admin@example.com"]

[dns.main]
server = "ns1.example.com"
zone = "example.com"
tsig_key_credential = "/etc/credstore.encrypted/dns-tsig-key"
tsig_key_name = "certforge-update."
tsig_algorithm = "hmac-sha256"
port = 53
protocol = "tcp"

[dns.org]
server = "ns2.example.org"
zone = "example.org"
tsig_key_credential = "/etc/credstore.encrypted/dns-tsig-org"
tsig_key_name = "certforge-org."

[solver.dns]
type = "dns-01"
dns = "main"

[solver.dns-org]
type = "dns-01"
dns = "org"

[solver.http]
type = "http-01"
listen = "[::]:80"

[[certificate]]
name = "mail"
domains = ["mail.example.com", "mail.example.org"]
key_type = "ecdsa-p256"
key_credential = "/etc/credstore.encrypted/mail-tls-key"
cert_path = "/etc/certforge/certs/mail.pem"
renew_before_days = 30
rotate_key = false
solvers = ["dns", "dns-org"]

  [[certificate.dane]]
  dns = "main"
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

[[certificate]]
name = "mixed"
domains = ["example.com", "203.0.113.1"]
key_path = "/etc/certforge/keys/mixed.key"
cert_path = "/etc/certforge/certs/mixed.pem"
profile = "shortlived"
solvers = ["dns", "http"]
"#;

        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();

        assert_eq!(config.dns.len(), 2);
        assert_eq!(config.solver.len(), 3);
        assert_eq!(config.certificates.len(), 2);

        let cert = &config.certificates[0];
        assert_eq!(cert.name, "mail");
        assert_eq!(cert.domains, vec!["mail.example.com", "mail.example.org"]);
        assert_eq!(cert.solvers.as_ref().unwrap(), &vec!["dns", "dns-org"]);
        assert_eq!(cert.dane.len(), 1);
        assert_eq!(cert.dane[0].dns, "main");
        assert_eq!(cert.dane[0].usage, DaneUsage::Ee);
        assert!(cert.dane[0].pre_publish);
        assert_eq!(cert.inline_hooks.len(), 2);

        // Solver resolution
        assert_eq!(cert.solver_for_domain(0, None), Some("dns"));
        assert_eq!(cert.solver_for_domain(1, None), Some("dns-org"));

        // Mixed cert
        let mixed = &config.certificates[1];
        assert_eq!(mixed.solvers.as_ref().unwrap(), &vec!["dns", "http"]);
    }

    #[test]
    fn parse_minimal_config() {
        let toml = r#"
[acme]
account_key_path = "/etc/certforge/account.key"
contact = ["mailto:admin@example.com"]

[dns.default]
server = "ns1.example.com"
zone = "example.com"
tsig_key_path = "/etc/certforge/tsig.key"
tsig_key_name = "certforge."

[solver.dns]
type = "dns-01"
dns = "default"

[[certificate]]
name = "web"
domains = ["example.com"]
key_path = "/etc/certforge/keys/web.key"
cert_path = "/etc/certforge/certs/web.pem"
solver = "dns"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        assert_eq!(config.certificates[0].key_type, KeyType::EcdsaP256);
        assert_eq!(config.certificates[0].renew_before_days, 30);
        assert_eq!(config.certificates[0].solver_for_domain(0, None), Some("dns"));
    }

    #[test]
    fn default_solver_fallback() {
        let toml = r#"
default_solver = "dns"

[acme]
account_key_path = "/etc/certforge/account.key"
contact = ["mailto:admin@example.com"]

[dns.main]
server = "ns1.example.com"
zone = "example.com"
tsig_key_path = "/etc/certforge/tsig.key"
tsig_key_name = "certforge."

[solver.dns]
type = "dns-01"
dns = "main"

[[certificate]]
name = "web"
domains = ["example.com"]
key_path = "/etc/certforge/keys/web.key"
cert_path = "/etc/certforge/certs/web.pem"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
        // No solver/solvers on cert — falls back to default_solver
        assert_eq!(
            config.certificates[0].solver_for_domain(0, config.default_solver.as_deref()),
            Some("dns")
        );
    }

    #[test]
    fn validation_rejects_missing_key() {
        let toml = r#"
[acme]
account_key_path = "/etc/certforge/account.key"
contact = ["mailto:admin@example.com"]

[dns.main]
server = "ns1.example.com"
zone = "example.com"
tsig_key_path = "/etc/certforge/tsig.key"
tsig_key_name = "certforge."

[solver.dns]
type = "dns-01"
dns = "main"

[[certificate]]
name = "web"
domains = ["example.com"]
cert_path = "/etc/certforge/certs/web.pem"
solver = "dns"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("key_credential or key_path"));
    }

    #[test]
    fn validation_rejects_dns01_with_ip() {
        let toml = r#"
[acme]
account_key_path = "/etc/certforge/account.key"
contact = ["mailto:admin@example.com"]

[dns.main]
server = "ns1.example.com"
zone = "example.com"
tsig_key_path = "/etc/certforge/tsig.key"
tsig_key_name = "certforge."

[solver.dns]
type = "dns-01"
dns = "main"

[[certificate]]
name = "ip"
domains = ["203.0.113.1"]
key_path = "/etc/certforge/keys/ip.key"
cert_path = "/etc/certforge/certs/ip.pem"
profile = "shortlived"
solver = "dns"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("DNS-01 solver cannot be used with IP address"));
    }

    #[test]
    fn validation_rejects_solvers_length_mismatch() {
        let toml = r#"
[acme]
account_key_path = "/etc/certforge/account.key"
contact = ["mailto:admin@example.com"]

[dns.main]
server = "ns1.example.com"
zone = "example.com"
tsig_key_path = "/etc/certforge/tsig.key"
tsig_key_name = "certforge."

[solver.dns]
type = "dns-01"
dns = "main"

[[certificate]]
name = "web"
domains = ["a.example.com", "b.example.com"]
key_path = "/etc/certforge/keys/web.key"
cert_path = "/etc/certforge/certs/web.pem"
solvers = ["dns"]
"#;

        let config: Config = toml::from_str(toml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("solvers length"));
    }

    #[test]
    fn zone_matching() {
        let dns = DnsClientConfig {
            server: "ns1.example.com".into(),
            zone: None,
            zones: Some(vec!["example.com".into(), "example.org".into(), "sub.example.com".into()]),
            tsig_key_credential: None,
            tsig_key_path: Some("/tmp/key".into()),
            tsig_key_name: "test.".into(),
            tsig_algorithm: TsigAlgorithm::HmacSha256,
            port: 53,
            protocol: DnsProtocol::Tcp,
        };

        // Basic matches
        assert_eq!(dns.find_zone("mail.example.com"), Some("example.com"));
        assert_eq!(dns.find_zone("mail.example.org"), Some("example.org"));
        assert_eq!(dns.find_zone("example.com"), Some("example.com"));

        // Longest match wins
        assert_eq!(dns.find_zone("host.sub.example.com"), Some("sub.example.com"));

        // DANE-style names
        assert_eq!(dns.find_zone("_25._tcp.mail.example.com"), Some("example.com"));
        assert_eq!(dns.find_zone("_443._tcp.host.sub.example.com"), Some("sub.example.com"));

        // No match
        assert_eq!(dns.find_zone("other.net"), None);

        // Case insensitive
        assert_eq!(dns.find_zone("Mail.Example.COM"), Some("example.com"));
    }

    #[test]
    fn multi_zone_config() {
        let toml = r#"
[acme]
account_key_path = "/etc/certforge/account.key"
contact = ["mailto:admin@example.com"]

[dns.main]
server = "ns1.example.com"
zones = ["example.com", "example.org"]
tsig_key_path = "/etc/certforge/tsig.key"
tsig_key_name = "certforge."

[solver.dns]
type = "dns-01"
dns = "main"

[[certificate]]
name = "multi"
domains = ["mail.example.com", "mail.example.org"]
key_path = "/etc/certforge/keys/multi.key"
cert_path = "/etc/certforge/certs/multi.pem"
solver = "dns"

  [[certificate.dane]]
  dns = "main"
  names = ["_25._tcp.mail.example.com", "_25._tcp.mail.example.org"]
"#;

        let config: Config = toml::from_str(toml).unwrap();
        config.validate().unwrap();
    }

    #[test]
    fn validation_rejects_domain_without_matching_zone() {
        let toml = r#"
[acme]
account_key_path = "/etc/certforge/account.key"
contact = ["mailto:admin@example.com"]

[dns.main]
server = "ns1.example.com"
zone = "example.com"
tsig_key_path = "/etc/certforge/tsig.key"
tsig_key_name = "certforge."

[solver.dns]
type = "dns-01"
dns = "main"

[[certificate]]
name = "bad"
domains = ["mail.other.net"]
key_path = "/etc/certforge/keys/bad.key"
cert_path = "/etc/certforge/certs/bad.pem"
solver = "dns"
"#;

        let config: Config = toml::from_str(toml).unwrap();
        let err = config.validate().unwrap_err();
        assert!(err.to_string().contains("does not match any zone"));
    }

    #[test]
    fn zone_and_zones_combined() {
        let dns = DnsClientConfig {
            server: "ns1.example.com".into(),
            zone: Some("legacy.com".into()),
            zones: Some(vec!["example.com".into()]),
            tsig_key_credential: None,
            tsig_key_path: Some("/tmp/key".into()),
            tsig_key_name: "test.".into(),
            tsig_algorithm: TsigAlgorithm::HmacSha256,
            port: 53,
            protocol: DnsProtocol::Tcp,
        };

        assert_eq!(dns.all_zones(), vec!["example.com", "legacy.com"]);
        assert_eq!(dns.find_zone("host.legacy.com"), Some("legacy.com"));
        assert_eq!(dns.find_zone("host.example.com"), Some("example.com"));
    }
}
