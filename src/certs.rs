use std::path::Path;
use x509_parser::prelude::*;

use crate::error::{Error, Result};

/// Parsed certificate information.
pub struct CertInfo {
    /// DER-encoded leaf certificate
    pub leaf_der: Vec<u8>,
    /// Not-after (expiry) timestamp
    pub not_after: chrono::DateTime<chrono::Utc>,
    /// Subject Alternative Names
    pub san: Vec<String>,
    /// SubjectPublicKeyInfo DER bytes
    pub spki_der: Vec<u8>,
}

impl CertInfo {
    /// Load and parse a certificate from a PEM file.
    pub fn load(path: &Path) -> Result<Self> {
        let pem_chain = std::fs::read_to_string(path).map_err(|e| {
            Error::Certificate(format!("failed to read cert {}: {e}", path.display()))
        })?;
        Self::from_pem(&pem_chain)
    }

    /// Parse a certificate from PEM data.
    pub fn from_pem(pem_data: &str) -> Result<Self> {
        let pem_blocks: Vec<::pem::Pem> = ::pem::parse_many(pem_data.as_bytes())
            .map_err(|e| Error::Certificate(format!("failed to parse PEM: {e}")))?;

        if pem_blocks.is_empty() {
            return Err(Error::Certificate("no certificates found in PEM data".into()));
        }

        let leaf_der = pem_blocks[0].contents().to_vec();
        let (_, cert) = X509Certificate::from_der(&leaf_der)
            .map_err(|e| Error::Certificate(format!("failed to parse X.509: {e}")))?;

        let not_after = asn1_time_to_chrono(cert.validity().not_after)?;

        let san = extract_san(&cert);

        let spki_der = cert.public_key().raw.to_vec();

        Ok(Self {
            leaf_der,
            not_after,
            san,
            spki_der,
        })
    }

    /// Check if the certificate expires within the given number of days.
    pub fn expires_within_days(&self, days: u32) -> bool {
        let now = chrono::Utc::now();
        let threshold = now + chrono::Duration::days(days as i64);
        self.not_after <= threshold
    }

    /// Days until expiry (negative if already expired).
    pub fn days_until_expiry(&self) -> i64 {
        let now = chrono::Utc::now();
        (self.not_after - now).num_days()
    }
}

fn extract_san(cert: &X509Certificate) -> Vec<String> {
    let mut names = Vec::new();

    if let Ok(Some(san_ext)) = cert.subject_alternative_name() {
        for name in &san_ext.value.general_names {
            match name {
                GeneralName::DNSName(dns) => names.push(dns.to_string()),
                GeneralName::IPAddress(ip) => {
                    // IP addresses come as byte slices
                    if ip.len() == 4 {
                        names.push(format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3]));
                    } else if ip.len() == 16 {
                        let parts: Vec<String> = ip
                            .chunks(2)
                            .map(|c| format!("{:02x}{:02x}", c[0], c[1]))
                            .collect();
                        names.push(parts.join(":"));
                    }
                }
                _ => {}
            }
        }
    }

    names
}

fn asn1_time_to_chrono(time: ASN1Time) -> Result<chrono::DateTime<chrono::Utc>> {
    let ts = time.timestamp();
    chrono::DateTime::from_timestamp(ts, 0)
        .ok_or_else(|| Error::Certificate(format!("invalid timestamp: {ts}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn generate_test_cert() -> String {
        use rcgen::{CertificateParams, KeyPair};

        let mut params = CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        params.not_after = rcgen::date_time_ymd(2030, 1, 1);
        let key_pair = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let cert = params.self_signed(&key_pair).unwrap();
        cert.pem()
    }

    #[test]
    fn parse_cert() {
        let pem_data = generate_test_cert();
        let info = CertInfo::from_pem(&pem_data).unwrap();
        assert!(info.san.contains(&"test.example.com".to_string()));
        assert!(!info.spki_der.is_empty());
        assert!(info.days_until_expiry() > 0);
    }

    #[test]
    fn expiry_check() {
        let pem_data = generate_test_cert();
        let info = CertInfo::from_pem(&pem_data).unwrap();
        // Cert expires in 2030, so it should not expire within 30 days
        assert!(!info.expires_within_days(30));
    }
}
