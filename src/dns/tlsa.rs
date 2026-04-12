use sha2::{Digest, Sha256, Sha512};

use crate::config::{DaneMatching, DaneSelector, DaneUsage};
use crate::error::Result;

/// Represents a TLSA record's rdata fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TlsaRecord {
    pub usage: u8,
    pub selector: u8,
    pub matching_type: u8,
    pub association_data: Vec<u8>,
}

impl TlsaRecord {
    /// Compute a TLSA record from a DER-encoded certificate.
    pub fn from_certificate(
        cert_der: &[u8],
        spki_der: &[u8],
        usage: &DaneUsage,
        selector: &DaneSelector,
        matching: &DaneMatching,
    ) -> Result<Self> {
        let data = match selector {
            DaneSelector::Full => cert_der.to_vec(),
            DaneSelector::Spki => spki_der.to_vec(),
        };

        let association_data = match matching {
            DaneMatching::Full => data,
            DaneMatching::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(&data);
                hasher.finalize().to_vec()
            }
            DaneMatching::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(&data);
                hasher.finalize().to_vec()
            }
        };

        Ok(Self {
            usage: usage.to_u8(),
            selector: selector.to_u8(),
            matching_type: matching.to_u8(),
            association_data,
        })
    }

    /// Compute a TLSA record from a public key's SPKI DER.
    /// Only valid with Selector::Spki.
    pub fn from_spki(
        spki_der: &[u8],
        usage: &DaneUsage,
        matching: &DaneMatching,
    ) -> Result<Self> {
        let association_data = match matching {
            DaneMatching::Full => spki_der.to_vec(),
            DaneMatching::Sha256 => {
                let mut hasher = Sha256::new();
                hasher.update(spki_der);
                hasher.finalize().to_vec()
            }
            DaneMatching::Sha512 => {
                let mut hasher = Sha512::new();
                hasher.update(spki_der);
                hasher.finalize().to_vec()
            }
        };

        Ok(Self {
            usage: usage.to_u8(),
            selector: DaneSelector::Spki.to_u8(),
            matching_type: matching.to_u8(),
            association_data,
        })
    }

    /// Format the association data as a hex string (for display / DNS zone format).
    pub fn association_data_hex(&self) -> String {
        hex::encode(&self.association_data)
    }

    /// Format as a DNS record data string: "usage selector matching hex"
    pub fn to_rdata_string(&self) -> String {
        format!(
            "{} {} {} {}",
            self.usage,
            self.selector,
            self.matching_type,
            self.association_data_hex()
        )
    }
}

impl DaneUsage {
    pub fn to_u8(&self) -> u8 {
        match self {
            DaneUsage::PkixTa => 0,
            DaneUsage::PkixEe => 1,
            DaneUsage::Ta => 2,
            DaneUsage::Ee => 3,
        }
    }
}

impl DaneSelector {
    pub fn to_u8(&self) -> u8 {
        match self {
            DaneSelector::Full => 0,
            DaneSelector::Spki => 1,
        }
    }
}

impl DaneMatching {
    pub fn to_u8(&self) -> u8 {
        match self {
            DaneMatching::Full => 0,
            DaneMatching::Sha256 => 1,
            DaneMatching::Sha512 => 2,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tlsa_from_spki_sha256() {
        let fake_spki = b"this is a fake spki for testing";
        let record = TlsaRecord::from_spki(
            fake_spki,
            &DaneUsage::Ee,
            &DaneMatching::Sha256,
        )
        .unwrap();

        assert_eq!(record.usage, 3);
        assert_eq!(record.selector, 1);
        assert_eq!(record.matching_type, 1);
        assert_eq!(record.association_data.len(), 32); // SHA-256 output
    }

    #[test]
    fn tlsa_from_spki_sha512() {
        let fake_spki = b"this is a fake spki for testing";
        let record = TlsaRecord::from_spki(
            fake_spki,
            &DaneUsage::Ee,
            &DaneMatching::Sha512,
        )
        .unwrap();

        assert_eq!(record.association_data.len(), 64); // SHA-512 output
    }

    #[test]
    fn tlsa_rdata_string() {
        let record = TlsaRecord {
            usage: 3,
            selector: 1,
            matching_type: 1,
            association_data: vec![0xab, 0xcd, 0xef],
        };
        assert_eq!(record.to_rdata_string(), "3 1 1 abcdef");
    }

    #[test]
    fn tlsa_from_cert_with_spki_selector() {
        use crate::keys::CertKeyPair;
        use crate::config::KeyType;

        let kp = CertKeyPair::generate(&KeyType::EcdsaP256).unwrap();
        let spki = kp.spki_der().unwrap();

        // Generate a self-signed cert to get DER
        let pkcs8_der = rustls_pki_types::PrivatePkcs8KeyDer::from(kp.pkcs8_der.as_slice());
        let rcgen_kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(
            &pkcs8_der,
            &rcgen::PKCS_ECDSA_P256_SHA256,
        )
        .unwrap();
        let params =
            rcgen::CertificateParams::new(vec!["test.example.com".to_string()]).unwrap();
        let cert = params.self_signed(&rcgen_kp).unwrap();
        let cert_der = cert.der().to_vec();

        let record = TlsaRecord::from_certificate(
            &cert_der,
            &spki,
            &DaneUsage::Ee,
            &DaneSelector::Spki,
            &DaneMatching::Sha256,
        )
        .unwrap();

        // SPKI-based TLSA from cert should match SPKI-based TLSA from key
        let record_from_key = TlsaRecord::from_spki(
            &spki,
            &DaneUsage::Ee,
            &DaneMatching::Sha256,
        )
        .unwrap();

        assert_eq!(record.association_data, record_from_key.association_data);
    }
}
