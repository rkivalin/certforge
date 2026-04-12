use ring::rand::SystemRandom;
use ring::signature::{self, EcdsaKeyPair, KeyPair as _};

use crate::config::KeyType;
use crate::credentials;
use crate::error::{Error, Result};
use std::path::Path;

/// A generated or loaded key pair with its type metadata.
pub struct CertKeyPair {
    pub key_type: KeyType,
    /// PKCS#8 v1 DER-encoded private key
    pub pkcs8_der: Vec<u8>,
}

impl CertKeyPair {
    /// Generate a new key pair of the specified type.
    pub fn generate(key_type: &KeyType) -> Result<Self> {
        let rng = SystemRandom::new();

        let pkcs8_der = match key_type {
            KeyType::EcdsaP256 => {
                EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P256_SHA256_ASN1_SIGNING, &rng)
                    .map_err(|e| Error::Key(format!("failed to generate ECDSA P-256 key: {e}")))?
                    .as_ref()
                    .to_vec()
            }
            KeyType::EcdsaP384 => {
                EcdsaKeyPair::generate_pkcs8(&signature::ECDSA_P384_SHA384_ASN1_SIGNING, &rng)
                    .map_err(|e| Error::Key(format!("failed to generate ECDSA P-384 key: {e}")))?
                    .as_ref()
                    .to_vec()
            }
            KeyType::Rsa2048 | KeyType::Rsa4096 => {
                return Err(Error::Key(
                    "RSA key generation not yet supported; use ecdsa-p256 or ecdsa-p384".into(),
                ));
            }
        };

        Ok(Self {
            key_type: key_type.clone(),
            pkcs8_der,
        })
    }

    /// Load a key pair from a credential or file path.
    pub async fn load(
        credential: Option<&Path>,
        path: Option<&Path>,
        key_type: &KeyType,
    ) -> Result<Self> {
        let pem_or_der = credentials::load_secret(credential, path).await?;
        Self::from_pem_or_der(&pem_or_der, key_type)
    }

    /// Parse a key from PEM or raw DER bytes.
    pub fn from_pem_or_der(data: &[u8], key_type: &KeyType) -> Result<Self> {
        // Try PEM first
        let der = if let Ok(pem) = pem::parse(data) {
            pem.contents().to_vec()
        } else {
            data.to_vec()
        };

        // Validate the key can be parsed
        match key_type {
            KeyType::EcdsaP256 => {
                EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &der,
                    &SystemRandom::new(),
                )
                .map_err(|e| Error::Key(format!("invalid ECDSA P-256 key: {e}")))?;
            }
            KeyType::EcdsaP384 => {
                EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    &der,
                    &SystemRandom::new(),
                )
                .map_err(|e| Error::Key(format!("invalid ECDSA P-384 key: {e}")))?;
            }
            KeyType::Rsa2048 | KeyType::Rsa4096 => {
                return Err(Error::Key("RSA keys not yet supported".into()));
            }
        }

        Ok(Self {
            key_type: key_type.clone(),
            pkcs8_der: der,
        })
    }

    /// Encode the private key as PEM.
    pub fn to_pem(&self) -> String {
        pem::encode(&pem::Pem::new("PRIVATE KEY", self.pkcs8_der.clone()))
    }

    /// Extract the SubjectPublicKeyInfo (SPKI) in DER format.
    pub fn spki_der(&self) -> Result<Vec<u8>> {
        match self.key_type {
            KeyType::EcdsaP256 => {
                let kp = EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P256_SHA256_ASN1_SIGNING,
                    &self.pkcs8_der,
                    &SystemRandom::new(),
                )
                .map_err(|e| Error::Key(format!("failed to parse key for SPKI: {e}")))?;
                // ring's public_key() returns the raw public key bytes.
                // We need to wrap it in SPKI ASN.1 structure.
                Ok(wrap_ec_spki(
                    kp.public_key().as_ref(),
                    EC_P256_OID,
                ))
            }
            KeyType::EcdsaP384 => {
                let kp = EcdsaKeyPair::from_pkcs8(
                    &signature::ECDSA_P384_SHA384_ASN1_SIGNING,
                    &self.pkcs8_der,
                    &SystemRandom::new(),
                )
                .map_err(|e| Error::Key(format!("failed to parse key for SPKI: {e}")))?;
                Ok(wrap_ec_spki(
                    kp.public_key().as_ref(),
                    EC_P384_OID,
                ))
            }
            KeyType::Rsa2048 | KeyType::Rsa4096 => {
                Err(Error::Key("RSA SPKI extraction not yet supported".into()))
            }
        }
    }
}

// OID for id-ecPublicKey (1.2.840.10045.2.1)
const EC_PUBLIC_KEY_OID: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];

// OID for secp256r1 (1.2.840.10045.3.1.7)
const EC_P256_OID: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];

// OID for secp384r1 (1.3.132.0.34)
const EC_P384_OID: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];

/// Wrap an EC public key in a SubjectPublicKeyInfo ASN.1 structure.
///
/// SPKI = SEQUENCE {
///   algorithm AlgorithmIdentifier = SEQUENCE { id-ecPublicKey, namedCurve },
///   subjectPublicKey BIT STRING
/// }
fn wrap_ec_spki(public_key_bytes: &[u8], curve_oid: &[u8]) -> Vec<u8> {
    // AlgorithmIdentifier = SEQUENCE { ecPublicKey OID, curve OID }
    let alg_id_content_len = EC_PUBLIC_KEY_OID.len() + curve_oid.len();
    let mut alg_id = vec![0x30]; // SEQUENCE
    encode_asn1_length(alg_id_content_len, &mut alg_id);
    alg_id.extend_from_slice(EC_PUBLIC_KEY_OID);
    alg_id.extend_from_slice(curve_oid);

    // BIT STRING wrapping the public key
    // BIT STRING = 0x03 | length | 0x00 (no unused bits) | public_key_bytes
    let bit_string_content_len = 1 + public_key_bytes.len();
    let mut bit_string = vec![0x03];
    encode_asn1_length(bit_string_content_len, &mut bit_string);
    bit_string.push(0x00); // no unused bits
    bit_string.extend_from_slice(public_key_bytes);

    // SPKI = SEQUENCE { alg_id, bit_string }
    let spki_content_len = alg_id.len() + bit_string.len();
    let mut spki = vec![0x30]; // SEQUENCE
    encode_asn1_length(spki_content_len, &mut spki);
    spki.extend_from_slice(&alg_id);
    spki.extend_from_slice(&bit_string);

    spki
}

fn encode_asn1_length(len: usize, buf: &mut Vec<u8>) {
    if len < 0x80 {
        buf.push(len as u8);
    } else if len < 0x100 {
        buf.push(0x81);
        buf.push(len as u8);
    } else {
        buf.push(0x82);
        buf.push((len >> 8) as u8);
        buf.push(len as u8);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_ecdsa_p256() {
        let kp = CertKeyPair::generate(&KeyType::EcdsaP256).unwrap();
        assert!(!kp.pkcs8_der.is_empty());
        let pem = kp.to_pem();
        assert!(pem.starts_with("-----BEGIN PRIVATE KEY-----"));

        let spki = kp.spki_der().unwrap();
        assert!(!spki.is_empty());
        // SPKI should start with SEQUENCE tag
        assert_eq!(spki[0], 0x30);
    }

    #[test]
    fn generate_ecdsa_p384() {
        let kp = CertKeyPair::generate(&KeyType::EcdsaP384).unwrap();
        assert!(!kp.pkcs8_der.is_empty());
        let spki = kp.spki_der().unwrap();
        assert!(!spki.is_empty());
    }

    #[test]
    fn roundtrip_pem() {
        let kp = CertKeyPair::generate(&KeyType::EcdsaP256).unwrap();
        let pem_str = kp.to_pem();
        let kp2 = CertKeyPair::from_pem_or_der(pem_str.as_bytes(), &KeyType::EcdsaP256).unwrap();
        assert_eq!(kp.pkcs8_der, kp2.pkcs8_der);
    }
}
