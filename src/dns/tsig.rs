use std::sync::Arc;

use base64::Engine;
use hickory_proto::dnssec::tsig::TSigner;
use hickory_proto::dnssec::rdata::tsig::TsigAlgorithm;
use hickory_proto::op::MessageFinalizer;
use hickory_proto::rr::Name;

use crate::config;
use crate::credentials;
use crate::error::{Error, Result};

/// Load a TSIG signer from the DNS server config.
pub async fn load_tsig_signer(
    dns_config: &config::DnsClientConfig,
) -> Result<Arc<dyn MessageFinalizer>> {
    let raw_key = credentials::load_secret(
        dns_config.tsig_key_credential.as_deref(),
        dns_config.tsig_key_path.as_deref(),
    )
    .await?;

    // TSIG keys are typically stored as base64 (matching BIND's key format).
    // Try to decode as base64; if that fails, use the raw bytes as-is.
    let key_data = decode_tsig_key(&raw_key)?;

    let algorithm = match dns_config.tsig_algorithm {
        config::TsigAlgorithm::HmacSha256 => TsigAlgorithm::HmacSha256,
        config::TsigAlgorithm::HmacSha512 => TsigAlgorithm::HmacSha512,
    };

    let signer_name = Name::from_ascii(&dns_config.tsig_key_name)
        .map_err(|e| Error::DnsUpdate(format!("invalid TSIG key name: {e}")))?;

    // Default TSIG fudge is 300 seconds (5 minutes)
    let signer = TSigner::new(key_data, algorithm, signer_name, 300)
        .map_err(|e| Error::DnsUpdate(format!("failed to create TSIG signer: {e}")))?;

    Ok(Arc::new(signer))
}

/// Decode a TSIG key from base64 or return raw bytes.
///
/// Strips whitespace/newlines before decoding. If the data looks like
/// valid base64, decode it; otherwise use as-is (already binary).
fn decode_tsig_key(raw: &[u8]) -> Result<Vec<u8>> {
    let trimmed: Vec<u8> = raw.iter().copied().filter(|b| !b.is_ascii_whitespace()).collect();

    // Try standard base64 first, then URL-safe
    if let Ok(decoded) = base64::engine::general_purpose::STANDARD.decode(&trimmed)
        && !decoded.is_empty() {
            return Ok(decoded);
        }

    // If it doesn't decode as base64, assume it's already raw binary
    Ok(raw.to_vec())
}
