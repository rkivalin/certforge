use std::sync::Arc;

use base64::Engine;
use hickory_proto::dnssec::tsig::TSigner;
use hickory_proto::dnssec::rdata::tsig::TsigAlgorithm;
use hickory_proto::op::{Message, MessageFinalizer, MessageVerifier};
use hickory_proto::rr::{Name, Record};
use hickory_proto::ProtoError;

use crate::config;
use crate::credentials;
use crate::error::{Error, Result};

/// Wrapper around TSigner that signs all messages, not just updates.
///
/// The default TSigner only signs Update/Notify/AXFR/IXFR messages. This wrapper
/// overrides `should_finalize_message` to always return true, so regular queries
/// are also TSIG-signed. This is needed when the DNS server uses TSIG keys for
/// view selection.
struct AlwaysSignTsig(TSigner);

impl MessageFinalizer for AlwaysSignTsig {
    fn finalize_message(
        &self,
        message: &Message,
        current_time: u32,
    ) -> std::result::Result<(Vec<Record>, Option<MessageVerifier>), ProtoError> {
        self.0.finalize_message(message, current_time)
    }

    fn should_finalize_message(&self, _message: &Message) -> bool {
        true
    }
}

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
        config::TsigAlgorithm::HmacSha384 => TsigAlgorithm::HmacSha384,
        config::TsigAlgorithm::HmacSha512 => TsigAlgorithm::HmacSha512,
    };

    let signer_name = Name::from_ascii(&dns_config.tsig_key_name)
        .map_err(|e| Error::DnsUpdate(format!("invalid TSIG key name: {e}")))?;

    // Default TSIG fudge is 300 seconds (5 minutes)
    let signer = TSigner::new(key_data, algorithm, signer_name, 300)
        .map_err(|e| Error::DnsUpdate(format!("failed to create TSIG signer: {e}")))?;

    Ok(Arc::new(AlwaysSignTsig(signer)))
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
