use hickory_proto::rr::Name;

use crate::acme::ChallengeInfo;
use crate::config::DnsClientConfig;
use crate::dns::tsig;
use crate::dns::update::DnsUpdater;
use crate::error::{Error, Result};

/// DNS-01 challenge solver using RFC 2136 dynamic updates.
pub struct Dns01Solver {
    dns_config: DnsClientConfig,
}

impl Dns01Solver {
    pub fn new(dns_config: DnsClientConfig) -> Self {
        Self { dns_config }
    }

    /// Strip wildcard prefix for DNS-01 challenge name.
    /// Per RFC 8555 §8.4, the challenge for *.example.com uses _acme-challenge.example.com.
    fn base_domain(identifier: &str) -> &str {
        identifier.strip_prefix("*.").unwrap_or(identifier)
    }

    fn resolve_zone(&self, txt_name: &str) -> Result<String> {
        self.dns_config
            .find_zone(txt_name)
            .map(|z| z.to_string())
            .ok_or_else(|| {
                Error::DnsUpdate(format!(
                    "no matching zone for '{txt_name}' in zones {:?}",
                    self.dns_config.all_zones()
                ))
            })
    }
}

#[async_trait::async_trait]
impl super::Solver for Dns01Solver {
    async fn present(&self, challenge: &ChallengeInfo) -> Result<()> {
        let txt_name = format!("_acme-challenge.{}", Self::base_domain(&challenge.identifier));
        let zone_str = self.resolve_zone(&txt_name)?;

        tracing::debug!(
            identifier = %challenge.identifier,
            zone = %zone_str,
            server = %self.dns_config.server,
            %txt_name,
            "publishing DNS-01 challenge TXT record"
        );

        let signer = tsig::load_tsig_signer(&self.dns_config).await?;
        let mut updater = DnsUpdater::connect(&self.dns_config, signer).await?;

        let name = Name::from_ascii(&txt_name)
            .map_err(|e| Error::DnsUpdate(format!("invalid TXT name: {e}")))?;
        let zone = Name::from_ascii(&zone_str)
            .map_err(|e| Error::DnsUpdate(format!("invalid zone: {e}")))?;

        updater.add_txt_record(&zone, &name, &challenge.dns_value, 60).await
    }

    async fn cleanup(&self, challenge: &ChallengeInfo) -> Result<()> {
        let txt_name = format!("_acme-challenge.{}", Self::base_domain(&challenge.identifier));
        let zone_str = self.resolve_zone(&txt_name)?;

        tracing::debug!(
            identifier = %challenge.identifier,
            %txt_name,
            "cleaning up DNS-01 challenge TXT record"
        );

        let signer = tsig::load_tsig_signer(&self.dns_config).await?;
        let mut updater = DnsUpdater::connect(&self.dns_config, signer).await?;

        let name = Name::from_ascii(&txt_name)
            .map_err(|e| Error::DnsUpdate(format!("invalid TXT name: {e}")))?;
        let zone = Name::from_ascii(&zone_str)
            .map_err(|e| Error::DnsUpdate(format!("invalid zone: {e}")))?;

        updater.delete_txt_record(&zone, &name, &challenge.dns_value).await
    }

    fn needs_propagation_delay(&self) -> bool {
        true
    }
}
