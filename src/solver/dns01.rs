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
}

#[async_trait::async_trait]
impl super::Solver for Dns01Solver {
    async fn present(&self, challenge: &ChallengeInfo) -> Result<()> {
        let txt_name = format!("_acme-challenge.{}", challenge.identifier);
        tracing::debug!(
            identifier = %challenge.identifier,
            zone = %self.dns_config.zone,
            server = %self.dns_config.server,
            %txt_name,
            "publishing DNS-01 challenge TXT record"
        );

        let signer = tsig::load_tsig_signer(&self.dns_config).await?;
        let mut updater = DnsUpdater::connect(&self.dns_config, signer).await?;

        let name = Name::from_ascii(&txt_name)
            .map_err(|e| Error::DnsUpdate(format!("invalid TXT name: {e}")))?;
        let zone = Name::from_ascii(&self.dns_config.zone)
            .map_err(|e| Error::DnsUpdate(format!("invalid zone: {e}")))?;

        updater.add_txt_record(&zone, &name, &challenge.dns_value, 60).await
    }

    async fn cleanup(&self, challenge: &ChallengeInfo) -> Result<()> {
        let txt_name = format!("_acme-challenge.{}", challenge.identifier);
        tracing::debug!(
            identifier = %challenge.identifier,
            %txt_name,
            "cleaning up DNS-01 challenge TXT record"
        );

        let signer = tsig::load_tsig_signer(&self.dns_config).await?;
        let mut updater = DnsUpdater::connect(&self.dns_config, signer).await?;

        let name = Name::from_ascii(&txt_name)
            .map_err(|e| Error::DnsUpdate(format!("invalid TXT name: {e}")))?;
        let zone = Name::from_ascii(&self.dns_config.zone)
            .map_err(|e| Error::DnsUpdate(format!("invalid zone: {e}")))?;

        updater.delete_txt_record(&zone, &name, &challenge.dns_value).await
    }

    fn needs_propagation_delay(&self) -> bool {
        true
    }
}
