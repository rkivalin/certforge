use hickory_proto::rr::Name;

use crate::certs::CertInfo;
use crate::config::{DaneConfig, DnsClientConfig};
use crate::dns::tlsa::TlsaRecord;
use crate::dns::update::DnsUpdater;
use crate::error::{Error, Result};
use crate::keys::CertKeyPair;

/// Compute all TLSA records needed for a certificate's DANE config.
pub fn compute_tlsa_records(
    cert: &CertInfo,
    dane: &DaneConfig,
) -> Result<Vec<TlsaRecord>> {
    let record = TlsaRecord::from_certificate(
        &cert.leaf_der,
        &cert.spki_der,
        &dane.usage,
        &dane.selector,
        &dane.matching,
    )?;

    Ok(vec![record; dane.names.len()])
}

/// Compute TLSA records from a key pair (for pre-publication before cert issuance).
/// Only valid with SPKI selector.
pub fn compute_tlsa_from_key(
    key: &CertKeyPair,
    dane: &DaneConfig,
) -> Result<Vec<TlsaRecord>> {
    use crate::config::DaneSelector;

    if dane.selector != DaneSelector::Spki {
        return Err(Error::Certificate(
            "DANE pre-publication requires SPKI selector".into(),
        ));
    }

    let spki = key.spki_der()?;
    let record = TlsaRecord::from_spki(&spki, &dane.usage, &dane.matching)?;

    Ok(vec![record; dane.names.len()])
}

/// Publish TLSA records for a certificate via DNS updates.
/// Zone is taken from the DnsClientConfig.
pub async fn publish_tlsa(
    updater: &mut DnsUpdater,
    dns_config: &DnsClientConfig,
    dane: &DaneConfig,
    records: &[TlsaRecord],
) -> Result<()> {
    let record = &records[0];
    let zone = Name::from_ascii(&dns_config.zone)
        .map_err(|e| Error::DnsUpdate(format!("invalid zone '{}': {e}", dns_config.zone)))?;

    for name_str in &dane.names {
        let name = Name::from_ascii(name_str)
            .map_err(|e| Error::DnsUpdate(format!("invalid TLSA name {name_str}: {e}")))?;

        updater
            .replace_tlsa_records(&zone, &name, std::slice::from_ref(record), dane.ttl)
            .await?;
    }

    Ok(())
}

/// Add TLSA records alongside existing ones (for pre-publication).
pub async fn add_tlsa(
    updater: &mut DnsUpdater,
    dns_config: &DnsClientConfig,
    dane: &DaneConfig,
    record: &TlsaRecord,
) -> Result<()> {
    let zone = Name::from_ascii(&dns_config.zone)
        .map_err(|e| Error::DnsUpdate(format!("invalid zone '{}': {e}", dns_config.zone)))?;

    for name_str in &dane.names {
        let name = Name::from_ascii(name_str)
            .map_err(|e| Error::DnsUpdate(format!("invalid TLSA name {name_str}: {e}")))?;

        updater
            .add_tlsa_record(&zone, &name, record, dane.ttl)
            .await?;
    }

    Ok(())
}
