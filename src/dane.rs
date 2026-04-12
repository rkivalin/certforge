use hickory_proto::rr::Name;

use crate::certs::CertInfo;
use crate::config::DaneConfig;
use crate::dns::tlsa::TlsaRecord;
use crate::dns::update::DnsUpdater;
use crate::error::{Error, Result};
use crate::keys::CertKeyPair;

/// Compute all TLSA records needed for a certificate's DANE config.
pub fn compute_tlsa_records(
    cert: &CertInfo,
    dane: &DaneConfig,
) -> Result<Vec<TlsaRecord>> {
    let mut records = Vec::new();

    let record = TlsaRecord::from_certificate(
        &cert.leaf_der,
        &cert.spki_der,
        &dane.usage,
        &dane.selector,
        &dane.matching,
    )?;

    // Same TLSA rdata for all names in this block
    for _ in &dane.names {
        records.push(record.clone());
    }

    Ok(records)
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
pub async fn publish_tlsa(
    updater: &mut DnsUpdater,
    dane: &DaneConfig,
    records: &[TlsaRecord],
) -> Result<()> {
    // All names in a DANE block share the same TLSA rdata
    let record = &records[0];

    for name_str in &dane.names {
        let name = Name::from_ascii(name_str)
            .map_err(|e| Error::DnsUpdate(format!("invalid TLSA name {name_str}: {e}")))?;

        let zone = find_zone(&name)?;

        updater
            .replace_tlsa_records(&zone, &name, &[record.clone()], dane.ttl)
            .await?;
    }

    Ok(())
}

/// Add TLSA records alongside existing ones (for pre-publication).
pub async fn add_tlsa(
    updater: &mut DnsUpdater,
    dane: &DaneConfig,
    record: &TlsaRecord,
) -> Result<()> {
    for name_str in &dane.names {
        let name = Name::from_ascii(name_str)
            .map_err(|e| Error::DnsUpdate(format!("invalid TLSA name {name_str}: {e}")))?;

        let zone = find_zone(&name)?;

        updater
            .add_tlsa_record(&zone, &name, record, dane.ttl)
            .await?;
    }

    Ok(())
}

/// Extract the zone (parent domain) from a TLSA name like _25._tcp.mx1.example.com.
///
/// Strategy: strip the _port._proto prefix, then take the last two labels as zone.
/// This is a heuristic; a proper implementation would query for SOA.
fn find_zone(name: &Name) -> Result<Name> {
    // TLSA names are like _25._tcp.host.example.com.
    // We need the zone, which is typically example.com.
    // Strip underscore-prefixed labels, then take parent as zone.
    let labels: Vec<&[u8]> = name.iter().collect();

    // Find the first non-underscore label
    let mut start = 0;
    for (i, label) in labels.iter().enumerate() {
        if !label.starts_with(b"_") {
            start = i;
            break;
        }
    }

    // The zone is everything after the hostname
    // e.g., for _25._tcp.mx1.example.com, start=2 (mx1), zone = example.com
    if labels.len() > start + 1 {
        // Take from start+1 onwards as zone
        let zone_labels = &labels[start + 1..];
        let zone_str = zone_labels
            .iter()
            .map(|l| String::from_utf8_lossy(l).to_string())
            .collect::<Vec<_>>()
            .join(".");

        Name::from_ascii(&zone_str)
            .map_err(|e| Error::DnsUpdate(format!("invalid zone name: {e}")))
    } else {
        Err(Error::DnsUpdate(format!(
            "cannot determine zone from TLSA name: {name}"
        )))
    }
}
