use std::path::Path;

use hickory_proto::rr::Name;

use crate::acme::{AcmeClient, DnsChallenge};
use crate::certs::CertInfo;
use crate::config::{CertificateConfig, Config, DaneSelector};
use crate::credentials;
use crate::dane;
use crate::dns::tsig;
use crate::dns::update::DnsUpdater;
use crate::error::{Error, Result};
use crate::hooks;
use crate::keys::CertKeyPair;
use crate::state::{PendingRotation, State};

/// Run the renewal process for all certificates (or a specific one).
pub async fn run(
    config: &Config,
    state_dir: &Path,
    name_filter: Option<&str>,
    force: bool,
    dry_run: bool,
) -> Result<()> {
    let mut state = State::load(state_dir)?;
    let mut state_dirty = false;

    let acme = AcmeClient::new(&config.acme).await?;

    for cert_config in &config.certificates {
        if let Some(filter) = name_filter {
            if cert_config.name != filter {
                continue;
            }
        }

        match renew_certificate(config, &acme, cert_config, &mut state, state_dir, force, dry_run)
            .await
        {
            Ok(renewed) => {
                if renewed {
                    tracing::info!(name = %cert_config.name, "certificate renewed successfully");
                    state_dirty = true;
                }
                // "does not need renewal" is logged inside renew_certificate with days_remaining
            }
            Err(e) => {
                tracing::error!(name = %cert_config.name, error = %e, "certificate renewal failed");
            }
        }
    }

    if state_dirty {
        state.save(state_dir)?;
    }
    Ok(())
}

async fn renew_certificate(
    config: &Config,
    acme: &AcmeClient,
    cert_config: &CertificateConfig,
    state: &mut State,
    state_dir: &Path,
    force: bool,
    dry_run: bool,
) -> Result<bool> {
    // Check if there's a pending key rotation to complete
    if let Some(pending) = state.pending_rotations.get(&cert_config.name) {
        if pending.ttl_expired() {
            tracing::info!(
                name = %cert_config.name,
                "pending key rotation TTL expired, completing renewal"
            );
            // Continue with renewal using the pending key
        } else {
            tracing::info!(
                name = %cert_config.name,
                "pending key rotation, waiting for TTL expiry"
            );
            return Ok(false);
        }
    }

    // Check if existing certificate needs renewal
    if !force {
        if let Ok(cert) = CertInfo::load(&cert_config.cert_path) {
            let days = cert.days_until_expiry();
            if !cert.expires_within_days(cert_config.renew_before_days) {
                tracing::info!(
                    name = %cert_config.name,
                    days_remaining = days,
                    "certificate does not need renewal"
                );
                return Ok(false);
            }
            tracing::info!(
                name = %cert_config.name,
                days_remaining = days,
                "certificate expiring soon, renewing"
            );
        }
        // If cert doesn't exist or can't be parsed, proceed with issuance
    }

    // Determine key pair
    let key = if let Some(pending) = state.pending_rotations.remove(&cert_config.name) {
        // Use the pending key from pre-publication
        let key_data = std::fs::read(&pending.pending_key_path)
            .map_err(|e| Error::Key(format!("failed to read pending key: {e}")))?;
        CertKeyPair::from_pem_or_der(&key_data, &cert_config.key_type)?
    } else if cert_config.rotate_key {
        // Check if DANE pre-publication is needed
        let needs_pre_publish = cert_config
            .dane
            .iter()
            .any(|d| d.pre_publish && d.selector == DaneSelector::Spki);

        let new_key = CertKeyPair::generate(&cert_config.key_type)?;

        if needs_pre_publish {
            // Pre-publish TLSA with new key, defer renewal
            tracing::info!(name = %cert_config.name, "pre-publishing TLSA for key rotation");

            if !dry_run {
                // Save pending key
                let pending_dir = state_dir.join("pending");
                std::fs::create_dir_all(&pending_dir)?;
                let pending_key_path = pending_dir.join(format!("{}.key", cert_config.name));
                std::fs::write(&pending_key_path, new_key.to_pem())?;

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(
                        &pending_key_path,
                        std::fs::Permissions::from_mode(0o600),
                    )?;
                }

                // Publish new TLSA alongside old
                let max_ttl = pre_publish_dane(config, cert_config, &new_key, dry_run).await?;

                state.pending_rotations.insert(
                    cert_config.name.clone(),
                    PendingRotation {
                        pending_key_path,
                        published_at: chrono::Utc::now(),
                        old_ttl: max_ttl,
                    },
                );
                state.save(state_dir)?;
            }

            tracing::info!(
                name = %cert_config.name,
                "TLSA pre-published, renewal deferred to next run"
            );
            return Ok(false);
        }

        new_key
    } else {
        // Load existing key or generate if first time
        match CertKeyPair::load(
            cert_config.key_credential.as_deref(),
            cert_config.key_path.as_deref(),
            &cert_config.key_type,
        )
        .await
        {
            Ok(key) => key,
            Err(_) => {
                tracing::info!(name = %cert_config.name, "generating new key pair");
                CertKeyPair::generate(&cert_config.key_type)?
            }
        }
    };

    if dry_run {
        tracing::info!(name = %cert_config.name, "dry-run: would issue certificate");
        return Ok(true);
    }

    // Generate CSR
    tracing::debug!(
        name = %cert_config.name,
        domains = ?cert_config.domains,
        key_type = ?cert_config.key_type,
        "generating CSR"
    );
    let pkcs8_der = rustls_pki_types::PrivatePkcs8KeyDer::from(key.pkcs8_der.as_slice());
    let rcgen_alg = match cert_config.key_type {
        crate::config::KeyType::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        crate::config::KeyType::EcdsaP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
        _ => return Err(Error::Key("unsupported key type for CSR generation".into())),
    };
    let rcgen_kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_der, rcgen_alg)
        .map_err(|e| Error::Key(format!("failed to load key for CSR: {e}")))?;

    let mut params =
        rcgen::CertificateParams::new(cert_config.domains.clone())
            .map_err(|e| Error::Certificate(format!("invalid CSR params: {e}")))?;
    // Clear the default distinguished name - ACME uses SANs only,
    // and the default CN "rcgen self signed cert" causes rejection.
    params.distinguished_name = rcgen::DistinguishedName::new();

    let csr = params
        .serialize_request(&rcgen_kp)
        .map_err(|e| Error::Certificate(format!("failed to generate CSR: {e}")))?;

    // ACME order
    tracing::debug!(name = %cert_config.name, domains = ?cert_config.domains, "creating ACME order");
    let (mut order, _) = acme.create_order(&cert_config.domains).await?;

    // Collect DNS-01 challenge info
    let challenges = AcmeClient::collect_challenges(&mut order).await?;

    // Publish DNS-01 challenge TXT records
    for challenge in &challenges {
        tracing::debug!(
            domain = %challenge.domain,
            txt_name = %challenge.txt_name,
            txt_value = %challenge.txt_value,
            "publishing DNS-01 challenge TXT record"
        );
        publish_challenge_txt(config, challenge).await?;
    }

    // Run the ACME order flow, ensuring TXT cleanup happens even on failure
    let order_result = async {
        // Tell ACME server challenges are ready
        tracing::debug!(name = %cert_config.name, "setting challenges ready");
        AcmeClient::set_challenges_ready(&mut order).await?;

        // Finalize and download
        tracing::debug!(name = %cert_config.name, "finalizing order");
        AcmeClient::finalize_order(&mut order, csr.der()).await?;
        tracing::debug!(name = %cert_config.name, "downloading certificate");
        AcmeClient::download_certificate(&mut order).await
    }
    .await;

    // Always clean up challenge TXT records
    for challenge in &challenges {
        if let Err(e) = cleanup_challenge_txt(config, challenge).await {
            tracing::warn!(
                domain = %challenge.domain,
                error = %e,
                "failed to clean up challenge TXT record"
            );
        }
    }

    let cert_pem = order_result?;

    // Save certificate
    if let Some(parent) = cert_config.cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&cert_config.cert_path, &cert_pem)?;
    tracing::info!(path = %cert_config.cert_path.display(), "saved certificate");

    // Save key
    save_key(&key, cert_config).await?;

    // Publish DANE TLSA records
    if !cert_config.dane.is_empty() {
        let cert_info = CertInfo::from_pem(&cert_pem)?;
        for dane_config in &cert_config.dane {
            let records = dane::compute_tlsa_records(&cert_info, dane_config)?;

            let dns_config = config.dns.resolve_for_zone(&extract_zone_from_tlsa_name(
                dane_config.names.first().unwrap(),
            ));
            let signer = tsig::load_tsig_signer(&dns_config).await?;
            let mut updater = DnsUpdater::connect(&dns_config, signer).await?;

            dane::publish_tlsa(&mut updater, dane_config, &records).await?;
        }
    }

    // Run hooks
    let hook_results = hooks::run_hooks(&cert_config.hooks, false).await;
    for result in &hook_results {
        if let Err(e) = result {
            tracing::warn!(error = %e, "hook failed (non-fatal)");
        }
    }

    Ok(true)
}

async fn save_key(key: &CertKeyPair, cert_config: &CertificateConfig) -> Result<()> {
    let pem = key.to_pem();

    if let Some(cred_path) = &cert_config.key_credential {
        let cred_name = format!("{}-tls-key", cert_config.name);
        credentials::encrypt_credential(&cred_name, pem.as_bytes(), cred_path).await?;
        tracing::info!(path = %cred_path.display(), "saved private key (encrypted)");
    } else if let Some(key_path) = &cert_config.key_path {
        if let Some(parent) = key_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(key_path, &pem)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(key_path, std::fs::Permissions::from_mode(0o600))?;
        }
        tracing::info!(path = %key_path.display(), "saved private key");
    }

    Ok(())
}

async fn publish_challenge_txt(config: &Config, challenge: &DnsChallenge) -> Result<()> {
    let zone_str = extract_zone_from_domain(&challenge.domain);
    let dns_config = config.dns.resolve_for_zone(&zone_str);
    tracing::debug!(
        domain = %challenge.domain,
        zone = %zone_str,
        server = %dns_config.server,
        txt_name = %challenge.txt_name,
        "publishing challenge TXT via RFC 2136"
    );
    let signer = tsig::load_tsig_signer(&dns_config).await?;
    let mut updater = DnsUpdater::connect(&dns_config, signer).await?;

    let name = Name::from_ascii(&challenge.txt_name)
        .map_err(|e| Error::DnsUpdate(format!("invalid TXT name: {e}")))?;
    let zone = Name::from_ascii(&zone_str)
        .map_err(|e| Error::DnsUpdate(format!("invalid zone: {e}")))?;

    updater.add_txt_record(&zone, &name, &challenge.txt_value, 60).await
}

async fn cleanup_challenge_txt(config: &Config, challenge: &DnsChallenge) -> Result<()> {
    let zone_str = extract_zone_from_domain(&challenge.domain);
    let dns_config = config.dns.resolve_for_zone(&zone_str);
    let signer = tsig::load_tsig_signer(&dns_config).await?;
    let mut updater = DnsUpdater::connect(&dns_config, signer).await?;

    let name = Name::from_ascii(&challenge.txt_name)
        .map_err(|e| Error::DnsUpdate(format!("invalid TXT name: {e}")))?;
    let zone = Name::from_ascii(&zone_str)
        .map_err(|e| Error::DnsUpdate(format!("invalid zone: {e}")))?;

    updater.delete_txt_record(&zone, &name, &challenge.txt_value).await
}

async fn pre_publish_dane(
    config: &Config,
    cert_config: &CertificateConfig,
    new_key: &CertKeyPair,
    dry_run: bool,
) -> Result<u32> {
    let mut max_ttl = 0;

    for dane_config in &cert_config.dane {
        if !dane_config.pre_publish || dane_config.selector != DaneSelector::Spki {
            continue;
        }

        max_ttl = max_ttl.max(dane_config.ttl);

        if dry_run {
            tracing::info!("dry-run: would pre-publish TLSA for {:?}", dane_config.names);
            continue;
        }

        let records = dane::compute_tlsa_from_key(new_key, dane_config)?;
        let record = &records[0];

        let dns_config = config.dns.resolve_for_zone(&extract_zone_from_tlsa_name(
            dane_config.names.first().unwrap(),
        ));
        let signer = tsig::load_tsig_signer(&dns_config).await?;
        let mut updater = DnsUpdater::connect(&dns_config, signer).await?;

        dane::add_tlsa(&mut updater, dane_config, record).await?;
    }

    Ok(max_ttl)
}

/// Extract zone from a domain (heuristic: last two labels).
fn extract_zone_from_domain(domain: &str) -> String {
    let parts: Vec<&str> = domain.split('.').collect();
    if parts.len() >= 2 {
        parts[parts.len() - 2..].join(".")
    } else {
        domain.to_string()
    }
}

/// Extract zone from a TLSA name like _25._tcp.mx1.example.com.
fn extract_zone_from_tlsa_name(name: &str) -> String {
    let parts: Vec<&str> = name.split('.').collect();
    // Skip underscore-prefixed parts, then skip hostname, take zone
    let non_underscore: Vec<&&str> = parts.iter().filter(|p| !p.starts_with('_')).collect();
    if non_underscore.len() >= 2 {
        non_underscore[non_underscore.len() - 2..].iter().map(|s| **s).collect::<Vec<&str>>().join(".")
    } else {
        name.to_string()
    }
}
