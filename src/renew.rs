use std::collections::HashMap;
use std::path::Path;

use instant_acme::ChallengeType;

use crate::acme::AcmeClient;
use crate::certs::CertInfo;
use crate::config::{CertificateConfig, Config, DaneSelector, SolverConfig};
use crate::credentials;
use crate::dane;
use crate::dns::tsig;
use crate::dns::update::DnsUpdater;
use crate::error::{Error, Result};
use crate::hooks;
use crate::keys::CertKeyPair;
use crate::solver::dns01::Dns01Solver;
use crate::solver::http01::{Http01StandaloneSolver, Http01WebrootSolver};
use crate::solver::tls_alpn01::TlsAlpn01Solver;
use crate::solver::Solver;
use crate::state::{PendingRotation, State};

/// Build solver instances from config, deduplicating by solver name.
fn build_solvers(config: &Config, solver_names: &[&str]) -> Result<HashMap<String, Box<dyn Solver>>> {
    let mut solvers: HashMap<String, Box<dyn Solver>> = HashMap::new();

    for &name in solver_names {
        if solvers.contains_key(name) {
            continue;
        }
        let solver_config = config.solver_config(name)?;
        let solver: Box<dyn Solver> = match solver_config {
            SolverConfig::Dns01 { dns } => {
                let dns_config = config.dns_client(dns)?;
                Box::new(Dns01Solver::new(dns_config.clone()))
            }
            SolverConfig::Http01 { listen, webroot } => {
                if let Some(webroot) = webroot {
                    Box::new(Http01WebrootSolver::new(webroot.clone()))
                } else if let Some(listen) = listen {
                    Box::new(Http01StandaloneSolver::new(*listen))
                } else {
                    return Err(Error::Config(format!(
                        "solver '{name}': HTTP-01 requires either listen or webroot"
                    )));
                }
            }
            SolverConfig::TlsAlpn01 { listen } => {
                Box::new(TlsAlpn01Solver::new(*listen))
            }
        };
        solvers.insert(name.to_string(), solver);
    }

    Ok(solvers)
}

/// Map a solver config to its ACME challenge type.
fn solver_challenge_type(config: &Config, solver_name: &str) -> Result<ChallengeType> {
    match config.solver_config(solver_name)? {
        SolverConfig::Dns01 { .. } => Ok(ChallengeType::Dns01),
        SolverConfig::Http01 { .. } => Ok(ChallengeType::Http01),
        SolverConfig::TlsAlpn01 { .. } => Ok(ChallengeType::TlsAlpn01),
    }
}

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
        if let Some(filter) = name_filter
            && cert_config.name != filter {
                continue;
            }

        match renew_certificate(config, &acme, cert_config, &mut state, state_dir, force, dry_run)
            .await
        {
            Ok(renewed) => {
                if renewed {
                    tracing::info!(name = %cert_config.name, "certificate renewed successfully");
                    state_dirty = true;
                }
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
    // Check pending key rotation
    if let Some(pending) = state.pending_rotations.get(&cert_config.name) {
        if pending.ttl_expired() {
            tracing::info!(name = %cert_config.name, "pending key rotation TTL expired, completing renewal");
        } else {
            tracing::info!(name = %cert_config.name, "pending key rotation, waiting for TTL expiry");
            return Ok(false);
        }
    }

    // Check if existing certificate needs renewal
    if !force
        && let Ok(cert) = CertInfo::load(&cert_config.cert_path) {
            let days = cert.days_until_expiry();
            if !cert.expires_within_days(cert_config.renew_before_days) {
                tracing::info!(name = %cert_config.name, days_remaining = days, "certificate does not need renewal");
                return Ok(false);
            }
            tracing::info!(name = %cert_config.name, days_remaining = days, "certificate expiring soon, renewing");
        }

    // Resolve solver names for each domain
    let solver_names: Vec<&str> = cert_config
        .domains
        .iter()
        .enumerate()
        .map(|(i, domain)| {
            cert_config
                .solver_for_domain(i, config.default_solver.as_deref())
                .ok_or_else(|| {
                    Error::Config(format!(
                        "certificate {}: no solver configured for domain '{domain}'",
                        cert_config.name
                    ))
                })
        })
        .collect::<Result<Vec<_>>>()?;

    // Build solver instances
    let solvers = build_solvers(config, &solver_names)?;

    // Determine key pair
    let key = determine_key(config, cert_config, state, state_dir, dry_run).await?;
    let key = match key {
        Some(k) => k,
        None => return Ok(false), // Pre-publication deferred
    };

    if dry_run {
        tracing::info!(name = %cert_config.name, "dry-run: would issue certificate");
        return Ok(true);
    }

    // Generate CSR
    tracing::debug!(name = %cert_config.name, domains = ?cert_config.domains, key_type = ?cert_config.key_type, "generating CSR");
    let pkcs8_der = rustls_pki_types::PrivatePkcs8KeyDer::from(key.pkcs8_der.as_slice());
    let rcgen_alg = match cert_config.key_type {
        crate::config::KeyType::EcdsaP256 => &rcgen::PKCS_ECDSA_P256_SHA256,
        crate::config::KeyType::EcdsaP384 => &rcgen::PKCS_ECDSA_P384_SHA384,
        _ => return Err(Error::Key("unsupported key type for CSR generation".into())),
    };
    let rcgen_kp = rcgen::KeyPair::from_pkcs8_der_and_sign_algo(&pkcs8_der, rcgen_alg)
        .map_err(|e| Error::Key(format!("failed to load key for CSR: {e}")))?;
    let mut params = rcgen::CertificateParams::new(cert_config.domains.clone())
        .map_err(|e| Error::Certificate(format!("invalid CSR params: {e}")))?;
    params.distinguished_name = rcgen::DistinguishedName::new();
    let csr = params
        .serialize_request(&rcgen_kp)
        .map_err(|e| Error::Certificate(format!("failed to generate CSR: {e}")))?;

    // Build desired challenge types per identifier
    let desired_types: Vec<(String, ChallengeType)> = cert_config
        .domains
        .iter()
        .zip(solver_names.iter())
        .map(|(domain, &solver_name)| {
            Ok((domain.clone(), solver_challenge_type(config, solver_name)?))
        })
        .collect::<Result<Vec<_>>>()?;

    // Create ACME order
    tracing::debug!(name = %cert_config.name, domains = ?cert_config.domains, "creating ACME order");
    let mut order = acme.create_order(&cert_config.domains, cert_config.profile.as_deref()).await?;

    // Collect challenges
    let challenges = AcmeClient::collect_challenges(&mut order, &desired_types).await?;

    // Present all challenges
    for (challenge, &solver_name) in challenges.iter().zip(solver_names.iter()) {
        let solver = &solvers[solver_name];
        solver.present(challenge).await?;
    }

    // Run ACME flow, ensuring cleanup happens even on failure
    let order_result = async {
        // Wait for DNS propagation if any solver needs it
        if solvers.values().any(|s| s.needs_propagation_delay()) {
            tracing::debug!("waiting 5s for DNS propagation");
            tokio::time::sleep(std::time::Duration::from_secs(5)).await;
        }

        tracing::debug!(name = %cert_config.name, "setting challenges ready");
        AcmeClient::set_challenges_ready(&mut order, &desired_types).await?;

        tracing::debug!(name = %cert_config.name, "finalizing order");
        AcmeClient::finalize_order(&mut order, csr.der()).await?;

        tracing::debug!(name = %cert_config.name, "downloading certificate");
        AcmeClient::download_certificate(&mut order).await
    }
    .await;

    // Always clean up challenges
    for (challenge, &solver_name) in challenges.iter().zip(solver_names.iter()) {
        let solver = &solvers[solver_name];
        if let Err(e) = solver.cleanup(challenge).await {
            tracing::warn!(identifier = %challenge.identifier, error = %e, "failed to clean up challenge");
        }
    }

    let cert_pem = order_result?;

    // Save certificate
    if let Some(parent) = cert_config.cert_path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    std::fs::write(&cert_config.cert_path, &cert_pem)?;
    tracing::info!(path = %cert_config.cert_path.display(), "saved certificate");

    save_key(&key, cert_config).await?;

    // Publish DANE TLSA records
    if !cert_config.dane.is_empty() {
        let cert_info = CertInfo::from_pem(&cert_pem)?;
        for dane_config in &cert_config.dane {
            let records = dane::compute_tlsa_records(&cert_info, dane_config)?;
            let dns_config = config.dns_client(&dane_config.dns)?;
            let signer = tsig::load_tsig_signer(dns_config).await?;
            let mut updater = DnsUpdater::connect(dns_config, signer).await?;
            dane::publish_tlsa(&mut updater, dns_config, dane_config, &records).await?;
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

/// Determine the key pair for a certificate, handling key rotation and pre-publication.
/// Returns None if renewal is deferred due to DANE pre-publication.
async fn determine_key(
    config: &Config,
    cert_config: &CertificateConfig,
    state: &mut State,
    state_dir: &Path,
    dry_run: bool,
) -> Result<Option<CertKeyPair>> {
    if let Some(pending) = state.pending_rotations.remove(&cert_config.name) {
        let key_data = std::fs::read(&pending.pending_key_path)
            .map_err(|e| Error::Key(format!("failed to read pending key: {e}")))?;
        return Ok(Some(CertKeyPair::from_pem_or_der(&key_data, &cert_config.key_type)?));
    }

    if cert_config.rotate_key {
        let needs_pre_publish = cert_config
            .dane
            .iter()
            .any(|d| d.pre_publish && d.selector == DaneSelector::Spki);

        let new_key = CertKeyPair::generate(&cert_config.key_type)?;

        if needs_pre_publish {
            tracing::info!(name = %cert_config.name, "pre-publishing TLSA for key rotation");

            if !dry_run {
                let pending_dir = state_dir.join("pending");
                std::fs::create_dir_all(&pending_dir)?;
                let pending_key_path = pending_dir.join(format!("{}.key", cert_config.name));
                std::fs::write(&pending_key_path, new_key.to_pem())?;

                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    std::fs::set_permissions(&pending_key_path, std::fs::Permissions::from_mode(0o600))?;
                }

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

            tracing::info!(name = %cert_config.name, "TLSA pre-published, renewal deferred to next run");
            return Ok(None);
        }

        return Ok(Some(new_key));
    }

    // Load existing key or generate if first time
    match CertKeyPair::load(
        cert_config.key_credential.as_deref(),
        cert_config.key_path.as_deref(),
        &cert_config.key_type,
    )
    .await
    {
        Ok(key) => Ok(Some(key)),
        Err(_) => {
            tracing::info!(name = %cert_config.name, "generating new key pair");
            Ok(Some(CertKeyPair::generate(&cert_config.key_type)?))
        }
    }
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

        let dns_config = config.dns_client(&dane_config.dns)?;
        let signer = tsig::load_tsig_signer(dns_config).await?;
        let mut updater = DnsUpdater::connect(dns_config, signer).await?;

        dane::add_tlsa(&mut updater, dns_config, dane_config, record).await?;
    }

    Ok(max_ttl)
}
