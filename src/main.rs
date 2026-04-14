mod acme;
mod certs;
mod cli;
mod config;
mod credentials;
mod dane;
mod dns;
mod error;
mod hooks;
mod keys;
mod renew;
mod solver;
mod state;

use clap::Parser;
use tracing_subscriber::EnvFilter;

use cli::{AccountAction, Cli, Command};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    let filter = match cli.verbose {
        0 => "certforge=info",
        1 => "certforge=debug",
        2 => "certforge=trace",
        _ => "trace",
    };
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(filter)),
        )
        .init();

    match cli.command {
        Command::Renew { name, force } => {
            let config = config::Config::load(&cli.config)?;
            renew::run(&config, &cli.state_dir, name.as_deref(), force, cli.dry_run).await?;
        }

        Command::Status { name } => {
            let config = config::Config::load(&cli.config)?;
            print_status(&config, name.as_deref());
        }

        Command::Issue { name } => {
            let config = config::Config::load(&cli.config)?;
            renew::run(&config, &cli.state_dir, Some(&name), true, cli.dry_run).await?;
        }

        Command::DanePublish { name } => {
            let config = config::Config::load(&cli.config)?;
            dane_publish(&config, name.as_deref(), cli.dry_run).await?;
        }

        Command::DaneCheck { name } => {
            let config = config::Config::load(&cli.config)?;
            dane_check(&config, name.as_deref()).await?;
        }

        Command::ConfigCheck => {
            let config = config::Config::load(&cli.config)?;
            println!(
                "Configuration is valid. {} certificate(s) configured.",
                config.certificates.len()
            );
            for cert in &config.certificates {
                println!(
                    "  - {}: {} domain(s), {} DANE block(s), {} hook(s) ({} named, {} inline)",
                    cert.name,
                    cert.domains.len(),
                    cert.dane.len(),
                    cert.hooks.len() + cert.inline_hooks.len(),
                    cert.hooks.len(),
                    cert.inline_hooks.len()
                );
            }
        }

        Command::Account { action } => {
            let config = config::Config::load(&cli.config)?;
            match action {
                AccountAction::Create => {
                    let client = acme::AcmeClient::create(&config.acme).await?;
                    println!("Account ID: {}", client.account().id());
                }
                AccountAction::Show => {
                    let client = acme::AcmeClient::load(&config.acme).await?;
                    println!("Account ID: {}", client.account().id());
                }
                AccountAction::Deactivate => {
                    let client = acme::AcmeClient::load(&config.acme).await?;
                    let id = client.account().id().to_string();
                    client.deactivate().await?;

                    // Remove local credentials so show/renew don't use the stale account
                    if let Some(path) = &config.acme.account_key_credential
                        && path.exists()
                    {
                        std::fs::remove_file(path)?;
                        tracing::info!(path = %path.display(), "removed account credential");
                    }
                    if let Some(path) = &config.acme.account_key_path
                        && path.exists()
                    {
                        std::fs::remove_file(path)?;
                        tracing::info!(path = %path.display(), "removed account key file");
                    }

                    println!("Account {id} deactivated");
                }
            }
        }
    }

    Ok(())
}

fn print_status(config: &config::Config, name_filter: Option<&str>) {
    for cert_config in &config.certificates {
        if let Some(filter) = name_filter
            && cert_config.name != filter {
                continue;
            }

        println!("Certificate: {}", cert_config.name);
        println!("  Domains: {}", cert_config.domains.join(", "));
        println!("  Key type: {}", cert_config.key_type);
        println!("  Rotate key: {}", cert_config.rotate_key);
        println!("  Cert path: {}", cert_config.cert_path.display());

        match certs::CertInfo::load(&cert_config.cert_path) {
            Ok(info) => {
                let days = info.days_until_expiry();
                println!("  Expires: {} ({days} days)", info.not_after.format("%Y-%m-%d %H:%M UTC"));
                if info.expires_within_days(cert_config.renew_before_days) {
                    println!("  Status: NEEDS RENEWAL");
                } else {
                    println!("  Status: OK");
                }
                if !info.san.is_empty() {
                    println!("  SANs: {}", info.san.join(", "));
                }
            }
            Err(_) => {
                println!("  Status: NOT ISSUED");
            }
        }

        for (i, dane) in cert_config.dane.iter().enumerate() {
            println!("  DANE block {} (dns={}): {}/{}/{}", i, dane.dns, dane.usage, dane.selector, dane.matching);
            println!("    Names: {}", dane.names.join(", "));
            println!("    TTL: {}, Pre-publish: {}", dane.ttl, dane.pre_publish);
        }

        println!();
    }
}

async fn dane_publish(
    config: &config::Config,
    name_filter: Option<&str>,
    dry_run: bool,
) -> anyhow::Result<()> {
    for cert_config in &config.certificates {
        if let Some(filter) = name_filter
            && cert_config.name != filter {
                continue;
            }

        if cert_config.dane.is_empty() {
            continue;
        }

        let cert_info = certs::CertInfo::load(&cert_config.cert_path)?;

        for dane_config in &cert_config.dane {
            let records = dane::compute_tlsa_records(&cert_info, dane_config)?;

            if dry_run {
                for (name, record) in dane_config.names.iter().zip(records.iter()) {
                    println!("{name}. IN TLSA {}", record.to_rdata_string());
                }
                continue;
            }

            let dns_config = config.dns_client(&dane_config.dns)?;
            let signer = dns::tsig::load_tsig_signer(dns_config).await?;
            let mut updater = dns::update::DnsUpdater::connect(dns_config, signer).await?;
            dane::publish_tlsa(&mut updater, dns_config, dane_config, &records).await?;
        }

        tracing::info!(name = %cert_config.name, "DANE TLSA records published");
    }

    Ok(())
}

async fn dane_check(
    config: &config::Config,
    name_filter: Option<&str>,
) -> anyhow::Result<()> {
    let mut all_ok = true;

    for cert_config in &config.certificates {
        if let Some(filter) = name_filter
            && cert_config.name != filter {
                continue;
            }

        if cert_config.dane.is_empty() {
            continue;
        }

        println!("Certificate: {}", cert_config.name);

        let cert_result = certs::CertInfo::load(&cert_config.cert_path);

        for dane_config in &cert_config.dane {
            let expected = match &cert_result {
                Ok(cert_info) => dane::compute_tlsa_records(cert_info, dane_config)?,
                Err(_) => {
                    println!("  Certificate not found, cannot compute expected TLSA records");
                    continue;
                }
            };
            let expected_record = &expected[0];

            let dns_config = config.dns_client(&dane_config.dns)?;
            let signer = dns::tsig::load_tsig_signer(dns_config).await?;
            let mut querier = dns::update::DnsUpdater::connect(dns_config, signer).await?;

            for tlsa_name in &dane_config.names {
                let name = hickory_proto::rr::Name::from_ascii(tlsa_name)
                    .map_err(|e| anyhow::anyhow!("invalid TLSA name '{tlsa_name}': {e}"))?;

                match querier.query_tlsa(&name).await {
                    Ok(published) if published.is_empty() => {
                        println!("  {tlsa_name}: MISSING (no TLSA records published)");
                        println!("    expected: {}", expected_record.to_rdata_string());
                        all_ok = false;
                    }
                    Ok(published) => {
                        if published.contains(expected_record) {
                            println!("  {tlsa_name}: OK");
                        } else {
                            println!("  {tlsa_name}: MISMATCH");
                            println!("    expected: {}", expected_record.to_rdata_string());
                            for rec in &published {
                                println!("    found:    {}", rec.to_rdata_string());
                            }
                            all_ok = false;
                        }
                    }
                    Err(e) => {
                        println!("  {tlsa_name}: ERROR ({e})");
                        all_ok = false;
                    }
                }
            }
        }

        println!();
    }

    if !all_ok {
        std::process::exit(1);
    }

    Ok(())
}

