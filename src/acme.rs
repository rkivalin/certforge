use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, Order,
    OrderStatus,
};

use crate::config::AcmeConfig;
use crate::credentials;
use crate::error::{Error, Result};

/// ACME client wrapping instant-acme with credential management.
pub struct AcmeClient {
    account: Account,
}

/// Information about a pending DNS-01 challenge.
pub struct DnsChallenge {
    /// The domain being validated
    pub domain: String,
    /// The full DNS name for the TXT record: _acme-challenge.<domain>
    pub txt_name: String,
    /// The TXT record value (base64url-encoded SHA-256 of key authorization)
    pub txt_value: String,
}

impl AcmeClient {
    /// Load or create an ACME account.
    pub async fn new(config: &AcmeConfig) -> Result<Self> {
        let cred_data = credentials::load_secret(
            config.account_key_credential.as_deref(),
            config.account_key_path.as_deref(),
        )
        .await;

        match cred_data {
            Ok(data) => {
                let creds: AccountCredentials = serde_json::from_slice(&data).map_err(|e| {
                    Error::Config(format!("invalid account credentials: {e}"))
                })?;
                let account = Account::builder()
                    .map_err(|e| Error::Acme(e))?
                    .from_credentials(creds)
                    .await?;
                tracing::info!(id = %account.id(), "loaded existing ACME account");
                Ok(Self { account })
            }
            Err(_) => {
                tracing::info!(directory = %config.directory_url, "creating new ACME account");
                let (account, creds) = Account::builder()
                    .map_err(|e| Error::Acme(e))?
                    .create(
                        &NewAccount {
                            contact: &config
                                .contact
                                .iter()
                                .map(|s| s.as_str())
                                .collect::<Vec<_>>(),
                            terms_of_service_agreed: true,
                            only_return_existing: false,
                        },
                        config.directory_url.clone(),
                        None,
                    )
                    .await?;

                tracing::info!(id = %account.id(), "created new ACME account");

                let creds_json = serde_json::to_vec(&creds)
                    .map_err(|e| Error::Config(format!("failed to serialize credentials: {e}")))?;

                if let Some(cred_path) = &config.account_key_credential {
                    credentials::encrypt_credential("acme-account-key", &creds_json, cred_path)
                        .await?;
                    tracing::info!(path = %cred_path.display(), "saved account credentials (encrypted)");
                } else if let Some(file_path) = &config.account_key_path {
                    if let Some(parent) = file_path.parent() {
                        std::fs::create_dir_all(parent)?;
                    }
                    std::fs::write(file_path, &creds_json)?;
                    #[cfg(unix)]
                    {
                        use std::os::unix::fs::PermissionsExt;
                        std::fs::set_permissions(
                            file_path,
                            std::fs::Permissions::from_mode(0o600),
                        )?;
                    }
                    tracing::info!(path = %file_path.display(), "saved account credentials");
                }

                Ok(Self { account })
            }
        }
    }

    /// Create a new certificate order, extract DNS-01 challenge info, and set challenges ready.
    ///
    /// The caller should publish DNS TXT records for the returned challenges BEFORE calling
    /// this method. This method collects challenge info, publishes DNS, then sets challenges ready.
    ///
    /// Returns the order and challenge info needed for DNS TXT records.
    pub async fn create_order(&self, domains: &[String]) -> Result<(Order, Vec<DnsChallenge>)> {
        let identifiers: Vec<Identifier> = domains
            .iter()
            .map(|d| Identifier::Dns(d.clone()))
            .collect();

        let order = self
            .account
            .new_order(&NewOrder::new(&identifiers))
            .await?;

        Ok((order, Vec::new()))
    }

    /// Collect DNS-01 challenge info from an order's authorizations.
    pub async fn collect_challenges(order: &mut Order) -> Result<Vec<DnsChallenge>> {
        let mut challenges = Vec::new();

        let mut auths = order.authorizations();
        while let Some(auth_result) = auths.next().await {
            let mut auth = auth_result?;

            let domain = auth.identifier().to_string();

            let dns01 = auth.challenge(ChallengeType::Dns01).ok_or_else(|| {
                Error::Acme(instant_acme::Error::Other(
                    format!("no DNS-01 challenge for {domain}").into(),
                ))
            })?;

            let key_auth = dns01.key_authorization();
            let txt_value = key_auth.dns_value();

            challenges.push(DnsChallenge {
                txt_name: format!("_acme-challenge.{domain}"),
                domain,
                txt_value,
            });
        }

        Ok(challenges)
    }

    /// Set all DNS-01 challenges as ready (call after publishing TXT records).
    pub async fn set_challenges_ready(order: &mut Order) -> Result<()> {
        let mut auths = order.authorizations();
        while let Some(auth_result) = auths.next().await {
            let mut auth = auth_result?;
            if let Some(mut dns01) = auth.challenge(ChallengeType::Dns01) {
                dns01.set_ready().await?;
            }
        }
        Ok(())
    }

    /// Wait for the order to become ready, then finalize with a CSR.
    pub async fn finalize_order(order: &mut Order, csr_der: &[u8]) -> Result<()> {
        let mut retries = 20;
        loop {
            let state = order.refresh().await?;
            match state.status {
                OrderStatus::Ready => break,
                OrderStatus::Pending => {
                    if retries == 0 {
                        return Err(Error::Acme(instant_acme::Error::Other(
                            "order still pending after max retries".into(),
                        )));
                    }
                    retries -= 1;
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
                OrderStatus::Invalid => {
                    return Err(Error::Acme(instant_acme::Error::Other(
                        "order became invalid".into(),
                    )));
                }
                OrderStatus::Processing | OrderStatus::Valid => break,
            }
        }

        order.finalize_csr(csr_der).await?;
        Ok(())
    }

    /// Wait for the certificate to be available and download it.
    pub async fn download_certificate(order: &mut Order) -> Result<String> {
        let mut retries = 20;
        loop {
            let state = order.refresh().await?;
            match state.status {
                OrderStatus::Valid => {
                    let cert = order.certificate().await?.ok_or_else(|| {
                        Error::Acme(instant_acme::Error::Other(
                            "order valid but no certificate available".into(),
                        ))
                    })?;
                    return Ok(cert);
                }
                OrderStatus::Processing => {
                    if retries == 0 {
                        return Err(Error::Acme(instant_acme::Error::Other(
                            "certificate still processing after max retries".into(),
                        )));
                    }
                    retries -= 1;
                    tokio::time::sleep(Duration::from_secs(3)).await;
                }
                status => {
                    return Err(Error::Acme(instant_acme::Error::Other(
                        format!("unexpected order status: {status:?}").into(),
                    )));
                }
            }
        }
    }

    pub fn account(&self) -> &Account {
        &self.account
    }
}
