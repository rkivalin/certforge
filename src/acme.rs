use std::net::IpAddr;
use std::time::Duration;

use instant_acme::{
    Account, AccountCredentials, ChallengeType, Identifier, NewAccount, NewOrder, Order,
    OrderStatus,
};

use crate::config::AcmeConfig;
use crate::credentials;
use crate::error::{Error, Result};

pub struct AcmeClient {
    account: Account,
}

/// Generic challenge information for any challenge type.
#[allow(dead_code)]
pub struct ChallengeInfo {
    /// The identifier being validated (domain name or IP address).
    pub identifier: String,
    /// The challenge type that was selected.
    pub challenge_type: ChallengeType,
    /// The challenge token.
    pub token: String,
    /// The full key authorization string.
    pub key_authorization: String,
    /// The DNS TXT record value (base64url(sha256(key_auth))). Only meaningful for DNS-01.
    pub dns_value: String,
}

impl AcmeClient {
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
                    .map_err(Error::Acme)?
                    .from_credentials(creds)
                    .await?;
                tracing::info!(id = %account.id(), "loaded existing ACME account");
                Ok(Self { account })
            }
            Err(_) => {
                tracing::info!(directory = %config.directory_url, "creating new ACME account");
                let (account, creds) = Account::builder()
                    .map_err(Error::Acme)?
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

    /// Create a new ACME order for the given domains/IPs.
    pub async fn create_order(&self, domains: &[String], profile: Option<&str>) -> Result<Order> {
        let identifiers: Vec<Identifier> = domains
            .iter()
            .map(|d| {
                if let Ok(ip) = d.parse::<IpAddr>() {
                    Identifier::Ip(ip)
                } else {
                    Identifier::Dns(d.clone())
                }
            })
            .collect();

        let mut new_order = NewOrder::new(&identifiers);
        if let Some(profile) = profile {
            new_order = new_order.profile(profile);
        }

        let order = self.account.new_order(&new_order).await?;

        Ok(order)
    }

    /// Collect challenge info from an order, selecting the desired challenge type per identifier.
    ///
    /// `desired_types` maps each identifier to the challenge type to use.
    /// The order of identifiers matches the order from `create_order`.
    pub async fn collect_challenges(
        order: &mut Order,
        desired_types: &[(String, ChallengeType)],
    ) -> Result<Vec<ChallengeInfo>> {
        let mut challenges = Vec::new();

        let mut auths = order.authorizations();
        while let Some(auth_result) = auths.next().await {
            let mut auth = auth_result?;
            let identifier = auth.identifier().to_string();

            // Find which challenge type was requested for this identifier
            let desired = desired_types
                .iter()
                .find(|(id, _)| *id == identifier)
                .map(|(_, ct)| ct.clone())
                .unwrap_or(ChallengeType::Dns01);

            let challenge = auth.challenge(desired.clone()).ok_or_else(|| {
                Error::Acme(instant_acme::Error::Other(
                    format!("no {desired:?} challenge for {identifier}").into(),
                ))
            })?;

            let key_auth = challenge.key_authorization();
            let token = challenge.token.clone();
            let dns_value = key_auth.dns_value();
            let key_authorization = key_auth.as_str().to_string();

            challenges.push(ChallengeInfo {
                identifier,
                challenge_type: desired,
                token,
                key_authorization,
                dns_value,
            });
        }

        Ok(challenges)
    }

    /// Set all challenges as ready.
    pub async fn set_challenges_ready(
        order: &mut Order,
        desired_types: &[(String, ChallengeType)],
    ) -> Result<()> {
        let mut auths = order.authorizations();
        while let Some(auth_result) = auths.next().await {
            let mut auth = auth_result?;
            let identifier = auth.identifier().to_string();

            let desired = desired_types
                .iter()
                .find(|(id, _)| *id == identifier)
                .map(|(_, ct)| ct.clone())
                .unwrap_or(ChallengeType::Dns01);

            if let Some(mut ch) = auth.challenge(desired) {
                ch.set_ready().await?;
            }
        }
        Ok(())
    }

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
