pub mod dns01;
pub mod http01;
pub mod tls_alpn01;

use crate::acme::ChallengeInfo;
use crate::error::Result;

/// A challenge solver that can present and clean up ACME challenges.
#[async_trait::async_trait]
pub trait Solver: Send + Sync {
    /// Present a challenge to make it available for ACME validation.
    async fn present(&self, challenge: &ChallengeInfo) -> Result<()>;

    /// Clean up a challenge after validation (success or failure).
    async fn cleanup(&self, challenge: &ChallengeInfo) -> Result<()>;

    /// Whether this solver needs a DNS propagation delay after presenting.
    fn needs_propagation_delay(&self) -> bool {
        false
    }
}
