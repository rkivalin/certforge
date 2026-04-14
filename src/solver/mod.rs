pub mod dns01;
pub mod http01;
pub mod tls_alpn01;

use std::time::Duration;

use crate::acme::ChallengeInfo;
use crate::error::Result;

/// A challenge solver that can present and clean up ACME challenges.
#[async_trait::async_trait]
pub trait Solver: Send + Sync {
    /// Present a challenge to make it available for ACME validation.
    async fn present(&self, challenge: &ChallengeInfo) -> Result<()>;

    /// Clean up a challenge after validation (success or failure).
    async fn cleanup(&self, challenge: &ChallengeInfo) -> Result<()>;

    /// Propagation delay to wait after presenting challenges.
    /// Returns None for solvers that don't need a delay (HTTP-01, TLS-ALPN-01).
    fn propagation_delay(&self) -> Option<Duration> {
        None
    }
}
