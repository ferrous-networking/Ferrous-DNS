use std::sync::Arc;
use tracing::instrument;

use crate::ports::ApiTokenRepository;
use ferrous_dns_domain::DomainError;

/// Validates a raw API token against stored hashes.
///
/// On success, updates `last_used_at` and returns the token ID.
pub struct ValidateApiTokenUseCase {
    repo: Arc<dyn ApiTokenRepository>,
}

impl ValidateApiTokenUseCase {
    pub fn new(repo: Arc<dyn ApiTokenRepository>) -> Self {
        Self { repo }
    }

    /// Validates the raw token by hashing it and comparing against stored hashes.
    /// Returns `Ok(token_id)` on match, `Err(InvalidCredentials)` otherwise.
    #[instrument(skip(self, raw_token))]
    pub async fn execute(&self, raw_token: &str) -> Result<i64, DomainError> {
        let incoming_hash = super::hash_token(raw_token);
        let all_hashes = self.repo.get_all_hashes().await?;

        for (id, stored_hash) in &all_hashes {
            if timing_safe_eq(incoming_hash.as_bytes(), stored_hash.as_bytes()) {
                self.repo.update_last_used(*id).await?;
                return Ok(*id);
            }
        }

        Err(DomainError::InvalidCredentials)
    }
}

/// Constant-time comparison to prevent timing attacks on token validation.
fn timing_safe_eq(a: &[u8], b: &[u8]) -> bool {
    use subtle::ConstantTimeEq;
    a.ct_eq(b).into()
}
