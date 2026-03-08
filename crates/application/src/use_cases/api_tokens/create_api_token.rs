use std::sync::Arc;
use tracing::{info, instrument};

use crate::ports::ApiTokenRepository;
use ferrous_dns_domain::{ApiToken, DomainError};

/// Response returned when a new API token is created.
/// The raw token is included only in this response — never again.
pub struct CreatedApiToken {
    /// The persisted token metadata.
    pub token: ApiToken,
    /// The raw token value (shown once, never stored).
    pub raw_token: String,
}

/// Creates a named API token. The raw token is returned once and never stored.
pub struct CreateApiTokenUseCase {
    repo: Arc<dyn ApiTokenRepository>,
}

impl CreateApiTokenUseCase {
    pub fn new(repo: Arc<dyn ApiTokenRepository>) -> Self {
        Self { repo }
    }

    #[instrument(skip(self))]
    pub async fn execute(&self, name: &str) -> Result<CreatedApiToken, DomainError> {
        ApiToken::validate_name(name).map_err(DomainError::ConfigError)?;

        if self.repo.get_by_name(name).await?.is_some() {
            return Err(DomainError::DuplicateApiTokenName(name.to_string()));
        }

        let raw_token = super::generate_token()?;
        let key_prefix = &raw_token[..8];
        let key_hash = super::hash_token(&raw_token);

        let token = self.repo.create(name, key_prefix, &key_hash).await?;

        info!(name = name, "API token created");
        Ok(CreatedApiToken { token, raw_token })
    }
}
