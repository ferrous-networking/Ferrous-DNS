use std::sync::Arc;
use tracing::instrument;

use ferrous_dns_domain::AuthConfig;

/// Returns authentication status info (no auth required to call).
pub struct GetAuthStatusUseCase {
    auth_config: Arc<AuthConfig>,
}

impl GetAuthStatusUseCase {
    pub fn new(auth_config: Arc<AuthConfig>) -> Self {
        Self { auth_config }
    }

    #[instrument(skip(self))]
    pub fn execute(&self) -> AuthStatus {
        let password_configured = self
            .auth_config
            .admin
            .password_hash
            .as_ref()
            .map(|h| !h.is_empty())
            .unwrap_or(false);

        AuthStatus {
            auth_enabled: self.auth_config.enabled,
            password_configured,
        }
    }
}

/// Auth status returned to the frontend for login/setup flow.
#[derive(Debug, Clone)]
pub struct AuthStatus {
    /// Whether authentication is globally enabled.
    pub auth_enabled: bool,
    /// Whether the admin password has been set (first-run setup complete).
    pub password_configured: bool,
}
