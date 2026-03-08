use std::sync::Arc;

use async_trait::async_trait;
use sqlx::SqlitePool;
use tracing::{error, info, instrument};

use ferrous_dns_application::ports::ApiTokenRepository;
use ferrous_dns_domain::{ApiToken, DomainError};

pub struct SqliteApiTokenRepository {
    pool: Arc<SqlitePool>,
}

impl SqliteApiTokenRepository {
    pub fn new(pool: Arc<SqlitePool>) -> Self {
        Self { pool }
    }
}

type TokenRow = (i64, String, String, String, String, Option<String>);

#[async_trait]
impl ApiTokenRepository for SqliteApiTokenRepository {
    #[instrument(skip(self, key_hash))]
    async fn create(
        &self,
        name: &str,
        key_prefix: &str,
        key_hash: &str,
    ) -> Result<ApiToken, DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        let row: TokenRow = sqlx::query_as(
            "INSERT INTO api_tokens (name, key_prefix, key_hash, created_at)
             VALUES (?, ?, ?, ?)
             RETURNING id, name, key_prefix, key_hash, created_at, last_used_at",
        )
        .bind(name)
        .bind(key_prefix)
        .bind(key_hash)
        .bind(&now)
        .fetch_one(self.pool.as_ref())
        .await
        .map_err(|e| match &e {
            sqlx::Error::Database(db_err) if db_err.is_unique_violation() => {
                DomainError::DuplicateApiTokenName(name.to_string())
            }
            _ => {
                error!("Failed to create API token: {e}");
                DomainError::DatabaseError(e.to_string())
            }
        })?;

        info!(name = name, "API token created");
        Ok(row_to_token(row))
    }

    #[instrument(skip(self))]
    async fn get_all(&self) -> Result<Vec<ApiToken>, DomainError> {
        let rows: Vec<TokenRow> = sqlx::query_as(
            "SELECT id, name, key_prefix, key_hash, created_at, last_used_at
             FROM api_tokens ORDER BY id",
        )
        .fetch_all(self.pool.as_ref())
        .await
        .map_err(|e| {
            error!("Failed to get all API tokens: {e}");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(rows.into_iter().map(row_to_token).collect())
    }

    #[instrument(skip(self))]
    async fn get_by_id(&self, id: i64) -> Result<Option<ApiToken>, DomainError> {
        let row: Option<TokenRow> = sqlx::query_as(
            "SELECT id, name, key_prefix, key_hash, created_at, last_used_at
             FROM api_tokens WHERE id = ?",
        )
        .bind(id)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(|e| {
            error!("Failed to get API token by id: {e}");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(row_to_token))
    }

    #[instrument(skip(self))]
    async fn get_by_name(&self, name: &str) -> Result<Option<ApiToken>, DomainError> {
        let row: Option<TokenRow> = sqlx::query_as(
            "SELECT id, name, key_prefix, key_hash, created_at, last_used_at
             FROM api_tokens WHERE name = ?",
        )
        .bind(name)
        .fetch_optional(self.pool.as_ref())
        .await
        .map_err(|e| {
            error!("Failed to get API token by name: {e}");
            DomainError::DatabaseError(e.to_string())
        })?;

        Ok(row.map(row_to_token))
    }

    #[instrument(skip(self))]
    async fn delete(&self, id: i64) -> Result<(), DomainError> {
        let result = sqlx::query("DELETE FROM api_tokens WHERE id = ?")
            .bind(id)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| {
                error!("Failed to delete API token: {e}");
                DomainError::DatabaseError(e.to_string())
            })?;

        if result.rows_affected() == 0 {
            return Err(DomainError::ApiTokenNotFound(id));
        }

        Ok(())
    }

    #[instrument(skip(self))]
    async fn update_last_used(&self, id: i64) -> Result<(), DomainError> {
        let now = chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string();

        sqlx::query("UPDATE api_tokens SET last_used_at = ? WHERE id = ?")
            .bind(&now)
            .bind(id)
            .execute(self.pool.as_ref())
            .await
            .map_err(|e| {
                error!("Failed to update API token last_used: {e}");
                DomainError::DatabaseError(e.to_string())
            })?;

        Ok(())
    }

    #[instrument(skip(self))]
    async fn get_all_hashes(&self) -> Result<Vec<(i64, String)>, DomainError> {
        let rows: Vec<(i64, String)> = sqlx::query_as("SELECT id, key_hash FROM api_tokens")
            .fetch_all(self.pool.as_ref())
            .await
            .map_err(|e| {
                error!("Failed to get API token hashes: {e}");
                DomainError::DatabaseError(e.to_string())
            })?;

        Ok(rows)
    }
}

fn row_to_token(row: TokenRow) -> ApiToken {
    ApiToken {
        id: Some(row.0),
        name: Arc::from(row.1.as_str()),
        key_prefix: Arc::from(row.2.as_str()),
        key_hash: Arc::from(row.3.as_str()),
        created_at: Some(row.4),
        last_used_at: row.5,
    }
}
