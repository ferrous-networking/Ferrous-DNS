use crate::ports::QueryLogRepository;
use ferrous_dns_domain::{query_log::QueryStats, DomainError};
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};

/// How long a stats result is served from cache before being recomputed.
/// The dashboard polls every 5 s; a 10 s TTL means at most 1 DB query per
/// 10 s regardless of how many tabs are open or how fast the client polls.
const CACHE_TTL: Duration = Duration::from_secs(10);

struct CachedStats {
    computed_at: Instant,
    period_hours: f32,
    data: QueryStats,
}

pub struct GetQueryStatsUseCase {
    repository: Arc<dyn QueryLogRepository>,
    cache: RwLock<Option<CachedStats>>,
}

impl GetQueryStatsUseCase {
    pub fn new(repository: Arc<dyn QueryLogRepository>) -> Self {
        Self {
            repository,
            cache: RwLock::new(None),
        }
    }

    pub async fn execute(&self, period_hours: f32) -> Result<QueryStats, DomainError> {
        // Fast path: return cached value if still fresh for the same period.
        {
            let guard = self.cache.read().unwrap();
            if let Some(ref cached) = *guard {
                if cached.period_hours == period_hours
                    && cached.computed_at.elapsed() < CACHE_TTL
                {
                    return Ok(cached.data.clone());
                }
            }
        }

        // Slow path: hit the database.
        let stats = self.repository.get_stats(period_hours).await?;

        {
            let mut guard = self.cache.write().unwrap();
            *guard = Some(CachedStats {
                computed_at: Instant::now(),
                period_hours,
                data: stats.clone(),
            });
        }

        Ok(stats)
    }
}
