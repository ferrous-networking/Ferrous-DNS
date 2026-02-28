use async_trait::async_trait;
use ferrous_dns_domain::{DnsQuery, DomainError};
use std::any::Any;
use std::net::IpAddr;
use std::sync::{Arc, LazyLock};

pub static EMPTY_CNAME_CHAIN: LazyLock<Arc<[Arc<str>]>> = LazyLock::new(|| Arc::from([]));

#[derive(Debug, Clone)]
pub struct DnsResolution {
    pub addresses: Arc<Vec<IpAddr>>,
    pub cache_hit: bool,
    pub local_dns: bool,
    pub dnssec_status: Option<&'static str>,
    pub cname_chain: Arc<[Arc<str>]>,
    pub upstream_server: Option<Arc<str>>,
    pub upstream_pool: Option<Arc<str>>,
    pub min_ttl: Option<u32>,
    pub authority_data: Option<Arc<dyn Any + Send + Sync>>,
    pub raw_upstream_data: Option<Arc<dyn Any + Send + Sync>>,
}

impl DnsResolution {
    pub fn new(addresses: Vec<IpAddr>, cache_hit: bool) -> Self {
        Self {
            addresses: Arc::new(addresses),
            cache_hit,
            local_dns: false,
            dnssec_status: None,
            cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
            upstream_server: None,
            upstream_pool: None,
            min_ttl: None,
            authority_data: None,
            raw_upstream_data: None,
        }
    }

    pub fn with_dnssec(
        addresses: Vec<IpAddr>,
        cache_hit: bool,
        dnssec_status: Option<&'static str>,
    ) -> Self {
        Self {
            addresses: Arc::new(addresses),
            cache_hit,
            local_dns: false,
            dnssec_status,
            cname_chain: Arc::clone(&EMPTY_CNAME_CHAIN),
            upstream_server: None,
            upstream_pool: None,
            min_ttl: None,
            authority_data: None,
            raw_upstream_data: None,
        }
    }
}

#[async_trait]
pub trait DnsResolver: Send + Sync {
    async fn resolve(&self, query: &DnsQuery) -> Result<DnsResolution, DomainError>;

    fn try_cache(&self, _query: &DnsQuery) -> Option<DnsResolution> {
        None
    }
}
