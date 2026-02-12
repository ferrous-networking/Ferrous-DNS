use std::net::IpAddr;
use std::sync::Arc;

/// Represents a network client detected via DNS queries
#[derive(Debug, Clone)]
pub struct Client {
    pub id: Option<i64>,
    pub ip_address: IpAddr,
    pub mac_address: Option<Arc<str>>,
    pub hostname: Option<Arc<str>>,
    pub first_seen: Option<String>,
    pub last_seen: Option<String>,
    pub query_count: u64,
    pub last_mac_update: Option<String>,
    pub last_hostname_update: Option<String>,
}

impl Client {
    pub fn new(ip_address: IpAddr) -> Self {
        Self {
            id: None,
            ip_address,
            mac_address: None,
            hostname: None,
            first_seen: None,
            last_seen: None,
            query_count: 0,
            last_mac_update: None,
            last_hostname_update: None,
        }
    }

    /// Check if MAC address needs updating (>5 minutes since last update)
    pub fn should_update_mac(&self) -> bool {
        self.last_mac_update.is_none()
            || self.mac_address.is_none()
            || self.is_stale(&self.last_mac_update, 300) // 5 minutes
    }

    /// Check if hostname needs updating (>1 hour since last update)
    pub fn should_update_hostname(&self) -> bool {
        self.last_hostname_update.is_none()
            || self.hostname.is_none()
            || self.is_stale(&self.last_hostname_update, 3600) // 1 hour
    }

    fn is_stale(&self, last_update: &Option<String>, threshold_secs: i64) -> bool {
        if let Some(ts) = last_update {
            if let Ok(time) =
                chrono::NaiveDateTime::parse_from_str(ts, "%Y-%m-%d %H:%M:%S")
            {
                let update_time =
                    chrono::DateTime::<chrono::Utc>::from_naive_utc_and_offset(
                        time,
                        chrono::Utc,
                    );
                let now = chrono::Utc::now();
                return (now - update_time).num_seconds() > threshold_secs;
            }
        }
        true
    }
}

/// Statistics about tracked clients
#[derive(Debug, Clone)]
pub struct ClientStats {
    pub total_clients: u64,
    pub active_24h: u64,
    pub active_7d: u64,
    pub with_mac: u64,
    pub with_hostname: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_new() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let client = Client::new(ip);

        assert_eq!(client.ip_address, ip);
        assert!(client.id.is_none());
        assert!(client.mac_address.is_none());
        assert!(client.hostname.is_none());
        assert_eq!(client.query_count, 0);
    }

    #[test]
    fn test_should_update_mac_when_none() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let client = Client::new(ip);

        assert!(client.should_update_mac());
    }

    #[test]
    fn test_should_update_hostname_when_none() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let client = Client::new(ip);

        assert!(client.should_update_hostname());
    }

    #[test]
    fn test_should_not_update_mac_when_recent() {
        let ip: IpAddr = "192.168.1.100".parse().unwrap();
        let mut client = Client::new(ip);
        client.mac_address = Some(Arc::from("aa:bb:cc:dd:ee:ff"));
        client.last_mac_update =
            Some(chrono::Utc::now().format("%Y-%m-%d %H:%M:%S").to_string());

        assert!(!client.should_update_mac());
    }
}
