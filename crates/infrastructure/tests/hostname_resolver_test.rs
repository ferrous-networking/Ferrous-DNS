use ferrous_dns_application::ports::HostnameResolver;
use ferrous_dns_infrastructure::system::hostname_resolver::PtrHostnameResolver;
use std::net::IpAddr;

#[tokio::test]
async fn test_resolve_returns_none() {
    let resolver = PtrHostnameResolver::new(5);
    let ip: IpAddr = "127.0.0.1".parse().unwrap();

    let result = resolver.resolve_hostname(ip).await;
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), None);
}

#[tokio::test]
async fn test_resolve_timeout() {
    let resolver = PtrHostnameResolver::new(1);
    let ip: IpAddr = "8.8.8.8".parse().unwrap();

    let result = resolver.resolve_hostname(ip).await;
    assert!(result.is_ok());
}

#[tokio::test]
async fn test_resolve_invalid_ip() {
    let resolver = PtrHostnameResolver::new(2);
    let ip: IpAddr = "0.0.0.0".parse().unwrap();

    let result = resolver.resolve_hostname(ip).await;
    assert!(result.is_ok());
}
