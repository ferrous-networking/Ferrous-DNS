use super::udp_pool::UdpSocketPool;
use super::{DnsTransport, TransportResponse};
use async_trait::async_trait;
use ferrous_dns_domain::DomainError;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;
use tokio::net::UdpSocket;
use tracing::{debug, warn};

fn validate_response_id(
    query_bytes: &[u8],
    response_bytes: &[u8],
    server: SocketAddr,
) -> Result<(), DomainError> {
    if query_bytes.len() < 2 || response_bytes.len() < 2 {
        return Err(DomainError::InvalidDomainName(format!(
            "DNS response from {} is too short to contain a message ID",
            server
        )));
    }
    let query_id = u16::from_be_bytes([query_bytes[0], query_bytes[1]]);
    let response_id = u16::from_be_bytes([response_bytes[0], response_bytes[1]]);
    if query_id != response_id {
        warn!(
            server = %server,
            query_id,
            response_id,
            "DNS message ID mismatch — discarding response to prevent spoofing"
        );
        return Err(DomainError::InvalidDomainName(format!(
            "DNS message ID mismatch from {}: expected {}, got {}",
            server, query_id, response_id
        )));
    }
    Ok(())
}

const MAX_UDP_RESPONSE_SIZE: usize = 4096;

pub struct UdpTransport {
    server_addr: SocketAddr,
    pool: Option<Arc<UdpSocketPool>>,
}

impl UdpTransport {
    pub fn new(server_addr: SocketAddr) -> Self {
        Self {
            server_addr,
            pool: None,
        }
    }

    pub fn with_pool(server_addr: SocketAddr, pool: Arc<UdpSocketPool>) -> Self {
        Self {
            server_addr,
            pool: Some(pool),
        }
    }

    async fn send_with_pool(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        if let Some(ref pool) = self.pool {
            let pooled = pool.acquire(self.server_addr).await.map_err(|e| {
                DomainError::InvalidDomainName(format!("Failed to acquire UDP socket: {}", e))
            })?;

            let socket = pooled.socket();

            let bytes_sent =
                tokio::time::timeout(timeout, socket.send_to(message_bytes, self.server_addr))
                    .await
                    .map_err(|_| {
                        DomainError::InvalidDomainName(format!(
                            "Timeout sending UDP query to {}",
                            self.server_addr
                        ))
                    })?
                    .map_err(|e| {
                        DomainError::InvalidDomainName(format!(
                            "Failed to send UDP query to {}: {}",
                            self.server_addr, e
                        ))
                    })?;

            debug!(
                server = %self.server_addr,
                bytes_sent = bytes_sent,
                pooled = true,
                "UDP query sent"
            );

            let mut recv_buf = [0u8; MAX_UDP_RESPONSE_SIZE];

            let (bytes_received, from_addr) =
                tokio::time::timeout(timeout, socket.recv_from(&mut recv_buf))
                    .await
                    .map_err(|_| {
                        DomainError::InvalidDomainName(format!(
                            "Timeout waiting for UDP response from {}",
                            self.server_addr
                        ))
                    })?
                    .map_err(|e| {
                        DomainError::InvalidDomainName(format!(
                            "Failed to receive UDP response from {}: {}",
                            self.server_addr, e
                        ))
                    })?;

            if from_addr.ip() != self.server_addr.ip() {
                warn!(
                    expected = %self.server_addr,
                    received_from = %from_addr,
                    "UDP response from unexpected source"
                );
            }

            validate_response_id(message_bytes, &recv_buf[..bytes_received], self.server_addr)?;

            debug!(
                server = %self.server_addr,
                bytes_received = bytes_received,
                pooled = true,
                "UDP response received"
            );

            Ok(TransportResponse {
                bytes: bytes::Bytes::copy_from_slice(&recv_buf[..bytes_received]),
                protocol_used: "UDP",
            })
        } else {
            self.send_without_pool(message_bytes, timeout).await
        }
    }

    async fn send_without_pool(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        let bind_addr: SocketAddr = if self.server_addr.is_ipv4() {
            "0.0.0.0:0".parse().unwrap()
        } else {
            "[::]:0".parse().unwrap()
        };

        let socket = UdpSocket::bind(bind_addr).await.map_err(|e| {
            DomainError::InvalidDomainName(format!("Failed to bind UDP socket: {}", e))
        })?;

        let bytes_sent =
            tokio::time::timeout(timeout, socket.send_to(message_bytes, self.server_addr))
                .await
                .map_err(|_| {
                    DomainError::InvalidDomainName(format!(
                        "Timeout sending UDP query to {}",
                        self.server_addr
                    ))
                })?
                .map_err(|e| {
                    DomainError::InvalidDomainName(format!(
                        "Failed to send UDP query to {}: {}",
                        self.server_addr, e
                    ))
                })?;

        debug!(
            server = %self.server_addr,
            bytes_sent = bytes_sent,
            pooled = false,
            "UDP query sent"
        );

        let mut recv_buf = [0u8; MAX_UDP_RESPONSE_SIZE];

        let (bytes_received, from_addr) =
            tokio::time::timeout(timeout, socket.recv_from(&mut recv_buf))
                .await
                .map_err(|_| {
                    DomainError::InvalidDomainName(format!(
                        "Timeout waiting for UDP response from {}",
                        self.server_addr
                    ))
                })?
                .map_err(|e| {
                    DomainError::InvalidDomainName(format!(
                        "Failed to receive UDP response from {}: {}",
                        self.server_addr, e
                    ))
                })?;

        if from_addr.ip() != self.server_addr.ip() {
            warn!(
                expected = %self.server_addr,
                received_from = %from_addr,
                "UDP response from unexpected source"
            );
        }

        validate_response_id(message_bytes, &recv_buf[..bytes_received], self.server_addr)?;

        debug!(
            server = %self.server_addr,
            bytes_received = bytes_received,
            pooled = false,
            "UDP response received"
        );

        Ok(TransportResponse {
            bytes: bytes::Bytes::copy_from_slice(&recv_buf[..bytes_received]),
            protocol_used: "UDP",
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr() -> SocketAddr {
        "8.8.8.8:53".parse().unwrap()
    }

    #[test]
    fn test_validate_response_id_matching_ids_ok() {
        let query = [0xAB, 0xCD, 0x01, 0x00]; // ID = 0xABCD
        let response = [0xAB, 0xCD, 0x81, 0x80]; // same ID
        assert!(validate_response_id(&query, &response, addr()).is_ok());
    }

    #[test]
    fn test_validate_response_id_mismatch_returns_error() {
        let query = [0xAB, 0xCD, 0x01, 0x00]; // ID = 0xABCD
        let response = [0x12, 0x34, 0x81, 0x80]; // wrong ID = 0x1234
        let result = validate_response_id(&query, &response, addr());
        assert!(result.is_err(), "Mismatched DNS IDs must return an error");
        let err = result.unwrap_err().to_string();
        assert!(
            err.contains("mismatch"),
            "Error message should mention mismatch: {}",
            err
        );
    }

    #[test]
    fn test_validate_response_id_short_query_returns_error() {
        let query = [0xAB]; // only 1 byte — too short
        let response = [0xAB, 0xCD, 0x81, 0x80];
        assert!(validate_response_id(&query, &response, addr()).is_err());
    }

    #[test]
    fn test_validate_response_id_short_response_returns_error() {
        let query = [0xAB, 0xCD, 0x01, 0x00];
        let response = [0xAB]; // only 1 byte — too short
        assert!(validate_response_id(&query, &response, addr()).is_err());
    }
}

#[async_trait]
impl DnsTransport for UdpTransport {
    async fn send(
        &self,
        message_bytes: &[u8],
        timeout: Duration,
    ) -> Result<TransportResponse, DomainError> {
        self.send_with_pool(message_bytes, timeout).await
    }

    fn protocol_name(&self) -> &'static str {
        "UDP"
    }
}
