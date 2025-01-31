use std::sync::Arc;
use tokio::sync::RwLock;
use std::net::{IpAddr, SocketAddr};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use dashmap::DashMap;
use std::time::{Duration, Instant};
use ipnet::IpNet;
use maxminddb::geoip2;
use trust_dns_resolver::TokioAsyncResolver;
use cidr_utils::cidr::Ipv4Cidr;

// Connection validation constants
const MAX_CONNECTIONS_PER_IP: usize = 100;
const MAX_FAILED_ATTEMPTS: usize = 5;
const BLOCK_DURATION: Duration = Duration::from_secs(3600); // 1 hour
const CLEANUP_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes
const DNS_TIMEOUT: Duration = Duration::from_secs(5);
const CONNECTION_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum ConnectionError {
    #[error("Connection blocked: {0}")]
    Blocked(String),
    
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),
    
    #[error("Invalid connection: {0}")]
    Invalid(String),
    
    #[error("DNS error: {0}")]
    Dns(#[from] trust_dns_resolver::error::ResolveError),
    
    #[error("GeoIP error: {0}")]
    GeoIP(String),
    
    #[error("Network error: {0}")]
    Network(String),
}

pub struct ConnectionValidator {
    blocked_ips: Arc<DashMap<IpAddr, BlockInfo>>,
    connection_counts: Arc<DashMap<IpAddr, usize>>,
    failed_attempts: Arc<DashMap<IpAddr, FailedAttempts>>,
    allowed_networks: Arc<RwLock<HashSet<IpNet>>>,
    blocked_networks: Arc<RwLock<HashSet<IpNet>>>,
    allowed_countries: Arc<RwLock<HashSet<String>>>,
    blocked_countries: Arc<RwLock<HashSet<String>>>,
    dns_resolver: Arc<TokioAsyncResolver>,
    geoip_reader: Arc<maxminddb::Reader<Vec<u8>>>,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
    cleanup_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

#[derive(Clone)]
struct BlockInfo {
    reason: String,
    expires_at: Instant,
}

#[derive(Clone)]
struct FailedAttempts {
    count: usize,
    last_attempt: Instant,
}

impl ConnectionValidator {
    pub async fn new(
        geoip_path: &str,
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Result<Self, ConnectionError> {
        let geoip_reader = maxminddb::Reader::open_readfile(geoip_path)
            .map_err(|e| ConnectionError::GeoIP(e.to_string()))?;
            
        let dns_resolver = TokioAsyncResolver::tokio_from_system_conf()
            .map_err(|e| ConnectionError::Dns(e))?;

        let validator = Self {
            blocked_ips: Arc::new(DashMap::new()),
            connection_counts: Arc::new(DashMap::new()),
            failed_attempts: Arc::new(DashMap::new()),
            allowed_networks: Arc::new(RwLock::new(HashSet::new())),
            blocked_networks: Arc::new(RwLock::new(HashSet::new())),
            allowed_countries: Arc::new(RwLock::new(HashSet::new())),
            blocked_countries: Arc::new(RwLock::new(HashSet::new())),
            dns_resolver: Arc::new(dns_resolver),
            geoip_reader: Arc::new(geoip_reader),
            metrics,
            error_handler,
            cleanup_task: Arc::new(tokio::sync::Mutex::new(None)),
        };
        
        validator.start_cleanup_task();
        Ok(validator)
    }

    pub async fn validate_connection(
        &self,
        addr: SocketAddr,
        hostname: Option<&str>,
    ) -> Result<(), ConnectionError> {
        let ip = addr.ip();

        // Check if IP is blocked
        if let Some(block_info) = self.blocked_ips.get(&ip) {
            if block_info.expires_at > Instant::now() {
                self.metrics.record_blocked_connection().await;
                return Err(ConnectionError::Blocked(block_info.reason.clone()));
            }
        }

        // Check connection count
        let count = self.connection_counts.entry(ip)
            .and_modify(|c| *c += 1)
            .or_insert(1);
            
        if *count > MAX_CONNECTIONS_PER_IP {
            self.metrics.record_rate_limited_connection().await;
            return Err(ConnectionError::RateLimit(
                format!("Too many connections from {}", ip)
            ));
        }

        // Validate against network rules
        self.validate_networks(ip).await?;

        // Validate country
        self.validate_country(ip).await?;

        // Validate hostname if provided
        if let Some(hostname) = hostname {
            self.validate_hostname(hostname, ip).await?;
        }

        self.metrics.record_valid_connection().await;
        Ok(())
    }

    async fn validate_networks(&self, ip: IpAddr) -> Result<(), ConnectionError> {
        let allowed_networks = self.allowed_networks.read().await;
        let blocked_networks = self.blocked_networks.read().await;

        // Check blocked networks first
        for network in blocked_networks.iter() {
            if network.contains(&ip) {
                return Err(ConnectionError::Blocked(
                    format!("IP {} in blocked network {}", ip, network)
                ));
            }
        }

        // If allowed networks are specified, IP must be in one
        if !allowed_networks.is_empty() {
            let mut allowed = false;
            for network in allowed_networks.iter() {
                if network.contains(&ip) {
                    allowed = true;
                    break;
                }
            }
            
            if !allowed {
                return Err(ConnectionError::Invalid(
                    format!("IP {} not in allowed networks", ip)
                ));
            }
        }

        Ok(())
    }

    async fn validate_country(&self, ip: IpAddr) -> Result<(), ConnectionError> {
        let country: geoip2::Country = self.geoip_reader.lookup(ip)
            .map_err(|e| ConnectionError::GeoIP(e.to_string()))?;
            
        let country_code = country.country
            .and_then(|c| c.iso_code)
            .ok_or_else(|| ConnectionError::GeoIP("Country code not found".to_string()))?;

        let allowed_countries = self.allowed_countries.read().await;
        let blocked_countries = self.blocked_countries.read().await;

        // Check blocked countries
        if blocked_countries.contains(country_code) {
            return Err(ConnectionError::Blocked(
                format!("Country {} is blocked", country_code)
            ));
        }

        // If allowed countries are specified, must be in list
        if !allowed_countries.is_empty() && !allowed_countries.contains(country_code) {
            return Err(ConnectionError::Invalid(
                format!("Country {} not allowed", country_code)
            ));
        }

        Ok(())
    }

    async fn validate_hostname(
        &self,
        hostname: &str,
        ip: IpAddr,
    ) -> Result<(), ConnectionError> {
        let response = tokio::time::timeout(
            DNS_TIMEOUT,
            self.dns_resolver.lookup_ip(hostname)
        ).await
            .map_err(|_| ConnectionError::Dns(
                trust_dns_resolver::error::ResolveError::from(std::io::Error::new(
                    std::io::ErrorKind::TimedOut,
                    "DNS lookup timed out"
                ))
            ))??;

        let mut valid = false;
        for addr in response.iter() {
            if addr == ip {
                valid = true;
                break;
            }
        }

        if !valid {
            return Err(ConnectionError::Invalid(
                format!("Hostname {} does not resolve to IP {}", hostname, ip)
            ));
        }

        Ok(())
    }

    pub async fn record_failed_attempt(
        &self,
        ip: IpAddr,
        reason: &str,
    ) -> Result<(), ConnectionError> {
        let mut attempts = self.failed_attempts
            .entry(ip)
            .or_insert_with(|| FailedAttempts {
                count: 0,
                last_attempt: Instant::now(),
            });
            
        attempts.count += 1;
        attempts.last_attempt = Instant::now();

        if attempts.count >= MAX_FAILED_ATTEMPTS {
            self.block_ip(ip, format!(
                "Too many failed attempts: {}", reason
            )).await;
        }

        Ok(())
    }

    pub async fn block_ip(
        &self,
        ip: IpAddr,
        reason: String,
    ) {
        self.blocked_ips.insert(ip, BlockInfo {
            reason,
            expires_at: Instant::now() + BLOCK_DURATION,
        });
        
        self.metrics.record_ip_blocked().await;
    }

    pub async fn add_allowed_network(&self, network: IpNet) {
        self.allowed_networks.write().await.insert(network);
    }

    pub async fn add_blocked_network(&self, network: IpNet) {
        self.blocked_networks.write().await.insert(network);
    }

    pub async fn add_allowed_country(&self, country_code: String) {
        self.allowed_countries.write().await.insert(country_code);
    }

    pub async fn add_blocked_country(&self, country_code: String) {
        self.blocked_countries.write().await.insert(country_code);
    }

    fn start_cleanup_task(&self) {
        let blocked_ips = self.blocked_ips.clone();
        let failed_attempts = self.failed_attempts.clone();
        let connection_counts = self.connection_counts.clone();
        let metrics = self.metrics.clone();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            
            loop {
                interval.tick().await;
                
                let now = Instant::now();
                
                // Cleanup blocked IPs
                blocked_ips.retain(|_, info| info.expires_at > now);
                
                // Cleanup failed attempts
                failed_attempts.retain(|_, attempts| {
                    now.duration_since(attempts.last_attempt) < BLOCK_DURATION
                });
                
                // Reset connection counts
                connection_counts.clear();
                
                metrics.record_cleanup().await;
            }
        });

        *self.cleanup_task.lock().unwrap() = Some(handle);
    }
}

// Safe cleanup
impl Drop for ConnectionValidator {
    fn drop(&mut self) {
        if let Some(handle) = self.cleanup_task.lock().unwrap().take() {
            handle.abort();
        }
    }
} 