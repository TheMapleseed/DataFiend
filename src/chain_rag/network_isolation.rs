use std::sync::Arc;
use tokio::sync::RwLock;
use std::net::{IpAddr, SocketAddr};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use dashmap::DashMap;
use ipnet::IpNet;
use std::time::Duration;
use serde::{Serialize, Deserialize};

// Network isolation constants
const MAX_VLAN_ID: u16 = 4094;
const MIN_VLAN_ID: u16 = 1;
const MAX_SEGMENTS: usize = 100;
const SYNC_INTERVAL: Duration = Duration::from_secs(60);
const HEALTH_CHECK_INTERVAL: Duration = Duration::from_secs(30);
const MAX_ROUTES_PER_SEGMENT: usize = 1000;

#[derive(Debug, Error)]
pub enum NetworkIsolationError {
    #[error("Invalid segment: {0}")]
    InvalidSegment(String),
    
    #[error("Invalid VLAN: {0}")]
    InvalidVlan(String),
    
    #[error("Route error: {0}")]
    Route(String),
    
    #[error("Configuration error: {0}")]
    Config(String),
    
    #[error("Network error: {0}")]
    Network(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NetworkSegment {
    id: String,
    vlan_id: u16,
    network: IpNet,
    allowed_routes: HashSet<IpNet>,
    allowed_services: HashSet<String>,
    allowed_segments: HashSet<String>,
    isolation_level: IsolationLevel,
    encryption_required: bool,
    monitoring_enabled: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum IsolationLevel {
    High,    // No external access, strict isolation
    Medium,  // Limited external access, controlled routes
    Low,     // Standard network isolation
}

pub struct NetworkIsolationManager {
    segments: Arc<DashMap<String, NetworkSegment>>,
    route_table: Arc<DashMap<IpNet, HashSet<String>>>,
    active_connections: Arc<DashMap<(String, String), usize>>,
    health_status: Arc<DashMap<String, HealthStatus>>,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
    sync_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    health_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

#[derive(Debug, Clone)]
struct HealthStatus {
    last_check: std::time::Instant,
    status: HealthState,
    error_count: usize,
}

#[derive(Debug, Clone, PartialEq)]
enum HealthState {
    Healthy,
    Degraded,
    Failed,
}

impl NetworkIsolationManager {
    pub async fn new(
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Result<Self, NetworkIsolationError> {
        let manager = Self {
            segments: Arc::new(DashMap::new()),
            route_table: Arc::new(DashMap::new()),
            active_connections: Arc::new(DashMap::new()),
            health_status: Arc::new(DashMap::new()),
            metrics,
            error_handler,
            sync_task: Arc::new(tokio::sync::Mutex::new(None)),
            health_task: Arc::new(tokio::sync::Mutex::new(None)),
        };
        
        manager.start_sync_task();
        manager.start_health_task();
        
        Ok(manager)
    }

    pub async fn add_segment(
        &self,
        segment: NetworkSegment,
    ) -> Result<(), NetworkIsolationError> {
        // Validate segment configuration
        self.validate_segment(&segment)?;

        // Check segment limit
        if self.segments.len() >= MAX_SEGMENTS {
            return Err(NetworkIsolationError::Config(
                "Maximum number of segments reached".to_string()
            ));
        }

        // Update route table
        for route in &segment.allowed_routes {
            self.route_table
                .entry(*route)
                .or_default()
                .insert(segment.id.clone());
        }

        // Add segment
        self.segments.insert(segment.id.clone(), segment);
        self.metrics.record_segment_added().await;
        
        Ok(())
    }

    fn validate_segment(
        &self,
        segment: &NetworkSegment,
    ) -> Result<(), NetworkIsolationError> {
        // Validate VLAN ID
        if segment.vlan_id < MIN_VLAN_ID || segment.vlan_id > MAX_VLAN_ID {
            return Err(NetworkIsolationError::InvalidVlan(
                format!("Invalid VLAN ID: {}", segment.vlan_id)
            ));
        }

        // Validate route count
        if segment.allowed_routes.len() > MAX_ROUTES_PER_SEGMENT {
            return Err(NetworkIsolationError::Config(
                "Too many routes defined for segment".to_string()
            ));
        }

        // Validate allowed segments exist
        for allowed_segment in &segment.allowed_segments {
            if !self.segments.contains_key(allowed_segment) {
                return Err(NetworkIsolationError::InvalidSegment(
                    format!("Referenced segment does not exist: {}", allowed_segment)
                ));
            }
        }

        Ok(())
    }

    pub async fn validate_connection(
        &self,
        source_segment: &str,
        dest_segment: &str,
        service: &str,
    ) -> Result<(), NetworkIsolationError> {
        let source = self.segments.get(source_segment)
            .ok_or_else(|| NetworkIsolationError::InvalidSegment(
                format!("Source segment not found: {}", source_segment)
            ))?;
            
        let dest = self.segments.get(dest_segment)
            .ok_or_else(|| NetworkIsolationError::InvalidSegment(
                format!("Destination segment not found: {}", dest_segment)
            ))?;

        // Check isolation levels
        match (source.isolation_level, dest.isolation_level) {
            (IsolationLevel::High, _) | (_, IsolationLevel::High) => {
                if !source.allowed_segments.contains(dest_segment) {
                    return Err(NetworkIsolationError::Config(
                        "Connection not allowed due to isolation level".to_string()
                    ));
                }
            },
            _ => {}
        }

        // Validate service access
        if !dest.allowed_services.contains(service) {
            return Err(NetworkIsolationError::Config(
                format!("Service {} not allowed in destination segment", service)
            ));
        }

        // Update connection tracking
        self.active_connections
            .entry((source_segment.to_string(), dest_segment.to_string()))
            .and_modify(|count| *count += 1)
            .or_insert(1);

        self.metrics.record_connection_validated().await;
        Ok(())
    }

    pub async fn check_route(
        &self,
        source_ip: IpAddr,
        dest_ip: IpAddr,
    ) -> Result<(), NetworkIsolationError> {
        let source_segment = self.find_segment_for_ip(source_ip)?;
        let dest_segment = self.find_segment_for_ip(dest_ip)?;

        // Check if route is allowed
        if !source_segment.allowed_routes.iter().any(|net| net.contains(&dest_ip)) {
            return Err(NetworkIsolationError::Route(
                "Route not allowed".to_string()
            ));
        }

        self.metrics.record_route_checked().await;
        Ok(())
    }

    fn find_segment_for_ip(
        &self,
        ip: IpAddr,
    ) -> Result<NetworkSegment, NetworkIsolationError> {
        for entry in self.segments.iter() {
            if entry.network.contains(&ip) {
                return Ok(entry.clone());
            }
        }

        Err(NetworkIsolationError::InvalidSegment(
            format!("No segment found for IP: {}", ip)
        ))
    }

    async fn check_segment_health(&self, segment_id: &str) -> HealthState {
        let segment = match self.segments.get(segment_id) {
            Some(s) => s,
            None => return HealthState::Failed,
        };

        // Check connectivity within segment
        let mut errors = 0;
        for route in &segment.allowed_routes {
            if let Err(_) = self.validate_route(route).await {
                errors += 1;
            }
        }

        match errors {
            0 => HealthState::Healthy,
            1..=2 => HealthState::Degraded,
            _ => HealthState::Failed,
        }
    }

    async fn validate_route(&self, network: &IpNet) -> Result<(), NetworkIsolationError> {
        // Implement route validation logic
        Ok(())
    }

    fn start_sync_task(&self) {
        let segments = self.segments.clone();
        let metrics = self.metrics.clone();
        let error_handler = self.error_handler.clone();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(SYNC_INTERVAL);
            
            loop {
                interval.tick().await;
                
                // Sync segment configurations
                for segment in segments.iter() {
                    if let Err(e) = Self::sync_segment_config(&segment).await {
                        error_handler.handle_error(
                            e.into(),
                            "network_sync".to_string(),
                        ).await;
                    }
                }
                
                metrics.record_sync_completed().await;
            }
        });

        *self.sync_task.lock().unwrap() = Some(handle);
    }

    fn start_health_task(&self) {
        let segments = self.segments.clone();
        let health_status = self.health_status.clone();
        let metrics = self.metrics.clone();
        let error_handler = self.error_handler.clone();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(HEALTH_CHECK_INTERVAL);
            
            loop {
                interval.tick().await;
                
                for segment in segments.iter() {
                    let status = Self::check_segment_health(segment.id()).await;
                    health_status.insert(
                        segment.id().to_string(),
                        HealthStatus {
                            last_check: std::time::Instant::now(),
                            status,
                            error_count: 0,
                        },
                    );
                }
                
                metrics.record_health_check_completed().await;
            }
        });

        *self.health_task.lock().unwrap() = Some(handle);
    }
}

// Safe cleanup
impl Drop for NetworkIsolationManager {
    fn drop(&mut self) {
        if let Some(handle) = self.sync_task.lock().unwrap().take() {
            handle.abort();
        }
        if let Some(handle) = self.health_task.lock().unwrap().take() {
            handle.abort();
        }
    }
} 