use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque};

const HEALTH_CHECK_INTERVAL_MS: u64 = 1000;
const HISTORY_WINDOW_SECS: u64 = 3600;
const ALERT_CHANNEL_SIZE: usize = 1000;
const MAX_INCIDENTS: usize = 1000;

#[derive(Clone, Serialize, Deserialize)]
pub struct HealthMetrics {
    system_status: SystemStatus,
    component_status: HashMap<String, ComponentHealth>,
    resource_utilization: ResourceMetrics,
    incident_count: u64,
    last_incident: Option<HealthIncident>,
    uptime_percentage: f64,
    degraded_services: Vec<String>,
    health_score: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ComponentHealth {
    status: HealthStatus,
    last_check: u64,
    error_rate: f64,
    response_time_ms: f64,
    resource_usage: f64,
    dependencies: Vec<String>,
    incidents: VecDeque<HealthIncident>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ResourceMetrics {
    cpu_usage: f64,
    memory_usage: f64,
    disk_usage: f64,
    network_latency: f64,
    thread_count: u32,
    open_connections: u32,
    queue_depth: u32,
    io_wait: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HealthIncident {
    id: String,
    component: String,
    severity: Severity,
    timestamp: u64,
    description: String,
    resolution: Option<String>,
    duration_ms: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SystemStatus {
    Healthy,
    Degraded,
    Critical,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum HealthStatus {
    Up,
    Degraded,
    Down,
    Unknown,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Severity {
    Critical,
    High,
    Medium,
    Low,
}

#[wasm_bindgen]
pub struct HealthMonitor {
    metrics: Arc<DashMap<String, HealthMetrics>>,
    components: Arc<DashMap<String, ComponentHealth>>,
    incidents: Arc<RwLock<VecDeque<HealthIncident>>>,
    alert_tx: Arc<broadcast::Sender<HealthIncident>>,
    thresholds: Arc<DashMap<String, f64>>,
}

#[wasm_bindgen]
impl HealthMonitor {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let (alert_tx, _) = broadcast::channel(ALERT_CHANNEL_SIZE);
        
        let monitor = Self {
            metrics: Arc::new(DashMap::new()),
            components: Arc::new(DashMap::new()),
            incidents: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_INCIDENTS))),
            alert_tx: Arc::new(alert_tx),
            thresholds: Arc::new(DashMap::new()),
        };

        monitor.initialize_thresholds();
        monitor.start_monitoring_tasks();
        monitor
    }

    fn initialize_thresholds(&self) {
        let defaults = [
            ("cpu_threshold", 0.8),
            ("memory_threshold", 0.85),
            ("error_rate_threshold", 0.1),
            ("latency_threshold", 1000.0),
            ("resource_threshold", 0.9),
        ];

        for (key, value) in defaults {
            self.thresholds.insert(key.to_string(), value);
        }
    }

    #[wasm_bindgen]
    pub async fn update_component_health(
        &self,
        component: String,
        metrics: JsValue,
    ) -> Result<(), JsValue> {
        let health_data: ComponentHealth = serde_wasm_bindgen::from_value(metrics)?;
        let timestamp = get_timestamp()?;

        // Update component health
        self.components
            .entry(component.clone())
            .and_modify(|h| {
                h.status = health_data.status;
                h.last_check = timestamp;
                h.error_rate = health_data.error_rate;
                h.response_time_ms = health_data.response_time_ms;
                h.resource_usage = health_data.resource_usage;
                h.dependencies = health_data.dependencies.clone();
            })
            .or_insert(health_data.clone());

        // Check for incidents
        self.check_component_health(&component, &health_data).await?;

        // Update system health
        self.update_system_health().await?;

        Ok(())
    }

    async fn check_component_health(
        &self,
        component: &str,
        health: &ComponentHealth,
    ) -> Result<(), JsValue> {
        let mut incidents = Vec::new();

        // Check error rate
        if health.error_rate > self.thresholds.get("error_rate_threshold").unwrap().to_owned() {
            incidents.push(HealthIncident {
                id: generate_incident_id(),
                component: component.to_string(),
                severity: Severity::High,
                timestamp: get_timestamp()?,
                description: format!("High error rate: {:.2}%", health.error_rate * 100.0),
                resolution: None,
                duration_ms: None,
            });
        }

        // Check response time
        if health.response_time_ms > self.thresholds.get("latency_threshold").unwrap().to_owned() {
            incidents.push(HealthIncident {
                id: generate_incident_id(),
                component: component.to_string(),
                severity: Severity::Medium,
                timestamp: get_timestamp()?,
                description: format!("High latency: {:.2}ms", health.response_time_ms),
                resolution: None,
                duration_ms: None,
            });
        }

        // Check resource usage
        if health.resource_usage > self.thresholds.get("resource_threshold").unwrap().to_owned() {
            incidents.push(HealthIncident {
                id: generate_incident_id(),
                component: component.to_string(),
                severity: Severity::High,
                timestamp: get_timestamp()?,
                description: format!("High resource usage: {:.2}%", health.resource_usage * 100.0),
                resolution: None,
                duration_ms: None,
            });
        }

        // Record and alert incidents
        for incident in incidents {
            self.record_incident(incident).await?;
        }

        Ok(())
    }

    async fn record_incident(
        &self,
        incident: HealthIncident,
    ) -> Result<(), JsValue> {
        // Store incident
        let mut incidents = self.incidents.write().await;
        incidents.push_back(incident.clone());

        // Maintain history limit
        while incidents.len() > MAX_INCIDENTS {
            incidents.pop_front();
        }

        // Send alert
        if let Err(e) = self.alert_tx.send(incident.clone()) {
            web_sys::console::error_1(&JsValue::from_str(
                &format!("Alert sending error: {}", e)
            ));
        }

        // Update component incidents
        if let Some(mut component) = self.components.get_mut(&incident.component) {
            component.incidents.push_back(incident);
            while component.incidents.len() > 100 {
                component.incidents.pop_front();
            }
        }

        Ok(())
    }

    async fn update_system_health(&self) -> Result<(), JsValue> {
        let components: Vec<_> = self.components.iter().map(|c| c.clone()).collect();
        let timestamp = get_timestamp()?;

        let mut degraded_services = Vec::new();
        let mut total_score = 0.0;
        let mut critical_components = 0;

        for component in &components {
            if component.status == HealthStatus::Degraded {
                degraded_services.push(component.key().clone());
            } else if component.status == HealthStatus::Down {
                critical_components += 1;
            }
            
            total_score += calculate_component_score(component);
        }

        let system_status = if critical_components > 0 {
            SystemStatus::Critical
        } else if !degraded_services.is_empty() {
            SystemStatus::Degraded
        } else {
            SystemStatus::Healthy
        };

        let health_score = if components.is_empty() {
            0.0
        } else {
            total_score / components.len() as f64
        };

        // Update metrics
        self.metrics
            .entry("global".to_string())
            .and_modify(|m| {
                m.system_status = system_status;
                m.degraded_services = degraded_services.clone();
                m.health_score = health_score;
                
                let component_status: HashMap<_, _> = components.iter()
                    .map(|c| (c.key().clone(), c.value().clone()))
                    .collect();
                m.component_status = component_status;
            })
            .or_insert_with(|| HealthMetrics {
                system_status,
                component_status: components.iter()
                    .map(|c| (c.key().clone(), c.value().clone()))
                    .collect(),
                resource_utilization: ResourceMetrics {
                    cpu_usage: 0.0,
                    memory_usage: 0.0,
                    disk_usage: 0.0,
                    network_latency: 0.0,
                    thread_count: 0,
                    open_connections: 0,
                    queue_depth: 0,
                    io_wait: 0.0,
                },
                incident_count: 0,
                last_incident: None,
                uptime_percentage: 100.0,
                degraded_services,
                health_score,
            });

        Ok(())
    }

    fn start_monitoring_tasks(&self) {
        let monitor = Arc::new(self.clone());

        // Health check task
        tokio::spawn({
            let monitor = monitor.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(HEALTH_CHECK_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    if let Err(e) = monitor.perform_health_check().await {
                        web_sys::console::error_1(&e);
                    }
                }
            }
        });

        // Cleanup task
        tokio::spawn({
            let monitor = monitor.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    monitor.cleanup_old_incidents().await;
                }
            }
        });
    }

    async fn perform_health_check(&self) -> Result<(), JsValue> {
        let resource_metrics = self.collect_resource_metrics().await?;
        
        self.metrics
            .entry("global".to_string())
            .and_modify(|m| {
                m.resource_utilization = resource_metrics.clone();
            });

        // Check resource thresholds
        if resource_metrics.cpu_usage > self.thresholds.get("cpu_threshold").unwrap().to_owned() {
            self.record_incident(HealthIncident {
                id: generate_incident_id(),
                component: "system".to_string(),
                severity: Severity::High,
                timestamp: get_timestamp()?,
                description: format!("High CPU usage: {:.2}%", resource_metrics.cpu_usage * 100.0),
                resolution: None,
                duration_ms: None,
            }).await?;
        }

        if resource_metrics.memory_usage > self.thresholds.get("memory_threshold").unwrap().to_owned() {
            self.record_incident(HealthIncident {
                id: generate_incident_id(),
                component: "system".to_string(),
                severity: Severity::High,
                timestamp: get_timestamp()?,
                description: format!("High memory usage: {:.2}%", resource_metrics.memory_usage * 100.0),
                resolution: None,
                duration_ms: None,
            }).await?;
        }

        Ok(())
    }

    async fn collect_resource_metrics(&self) -> Result<ResourceMetrics, JsValue> {
        // Collect system metrics
        Ok(ResourceMetrics {
            cpu_usage: web_sys::window()
                .ok_or_else(|| JsValue::from_str("No window object"))?
                .navigator()
                .hardware_concurrency() as f64,
            memory_usage: 0.0, // Add actual memory usage collection
            disk_usage: 0.0,   // Add actual disk usage collection
            network_latency: 0.0,
            thread_count: 0,
            open_connections: 0,
            queue_depth: 0,
            io_wait: 0.0,
        })
    }

    async fn cleanup_old_incidents(&self) {
        let cutoff = get_timestamp().unwrap_or(0) - HISTORY_WINDOW_SECS;
        
        let mut incidents = self.incidents.write().await;
        while let Some(incident) = incidents.front() {
            if incident.timestamp < cutoff {
                incidents.pop_front();
            } else {
                break;
            }
        }
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&HealthMetrics {
                system_status: SystemStatus::Unknown,
                component_status: HashMap::new(),
                resource_utilization: ResourceMetrics {
                    cpu_usage: 0.0,
                    memory_usage: 0.0,
                    disk_usage: 0.0,
                    network_latency: 0.0,
                    thread_count: 0,
                    open_connections: 0,
                    queue_depth: 0,
                    io_wait: 0.0,
                },
                incident_count: 0,
                last_incident: None,
                uptime_percentage: 0.0,
                degraded_services: Vec::new(),
                health_score: 0.0,
            })?)
        }
    }
}

fn calculate_component_score(component: &dashmap::mapref::one::Ref<'_, String, ComponentHealth>) -> f64 {
    let status_score = match component.status {
        HealthStatus::Up => 1.0,
        HealthStatus::Degraded => 0.5,
        HealthStatus::Down => 0.0,
        HealthStatus::Unknown => 0.0,
    };

    let error_score = 1.0 - component.error_rate;
    let resource_score = 1.0 - component.resource_usage;
    
    (status_score + error_score + resource_score) / 3.0
}

fn generate_incident_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("INC-{:016x}", rng.gen::<u64>())
}

fn get_timestamp() -> Result<u64, JsValue> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for HealthMonitor {
    fn drop(&mut self) {
        self.metrics.clear();
        self.components.clear();
    }
}
