use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, Semaphore};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque, HashSet};

const MAX_RESOURCE_HISTORY: usize = 1000;
const TRACKING_INTERVAL_MS: u64 = 100;
const MAX_CONCURRENT_TRACKERS: usize = 50;
const RESOURCE_EXPIRY_SECS: u64 = 3600;

#[derive(Clone, Serialize, Deserialize)]
pub struct ResourceTracker {
    resource_id: String,
    resource_type: ResourceType,
    allocation_time: u64,
    last_access: u64,
    state: ResourceState,
    metrics: ResourceMetrics,
    dependencies: Vec<String>,
    owner: String,
    tags: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ResourceMetrics {
    usage_count: u64,
    peak_memory_bytes: usize,
    average_latency_ms: f64,
    error_count: u64,
    last_error: Option<String>,
    performance_score: f64,
    health_score: f64,
    utilization_percentage: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TrackingEvent {
    event_id: String,
    resource_id: String,
    event_type: EventType,
    timestamp: u64,
    data: HashMap<String, String>,
    impact_score: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ResourceSnapshot {
    snapshot_id: String,
    resource_id: String,
    timestamp: u64,
    state_data: HashMap<String, String>,
    metrics: ResourceMetrics,
    health_status: HealthStatus,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TrackerMetrics {
    total_resources: u64,
    active_resources: u64,
    resource_usage: HashMap<ResourceType, ResourceTypeMetrics>,
    error_rates: HashMap<String, f64>,
    performance_patterns: Vec<PerformancePattern>,
    resource_distribution: HashMap<String, u64>,
    health_scores: HashMap<String, f64>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    Memory,
    CPU,
    Network,
    Storage,
    Database,
    Cache,
    Thread,
    Connection,
    File,
    Service,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ResourceState {
    Active,
    Idle,
    Degraded,
    Failed,
    Terminated,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum EventType {
    Allocation,
    Access,
    Modification,
    Error,
    Performance,
    Security,
    Lifecycle,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum HealthStatus {
    Healthy,
    Warning,
    Critical,
    Unknown,
}

#[derive(Clone, Serialize, Deserialize)]
struct ResourceTypeMetrics {
    count: u64,
    average_lifetime_secs: f64,
    error_rate: f64,
    utilization: f64,
    cost_score: f64,
}

#[derive(Clone, Serialize, Deserialize)]
struct PerformancePattern {
    pattern_id: String,
    resource_type: ResourceType,
    frequency: u32,
    impact_score: f64,
    average_duration_ms: f64,
}

#[wasm_bindgen]
pub struct ResourceTrackingManager {
    resources: Arc<DashMap<String, ResourceTracker>>,
    events: Arc<DashMap<String, VecDeque<TrackingEvent>>>,
    snapshots: Arc<DashMap<String, VecDeque<ResourceSnapshot>>>,
    metrics: Arc<DashMap<String, TrackerMetrics>>,
    tracker_semaphore: Arc<Semaphore>,
    notification_tx: Arc<broadcast::Sender<TrackingEvent>>,
    active_trackers: Arc<RwLock<HashSet<String>>>,
}

#[wasm_bindgen]
impl ResourceTrackingManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let (notification_tx, _) = broadcast::channel(1000);
        
        let manager = Self {
            resources: Arc::new(DashMap::new()),
            events: Arc::new(DashMap::new()),
            snapshots: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            tracker_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_TRACKERS)),
            notification_tx: Arc::new(notification_tx),
            active_trackers: Arc::new(RwLock::new(HashSet::new())),
        };

        manager.start_tracking_tasks();
        manager
    }

    #[wasm_bindgen]
    pub async fn track_resource(
        &self,
        resource_type: u32,
        owner: String,
        tags: JsValue,
    ) -> Result<String, JsValue> {
        let resource_type = unsafe { std::mem::transmute(resource_type) };
        let tags: HashMap<String, String> = serde_wasm_bindgen::from_value(tags)?;
        
        let _permit = self.tracker_semaphore.acquire().await.map_err(|e| {
            JsValue::from_str(&format!("Failed to acquire tracker permit: {}", e))
        })?;

        let resource_id = generate_resource_id();
        let timestamp = get_timestamp()?;

        let resource = ResourceTracker {
            resource_id: resource_id.clone(),
            resource_type,
            allocation_time: timestamp,
            last_access: timestamp,
            state: ResourceState::Active,
            metrics: ResourceMetrics {
                usage_count: 0,
                peak_memory_bytes: 0,
                average_latency_ms: 0.0,
                error_count: 0,
                last_error: None,
                performance_score: 1.0,
                health_score: 1.0,
                utilization_percentage: 0.0,
            },
            dependencies: Vec::new(),
            owner,
            tags,
        };

        self.resources.insert(resource_id.clone(), resource.clone());
        self.record_event(
            &resource_id,
            EventType::Allocation,
            HashMap::new(),
            0.0,
        ).await?;

        self.active_trackers.write().await.insert(resource_id.clone());
        
        Ok(resource_id)
    }

    #[wasm_bindgen]
    pub async fn update_resource_metrics(
        &self,
        resource_id: String,
        metrics: JsValue,
    ) -> Result<(), JsValue> {
        let metrics: ResourceMetrics = serde_wasm_bindgen::from_value(metrics)?;
        
        if let Some(mut resource) = self.resources.get_mut(&resource_id) {
            resource.metrics = metrics;
            resource.last_access = get_timestamp()?;
            
            self.create_snapshot(&resource_id).await?;
        }

        Ok(())
    }

    async fn record_event(
        &self,
        resource_id: &str,
        event_type: EventType,
        data: HashMap<String, String>,
        impact_score: f64,
    ) -> Result<(), JsValue> {
        let event = TrackingEvent {
            event_id: generate_event_id(),
            resource_id: resource_id.to_string(),
            event_type,
            timestamp: get_timestamp()?,
            data,
            impact_score,
        };

        self.events
            .entry(resource_id.to_string())
            .or_insert_with(|| VecDeque::with_capacity(MAX_RESOURCE_HISTORY))
            .push_back(event.clone());

        self.notify_event(event).await?;
        Ok(())
    }

    async fn create_snapshot(&self, resource_id: &str) -> Result<(), JsValue> {
        if let Some(resource) = self.resources.get(resource_id) {
            let snapshot = ResourceSnapshot {
                snapshot_id: generate_snapshot_id(),
                resource_id: resource_id.to_string(),
                timestamp: get_timestamp()?,
                state_data: HashMap::new(), // Implement state data collection
                metrics: resource.metrics.clone(),
                health_status: self.calculate_health_status(&resource),
            };

            self.snapshots
                .entry(resource_id.to_string())
                .or_insert_with(|| VecDeque::with_capacity(MAX_RESOURCE_HISTORY))
                .push_back(snapshot);
        }

        Ok(())
    }

    fn calculate_health_status(&self, resource: &ResourceTracker) -> HealthStatus {
        if resource.metrics.health_score >= 0.8 {
            HealthStatus::Healthy
        } else if resource.metrics.health_score >= 0.5 {
            HealthStatus::Warning
        } else {
            HealthStatus::Critical
        }
    }

    async fn notify_event(&self, event: TrackingEvent) -> Result<(), JsValue> {
        if let Err(e) = self.notification_tx.send(event) {
            return Err(JsValue::from_str(&format!("Notification error: {}", e)));
        }
        Ok(())
    }

    fn start_tracking_tasks(&self) {
        let manager = Arc::new(self.clone());

        // Metrics update task
        tokio::spawn({
            let manager = manager.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(TRACKING_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    manager.update_tracking_metrics().await;
                }
            }
        });

        // Cleanup task
        tokio::spawn({
            let manager = manager.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    manager.cleanup_old_resources().await;
                }
            }
        });
    }

    async fn update_tracking_metrics(&self) {
        let mut total_resources = 0;
        let mut active_resources = 0;
        let mut resource_usage = HashMap::new();
        let mut error_rates = HashMap::new();
        let mut health_scores = HashMap::new();

        for resource in self.resources.iter() {
            total_resources += 1;
            if resource.state == ResourceState::Active {
                active_resources += 1;
            }

            let type_metrics = resource_usage
                .entry(resource.resource_type)
                .or_insert_with(|| ResourceTypeMetrics {
                    count: 0,
                    average_lifetime_secs: 0.0,
                    error_rate: 0.0,
                    utilization: 0.0,
                    cost_score: 0.0,
                });

            type_metrics.count += 1;
            type_metrics.error_rate = resource.metrics.error_count as f64
                / resource.metrics.usage_count.max(1) as f64;
            type_metrics.utilization = resource.metrics.utilization_percentage;

            error_rates.insert(
                resource.resource_id.clone(),
                resource.metrics.error_count as f64 / resource.metrics.usage_count.max(1) as f64,
            );

            health_scores.insert(
                resource.resource_id.clone(),
                resource.metrics.health_score,
            );
        }

        self.metrics
            .entry("global".to_string())
            .and_modify(|m| {
                m.total_resources = total_resources;
                m.active_resources = active_resources;
                m.resource_usage = resource_usage;
                m.error_rates = error_rates;
                m.health_scores = health_scores;
            })
            .or_insert_with(|| TrackerMetrics {
                total_resources,
                active_resources,
                resource_usage,
                error_rates,
                performance_patterns: Vec::new(),
                resource_distribution: HashMap::new(),
                health_scores,
            });
    }

    async fn cleanup_old_resources(&self) {
        let cutoff = get_timestamp().unwrap_or(0) - RESOURCE_EXPIRY_SECS;
        
        let mut active_trackers = self.active_trackers.write().await;
        let mut to_remove = Vec::new();

        for resource_id in active_trackers.iter() {
            if let Some(resource) = self.resources.get(resource_id) {
                if resource.last_access < cutoff {
                    to_remove.push(resource_id.clone());
                }
            }
        }

        for resource_id in to_remove {
            active_trackers.remove(&resource_id);
            self.resources.remove(&resource_id);
            self.events.remove(&resource_id);
            self.snapshots.remove(&resource_id);
        }
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&TrackerMetrics {
                total_resources: 0,
                active_resources: 0,
                resource_usage: HashMap::new(),
                error_rates: HashMap::new(),
                performance_patterns: Vec::new(),
                resource_distribution: HashMap::new(),
                health_scores: HashMap::new(),
            })?)
        }
    }
}

fn generate_resource_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("RESOURCE-{:016x}", rng.gen::<u64>())
}

fn generate_event_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("EVENT-{:016x}", rng.gen::<u64>())
}

fn generate_snapshot_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("SNAPSHOT-{:016x}", rng.gen::<u64>())
}

fn get_timestamp() -> Result<u64, JsValue> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for ResourceTrackingManager {
    fn drop(&mut self) {
        self.resources.clear();
        self.events.clear();
        self.snapshots.clear();
        self.metrics.clear();
    }
} 