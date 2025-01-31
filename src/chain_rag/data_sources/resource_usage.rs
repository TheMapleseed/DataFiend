use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use dashmap::DashMap;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsageSource {
    usage_buffer: Arc<RwLock<Vec<ResourcePoint>>>,
    active_resources: Arc<DashMap<String, ResourceState>>,
    allocation_history: Arc<RwLock<Vec<AllocationEvent>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePoint {
    timestamp: DateTime<Utc>,
    resource_type: ResourceType,
    usage: ResourceUsage,
    allocation: ResourceAllocation,
    performance_metrics: ResourcePerformance,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceState {
    resource_id: String,
    current_usage: ResourceUsage,
    allocation: ResourceAllocation,
    last_updated: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    memory_mb: u64,
    cpu_percent: f64,
    disk_mb: u64,
    network_kbps: u64,
    threads: u32,
    connections: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourceAllocation {
    memory_limit_mb: u64,
    cpu_limit_percent: f64,
    disk_limit_mb: u64,
    network_limit_kbps: u64,
    thread_limit: u32,
    connection_limit: u32,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ResourcePerformance {
    latency_ms: f64,
    throughput: f64,
    error_rate: f64,
    saturation: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AllocationEvent {
    timestamp: DateTime<Utc>,
    resource_id: String,
    event_type: AllocationEventType,
    previous: Option<ResourceAllocation>,
    new: Option<ResourceAllocation>,
    reason: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum ResourceType {
    Container,
    Database,
    Cache,
    Queue,
    Storage,
    Compute,
    Network,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum AllocationEventType {
    Created,
    Updated,
    Scaled,
    Released,
    Failed,
}

impl ResourceUsageSource {
    pub fn new() -> Self {
        Self {
            usage_buffer: Arc::new(RwLock::new(Vec::with_capacity(1000))),
            active_resources: Arc::new(DashMap::new()),
            allocation_history: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub async fn record_usage(&self, 
        resource_id: &str, 
        resource_type: ResourceType,
        usage: ResourceUsage,
        performance: ResourcePerformance
    ) {
        let resource = self.active_resources
            .get(resource_id)
            .map(|r| r.clone());

        if let Some(resource_state) = resource {
            let point = ResourcePoint {
                timestamp: Utc::now(),
                resource_type,
                usage,
                allocation: resource_state.allocation,
                performance_metrics: performance,
            };

            let mut buffer = self.usage_buffer.write().await;
            buffer.push(point);

            // Update active resource state
            self.active_resources.insert(resource_id.to_string(), ResourceState {
                resource_id: resource_id.to_string(),
                current_usage: usage,
                allocation: resource_state.allocation,
                last_updated: Utc::now(),
            });

            // Trim buffer if needed
            if buffer.len() > 1000 {
                buffer.drain(0..100);
            }
        }
    }

    pub async fn record_allocation_event(&self, event: AllocationEvent) {
        let mut history = self.allocation_history.write().await;
        history.push(event.clone());

        match event.event_type {
            AllocationEventType::Created | AllocationEventType::Updated | AllocationEventType::Scaled => {
                if let Some(new_allocation) = event.new {
                    self.active_resources.insert(event.resource_id.clone(), ResourceState {
                        resource_id: event.resource_id,
                        current_usage: ResourceUsage {
                            memory_mb: 0,
                            cpu_percent: 0.0,
                            disk_mb: 0,
                            network_kbps: 0,
                            threads: 0,
                            connections: 0,
                        },
                        allocation: new_allocation,
                        last_updated: Utc::now(),
                    });
                }
            },
            AllocationEventType::Released => {
                self.active_resources.remove(&event.resource_id);
            },
            AllocationEventType::Failed => {
                // Log failure but maintain current state
            }
        }
    }

    pub async fn get_resource_metrics(&self, resource_id: &str, duration: chrono::Duration) -> Vec<ResourcePoint> {
        let cutoff = Utc::now() - duration;
        let buffer = self.usage_buffer.read().await;
        
        buffer.iter()
            .filter(|point| point.timestamp > cutoff)
            .cloned()
            .collect()
    }

    pub async fn get_allocation_history(&self, resource_id: &str) -> Vec<AllocationEvent> {
        let history = self.allocation_history.read().await;
        
        history.iter()
            .filter(|event| event.resource_id == resource_id)
            .cloned()
            .collect()
    }

    pub fn get_current_state(&self, resource_id: &str) -> Option<ResourceState> {
        self.active_resources.get(resource_id).map(|r| r.clone())
    }

    pub async fn get_usage_patterns(&self) -> Vec<ResourcePoint> {
        self.usage_buffer.read().await.clone()
    }
}

// CoRAG integration for resource usage analysis
impl crate::corag::CoRAG {
    pub async fn analyze_resource_patterns(&self) -> Result<(), crate::error::error_system::SystemError> {
        let resource_source = self.get_resource_source();
        let usage_patterns = resource_source.get_usage_patterns().await;

        // Analyze resource usage patterns
        self.learn_from_resource_usage(&usage_patterns).await?;

        // Optimize resource allocations based on learned patterns
        self.optimize_resource_allocations().await?;

        Ok(())
    }
} 