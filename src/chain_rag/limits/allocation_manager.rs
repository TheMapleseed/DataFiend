use wasm_bindgen::prelude::*;
use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

// Firecracker VM memory constraints
const FIRECRACKER_MIN_MEMORY_MB: u64 = 64;  // Minimum memory per VM
const FIRECRACKER_MAX_MEMORY_MB: u64 = 24576; // Maximum memory (24GB per VM)
const FIRECRACKER_MEMORY_PAGE_SIZE: u64 = 4096; // 4KB page size
const MEMORY_OVERHEAD_FACTOR: f64 = 1.1; // 10% overhead for system operations

#[derive(Clone, Serialize, Deserialize)]
pub struct ResourceLimit {
    max_memory_mb: u64,
    max_instances: u32,
    max_concurrent_ops: u32,
    max_rate_per_second: f64,
    burst_allowance: u32,
    cooldown_seconds: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ResourceUsage {
    current_memory_bytes: u64,
    current_instances: u32,
    current_ops: u32,
    operation_timestamps: Vec<DateTime<Utc>>,
    last_burst_time: DateTime<Utc>,
    burst_count: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AllocationMetrics {
    memory_high_water: u64,
    max_concurrent_seen: u32,
    throttle_events: u32,
    allocation_failures: u32,
}

#[wasm_bindgen]
pub struct AllocationManager {
    limits: Arc<DashMap<String, ResourceLimit>>,
    usage: Arc<DashMap<String, ResourceUsage>>,
    metrics: Arc<DashMap<String, AllocationMetrics>>,
    global_memory_limit: u64,
    current_global_memory: Arc<RwLock<u64>>,
}

#[wasm_bindgen]
impl AllocationManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            limits: Arc::new(DashMap::new()),
            usage: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            global_memory_limit: FIRECRACKER_MAX_MEMORY_MB * 1024 * 1024, // Convert to bytes
            current_global_memory: Arc::new(RwLock::new(0)),
        }
    }

    #[wasm_bindgen]
    pub fn set_resource_limit(
        &self,
        resource_type: String,
        mut limit_config: ResourceLimit,
    ) -> Result<(), JsValue> {
        // Validate memory limits against Firecracker constraints
        if limit_config.max_memory_mb < FIRECRACKER_MIN_MEMORY_MB {
            return Err(JsValue::from_str(&format!(
                "Memory limit must be at least {}MB",
                FIRECRACKER_MIN_MEMORY_MB
            )));
        }

        if limit_config.max_memory_mb > FIRECRACKER_MAX_MEMORY_MB {
            return Err(JsValue::from_str(&format!(
                "Memory limit cannot exceed {}MB",
                FIRECRACKER_MAX_MEMORY_MB
            )));
        }

        // Align memory to page size
        limit_config.max_memory_mb = (limit_config.max_memory_mb * 1024 * 1024 / FIRECRACKER_MEMORY_PAGE_SIZE)
            * FIRECRACKER_MEMORY_PAGE_SIZE / 1024 / 1024;

        // Add overhead allowance
        let total_memory = (limit_config.max_memory_mb as f64 * MEMORY_OVERHEAD_FACTOR) as u64;
        if total_memory > FIRECRACKER_MAX_MEMORY_MB {
            return Err(JsValue::from_str(&format!(
                "Total memory with overhead cannot exceed {}MB",
                FIRECRACKER_MAX_MEMORY_MB
            )));
        }

        limit_config.max_memory_mb = total_memory;
        self.limits.insert(resource_type, limit_config);
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn request_allocation(
        &self,
        resource_type: String,
        requested_memory_mb: u64,
    ) -> Result<bool, JsValue> {
        // Validate against Firecracker constraints
        if requested_memory_mb < FIRECRACKER_MIN_MEMORY_MB {
            return Err(JsValue::from_str(&format!(
                "Requested memory must be at least {}MB",
                FIRECRACKER_MIN_MEMORY_MB
            )));
        }

        if requested_memory_mb > FIRECRACKER_MAX_MEMORY_MB {
            return Err(JsValue::from_str(&format!(
                "Requested memory cannot exceed {}MB",
                FIRECRACKER_MAX_MEMORY_MB
            )));
        }

        // Align to page size
        let aligned_memory = (requested_memory_mb * 1024 * 1024 / FIRECRACKER_MEMORY_PAGE_SIZE)
            * FIRECRACKER_MEMORY_PAGE_SIZE / 1024 / 1024;

        // Add overhead
        let total_memory = (aligned_memory as f64 * MEMORY_OVERHEAD_FACTOR) as u64;

        // Convert to bytes for internal tracking
        let memory_bytes = total_memory * 1024 * 1024;

        // Check global memory limit
        let current_global = *self.current_global_memory.read().await;
        if current_global + memory_bytes > self.global_memory_limit {
            self.update_metrics(&resource_type, "allocation_failures");
            return Ok(false);
        }

        // Get resource limits and usage
        let limit = self.limits.get(&resource_type)
            .ok_or_else(|| JsValue::from_str("No limits defined for resource type"))?;

        let mut usage = self.usage
            .entry(resource_type.clone())
            .or_insert_with(|| ResourceUsage {
                current_memory_bytes: 0,
                current_instances: 0,
                current_ops: 0,
                operation_timestamps: Vec::new(),
                last_burst_time: Utc::now(),
                burst_count: 0,
            });

        // Check memory limit
        if usage.current_memory_bytes + memory_bytes > limit.max_memory_mb as u64 {
            self.update_metrics(&resource_type, "allocation_failures");
            return Ok(false);
        }

        // Check instance limit
        if usage.current_instances >= limit.max_instances {
            self.update_metrics(&resource_type, "allocation_failures");
            return Ok(false);
        }

        // Check concurrent operations
        if usage.current_ops >= limit.max_concurrent_ops {
            self.update_metrics(&resource_type, "throttle_events");
            return Ok(false);
        }

        // Check rate limit
        let now = Utc::now();
        usage.operation_timestamps.retain(|&time| {
            (now - time).num_seconds() < 1
        });
        
        let current_rate = usage.operation_timestamps.len() as f64;
        if current_rate >= limit.max_rate_per_second {
            // Check burst allowance
            if (now - usage.last_burst_time).num_seconds() > limit.cooldown_seconds as i64 {
                usage.burst_count = 0;
                usage.last_burst_time = now;
            }

            if usage.burst_count >= limit.burst_allowance {
                self.update_metrics(&resource_type, "throttle_events");
                return Ok(false);
            }

            usage.burst_count += 1;
        }

        // Update usage
        usage.current_memory_bytes += memory_bytes;
        usage.current_instances += 1;
        usage.current_ops += 1;
        usage.operation_timestamps.push(now);

        // Update global memory
        *self.current_global_memory.write().await += memory_bytes;

        // Update metrics
        self.update_high_water_marks(&resource_type, &usage);

        Ok(true)
    }

    #[wasm_bindgen]
    pub async fn release_allocation(
        &self,
        resource_type: String,
        memory_bytes: u64,
    ) -> Result<(), JsValue> {
        if let Some(mut usage) = self.usage.get_mut(&resource_type) {
            usage.current_memory_bytes = usage.current_memory_bytes.saturating_sub(memory_bytes);
            usage.current_instances = usage.current_instances.saturating_sub(1);
            usage.current_ops = usage.current_ops.saturating_sub(1);

            // Update global memory
            let mut global_memory = self.current_global_memory.write().await;
            *global_memory = global_memory.saturating_sub(memory_bytes);
        }
        Ok(())
    }

    fn update_metrics(&self, resource_type: &str, metric_type: &str) {
        self.metrics
            .entry(resource_type.to_string())
            .or_insert_with(|| AllocationMetrics {
                memory_high_water: 0,
                max_concurrent_seen: 0,
                throttle_events: 0,
                allocation_failures: 0,
            })
            .and_modify(|m| {
                match metric_type {
                    "throttle_events" => m.throttle_events += 1,
                    "allocation_failures" => m.allocation_failures += 1,
                    _ => {}
                }
            });
    }

    fn update_high_water_marks(&self, resource_type: &str, usage: &ResourceUsage) {
        self.metrics
            .entry(resource_type.to_string())
            .or_insert_with(|| AllocationMetrics {
                memory_high_water: 0,
                max_concurrent_seen: 0,
                throttle_events: 0,
                allocation_failures: 0,
            })
            .and_modify(|m| {
                m.memory_high_water = m.memory_high_water.max(usage.current_memory_bytes);
                m.max_concurrent_seen = m.max_concurrent_seen.max(usage.current_ops);
            });
    }

    #[wasm_bindgen]
    pub fn get_resource_usage(&self, resource_type: String) -> Result<JsValue, JsValue> {
        if let Some(usage) = self.usage.get(&resource_type) {
            Ok(serde_wasm_bindgen::to_value(&*usage)?)
        } else {
            Err(JsValue::from_str("No usage data found"))
        }
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self, resource_type: String) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get(&resource_type) {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Err(JsValue::from_str("No metrics found"))
        }
    }
}

impl Drop for AllocationManager {
    fn drop(&mut self) {
        // Clear all allocations and metrics
        self.usage.clear();
        self.metrics.clear();
        self.limits.clear();
    }
}
