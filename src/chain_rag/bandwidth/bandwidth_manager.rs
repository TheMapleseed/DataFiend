use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, Semaphore};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque, HashSet};
use tokio::time::sleep;

const MAX_BANDWIDTH_MBPS: u64 = 10000;
const BUCKET_UPDATE_INTERVAL_MS: u64 = 10;
const MAX_BURST_SIZE_MB: u64 = 100;
const MAX_CONCURRENT_STREAMS: usize = 1000;

#[derive(Clone, Serialize, Deserialize)]
pub struct BandwidthManager {
    channel_id: String,
    token_bucket: TokenBucket,
    qos_policy: QoSPolicy,
    shaping_rules: Vec<ShapingRule>,
    metrics: BandwidthMetrics,
    allocations: HashMap<String, Allocation>,
    priorities: HashMap<String, u32>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TokenBucket {
    capacity_bytes: u64,
    tokens: f64,
    rate_bytes_sec: f64,
    last_update: u64,
    burst_size_bytes: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QoSPolicy {
    min_bandwidth_mbps: u64,
    max_bandwidth_mbps: u64,
    target_latency_ms: u64,
    priority_levels: u32,
    fairness_factor: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ShapingRule {
    rule_id: String,
    condition: ShapingCondition,
    action: ShapingAction,
    priority: u32,
    enabled: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BandwidthMetrics {
    current_usage_mbps: f64,
    peak_usage_mbps: f64,
    average_latency_ms: f64,
    dropped_packets: u64,
    throttled_streams: u64,
    qos_violations: u64,
    utilization_percentage: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Allocation {
    stream_id: String,
    allocated_bandwidth_mbps: u64,
    priority: u32,
    start_time: u64,
    last_active: u64,
    bytes_transferred: u64,
    current_rate_mbps: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StreamMetrics {
    throughput_mbps: f64,
    latency_ms: f64,
    packet_loss: f64,
    jitter_ms: f64,
    buffer_occupancy: f64,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ShapingCondition {
    UsageAbove(f64),
    LatencyAbove(u64),
    CongestionDetected,
    PriorityBelow(u32),
    Custom(String),
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ShapingAction {
    Throttle(f64),
    Prioritize(u32),
    DropPackets(f64),
    RescheduleStream,
    ApplyQoS,
}

#[wasm_bindgen]
pub struct BandwidthController {
    managers: Arc<DashMap<String, BandwidthManager>>,
    metrics: Arc<DashMap<String, BandwidthMetrics>>,
    stream_semaphore: Arc<Semaphore>,
    notification_tx: Arc<broadcast::Sender<BandwidthEvent>>,
    active_streams: Arc<RwLock<HashSet<String>>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct BandwidthEvent {
    event_id: String,
    stream_id: String,
    event_type: BandwidthEventType,
    timestamp: u64,
    details: HashMap<String, String>,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum BandwidthEventType {
    Throttled,
    Released,
    QoSViolation,
    Congestion,
    Shaped,
}

#[wasm_bindgen]
impl BandwidthController {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let (notification_tx, _) = broadcast::channel(1000);
        
        let controller = Self {
            managers: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            stream_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_STREAMS)),
            notification_tx: Arc::new(notification_tx),
            active_streams: Arc::new(RwLock::new(HashSet::new())),
        };

        controller.start_bandwidth_tasks();
        controller
    }

    #[wasm_bindgen]
    pub async fn allocate_bandwidth(
        &self,
        request: JsValue,
    ) -> Result<JsValue, JsValue> {
        let allocation_request: AllocationRequest = serde_wasm_bindgen::from_value(request)?;
        
        let _permit = self.stream_semaphore.acquire().await
            .map_err(|e| JsValue::from_str(&format!("Failed to acquire permit: {}", e)))?;

        // Check available bandwidth
        if !self.has_available_bandwidth(&allocation_request).await? {
            return Err(JsValue::from_str("Insufficient bandwidth"));
        }

        // Create allocation
        let allocation = self.create_allocation(&allocation_request).await?;
        
        // Apply QoS policies
        self.apply_qos_policies(&allocation).await?;

        // Update metrics
        self.update_allocation_metrics(&allocation).await?;

        Ok(serde_wasm_bindgen::to_value(&allocation)?)
    }

    async fn has_available_bandwidth(
        &self,
        request: &AllocationRequest,
    ) -> Result<bool, JsValue> {
        if let Some(manager) = self.managers.get(&request.channel_id) {
            let current_usage = manager.metrics.current_usage_mbps;
            let requested = request.bandwidth_mbps as f64;
            
            Ok(current_usage + requested <= manager.qos_policy.max_bandwidth_mbps as f64)
        } else {
            Ok(false)
        }
    }

    async fn create_allocation(
        &self,
        request: &AllocationRequest,
    ) -> Result<Allocation, JsValue> {
        let timestamp = get_timestamp()?;
        
        let allocation = Allocation {
            stream_id: generate_stream_id(),
            allocated_bandwidth_mbps: request.bandwidth_mbps,
            priority: request.priority,
            start_time: timestamp,
            last_active: timestamp,
            bytes_transferred: 0,
            current_rate_mbps: 0.0,
        };

        if let Some(mut manager) = self.managers.get_mut(&request.channel_id) {
            manager.allocations.insert(allocation.stream_id.clone(), allocation.clone());
        }

        Ok(allocation)
    }

    async fn apply_qos_policies(
        &self,
        allocation: &Allocation,
    ) -> Result<(), JsValue> {
        // Apply QoS policies based on priority and current conditions
        if let Some(manager) = self.managers.get(&allocation.stream_id) {
            for rule in &manager.shaping_rules {
                if !rule.enabled {
                    continue;
                }

                if self.evaluate_shaping_condition(&rule.condition, allocation).await? {
                    self.apply_shaping_action(&rule.action, allocation).await?;
                }
            }
        }
        Ok(())
    }

    async fn evaluate_shaping_condition(
        &self,
        condition: &ShapingCondition,
        allocation: &Allocation,
    ) -> Result<bool, JsValue> {
        match condition {
            ShapingCondition::UsageAbove(threshold) => {
                Ok(allocation.current_rate_mbps > *threshold)
            }
            ShapingCondition::LatencyAbove(threshold) => {
                if let Some(metrics) = self.get_stream_metrics(&allocation.stream_id).await? {
                    Ok(metrics.latency_ms > *threshold as f64)
                } else {
                    Ok(false)
                }
            }
            ShapingCondition::CongestionDetected => {
                self.is_congested(&allocation.stream_id).await
            }
            ShapingCondition::PriorityBelow(threshold) => {
                Ok(allocation.priority < *threshold)
            }
            ShapingCondition::Custom(_) => {
                // Implement custom condition evaluation
                Ok(false)
            }
        }
    }

    async fn apply_shaping_action(
        &self,
        action: &ShapingAction,
        allocation: &Allocation,
    ) -> Result<(), JsValue> {
        match action {
            ShapingAction::Throttle(rate) => {
                self.throttle_stream(&allocation.stream_id, *rate).await?;
            }
            ShapingAction::Prioritize(level) => {
                self.update_priority(&allocation.stream_id, *level).await?;
            }
            ShapingAction::DropPackets(percentage) => {
                self.apply_packet_drop(&allocation.stream_id, *percentage).await?;
            }
            ShapingAction::RescheduleStream => {
                self.reschedule_stream(&allocation.stream_id).await?;
            }
            ShapingAction::ApplyQoS => {
                self.apply_qos(&allocation.stream_id).await?;
            }
        }
        Ok(())
    }

    async fn update_allocation_metrics(
        &self,
        allocation: &Allocation,
    ) -> Result<(), JsValue> {
        if let Some(mut manager) = self.managers.get_mut(&allocation.stream_id) {
            manager.metrics.current_usage_mbps += allocation.allocated_bandwidth_mbps as f64;
            manager.metrics.peak_usage_mbps = manager.metrics.peak_usage_mbps
                .max(manager.metrics.current_usage_mbps);
            
            manager.metrics.utilization_percentage = 
                manager.metrics.current_usage_mbps / manager.qos_policy.max_bandwidth_mbps as f64 * 100.0;
        }
        Ok(())
    }

    fn start_bandwidth_tasks(&self) {
        let controller = Arc::new(self.clone());

        // Token bucket update task
        tokio::spawn({
            let controller = controller.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(BUCKET_UPDATE_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    controller.update_token_buckets().await;
                }
            }
        });

        // Metrics update task
        tokio::spawn({
            let controller = controller.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    controller.update_bandwidth_metrics().await;
                }
            }
        });
    }

    async fn update_token_buckets(&self) {
        for manager in self.managers.iter_mut() {
            let now = get_timestamp().unwrap_or(0);
            let elapsed = now - manager.token_bucket.last_update;
            
            let new_tokens = manager.token_bucket.rate_bytes_sec 
                * elapsed as f64 / 1000.0;
            
            manager.token_bucket.tokens = (manager.token_bucket.tokens + new_tokens)
                .min(manager.token_bucket.capacity_bytes as f64);
            
            manager.token_bucket.last_update = now;
        }
    }

    async fn update_bandwidth_metrics(&self) {
        // Update bandwidth metrics for all streams
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&BandwidthMetrics {
                current_usage_mbps: 0.0,
                peak_usage_mbps: 0.0,
                average_latency_ms: 0.0,
                dropped_packets: 0,
                throttled_streams: 0,
                qos_violations: 0,
                utilization_percentage: 0.0,
            })?)
        }
    }
}

fn generate_stream_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("STREAM-{:016x}", rng.gen::<u64>())
}

fn generate_event_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("EVENT-{:016x}", rng.gen::<u64>())
}

fn get_timestamp() -> Result<u64, JsValue> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for BandwidthController {
    fn drop(&mut self) {
        self.managers.clear();
        self.metrics.clear();
    }
} 
