use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque};
use metrics::{Counter, Gauge, Histogram};
use hdrhistogram::Histogram as HdrHistogram;

const HISTORY_WINDOW: Duration = Duration::from_secs(3600); // 1 hour
const ALERT_CHANNEL_SIZE: usize = 1000;
const MAX_SAMPLES: usize = 10000;

#[derive(Clone, Serialize, Deserialize)]
pub struct MetricsSnapshot {
    timestamp: u64,
    performance: PerformanceMetrics,
    resources: ResourceMetrics,
    errors: ErrorAnalytics,
    load: LoadMetrics,
    circuit: CircuitMetrics,
    historical: HistoricalMetrics,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PerformanceMetrics {
    throughput_per_second: f64,
    peak_latency_ms: u64,
    p95_latency_ms: u64,
    p99_latency_ms: u64,
    memory_usage_bytes: u64,
    cpu_utilization: f64,
    io_operations: u64,
    queue_depth: u32,
    latency_histogram: HdrHistogram<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ResourceMetrics {
    allocation_count: u64,
    deallocation_count: u64,
    active_resources: u32,
    memory_footprint: u64,
    lock_contentions: u32,
    deadlock_potential: f64,
    resource_pressure: f64,
    leak_suspects: Vec<ResourceLeak>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ErrorAnalytics {
    error_types: HashMap<String, u64>,
    error_patterns: Vec<ErrorPattern>,
    recovery_success_rate: f64,
    mean_time_to_recovery: u64,
    error_correlation: Vec<Vec<f64>>,
    impact_severity: HashMap<String, SeverityLevel>,
    error_trends: Vec<ErrorTrend>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LoadMetrics {
    node_distribution: HashMap<String, f64>,
    rebalance_operations: u64,
    load_variance: f64,
    hot_spots: Vec<HotSpot>,
    connection_pool_status: PoolStatus,
    routing_efficiency: f64,
    load_prediction: Vec<LoadPrediction>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CircuitMetrics {
    current_state: CircuitState,
    failure_threshold: u32,
    recovery_time_ms: u64,
    half_open_success_required: u32,
    consecutive_failures: u32,
    last_state_change: u64,
    trips_count: u32,
    state_transitions: Vec<StateTransition>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HistoricalMetrics {
    time_series: Vec<TimePoint>,
    trend_analysis: TrendData,
    seasonal_patterns: Vec<SeasonalPattern>,
    anomaly_scores: Vec<AnomalyScore>,
    prediction_accuracy: f64,
    historical_alerts: Vec<AlertHistory>,
}

// Additional types...
#[derive(Clone, Serialize, Deserialize)]
pub struct ResourceLeak {
    resource_id: String,
    allocation_time: u64,
    stack_trace: String,
    memory_size: u64,
    leak_probability: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum SeverityLevel {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ErrorPattern {
    pattern_id: String,
    frequency: u64,
    context: HashMap<String, String>,
    impact_score: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HotSpot {
    node_id: String,
    load_factor: f64,
    duration_ms: u64,
    resource_type: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PoolStatus {
    active_connections: u32,
    idle_connections: u32,
    waiting_requests: u32,
    max_connections: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum CircuitState {
    Closed,
    Open,
    HalfOpen,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StateTransition {
    from_state: CircuitState,
    to_state: CircuitState,
    timestamp: u64,
    reason: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TimePoint {
    timestamp: u64,
    metrics: HashMap<String, f64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TrendData {
    trend_type: String,
    coefficient: f64,
    r_squared: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SeasonalPattern {
    period: u64,
    amplitude: f64,
    phase: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AnomalyScore {
    timestamp: u64,
    score: f64,
    contributing_factors: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AlertHistory {
    alert_id: String,
    timestamp: u64,
    severity: SeverityLevel,
    description: String,
    resolution: Option<String>,
}
