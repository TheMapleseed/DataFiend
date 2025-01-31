use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant};
use rand::{Rng, thread_rng};
use subtle::{Choice, ConstantTimeEq};
use std::collections::VecDeque;

const MAX_TIMING_VARIANCE_US: u64 = 100;
const MIN_OPERATION_TIME_US: u64 = 1000;
const TIMING_HISTORY_SIZE: usize = 1000;
const SUSPICIOUS_VARIANCE_THRESHOLD: f64 = 0.1;

#[derive(Clone, Serialize, Deserialize)]
pub struct TimingMetrics {
    operation_count: u64,
    average_duration_us: f64,
    min_duration_us: u64,
    max_duration_us: u64,
    variance_us: f64,
    suspicious_patterns: u64,
    last_update: u64,
}

#[derive(Clone)]
struct OperationTiming {
    start: Instant,
    operation_type: String,
    expected_duration: Duration,
}

#[wasm_bindgen]
pub struct TimingGuard {
    metrics: Arc<DashMap<String, TimingMetrics>>,
    timing_history: Arc<RwLock<VecDeque<Duration>>>,
    active_operations: Arc<DashMap<String, OperationTiming>>,
    padding_enabled: Arc<RwLock<bool>>,
}

#[wasm_bindgen]
impl TimingGuard {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let guard = Self {
            metrics: Arc::new(DashMap::new()),
            timing_history: Arc::new(RwLock::new(VecDeque::with_capacity(TIMING_HISTORY_SIZE))),
            active_operations: Arc::new(DashMap::new()),
            padding_enabled: Arc::new(RwLock::new(true)),
        };

        guard.start_monitoring_tasks();
        guard
    }

    #[wasm_bindgen]
    pub async fn start_operation(
        &self,
        operation_id: String,
        operation_type: String,
    ) -> Result<(), JsValue> {
        let expected_duration = self.calculate_expected_duration(&operation_type).await;
        
        self.active_operations.insert(
            operation_id,
            OperationTiming {
                start: Instant::now(),
                operation_type,
                expected_duration,
            },
        );

        Ok(())
    }

    #[wasm_bindgen]
    pub async fn end_operation(
        &self,
        operation_id: String,
    ) -> Result<(), JsValue> {
        let timing = self.active_operations
            .remove(&operation_id)
            .ok_or_else(|| JsValue::from_str("Operation not found"))?;

        let actual_duration = timing.start.elapsed();
        
        // Constant-time comparison of actual vs expected duration
        let duration_diff = self.constant_time_duration_diff(
            actual_duration,
            timing.expected_duration,
        );

        // Add timing noise if needed
        if *self.padding_enabled.read().await {
            self.add_timing_noise(duration_diff).await?;
        }

        self.update_metrics(
            &timing.operation_type,
            actual_duration,
            timing.expected_duration,
        ).await;

        Ok(())
    }

    async fn calculate_expected_duration(&self, operation_type: &str) -> Duration {
        let base_duration = Duration::from_micros(MIN_OPERATION_TIME_US);
        
        if let Some(metrics) = self.metrics.get(operation_type) {
            Duration::from_micros(metrics.average_duration_us as u64)
        } else {
            base_duration
        }
    }

    fn constant_time_duration_diff(
        &self,
        actual: Duration,
        expected: Duration,
    ) -> Duration {
        let actual_nanos = actual.as_nanos() as u64;
        let expected_nanos = expected.as_nanos() as u64;
        
        // Constant-time absolute difference
        let mut diff = 0u64;
        let mut borrow = 0u64;
        
        for i in 0..64 {
            let a_bit = (actual_nanos >> i) & 1;
            let e_bit = (expected_nanos >> i) & 1;
            let d_bit = (a_bit ^ e_bit ^ borrow) & 1;
            borrow = ((!a_bit & e_bit) | (!a_bit & borrow) | (e_bit & borrow)) & 1;
            diff |= d_bit << i;
        }

        Duration::from_nanos(diff)
    }

    async fn add_timing_noise(&self, duration: Duration) -> Result<(), JsValue> {
        let mut rng = thread_rng();
        let noise = rng.gen_range(0..MAX_TIMING_VARIANCE_US);
        
        // Add random delay
        tokio::time::sleep(Duration::from_micros(noise)).await;
        
        Ok(())
    }

    async fn update_metrics(
        &self,
        operation_type: &str,
        actual_duration: Duration,
        expected_duration: Duration,
    ) {
        let duration_us = actual_duration.as_micros() as u64;
        
        self.metrics
            .entry(operation_type.to_string())
            .and_modify(|m| {
                m.operation_count += 1;
                
                // Update running average
                let old_avg = m.average_duration_us;
                let count = m.operation_count as f64;
                m.average_duration_us = old_avg + (duration_us as f64 - old_avg) / count;
                
                // Update min/max
                m.min_duration_us = m.min_duration_us.min(duration_us);
                m.max_duration_us = m.max_duration_us.max(duration_us);
                
                // Update variance
                let diff = duration_us as f64 - expected_duration.as_micros() as f64;
                m.variance_us = (m.variance_us * (count - 1.0) + diff * diff) / count;
                
                // Check for suspicious patterns
                if (diff.abs() / expected_duration.as_micros() as f64) > SUSPICIOUS_VARIANCE_THRESHOLD {
                    m.suspicious_patterns += 1;
                }
                
                m.last_update = std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs();
            })
            .or_insert_with(|| TimingMetrics {
                operation_count: 1,
                average_duration_us: duration_us as f64,
                min_duration_us: duration_us,
                max_duration_us: duration_us,
                variance_us: 0.0,
                suspicious_patterns: 0,
                last_update: std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap_or_default()
                    .as_secs(),
            });

        // Update timing history
        let mut history = self.timing_history.write().await;
        history.push_back(actual_duration);
        while history.len() > TIMING_HISTORY_SIZE {
            history.pop_front();
        }
    }

    fn start_monitoring_tasks(&self) {
        let guard = Arc::new(self.clone());

        // Metrics cleanup task
        tokio::spawn({
            let guard = guard.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    guard.cleanup_old_metrics();
                }
            }
        });

        // Pattern analysis task
        tokio::spawn({
            let guard = guard.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    guard.analyze_timing_patterns().await;
                }
            }
        });
    }

    fn cleanup_old_metrics(&self) {
        let cutoff = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() - 86400; // 24 hours

        self.metrics.retain(|_, m| m.last_update > cutoff);
    }

    async fn analyze_timing_patterns(&self) {
        let history = self.timing_history.read().await;
        if history.len() < 2 {
            return;
        }

        // Calculate timing patterns
        let mut diffs = Vec::with_capacity(history.len() - 1);
        let mut prev = None;
        
        for &duration in history.iter() {
            if let Some(p) = prev {
                diffs.push((duration - p).as_nanos() as i64);
            }
            prev = Some(duration);
        }

        // Check for suspicious patterns
        let mean = diffs.iter().sum::<i64>() as f64 / diffs.len() as f64;
        let variance = diffs.iter()
            .map(|&x| {
                let diff = x as f64 - mean;
                diff * diff
            })
            .sum::<f64>() / diffs.len() as f64;

        if variance < (MAX_TIMING_VARIANCE_US as f64).powi(2) {
            // Suspicious pattern detected - enable additional padding
            *self.padding_enabled.write().await = true;
        }
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self, operation_type: String) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get(&operation_type) {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&TimingMetrics {
                operation_count: 0,
                average_duration_us: 0.0,
                min_duration_us: 0,
                max_duration_us: 0,
                variance_us: 0.0,
                suspicious_patterns: 0,
                last_update: 0,
            })?)
        }
    }
}

impl Drop for TimingGuard {
    fn drop(&mut self) {
        self.metrics.clear();
        self.active_operations.clear();
    }
} 