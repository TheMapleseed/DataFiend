use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use chrono::{DateTime, Utc};

// Memory thresholds (in bytes)
const CRITICAL_MEMORY_THRESHOLD: f64 = 0.95; // 95% of max
const WARNING_MEMORY_THRESHOLD: f64 = 0.85;  // 85% of max
const RECOVERY_MEMORY_THRESHOLD: f64 = 0.75; // 75% of max

#[derive(Clone, Serialize, Deserialize)]
pub struct MemoryLimits {
    max_total_bytes: u64,
    max_allocation_bytes: u64,
    growth_rate_bytes_per_sec: u64,
    cleanup_threshold_bytes: u64,
    min_free_bytes: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MemoryMetrics {
    current_usage_bytes: u64,
    peak_usage_bytes: u64,
    total_allocations: u64,
    failed_allocations: u64,
    emergency_cleanups: u64,
    last_cleanup: Option<DateTime<Utc>>,
    growth_rate: f64,
}

#[derive(Clone, Serialize, Deserialize)]
enum MemoryState {
    Normal,
    Warning,
    Critical,
}

#[wasm_bindgen]
pub struct MemoryController {
    limits: Arc<RwLock<MemoryLimits>>,
    metrics: Arc<DashMap<String, MemoryMetrics>>,
    allocations: Arc<DashMap<String, u64>>,
    state: Arc<Mutex<MemoryState>>,
    cleanup_in_progress: Arc<Mutex<bool>>,
}

#[wasm_bindgen]
impl MemoryController {
    #[wasm_bindgen(constructor)]
    pub fn new(max_memory_mb: u64) -> Self {
        let controller = Self {
            limits: Arc::new(RwLock::new(MemoryLimits {
                max_total_bytes: max_memory_mb * 1024 * 1024,
                max_allocation_bytes: (max_memory_mb * 1024 * 1024) / 10, // 10% of total
                growth_rate_bytes_per_sec: 1024 * 1024 * 10, // 10MB/s
                cleanup_threshold_bytes: (max_memory_mb * 1024 * 1024) * 85 / 100, // 85%
                min_free_bytes: 1024 * 1024 * 50, // 50MB minimum free
            })),
            metrics: Arc::new(DashMap::new()),
            allocations: Arc::new(DashMap::new()),
            state: Arc::new(Mutex::new(MemoryState::Normal)),
            cleanup_in_progress: Arc::new(Mutex::new(false)),
        };

        controller.start_monitoring();
        controller
    }

    #[wasm_bindgen]
    pub async fn request_memory(
        &self,
        namespace: String,
        bytes: u64,
    ) -> Result<bool, JsValue> {
        // Check against limits
        let limits = self.limits.read().await;
        let current_total = self.get_total_memory_usage();

        // Validate request size
        if bytes > limits.max_allocation_bytes {
            self.update_metrics(&namespace, 0, false).await;
            return Ok(false);
        }

        // Check total memory limits
        if current_total + bytes > limits.max_total_bytes {
            // Try emergency cleanup if we're not already cleaning
            if !*self.cleanup_in_progress.lock().await {
                self.emergency_cleanup().await?;
                
                // Recheck after cleanup
                let new_total = self.get_total_memory_usage();
                if new_total + bytes > limits.max_total_bytes {
                    self.update_metrics(&namespace, 0, false).await;
                    return Ok(false);
                }
            } else {
                self.update_metrics(&namespace, 0, false).await;
                return Ok(false);
            }
        }

        // Check growth rate
        if !self.check_growth_rate(bytes).await {
            self.update_metrics(&namespace, 0, false).await;
            return Ok(false);
        }

        // Update allocations
        self.allocations
            .entry(namespace.clone())
            .and_modify(|e| *e += bytes)
            .or_insert(bytes);

        // Update metrics
        self.update_metrics(&namespace, bytes, true).await;

        // Update state if needed
        self.update_memory_state(current_total + bytes).await;

        Ok(true)
    }

    #[wasm_bindgen]
    pub async fn release_memory(
        &self,
        namespace: String,
        bytes: u64,
    ) -> Result<(), JsValue> {
        if let Some(mut allocation) = self.allocations.get_mut(&namespace) {
            *allocation = allocation.saturating_sub(bytes);
            
            // Update state
            let current_total = self.get_total_memory_usage();
            self.update_memory_state(current_total).await;
        }
        Ok(())
    }

    async fn update_memory_state(&self, total_bytes: u64) {
        let limits = self.limits.read().await;
        let mut state = self.state.lock().await;

        *state = if total_bytes as f64 >= limits.max_total_bytes as f64 * CRITICAL_MEMORY_THRESHOLD {
            MemoryState::Critical
        } else if total_bytes as f64 >= limits.max_total_bytes as f64 * WARNING_MEMORY_THRESHOLD {
            MemoryState::Warning
        } else {
            MemoryState::Normal
        };
    }

    async fn check_growth_rate(&self, requested_bytes: u64) -> bool {
        let limits = self.limits.read().await;
        let current_rate = self.calculate_growth_rate().await;
        
        // Check if this allocation would exceed growth rate
        current_rate + (requested_bytes as f64) <= limits.growth_rate_bytes_per_sec as f64
    }

    async fn calculate_growth_rate(&self) -> f64 {
        let mut total_rate = 0.0;
        for metric in self.metrics.iter() {
            total_rate += metric.growth_rate;
        }
        total_rate
    }

    async fn emergency_cleanup(&self) -> Result<(), JsValue> {
        let mut cleanup_lock = self.cleanup_in_progress.lock().await;
        if *cleanup_lock {
            return Ok(());
        }
        *cleanup_lock = true;

        // Perform cleanup
        let current_total = self.get_total_memory_usage();
        let limits = self.limits.read().await;
        
        if current_total > limits.cleanup_threshold_bytes {
            // Sort allocations by size
            let mut allocations: Vec<(String, u64)> = self.allocations
                .iter()
                .map(|entry| (entry.key().clone(), *entry.value()))
                .collect();
            
            allocations.sort_by_key(|k| std::cmp::Reverse(k.1));

            // Release memory from largest allocations first
            let target_reduction = current_total - (limits.max_total_bytes as f64 * RECOVERY_MEMORY_THRESHOLD) as u64;
            let mut reduced = 0u64;

            for (namespace, size) in allocations {
                if reduced >= target_reduction {
                    break;
                }

                // Release portion of memory
                let to_release = (size / 2).min(target_reduction - reduced);
                self.release_memory(namespace.clone(), to_release).await?;
                reduced += to_release;

                // Update metrics
                if let Some(mut metrics) = self.metrics.get_mut(&namespace) {
                    metrics.emergency_cleanups += 1;
                    metrics.last_cleanup = Some(Utc::now());
                }
            }
        }

        *cleanup_lock = false;
        Ok(())
    }

    async fn update_metrics(
        &self,
        namespace: &str,
        bytes: u64,
        success: bool,
    ) {
        self.metrics
            .entry(namespace.to_string())
            .or_insert_with(|| MemoryMetrics {
                current_usage_bytes: 0,
                peak_usage_bytes: 0,
                total_allocations: 0,
                failed_allocations: 0,
                emergency_cleanups: 0,
                last_cleanup: None,
                growth_rate: 0.0,
            })
            .and_modify(|m| {
                if success {
                    m.current_usage_bytes += bytes;
                    m.peak_usage_bytes = m.peak_usage_bytes.max(m.current_usage_bytes);
                    m.total_allocations += 1;
                    
                    // Update growth rate (bytes per second)
                    let now = Utc::now();
                    if let Some(last_cleanup) = m.last_cleanup {
                        let seconds = (now - last_cleanup).num_seconds() as f64;
                        if seconds > 0.0 {
                            m.growth_rate = bytes as f64 / seconds;
                        }
                    }
                } else {
                    m.failed_allocations += 1;
                }
            });
    }

    fn get_total_memory_usage(&self) -> u64 {
        self.allocations.iter().map(|entry| *entry.value()).sum()
    }

    fn start_monitoring(&self) {
        let controller = Arc::new(self.clone());
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                
                // Check memory state
                let current_total = controller.get_total_memory_usage();
                controller.update_memory_state(current_total).await;
                
                // Perform cleanup if needed
                if matches!(*controller.state.lock().await, MemoryState::Critical) {
                    if let Err(e) = controller.emergency_cleanup().await {
                        web_sys::console::error_1(&e);
                    }
                }
            }
        });
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self, namespace: String) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get(&namespace) {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Err(JsValue::from_str("No metrics found for namespace"))
        }
    }
}

impl Drop for MemoryController {
    fn drop(&mut self) {
        // Clear all allocations and metrics
        self.allocations.clear();
        self.metrics.clear();
    }
} 