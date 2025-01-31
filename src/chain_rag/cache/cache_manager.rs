use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use sha3::{Sha3_512, Digest};
use std::collections::{HashMap, VecDeque};

const MAX_CACHE_SIZE: usize = 10_000;
const MAX_ENTRY_SIZE: usize = 1024 * 1024; // 1MB
const CLEANUP_INTERVAL_MS: u64 = 5000;
const MAX_UPDATE_RETRIES: u32 = 3;
const UPDATE_TIMEOUT_MS: u64 = 1000;

#[derive(Clone, Serialize, Deserialize)]
pub struct CacheMetrics {
    total_entries: usize,
    total_updates: u64,
    failed_updates: u64,
    evicted_entries: u64,
    cache_size_bytes: usize,
    hit_rate: f64,
    update_latency_ms: f64,
    conflict_rate: f64,
}

#[derive(Clone, Serialize, Deserialize)]
struct CacheEntry {
    key: String,
    value: Vec<u8>,
    version: u64,
    last_access: u64,
    last_update: u64,
    update_count: u32,
    size: usize,
    checksum: Vec<u8>,
}

#[derive(Clone)]
struct UpdateOperation {
    key: String,
    new_value: Vec<u8>,
    expected_version: u64,
    priority: u8,
    timestamp: u64,
}

#[wasm_bindgen]
pub struct CacheManager {
    entries: Arc<DashMap<String, CacheEntry>>,
    metrics: Arc<DashMap<String, CacheMetrics>>,
    update_lock: Arc<Semaphore>,
    version_map: Arc<DashMap<String, u64>>,
    update_queue: Arc<RwLock<VecDeque<UpdateOperation>>>,
}

#[wasm_bindgen]
impl CacheManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let manager = Self {
            entries: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            update_lock: Arc::new(Semaphore::new(100)),
            version_map: Arc::new(DashMap::new()),
            update_queue: Arc::new(RwLock::new(VecDeque::new())),
        };

        manager.start_maintenance_tasks();
        manager
    }

    #[wasm_bindgen]
    pub async fn update_entry(
        &self,
        key: String,
        value: Vec<u8>,
        expected_version: u64,
        priority: u8,
    ) -> Result<bool, JsValue> {
        if value.len() > MAX_ENTRY_SIZE {
            return Err(JsValue::from_str("Entry size exceeds maximum"));
        }

        let timestamp = get_timestamp()?;
        let operation = UpdateOperation {
            key: key.clone(),
            new_value: value,
            expected_version,
            priority,
            timestamp,
        };

        // Acquire update permit
        let _permit = tokio::time::timeout(
            Duration::from_millis(UPDATE_TIMEOUT_MS),
            self.update_lock.acquire(),
        ).await
            .map_err(|_| JsValue::from_str("Update timeout"))?
            .map_err(|e| JsValue::from_str(&format!("Semaphore error: {}", e)))?;

        let start_time = Instant::now();
        let result = self.perform_update(&operation).await;

        self.update_metrics(
            result.is_ok(),
            start_time.elapsed(),
        ).await;

        result
    }

    async fn perform_update(
        &self,
        operation: &UpdateOperation,
    ) -> Result<bool, JsValue> {
        let mut retry_count = 0;
        let mut last_error = None;

        while retry_count < MAX_UPDATE_RETRIES {
            match self.try_update(operation).await {
                Ok(updated) => return Ok(updated),
                Err(e) => {
                    retry_count += 1;
                    last_error = Some(e);
                    
                    if retry_count < MAX_UPDATE_RETRIES {
                        let backoff = Duration::from_millis(
                            2u64.pow(retry_count) * 50
                        );
                        tokio::time::sleep(backoff).await;
                    }
                }
            }
        }

        Err(last_error.unwrap_or_else(|| {
            JsValue::from_str("Maximum update retries exceeded")
        }))
    }

    async fn try_update(
        &self,
        operation: &UpdateOperation,
    ) -> Result<bool, JsValue> {
        // Verify version
        if let Some(current_version) = self.version_map.get(&operation.key) {
            if *current_version != operation.expected_version {
                return Ok(false);
            }
        }

        // Calculate checksum
        let mut hasher = Sha3_512::new();
        hasher.update(&operation.new_value);
        let checksum = hasher.finalize().to_vec();

        let entry = CacheEntry {
            key: operation.key.clone(),
            value: operation.new_value.clone(),
            version: operation.expected_version + 1,
            last_access: operation.timestamp,
            last_update: operation.timestamp,
            update_count: 1,
            size: operation.new_value.len(),
            checksum,
        };

        // Update entry
        if let Some(mut old_entry) = self.entries.get_mut(&operation.key) {
            // Verify no concurrent updates
            if old_entry.version != operation.expected_version {
                return Ok(false);
            }

            // Update entry fields
            old_entry.value = operation.new_value.clone();
            old_entry.version += 1;
            old_entry.last_update = operation.timestamp;
            old_entry.update_count += 1;
            old_entry.size = operation.new_value.len();
            old_entry.checksum = checksum;
        } else {
            // New entry
            self.entries.insert(operation.key.clone(), entry);
        }

        // Update version map
        self.version_map.insert(
            operation.key.clone(),
            operation.expected_version + 1,
        );

        Ok(true)
    }

    async fn update_metrics(
        &self,
        success: bool,
        duration: Duration,
    ) {
        self.metrics
            .entry("global".to_string())
            .and_modify(|m| {
                m.total_updates += 1;
                if !success {
                    m.failed_updates += 1;
                }
                m.update_latency_ms = (m.update_latency_ms * 0.9)
                    + (duration.as_millis() as f64 * 0.1);
                m.conflict_rate = m.failed_updates as f64 / m.total_updates as f64;
            })
            .or_insert_with(|| CacheMetrics {
                total_entries: self.entries.len(),
                total_updates: 1,
                failed_updates: if success { 0 } else { 1 },
                evicted_entries: 0,
                cache_size_bytes: self.calculate_cache_size(),
                hit_rate: 0.0,
                update_latency_ms: duration.as_millis() as f64,
                conflict_rate: if success { 0.0 } else { 1.0 },
            });
    }

    fn calculate_cache_size(&self) -> usize {
        self.entries.iter()
            .map(|entry| entry.size)
            .sum()
    }

    fn start_maintenance_tasks(&self) {
        let manager = Arc::new(self.clone());

        // Cleanup task
        tokio::spawn({
            let manager = manager.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(CLEANUP_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    manager.cleanup_expired_entries().await;
                }
            }
        });

        // Metrics update task
        tokio::spawn({
            let manager = manager.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    manager.update_cache_metrics().await;
                }
            }
        });
    }

    async fn cleanup_expired_entries(&self) {
        let now = get_timestamp().unwrap_or(0);
        let mut evicted = 0;

        // Remove expired entries
        self.entries.retain(|_, entry| {
            let expired = now - entry.last_access > 3600;
            if expired {
                evicted += 1;
            }
            !expired
        });

        // Update metrics
        if evicted > 0 {
            self.metrics
                .entry("global".to_string())
                .and_modify(|m| {
                    m.evicted_entries += evicted;
                    m.total_entries = self.entries.len();
                    m.cache_size_bytes = self.calculate_cache_size();
                });
        }
    }

    async fn update_cache_metrics(&self) {
        let total_entries = self.entries.len();
        let cache_size = self.calculate_cache_size();

        self.metrics
            .entry("global".to_string())
            .and_modify(|m| {
                m.total_entries = total_entries;
                m.cache_size_bytes = cache_size;
            });
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&CacheMetrics {
                total_entries: 0,
                total_updates: 0,
                failed_updates: 0,
                evicted_entries: 0,
                cache_size_bytes: 0,
                hit_rate: 0.0,
                update_latency_ms: 0.0,
                conflict_rate: 0.0,
            })?)
        }
    }
}

fn get_timestamp() -> Result<u64, JsValue> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for CacheManager {
    fn drop(&mut self) {
        self.entries.clear();
        self.metrics.clear();
        self.version_map.clear();
    }
} 