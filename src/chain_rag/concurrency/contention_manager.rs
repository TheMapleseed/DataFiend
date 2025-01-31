use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use crossbeam_skiplist::SkipMap;
use dashmap::DashMap;
use parking_lot::{RwLock as PLRwLock, Mutex as PLMutex};
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant};
use futures::StreamExt;

const MAX_RETRY_ATTEMPTS: u32 = 3;
const BACKOFF_BASE_MS: u64 = 50;
const CONTENTION_THRESHOLD: u32 = 100;
const BATCH_SIZE: usize = 1000;

#[derive(Clone, Serialize, Deserialize)]
pub struct ContentionMetrics {
    total_contentions: u64,
    retry_count: u64,
    avg_wait_time_ms: f64,
    peak_contention: u32,
    last_backoff_ms: u64,
}

#[derive(Clone)]
struct LockState {
    contention_count: PLRwLock<u32>,
    last_acquired: PLRwLock<Instant>,
    waiting_threads: PLRwLock<u32>,
}

#[wasm_bindgen]
pub struct ContentionManager {
    locks: Arc<SkipMap<String, LockState>>,
    metrics: Arc<DashMap<String, ContentionMetrics>>,
    batch_processor: Arc<BatchProcessor>,
    backoff_policy: Arc<PLRwLock<BackoffPolicy>>,
}

#[derive(Clone)]
struct BatchProcessor {
    queue: Arc<SkipMap<u64, Vec<PendingOperation>>>,
    current_batch: Arc<PLRwLock<Vec<PendingOperation>>>,
    processing: Arc<PLMutex<bool>>,
}

#[derive(Clone)]
struct PendingOperation {
    id: u64,
    resource: String,
    operation: Operation,
    priority: u32,
    timestamp: Instant,
}

#[derive(Clone)]
enum Operation {
    Read,
    Write,
    Delete,
}

#[derive(Clone)]
struct BackoffPolicy {
    base_ms: u64,
    max_ms: u64,
    multiplier: f64,
}

#[wasm_bindgen]
impl ContentionManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let manager = Self {
            locks: Arc::new(SkipMap::new()),
            metrics: Arc::new(DashMap::new()),
            batch_processor: Arc::new(BatchProcessor::new()),
            backoff_policy: Arc::new(PLRwLock::new(BackoffPolicy {
                base_ms: BACKOFF_BASE_MS,
                max_ms: 1000,
                multiplier: 2.0,
            })),
        };

        manager.start_background_tasks();
        manager
    }

    #[wasm_bindgen]
    pub async fn acquire_lock(
        &self,
        resource: String,
        operation: String,
        priority: u32,
    ) -> Result<bool, JsValue> {
        let op = match operation.as_str() {
            "read" => Operation::Read,
            "write" => Operation::Write,
            "delete" => Operation::Delete,
            _ => return Err(JsValue::from_str("Invalid operation")),
        };

        let pending_op = PendingOperation {
            id: rand::random(),
            resource: resource.clone(),
            operation: op,
            priority,
            timestamp: Instant::now(),
        };

        for attempt in 0..MAX_RETRY_ATTEMPTS {
            match self.try_acquire_lock(&pending_op).await {
                Ok(true) => {
                    self.update_metrics(&resource, attempt, 0);
                    return Ok(true);
                }
                Ok(false) if attempt < MAX_RETRY_ATTEMPTS - 1 => {
                    let backoff = self.calculate_backoff(attempt);
                    tokio::time::sleep(Duration::from_millis(backoff)).await;
                    self.update_metrics(&resource, attempt, backoff);
                }
                Ok(false) => {
                    // Add to batch processing queue
                    self.batch_processor.add_operation(pending_op.clone()).await;
                    return Ok(false);
                }
                Err(e) => return Err(e),
            }
        }

        Ok(false)
    }

    async fn try_acquire_lock(&self, op: &PendingOperation) -> Result<bool, JsValue> {
        let lock_state = self.locks
            .get_or_insert(op.resource.clone(), LockState::new())
            .value()
            .clone();

        let mut contention = lock_state.contention_count.write();
        let mut waiting = lock_state.waiting_threads.write();
        
        if *contention >= CONTENTION_THRESHOLD {
            *waiting += 1;
            return Ok(false);
        }

        *contention += 1;
        *lock_state.last_acquired.write() = Instant::now();
        
        Ok(true)
    }

    #[wasm_bindgen]
    pub async fn release_lock(&self, resource: String) -> Result<(), JsValue> {
        if let Some(lock_state) = self.locks.get(&resource) {
            let mut contention = lock_state.value().contention_count.write();
            let mut waiting = lock_state.value().waiting_threads.write();
            
            *contention = contention.saturating_sub(1);
            if *waiting > 0 {
                *waiting -= 1;
            }
        }
        Ok(())
    }

    fn calculate_backoff(&self, attempt: u32) -> u64 {
        let policy = self.backoff_policy.read();
        let backoff = policy.base_ms * (policy.multiplier.powi(attempt as i32) as u64);
        backoff.min(policy.max_ms)
    }

    fn update_metrics(&self, resource: &str, attempt: u32, backoff: u64) {
        self.metrics
            .entry(resource.to_string())
            .and_modify(|m| {
                m.total_contentions += 1;
                m.retry_count += attempt as u64;
                m.last_backoff_ms = backoff;
                m.peak_contention = m.peak_contention.max(attempt);
            })
            .or_insert_with(|| ContentionMetrics {
                total_contentions: 1,
                retry_count: attempt as u64,
                avg_wait_time_ms: backoff as f64,
                peak_contention: attempt,
                last_backoff_ms: backoff,
            });
    }

    fn start_background_tasks(&self) {
        let manager = Arc::new(self.clone());
        
        // Batch processing task
        tokio::spawn({
            let manager = manager.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_millis(100));
                loop {
                    interval.tick().await;
                    manager.batch_processor.process_batch().await;
                }
            }
        });

        // Metrics cleanup task
        tokio::spawn({
            let manager = manager.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    manager.cleanup_old_metrics();
                }
            }
        });
    }

    fn cleanup_old_metrics(&self) {
        self.metrics.retain(|_, m| m.total_contentions > 0);
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self, resource: String) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get(&resource) {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&ContentionMetrics {
                total_contentions: 0,
                retry_count: 0,
                avg_wait_time_ms: 0.0,
                peak_contention: 0,
                last_backoff_ms: 0,
            })?)
        }
    }
}

impl BatchProcessor {
    fn new() -> Self {
        Self {
            queue: Arc::new(SkipMap::new()),
            current_batch: Arc::new(PLRwLock::new(Vec::with_capacity(BATCH_SIZE))),
            processing: Arc::new(PLMutex::new(false)),
        }
    }

    async fn add_operation(&self, op: PendingOperation) {
        self.queue.insert(op.priority as u64, vec![op]);
    }

    async fn process_batch(&self) {
        let mut processing = self.processing.lock();
        if *processing {
            return;
        }
        *processing = true;

        let mut current_batch = self.current_batch.write();
        current_batch.clear();

        // Collect operations by priority
        for item in self.queue.iter() {
            current_batch.extend(item.value().iter().cloned());
            if current_batch.len() >= BATCH_SIZE {
                break;
            }
        }

        // Sort by priority and timestamp
        current_batch.sort_by(|a, b| {
            b.priority.cmp(&a.priority)
                .then_with(|| a.timestamp.cmp(&b.timestamp))
        });

        // Process batch
        for op in current_batch.iter() {
            self.queue.remove(&(op.priority as u64));
        }

        *processing = false;
    }
}

impl LockState {
    fn new() -> Self {
        Self {
            contention_count: PLRwLock::new(0),
            last_acquired: PLRwLock::new(Instant::now()),
            waiting_threads: PLRwLock::new(0),
        }
    }
}

impl Drop for ContentionManager {
    fn drop(&mut self) {
        self.locks.clear();
        self.metrics.clear();
    }
} 
