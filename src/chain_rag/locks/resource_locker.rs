use wasm_bindgen::prelude::*;
use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::Mutex;
use chrono::{DateTime, Utc, Duration};
use std::collections::HashMap;
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct LockInfo {
    holder: String,
    acquired: DateTime<Utc>,
    timeout: Duration,
    lock_type: LockType,
    resource_type: String,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum LockType {
    Shared,
    Exclusive,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LockMetrics {
    total_locks: u64,
    timeouts: u64,
    deadlocks_detected: u64,
    avg_wait_time: Duration,
}

#[wasm_bindgen]
pub struct ResourceLocker {
    locks: Arc<DashMap<String, Vec<LockInfo>>>,
    wait_queues: Arc<DashMap<String, Vec<String>>>,
    metrics: Arc<DashMap<String, LockMetrics>>,
    deadlock_detector: Arc<Mutex<DeadlockDetector>>,
}

struct DeadlockDetector {
    resource_graph: HashMap<String, Vec<String>>,
    holder_graph: HashMap<String, Vec<String>>,
}

#[wasm_bindgen]
impl ResourceLocker {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let locker = Self {
            locks: Arc::new(DashMap::new()),
            wait_queues: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            deadlock_detector: Arc::new(Mutex::new(DeadlockDetector {
                resource_graph: HashMap::new(),
                holder_graph: HashMap::new(),
            })),
        };

        locker.start_timeout_monitor();
        locker
    }

    #[wasm_bindgen]
    pub async fn acquire_lock(
        &self,
        resource_id: String,
        holder_id: String,
        lock_type: String,
        timeout_ms: u64,
    ) -> Result<bool, JsValue> {
        let lock_type = match lock_type.as_str() {
            "shared" => LockType::Shared,
            "exclusive" => LockType::Exclusive,
            _ => return Err(JsValue::from_str("Invalid lock type")),
        };

        let timeout = Duration::milliseconds(timeout_ms as i64);
        let start_time = Utc::now();

        // Add to wait queue
        self.wait_queues
            .entry(resource_id.clone())
            .or_default()
            .push(holder_id.clone());

        // Check for deadlocks
        if self.would_deadlock(&resource_id, &holder_id).await {
            self.update_metrics(&resource_id, start_time, true);
            return Ok(false);
        }

        // Try to acquire lock
        loop {
            if let Some(mut current_locks) = self.locks.get_mut(&resource_id) {
                let can_acquire = match lock_type {
                    LockType::Shared => !current_locks.iter().any(|l| l.lock_type == LockType::Exclusive),
                    LockType::Exclusive => current_locks.is_empty(),
                };

                if can_acquire {
                    current_locks.push(LockInfo {
                        holder: holder_id.clone(),
                        acquired: Utc::now(),
                        timeout,
                        lock_type: lock_type.clone(),
                        resource_type: resource_id.clone(),
                    });

                    // Update wait queue
                    if let Some(mut queue) = self.wait_queues.get_mut(&resource_id) {
                        queue.retain(|id| id != &holder_id);
                    }

                    self.update_metrics(&resource_id, start_time, false);
                    return Ok(true);
                }
            } else {
                // No existing locks, create new entry
                self.locks.insert(resource_id.clone(), vec![LockInfo {
                    holder: holder_id.clone(),
                    acquired: Utc::now(),
                    timeout,
                    lock_type,
                    resource_type: resource_id.clone(),
                }]);

                // Update wait queue
                if let Some(mut queue) = self.wait_queues.get_mut(&resource_id) {
                    queue.retain(|id| id != &holder_id);
                }

                self.update_metrics(&resource_id, start_time, false);
                return Ok(true);
            }

            // Check if we've exceeded timeout
            if Utc::now() - start_time > timeout {
                // Remove from wait queue
                if let Some(mut queue) = self.wait_queues.get_mut(&resource_id) {
                    queue.retain(|id| id != &holder_id);
                }

                self.update_metrics(&resource_id, start_time, true);
                return Ok(false);
            }

            // Wait before trying again
            tokio::time::sleep(std::time::Duration::from_millis(100)).await;
        }
    }

    #[wasm_bindgen]
    pub fn release_lock(&self, resource_id: String, holder_id: String) -> Result<(), JsValue> {
        if let Some(mut current_locks) = self.locks.get_mut(&resource_id) {
            current_locks.retain(|lock| lock.holder != holder_id);
            
            // Remove from wait queue if present
            if let Some(mut queue) = self.wait_queues.get_mut(&resource_id) {
                queue.retain(|id| id != &holder_id);
            }

            // Update deadlock detector
            let mut detector = self.deadlock_detector.blocking_lock();
            if let Some(resources) = detector.holder_graph.get_mut(&holder_id) {
                resources.retain(|r| r != &resource_id);
            }
            if let Some(holders) = detector.resource_graph.get_mut(&resource_id) {
                holders.retain(|h| h != &holder_id);
            }

            Ok(())
        } else {
            Err(JsValue::from_str("Lock not found"))
        }
    }

    async fn would_deadlock(&self, resource_id: &str, holder_id: &str) -> bool {
        let mut detector = self.deadlock_detector.lock().await;
        
        // Update graphs
        detector.resource_graph
            .entry(resource_id.to_string())
            .or_default()
            .push(holder_id.to_string());
        
        detector.holder_graph
            .entry(holder_id.to_string())
            .or_default()
            .push(resource_id.to_string());

        // Check for cycles
        let mut visited = HashSet::new();
        let has_cycle = self.detect_cycle(
            holder_id,
            &detector.holder_graph,
            &mut visited
        );

        if has_cycle {
            // Update metrics
            if let Some(mut metrics) = self.metrics.get_mut(resource_id) {
                metrics.deadlocks_detected += 1;
            }
        }

        has_cycle
    }

    fn detect_cycle(
        &self,
        start: &str,
        graph: &HashMap<String, Vec<String>>,
        visited: &mut HashSet<String>
    ) -> bool {
        if !visited.insert(start.to_string()) {
            return true;
        }

        if let Some(neighbors) = graph.get(start) {
            for neighbor in neighbors {
                if self.detect_cycle(neighbor, graph, visited) {
                    return true;
                }
            }
        }

        visited.remove(start);
        false
    }

    fn start_timeout_monitor(&self) {
        let locks = Arc::clone(&self.locks);
        let metrics = Arc::clone(&self.metrics);

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(1));
            loop {
                interval.tick().await;
                let now = Utc::now();

                // Check all locks for timeouts
                for mut entry in locks.iter_mut() {
                    let resource_id = entry.key().clone();
                    entry.retain(|lock| {
                        let should_keep = now - lock.acquired <= lock.timeout;
                        if !should_keep {
                            // Update metrics
                            if let Some(mut m) = metrics.get_mut(&resource_id) {
                                m.timeouts += 1;
                            }
                        }
                        should_keep
                    });
                }
            }
        });
    }

    fn update_metrics(
        &self,
        resource_id: &str,
        start_time: DateTime<Utc>,
        is_timeout: bool,
    ) {
        let wait_time = Utc::now() - start_time;
        
        self.metrics
            .entry(resource_id.to_string())
            .and_modify(|m| {
                m.total_locks += 1;
                if is_timeout {
                    m.timeouts += 1;
                }
                m.avg_wait_time = Duration::milliseconds(
                    ((m.avg_wait_time.num_milliseconds() as f64 * (m.total_locks - 1) as f64 +
                      wait_time.num_milliseconds() as f64) / m.total_locks as f64) as i64
                );
            })
            .or_insert_with(|| LockMetrics {
                total_locks: 1,
                timeouts: if is_timeout { 1 } else { 0 },
                deadlocks_detected: 0,
                avg_wait_time: wait_time,
            });
    }

    #[wasm_bindgen]
    pub fn get_lock_info(&self, resource_id: String) -> Result<JsValue, JsValue> {
        if let Some(locks) = self.locks.get(&resource_id) {
            Ok(serde_wasm_bindgen::to_value(&*locks)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&Vec::<LockInfo>::new())?)
        }
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self, resource_id: String) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get(&resource_id) {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Err(JsValue::from_str("No metrics found"))
        }
    }
}

impl Drop for ResourceLocker {
    fn drop(&mut self) {
        // Clear all locks and queues
        self.locks.clear();
        self.wait_queues.clear();
        self.metrics.clear();
    }
} 