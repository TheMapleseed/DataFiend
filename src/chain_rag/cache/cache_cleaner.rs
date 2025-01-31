use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, mpsc};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use futures::StreamExt;
use tokio::time::interval;

const CLEANUP_INTERVAL_SECS: u64 = 300; // 5 minutes
const BATCH_SIZE: usize = 1000;
const MAX_CLEANUP_DURATION_SECS: u64 = 30;

#[derive(Clone, Serialize, Deserialize)]
pub struct CleanupMetrics {
    items_removed: u64,
    last_cleanup: u64,
    cleanup_duration_ms: u64,
    errors_encountered: u64,
    batches_processed: u64,
    bytes_freed: u64,
}

#[derive(Clone)]
struct CleanupTask {
    namespace: String,
    key: String,
    size_bytes: usize,
    last_access: u64,
}

#[wasm_bindgen]
pub struct CacheCleaner {
    metrics: Arc<DashMap<String, CleanupMetrics>>,
    shutdown_tx: Arc<broadcast::Sender<()>>,
    task_tx: Arc<mpsc::Sender<CleanupTask>>,
    is_running: Arc<RwLock<bool>>,
    max_age_secs: Arc<RwLock<u64>>,
}

#[wasm_bindgen]
impl CacheCleaner {
    #[wasm_bindgen(constructor)]
    pub fn new(max_age_secs: u64) -> Result<CacheCleaner, JsValue> {
        let (shutdown_tx, _) = broadcast::channel(1);
        let (task_tx, task_rx) = mpsc::channel(BATCH_SIZE);

        let cleaner = CacheCleaner {
            metrics: Arc::new(DashMap::new()),
            shutdown_tx: Arc::new(shutdown_tx),
            task_tx: Arc::new(task_tx),
            is_running: Arc::new(RwLock::new(true)),
            max_age_secs: Arc::new(RwLock::new(max_age_secs)),
        };

        cleaner.start_cleanup_tasks(task_rx)?;
        Ok(cleaner)
    }

    fn start_cleanup_tasks(
        &self,
        task_rx: mpsc::Receiver<CleanupTask>,
    ) -> Result<(), JsValue> {
        let cleaner = Arc::new(self.clone());

        // Main cleanup task
        tokio::spawn({
            let cleaner = cleaner.clone();
            let mut shutdown_rx = cleaner.shutdown_tx.subscribe();
            let mut task_rx = task_rx;
            
            async move {
                let mut interval = interval(Duration::from_secs(CLEANUP_INTERVAL_SECS));
                let mut batch = Vec::with_capacity(BATCH_SIZE);
                let cleanup_timeout = Duration::from_secs(MAX_CLEANUP_DURATION_SECS);

                loop {
                    tokio::select! {
                        _ = shutdown_rx.recv() => {
                            cleaner.handle_shutdown().await;
                            break;
                        }
                        _ = interval.tick() => {
                            let start = SystemTime::now();
                            
                            // Process cleanup tasks with timeout
                            match tokio::time::timeout(
                                cleanup_timeout,
                                cleaner.process_cleanup_batch(&mut task_rx, &mut batch)
                            ).await {
                                Ok(result) => {
                                    if let Err(e) = result {
                                        web_sys::console::error_1(&JsValue::from_str(
                                            &format!("Cleanup error: {}", e)
                                        ));
                                        cleaner.update_metrics(0, 0, true).await;
                                    }
                                }
                                Err(_) => {
                                    web_sys::console::warn_1(&JsValue::from_str(
                                        "Cleanup timeout exceeded"
                                    ));
                                    cleaner.update_metrics(0, 0, true).await;
                                }
                            }

                            // Update metrics
                            if let Ok(duration) = SystemTime::now().duration_since(start) {
                                cleaner.update_cleanup_duration(duration.as_millis() as u64).await;
                            }
                        }
                        Some(task) = task_rx.recv() => {
                            batch.push(task);
                            if batch.len() >= BATCH_SIZE {
                                if let Err(e) = cleaner.cleanup_batch(&batch).await {
                                    web_sys::console::error_1(&JsValue::from_str(
                                        &format!("Batch cleanup error: {}", e)
                                    ));
                                }
                                batch.clear();
                            }
                        }
                    }

                    if !*cleaner.is_running.read().await {
                        break;
                    }
                }
            }
        });

        Ok(())
    }

    async fn process_cleanup_batch(
        &self,
        task_rx: &mut mpsc::Receiver<CleanupTask>,
        batch: &mut Vec<CleanupTask>,
    ) -> Result<(), JsValue> {
        batch.clear();
        
        while let Ok(task) = task_rx.try_recv() {
            batch.push(task);
            if batch.len() >= BATCH_SIZE {
                self.cleanup_batch(batch).await?;
                batch.clear();
            }
        }

        if !batch.is_empty() {
            self.cleanup_batch(batch).await?;
        }

        Ok(())
    }

    async fn cleanup_batch(&self, batch: &[CleanupTask]) -> Result<(), JsValue> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))?
            .as_secs();

        let max_age = *self.max_age_secs.read().await;
        let mut items_removed = 0;
        let mut bytes_freed = 0;

        for task in batch {
            if now - task.last_access > max_age {
                // Remove from cache (implemented elsewhere)
                items_removed += 1;
                bytes_freed += task.size_bytes;
            }
        }

        self.update_metrics(items_removed, bytes_freed, false).await;
        Ok(())
    }

    async fn update_metrics(&self, items_removed: u64, bytes_freed: usize, error: bool) {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        self.metrics
            .entry("global".to_string())
            .and_modify(|m| {
                m.items_removed += items_removed;
                m.last_cleanup = now;
                m.batches_processed += 1;
                m.bytes_freed += bytes_freed as u64;
                if error {
                    m.errors_encountered += 1;
                }
            })
            .or_insert_with(|| CleanupMetrics {
                items_removed,
                last_cleanup: now,
                cleanup_duration_ms: 0,
                errors_encountered: if error { 1 } else { 0 },
                batches_processed: 1,
                bytes_freed: bytes_freed as u64,
            });
    }

    async fn update_cleanup_duration(&self, duration_ms: u64) {
        self.metrics
            .entry("global".to_string())
            .and_modify(|m| {
                m.cleanup_duration_ms = duration_ms;
            });
    }

    #[wasm_bindgen]
    pub async fn shutdown(&self) -> Result<(), JsValue> {
        let mut is_running = self.is_running.write().await;
        *is_running = false;
        
        // Notify all cleanup tasks
        if let Err(e) = self.shutdown_tx.send(()) {
            web_sys::console::error_1(&JsValue::from_str(
                &format!("Shutdown notification error: {}", e)
            ));
        }

        // Wait for tasks to complete
        let timeout = Duration::from_secs(5);
        match tokio::time::timeout(timeout, self.wait_for_tasks()).await {
            Ok(_) => Ok(()),
            Err(_) => {
                web_sys::console::warn_1(&JsValue::from_str(
                    "Cleanup tasks did not complete within timeout"
                ));
                Ok(())
            }
        }
    }

    async fn wait_for_tasks(&self) {
        // Wait for task queue to empty
        while self.task_tx.capacity() != BATCH_SIZE {
            tokio::time::sleep(Duration::from_millis(100)).await;
        }
    }

    async fn handle_shutdown(&self) {
        let mut is_running = self.is_running.write().await;
        *is_running = false;
        
        // Perform final cleanup if needed
        if let Err(e) = self.perform_final_cleanup().await {
            web_sys::console::error_1(&JsValue::from_str(
                &format!("Final cleanup error: {}", e)
            ));
        }
    }

    async fn perform_final_cleanup(&self) -> Result<(), JsValue> {
        // Process any remaining tasks
        let mut batch = Vec::new();
        while let Ok(task) = self.task_tx.try_send(CleanupTask {
            namespace: String::new(),
            key: String::new(),
            size_bytes: 0,
            last_access: 0,
        }) {
            batch.push(task);
        }

        if !batch.is_empty() {
            self.cleanup_batch(&batch).await?;
        }

        Ok(())
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&CleanupMetrics {
                items_removed: 0,
                last_cleanup: 0,
                cleanup_duration_ms: 0,
                errors_encountered: 0,
                batches_processed: 0,
                bytes_freed: 0,
            })?)
        }
    }

    #[wasm_bindgen]
    pub async fn update_max_age(&self, max_age_secs: u64) -> Result<(), JsValue> {
        let mut current_max_age = self.max_age_secs.write().await;
        *current_max_age = max_age_secs;
        Ok(())
    }
}

impl Drop for CacheCleaner {
    fn drop(&mut self) {
        self.metrics.clear();
    }
} 
