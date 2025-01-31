use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, Semaphore};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque};
use crate::error::error_codes::{ErrorCode, ErrorSeverity};

const MAX_CLEANUP_RETRIES: u32 = 3;
const CLEANUP_TIMEOUT_MS: u64 = 5000;
const MAX_CONCURRENT_CLEANUPS: usize = 10;
const CLEANUP_BATCH_SIZE: usize = 100;

#[derive(Clone, Serialize, Deserialize)]
pub struct CleanupOperation {
    operation_id: String,
    error_code: ErrorCode,
    component: String,
    resources: Vec<ResourceIdentifier>,
    timestamp: u64,
    status: CleanupStatus,
    retries: u32,
    cleanup_steps: Vec<CleanupStep>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ResourceIdentifier {
    resource_type: ResourceType,
    identifier: String,
    state: ResourceState,
    dependencies: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CleanupStep {
    step_id: String,
    resource: ResourceIdentifier,
    action: CleanupAction,
    status: StepStatus,
    error: Option<ErrorCode>,
    timestamp: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CleanupMetrics {
    total_operations: u64,
    successful_cleanups: u64,
    failed_cleanups: u64,
    retry_count: u64,
    average_cleanup_time_ms: f64,
    resource_recovery_rate: f64,
    cleanup_patterns: Vec<CleanupPattern>,
    resource_states: HashMap<ResourceType, u32>,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CleanupStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    PartiallyCompleted,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    Memory,
    File,
    Network,
    Database,
    Cache,
    Lock,
    Thread,
    Process,
    Connection,
    Transaction,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ResourceState {
    Active,
    Corrupted,
    Locked,
    Leaking,
    Inconsistent,
    Orphaned,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum CleanupAction {
    Release,
    Reset,
    Rollback,
    Delete,
    Disconnect,
    Kill,
    Recreate,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum StepStatus {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

#[derive(Clone, Serialize, Deserialize)]
struct CleanupPattern {
    pattern_id: String,
    frequency: u32,
    success_rate: f64,
    average_duration_ms: f64,
    common_resources: Vec<ResourceType>,
}

#[wasm_bindgen]
pub struct ErrorCleanup {
    operations: Arc<DashMap<String, CleanupOperation>>,
    metrics: Arc<DashMap<String, CleanupMetrics>>,
    cleanup_semaphore: Arc<Semaphore>,
    notification_tx: Arc<broadcast::Sender<CleanupOperation>>,
    active_cleanups: Arc<RwLock<VecDeque<String>>>,
}

#[wasm_bindgen]
impl ErrorCleanup {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let (notification_tx, _) = broadcast::channel(1000);
        
        let cleanup = Self {
            operations: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            cleanup_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CLEANUPS)),
            notification_tx: Arc::new(notification_tx),
            active_cleanups: Arc::new(RwLock::new(VecDeque::new())),
        };

        cleanup.start_maintenance_tasks();
        cleanup
    }

    #[wasm_bindgen]
    pub async fn initiate_cleanup(
        &self,
        error_code: u32,
        component: String,
        resources: JsValue,
    ) -> Result<String, JsValue> {
        let error_code = unsafe { std::mem::transmute(error_code) };
        let resources: Vec<ResourceIdentifier> = serde_wasm_bindgen::from_value(resources)?;
        let timestamp = get_timestamp()?;

        let operation_id = generate_operation_id();
        let cleanup_steps = self.generate_cleanup_steps(&resources, timestamp)?;

        let operation = CleanupOperation {
            operation_id: operation_id.clone(),
            error_code,
            component,
            resources,
            timestamp,
            status: CleanupStatus::Pending,
            retries: 0,
            cleanup_steps,
        };

        self.operations.insert(operation_id.clone(), operation.clone());
        self.notify_cleanup_initiated(operation).await?;

        Ok(operation_id)
    }

    fn generate_cleanup_steps(
        &self,
        resources: &[ResourceIdentifier],
        timestamp: u64,
    ) -> Result<Vec<CleanupStep>, JsValue> {
        let mut steps = Vec::new();
        let mut processed = std::collections::HashSet::new();
        let mut queue = VecDeque::new();

        // Add all resources to queue
        for resource in resources {
            queue.push_back(resource.clone());
        }

        // Process resources in dependency order
        while let Some(resource) = queue.pop_front() {
            if processed.contains(&resource.identifier) {
                continue;
            }

            // Check if all dependencies are processed
            let deps_processed = resource.dependencies.iter()
                .all(|dep| processed.contains(dep));

            if !deps_processed {
                queue.push_back(resource.clone());
                continue;
            }

            let action = self.determine_cleanup_action(&resource);
            steps.push(CleanupStep {
                step_id: generate_step_id(),
                resource: resource.clone(),
                action,
                status: StepStatus::Pending,
                error: None,
                timestamp,
            });

            processed.insert(resource.identifier.clone());
        }

        Ok(steps)
    }

    fn determine_cleanup_action(&self, resource: &ResourceIdentifier) -> CleanupAction {
        match (resource.resource_type, resource.state) {
            (ResourceType::Memory, _) => CleanupAction::Release,
            (ResourceType::File, ResourceState::Corrupted) => CleanupAction::Delete,
            (ResourceType::Network, _) => CleanupAction::Disconnect,
            (ResourceType::Database, ResourceState::Inconsistent) => CleanupAction::Rollback,
            (ResourceType::Cache, _) => CleanupAction::Reset,
            (ResourceType::Lock, _) => CleanupAction::Release,
            (ResourceType::Thread, _) => CleanupAction::Kill,
            (ResourceType::Process, _) => CleanupAction::Kill,
            (ResourceType::Connection, _) => CleanupAction::Disconnect,
            (ResourceType::Transaction, _) => CleanupAction::Rollback,
            _ => CleanupAction::Release,
        }
    }

    async fn notify_cleanup_initiated(
        &self,
        operation: CleanupOperation,
    ) -> Result<(), JsValue> {
        if let Err(e) = self.notification_tx.send(operation) {
            return Err(JsValue::from_str(&format!("Notification error: {}", e)));
        }
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn execute_cleanup(
        &self,
        operation_id: String,
    ) -> Result<bool, JsValue> {
        let _permit = tokio::time::timeout(
            Duration::from_millis(CLEANUP_TIMEOUT_MS),
            self.cleanup_semaphore.acquire(),
        ).await
            .map_err(|_| JsValue::from_str("Cleanup timeout"))?
            .map_err(|e| JsValue::from_str(&format!("Semaphore error: {}", e)))?;

        let start_time = Instant::now();
        let result = self.perform_cleanup(&operation_id).await;
        
        self.update_metrics(
            &operation_id,
            result.is_ok(),
            start_time.elapsed(),
        ).await;

        result
    }

    async fn perform_cleanup(
        &self,
        operation_id: &str,
    ) -> Result<bool, JsValue> {
        let mut operation = self.operations.get_mut(operation_id)
            .ok_or_else(|| JsValue::from_str("Cleanup operation not found"))?;

        operation.status = CleanupStatus::InProgress;
        
        for step in operation.cleanup_steps.iter_mut() {
            step.status = StepStatus::Running;
            
            match self.execute_cleanup_step(step).await {
                Ok(()) => {
                    step.status = StepStatus::Completed;
                }
                Err(e) => {
                    step.status = StepStatus::Failed;
                    step.error = Some(e);
                    
                    if operation.retries < MAX_CLEANUP_RETRIES {
                        operation.retries += 1;
                        return self.perform_cleanup(operation_id).await;
                    } else {
                        operation.status = CleanupStatus::Failed;
                        return Ok(false);
                    }
                }
            }
        }

        operation.status = CleanupStatus::Completed;
        Ok(true)
    }

    async fn execute_cleanup_step(
        &self,
        step: &mut CleanupStep,
    ) -> Result<(), ErrorCode> {
        match step.action {
            CleanupAction::Release => {
                // Release resource logic
            }
            CleanupAction::Reset => {
                // Reset resource logic
            }
            CleanupAction::Rollback => {
                // Rollback resource logic
            }
            CleanupAction::Delete => {
                // Delete resource logic
            }
            CleanupAction::Disconnect => {
                // Disconnect resource logic
            }
            CleanupAction::Kill => {
                // Kill resource logic
            }
            CleanupAction::Recreate => {
                // Recreate resource logic
            }
        }
        Ok(())
    }

    async fn update_metrics(
        &self,
        operation_id: &str,
        success: bool,
        duration: Duration,
    ) {
        if let Some(operation) = self.operations.get(operation_id) {
            self.metrics
                .entry("global".to_string())
                .and_modify(|m| {
                    m.total_operations += 1;
                    if success {
                        m.successful_cleanups += 1;
                    } else {
                        m.failed_cleanups += 1;
                    }
                    m.retry_count += operation.retries as u64;
                    m.average_cleanup_time_ms = (m.average_cleanup_time_ms * 0.9)
                        + (duration.as_millis() as f64 * 0.1);
                    m.resource_recovery_rate = m.successful_cleanups as f64
                        / m.total_operations as f64;
                })
                .or_insert_with(|| CleanupMetrics {
                    total_operations: 1,
                    successful_cleanups: if success { 1 } else { 0 },
                    failed_cleanups: if success { 0 } else { 1 },
                    retry_count: operation.retries as u64,
                    average_cleanup_time_ms: duration.as_millis() as f64,
                    resource_recovery_rate: if success { 1.0 } else { 0.0 },
                    cleanup_patterns: Vec::new(),
                    resource_states: HashMap::new(),
                });
        }
    }

    fn start_maintenance_tasks(&self) {
        let cleanup = Arc::new(self.clone());

        // Cleanup task
        tokio::spawn({
            let cleanup = cleanup.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    cleanup.cleanup_old_operations().await;
                }
            }
        });
    }

    async fn cleanup_old_operations(&self) {
        let cutoff = get_timestamp().unwrap_or(0) - 86400; // 24 hours
        self.operations.retain(|_, op| {
            op.timestamp > cutoff || op.status == CleanupStatus::InProgress
        });
        
        let mut active_cleanups = self.active_cleanups.write().await;
        active_cleanups.retain(|op_id| {
            self.operations.contains_key(op_id)
        });
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&CleanupMetrics {
                total_operations: 0,
                successful_cleanups: 0,
                failed_cleanups: 0,
                retry_count: 0,
                average_cleanup_time_ms: 0.0,
                resource_recovery_rate: 0.0,
                cleanup_patterns: Vec::new(),
                resource_states: HashMap::new(),
            })?)
        }
    }
}

fn generate_operation_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("CLEANUP-{:016x}", rng.gen::<u64>())
}

fn generate_step_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("STEP-{:016x}", rng.gen::<u64>())
}

fn get_timestamp() -> Result<u64, JsValue> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for ErrorCleanup {
    fn drop(&mut self) {
        self.operations.clear();
        self.metrics.clear();
    }
} 