use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, Semaphore};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque};
use crate::error::error_codes::{ErrorCode, ErrorSeverity};

const MAX_RECOVERY_ATTEMPTS: u32 = 5;
const RECOVERY_TIMEOUT_MS: u64 = 10000;
const MAX_CONCURRENT_RECOVERIES: usize = 20;
const BACKOFF_BASE_MS: u64 = 100;

#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryOperation {
    operation_id: String,
    error_code: ErrorCode,
    component: String,
    state: RecoveryState,
    strategy: RecoveryStrategy,
    attempts: u32,
    timestamp: u64,
    checkpoints: Vec<RecoveryCheckpoint>,
    fallback_triggered: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryCheckpoint {
    checkpoint_id: String,
    timestamp: u64,
    state_snapshot: HashMap<String, String>,
    validation_status: bool,
    rollback_point: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RecoveryMetrics {
    total_attempts: u64,
    successful_recoveries: u64,
    failed_recoveries: u64,
    average_recovery_time_ms: f64,
    recovery_success_rate: f64,
    strategy_effectiveness: HashMap<RecoveryStrategy, f64>,
    error_recovery_patterns: Vec<RecoveryPattern>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum RecoveryStrategy {
    Retry,
    Rollback,
    Failover,
    Restart,
    StateReconstruction,
    CircuitBreaker,
    Quarantine,
    HotSwap,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RecoveryState {
    Initializing,
    AttemptingRecovery,
    ValidatingState,
    RollingBack,
    Succeeded,
    Failed,
    PartiallyRecovered,
}

#[derive(Clone, Serialize, Deserialize)]
struct RecoveryPattern {
    pattern_id: String,
    error_code: ErrorCode,
    successful_strategy: RecoveryStrategy,
    attempts_required: u32,
    recovery_time_ms: u64,
    success_rate: f64,
}

#[wasm_bindgen]
pub struct ErrorRecovery {
    operations: Arc<DashMap<String, RecoveryOperation>>,
    metrics: Arc<DashMap<String, RecoveryMetrics>>,
    recovery_semaphore: Arc<Semaphore>,
    notification_tx: Arc<broadcast::Sender<RecoveryOperation>>,
    active_recoveries: Arc<RwLock<VecDeque<String>>>,
    checkpoints: Arc<DashMap<String, Vec<RecoveryCheckpoint>>>,
}

#[wasm_bindgen]
impl ErrorRecovery {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let (notification_tx, _) = broadcast::channel(1000);
        
        let recovery = Self {
            operations: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            recovery_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_RECOVERIES)),
            notification_tx: Arc::new(notification_tx),
            active_recoveries: Arc::new(RwLock::new(VecDeque::new())),
            checkpoints: Arc::new(DashMap::new()),
        };

        recovery.start_maintenance_tasks();
        recovery
    }

    #[wasm_bindgen]
    pub async fn initiate_recovery(
        &self,
        error_code: u32,
        component: String,
        state: JsValue,
    ) -> Result<String, JsValue> {
        let error_code = unsafe { std::mem::transmute(error_code) };
        let state_snapshot: HashMap<String, String> = serde_wasm_bindgen::from_value(state)?;
        let timestamp = get_timestamp()?;

        let strategy = self.determine_recovery_strategy(error_code);
        let operation_id = generate_operation_id();

        let initial_checkpoint = RecoveryCheckpoint {
            checkpoint_id: generate_checkpoint_id(),
            timestamp,
            state_snapshot,
            validation_status: true,
            rollback_point: true,
        };

        let operation = RecoveryOperation {
            operation_id: operation_id.clone(),
            error_code,
            component,
            state: RecoveryState::Initializing,
            strategy,
            attempts: 0,
            timestamp,
            checkpoints: vec![initial_checkpoint],
            fallback_triggered: false,
        };

        self.operations.insert(operation_id.clone(), operation.clone());
        self.notify_recovery_initiated(operation).await?;

        Ok(operation_id)
    }

    fn determine_recovery_strategy(&self, error_code: ErrorCode) -> RecoveryStrategy {
        match error_code {
            ErrorCode::SystemOutOfMemory => RecoveryStrategy::Restart,
            ErrorCode::NetworkConnectionFailed => RecoveryStrategy::Retry,
            ErrorCode::DataCorruption => RecoveryStrategy::StateReconstruction,
            ErrorCode::SecurityAuthenticationFailed => RecoveryStrategy::CircuitBreaker,
            ErrorCode::ResourceDeadlock => RecoveryStrategy::Rollback,
            ErrorCode::CacheConsistencyError => RecoveryStrategy::HotSwap,
            ErrorCode::SystemStateCorruption => RecoveryStrategy::Failover,
            _ => RecoveryStrategy::Retry,
        }
    }

    async fn notify_recovery_initiated(
        &self,
        operation: RecoveryOperation,
    ) -> Result<(), JsValue> {
        if let Err(e) = self.notification_tx.send(operation) {
            return Err(JsValue::from_str(&format!("Notification error: {}", e)));
        }
        Ok(())
    }

    #[wasm_bindgen]
    pub async fn execute_recovery(
        &self,
        operation_id: String,
    ) -> Result<bool, JsValue> {
        let _permit = tokio::time::timeout(
            Duration::from_millis(RECOVERY_TIMEOUT_MS),
            self.recovery_semaphore.acquire(),
        ).await
            .map_err(|_| JsValue::from_str("Recovery timeout"))?
            .map_err(|e| JsValue::from_str(&format!("Semaphore error: {}", e)))?;

        let start_time = Instant::now();
        let result = self.perform_recovery(&operation_id).await;
        
        self.update_metrics(
            &operation_id,
            result.is_ok(),
            start_time.elapsed(),
        ).await;

        result
    }

    async fn perform_recovery(
        &self,
        operation_id: &str,
    ) -> Result<bool, JsValue> {
        let mut operation = self.operations.get_mut(operation_id)
            .ok_or_else(|| JsValue::from_str("Recovery operation not found"))?;

        if operation.attempts >= MAX_RECOVERY_ATTEMPTS {
            operation.state = RecoveryState::Failed;
            return Ok(false);
        }

        operation.attempts += 1;
        operation.state = RecoveryState::AttemptingRecovery;

        let recovery_result = match operation.strategy {
            RecoveryStrategy::Retry => {
                self.execute_retry_strategy(&mut operation).await
            }
            RecoveryStrategy::Rollback => {
                self.execute_rollback_strategy(&mut operation).await
            }
            RecoveryStrategy::Failover => {
                self.execute_failover_strategy(&mut operation).await
            }
            RecoveryStrategy::Restart => {
                self.execute_restart_strategy(&mut operation).await
            }
            RecoveryStrategy::StateReconstruction => {
                self.execute_reconstruction_strategy(&mut operation).await
            }
            RecoveryStrategy::CircuitBreaker => {
                self.execute_circuit_breaker_strategy(&mut operation).await
            }
            RecoveryStrategy::Quarantine => {
                self.execute_quarantine_strategy(&mut operation).await
            }
            RecoveryStrategy::HotSwap => {
                self.execute_hot_swap_strategy(&mut operation).await
            }
        };

        match recovery_result {
            Ok(()) => {
                operation.state = RecoveryState::ValidatingState;
                if self.validate_recovery_state(&operation).await? {
                    operation.state = RecoveryState::Succeeded;
                    Ok(true)
                } else {
                    self.attempt_fallback_recovery(&mut operation).await
                }
            }
            Err(_) => {
                if !operation.fallback_triggered {
                    self.attempt_fallback_recovery(&mut operation).await
                } else {
                    operation.state = RecoveryState::Failed;
                    Ok(false)
                }
            }
        }
    }

    async fn validate_recovery_state(
        &self,
        operation: &RecoveryOperation,
    ) -> Result<bool, JsValue> {
        // Implement state validation logic
        Ok(true)
    }

    async fn attempt_fallback_recovery(
        &self,
        operation: &mut RecoveryOperation,
    ) -> Result<bool, JsValue> {
        operation.fallback_triggered = true;
        operation.strategy = RecoveryStrategy::Rollback;
        self.perform_recovery(&operation.operation_id).await
    }

    async fn execute_retry_strategy(
        &self,
        operation: &mut RecoveryOperation,
    ) -> Result<(), JsValue> {
        let backoff = Duration::from_millis(
            BACKOFF_BASE_MS * 2u64.pow(operation.attempts - 1)
        );
        tokio::time::sleep(backoff).await;
        Ok(())
    }

    async fn execute_rollback_strategy(
        &self,
        operation: &mut RecoveryOperation,
    ) -> Result<(), JsValue> {
        if let Some(checkpoint) = operation.checkpoints
            .iter()
            .rev()
            .find(|cp| cp.rollback_point) {
                // Implement rollback logic
                Ok(())
            } else {
                Err(JsValue::from_str("No valid rollback point found"))
            }
    }

    async fn execute_failover_strategy(
        &self,
        operation: &mut RecoveryOperation,
    ) -> Result<(), JsValue> {
        // Implement failover logic
        Ok(())
    }

    async fn execute_restart_strategy(
        &self,
        operation: &mut RecoveryOperation,
    ) -> Result<(), JsValue> {
        // Implement restart logic
        Ok(())
    }

    async fn execute_reconstruction_strategy(
        &self,
        operation: &mut RecoveryOperation,
    ) -> Result<(), JsValue> {
        // Implement state reconstruction logic
        Ok(())
    }

    async fn execute_circuit_breaker_strategy(
        &self,
        operation: &mut RecoveryOperation,
    ) -> Result<(), JsValue> {
        // Implement circuit breaker logic
        Ok(())
    }

    async fn execute_quarantine_strategy(
        &self,
        operation: &mut RecoveryOperation,
    ) -> Result<(), JsValue> {
        // Implement quarantine logic
        Ok(())
    }

    async fn execute_hot_swap_strategy(
        &self,
        operation: &mut RecoveryOperation,
    ) -> Result<(), JsValue> {
        // Implement hot swap logic
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
                    m.total_attempts += 1;
                    if success {
                        m.successful_recoveries += 1;
                    } else {
                        m.failed_recoveries += 1;
                    }
                    m.average_recovery_time_ms = (m.average_recovery_time_ms * 0.9)
                        + (duration.as_millis() as f64 * 0.1);
                    m.recovery_success_rate = m.successful_recoveries as f64
                        / m.total_attempts as f64;
                    
                    let effectiveness = m.strategy_effectiveness
                        .entry(operation.strategy)
                        .or_insert(0.0);
                    *effectiveness = (*effectiveness * 0.9) + (if success { 1.0 } else { 0.0 } * 0.1);
                })
                .or_insert_with(|| RecoveryMetrics {
                    total_attempts: 1,
                    successful_recoveries: if success { 1 } else { 0 },
                    failed_recoveries: if success { 0 } else { 1 },
                    average_recovery_time_ms: duration.as_millis() as f64,
                    recovery_success_rate: if success { 1.0 } else { 0.0 },
                    strategy_effectiveness: {
                        let mut map = HashMap::new();
                        map.insert(operation.strategy, if success { 1.0 } else { 0.0 });
                        map
                    },
                    error_recovery_patterns: Vec::new(),
                });
        }
    }

    fn start_maintenance_tasks(&self) {
        let recovery = Arc::new(self.clone());

        // Cleanup task
        tokio::spawn({
            let recovery = recovery.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    recovery.cleanup_old_operations().await;
                }
            }
        });
    }

    async fn cleanup_old_operations(&self) {
        let cutoff = get_timestamp().unwrap_or(0) - 86400; // 24 hours
        self.operations.retain(|_, op| {
            op.timestamp > cutoff || op.state == RecoveryState::AttemptingRecovery
        });
        
        let mut active_recoveries = self.active_recoveries.write().await;
        active_recoveries.retain(|op_id| {
            self.operations.contains_key(op_id)
        });
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&RecoveryMetrics {
                total_attempts: 0,
                successful_recoveries: 0,
                failed_recoveries: 0,
                average_recovery_time_ms: 0.0,
                recovery_success_rate: 0.0,
                strategy_effectiveness: HashMap::new(),
                error_recovery_patterns: Vec::new(),
            })?)
        }
    }
}

fn generate_operation_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("RECOVERY-{:016x}", rng.gen::<u64>())
}

fn generate_checkpoint_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("CHECKPOINT-{:016x}", rng.gen::<u64>())
}

fn get_timestamp() -> Result<u64, JsValue> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for ErrorRecovery {
    fn drop(&mut self) {
        self.operations.clear();
        self.metrics.clear();
        self.checkpoints.clear();
    }
} 