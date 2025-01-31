use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, Semaphore};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque, HashSet, BTreeMap};
use sha3::{Sha3_512, Digest};
use chrono::{DateTime, Utc};

const MAX_AUDIT_ENTRIES: usize = 1_000_000;
const AUDIT_BATCH_SIZE: usize = 1000;
const AUDIT_FLUSH_INTERVAL_MS: u64 = 1000;
const MAX_CONCURRENT_WRITERS: usize = 20;

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditLogger {
    logger_id: String,
    retention_policy: RetentionPolicy,
    encryption_config: EncryptionConfig,
    filters: Vec<AuditFilter>,
    metrics: AuditMetrics,
    integrity_checks: Vec<IntegrityCheck>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    entry_id: String,
    timestamp: DateTime<Utc>,
    event_type: AuditEventType,
    severity: AuditSeverity,
    source: AuditSource,
    actor: Actor,
    action: Action,
    resource: Resource,
    context: HashMap<String, String>,
    metadata: HashMap<String, String>,
    chain_id: Option<String>,
    signature: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetentionPolicy {
    retention_period_days: u32,
    storage_limit_gb: u64,
    priority_levels: HashMap<AuditSeverity, u32>,
    compression_enabled: bool,
    encryption_required: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    algorithm: EncryptionAlgorithm,
    key_rotation_days: u32,
    key_strength: u32,
    initialization_vector: Vec<u8>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditFilter {
    filter_id: String,
    conditions: Vec<FilterCondition>,
    effect: FilterEffect,
    priority: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditMetrics {
    total_entries: u64,
    entries_by_severity: HashMap<AuditSeverity, u64>,
    average_entry_size_bytes: u64,
    integrity_violations: u64,
    compression_ratio: f64,
    retention_compliance: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IntegrityCheck {
    check_id: String,
    check_type: IntegrityCheckType,
    last_check: DateTime<Utc>,
    result: IntegrityResult,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditEventType {
    Security,
    Compliance,
    Operation,
    Performance,
    System,
    Custom(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum AuditSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditSource {
    source_type: SourceType,
    identifier: String,
    location: String,
    component: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Actor {
    actor_id: String,
    actor_type: ActorType,
    permissions: HashSet<String>,
    session_id: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Action {
    action_type: ActionType,
    status: ActionStatus,
    duration_ms: u64,
    error: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Resource {
    resource_id: String,
    resource_type: ResourceType,
    state_before: Option<String>,
    state_after: Option<String>,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum EncryptionAlgorithm {
    AES256GCM,
    ChaCha20Poly1305,
    Custom(String),
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum FilterEffect {
    Include,
    Exclude,
    Transform,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum IntegrityCheckType {
    Hash,
    Signature,
    Chain,
    Custom,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IntegrityResult {
    status: IntegrityStatus,
    details: String,
    timestamp: DateTime<Utc>,
}

#[wasm_bindgen]
pub struct AuditController {
    loggers: Arc<DashMap<String, AuditLogger>>,
    entries: Arc<DashMap<String, VecDeque<AuditEntry>>>,
    metrics: Arc<DashMap<String, AuditMetrics>>,
    writer_semaphore: Arc<Semaphore>,
    notification_tx: Arc<broadcast::Sender<AuditEvent>>,
    batch_queue: Arc<RwLock<VecDeque<Vec<AuditEntry>>>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    event_id: String,
    logger_id: String,
    event_type: AuditEventType,
    timestamp: DateTime<Utc>,
    details: HashMap<String, String>,
}

#[wasm_bindgen]
impl AuditController {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let (notification_tx, _) = broadcast::channel(1000);
        
        let controller = Self {
            loggers: Arc::new(DashMap::new()),
            entries: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            writer_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_WRITERS)),
            notification_tx: Arc::new(notification_tx),
            batch_queue: Arc::new(RwLock::new(VecDeque::new())),
        };

        controller.start_audit_tasks();
        controller
    }

    #[wasm_bindgen]
    pub async fn log_entry(
        &self,
        entry_data: JsValue,
    ) -> Result<JsValue, JsValue> {
        let mut entry: AuditEntry = serde_wasm_bindgen::from_value(entry_data)?;
        
        let _permit = self.writer_semaphore.acquire().await
            .map_err(|e| JsValue::from_str(&format!("Failed to acquire permit: {}", e)))?;

        // Apply filters
        if !self.should_log_entry(&entry).await? {
            return Ok(JsValue::NULL);
        }

        // Add integrity signature
        entry.signature = self.generate_entry_signature(&entry)?;

        // Add to batch queue
        self.queue_entry(entry.clone()).await?;

        // Update metrics
        self.update_entry_metrics(&entry).await?;

        Ok(serde_wasm_bindgen::to_value(&entry)?)
    }

    async fn should_log_entry(&self, entry: &AuditEntry) -> Result<bool, JsValue> {
        if let Some(logger) = self.loggers.get(&entry.source.component) {
            for filter in &logger.filters {
                if self.evaluate_filter(filter, entry).await? {
                    return Ok(filter.effect == FilterEffect::Include);
                }
            }
        }
        Ok(true)
    }

    fn generate_entry_signature(&self, entry: &AuditEntry) -> Result<String, JsValue> {
        let mut hasher = Sha3_512::new();
        
        // Create deterministic string from entry fields
        let entry_string = serde_json::to_string(entry)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;
        
        hasher.update(entry_string.as_bytes());
        Ok(format!("{:x}", hasher.finalize()))
    }

    async fn queue_entry(&self, entry: AuditEntry) -> Result<(), JsValue> {
        let mut batch_queue = self.batch_queue.write().await;
        
        if batch_queue.is_empty() || batch_queue.back().unwrap().len() >= AUDIT_BATCH_SIZE {
            batch_queue.push_back(Vec::with_capacity(AUDIT_BATCH_SIZE));
        }
        
        if let Some(current_batch) = batch_queue.back_mut() {
            current_batch.push(entry);
        }
        
        Ok(())
    }

    async fn flush_batch_queue(&self) -> Result<(), JsValue> {
        let mut batch_queue = self.batch_queue.write().await;
        
        while let Some(batch) = batch_queue.pop_front() {
            if !batch.is_empty() {
                self.write_batch(&batch).await?;
            }
        }
        
        Ok(())
    }

    async fn write_batch(&self, batch: &[AuditEntry]) -> Result<(), JsValue> {
        for entry in batch {
            if let Some(mut entries) = self.entries.get_mut(&entry.source.component) {
                entries.push_back(entry.clone());
                
                // Apply retention policy
                while entries.len() > MAX_AUDIT_ENTRIES {
                    entries.pop_front();
                }
            }
        }
        Ok(())
    }

    async fn update_entry_metrics(&self, entry: &AuditEntry) -> Result<(), JsValue> {
        if let Some(mut metrics) = self.metrics.get_mut(&entry.source.component) {
            metrics.total_entries += 1;
            *metrics.entries_by_severity.entry(entry.severity).or_insert(0) += 1;
            
            // Calculate entry size
            let entry_size = serde_json::to_string(entry)
                .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?
                .len() as u64;
            
            metrics.average_entry_size_bytes = 
                (metrics.average_entry_size_bytes * (metrics.total_entries - 1) + entry_size) 
                / metrics.total_entries;
        }
        Ok(())
    }

    fn start_audit_tasks(&self) {
        let controller = Arc::new(self.clone());

        // Batch flush task
        tokio::spawn({
            let controller = controller.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(AUDIT_FLUSH_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    if let Err(e) = controller.flush_batch_queue().await {
                        eprintln!("Error flushing batch queue: {:?}", e);
                    }
                }
            }
        });

        // Integrity check task
        tokio::spawn({
            let controller = controller.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    if let Err(e) = controller.perform_integrity_checks().await {
                        eprintln!("Error performing integrity checks: {:?}", e);
                    }
                }
            }
        });

        // Retention policy task
        tokio::spawn({
            let controller = controller.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(86400));
                loop {
                    interval.tick().await;
                    if let Err(e) = controller.apply_retention_policies().await {
                        eprintln!("Error applying retention policies: {:?}", e);
                    }
                }
            }
        });
    }

    async fn perform_integrity_checks(&self) -> Result<(), JsValue> {
        for logger in self.loggers.iter() {
            for check in &logger.integrity_checks {
                self.perform_integrity_check(check, &logger).await?;
            }
        }
        Ok(())
    }

    async fn perform_integrity_check(
        &self,
        check: &IntegrityCheck,
        logger: &AuditLogger,
    ) -> Result<(), JsValue> {
        match check.check_type {
            IntegrityCheckType::Hash => {
                self.verify_entry_hashes(logger).await?;
            }
            IntegrityCheckType::Signature => {
                self.verify_entry_signatures(logger).await?;
            }
            IntegrityCheckType::Chain => {
                self.verify_entry_chain(logger).await?;
            }
            IntegrityCheckType::Custom => {
                // Implement custom integrity checks
            }
        }
        Ok(())
    }

    async fn apply_retention_policies(&self) -> Result<(), JsValue> {
        for logger in self.loggers.iter() {
            self.apply_retention_policy(&logger).await?;
        }
        Ok(())
    }

    async fn apply_retention_policy(&self, logger: &AuditLogger) -> Result<(), JsValue> {
        if let Some(mut entries) = self.entries.get_mut(&logger.logger_id) {
            let now = Utc::now();
            let retention_threshold = now - chrono::Duration::days(
                logger.retention_policy.retention_period_days as i64
            );
            
            entries.retain(|entry| entry.timestamp > retention_threshold);
        }
        Ok(())
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&AuditMetrics {
                total_entries: 0,
                entries_by_severity: HashMap::new(),
                average_entry_size_bytes: 0,
                integrity_violations: 0,
                compression_ratio: 0.0,
                retention_compliance: 0.0,
            })?)
        }
    }
}

fn generate_entry_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("ENTRY-{:016x}", rng.gen::<u64>())
}

impl Drop for AuditController {
    fn drop(&mut self) {
        self.loggers.clear();
        self.entries.clear();
        self.metrics.clear();
    }
} 
