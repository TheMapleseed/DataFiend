use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, Semaphore};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque, HashSet};
use sha3::{Sha3_512, Digest};

const MAX_STATE_SIZE: usize = 1024 * 1024 * 10; // 10MB
const MAX_HISTORY_LENGTH: usize = 1000;
const STATE_CHECK_INTERVAL_MS: u64 = 100;
const MAX_CONCURRENT_TRANSITIONS: usize = 50;

#[derive(Clone, Serialize, Deserialize)]
pub struct StateSnapshot {
    snapshot_id: String,
    timestamp: u64,
    state_data: HashMap<String, StateValue>,
    checksum: String,
    version: u64,
    parent_id: Option<String>,
    metadata: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StateTransition {
    transition_id: String,
    from_state: String,
    to_state: String,
    changes: Vec<StateChange>,
    timestamp: u64,
    status: TransitionStatus,
    validation_result: Option<ValidationResult>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StateChange {
    key: String,
    old_value: Option<StateValue>,
    new_value: Option<StateValue>,
    change_type: ChangeType,
    validation_rules: Vec<ValidationRule>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ValidationResult {
    is_valid: bool,
    errors: Vec<ValidationError>,
    warnings: Vec<String>,
    timestamp: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ValidationError {
    error_code: String,
    message: String,
    field: Option<String>,
    severity: ValidationSeverity,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StateMetrics {
    total_transitions: u64,
    successful_transitions: u64,
    failed_transitions: u64,
    average_transition_time_ms: f64,
    state_size_bytes: usize,
    validation_success_rate: f64,
    transition_patterns: Vec<TransitionPattern>,
    state_access_patterns: HashMap<String, u64>,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum StateValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Array(Vec<StateValue>),
    Object(HashMap<String, StateValue>),
    Null,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TransitionStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    Rolled_Back,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ChangeType {
    Create,
    Update,
    Delete,
    Merge,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum ValidationRule {
    Required,
    Type(String),
    Range { min: f64, max: f64 },
    Length { min: usize, max: usize },
    Pattern(String),
    Custom(String),
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ValidationSeverity {
    Error,
    Warning,
    Info,
}

#[derive(Clone, Serialize, Deserialize)]
struct TransitionPattern {
    pattern_id: String,
    frequency: u32,
    success_rate: f64,
    average_duration_ms: f64,
    common_changes: Vec<String>,
}

#[wasm_bindgen]
pub struct StateManager {
    current_state: Arc<RwLock<StateSnapshot>>,
    history: Arc<RwLock<VecDeque<StateSnapshot>>>,
    transitions: Arc<DashMap<String, StateTransition>>,
    metrics: Arc<DashMap<String, StateMetrics>>,
    transition_semaphore: Arc<Semaphore>,
    notification_tx: Arc<broadcast::Sender<StateTransition>>,
    validation_rules: Arc<DashMap<String, Vec<ValidationRule>>>,
}

#[wasm_bindgen]
impl StateManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let (notification_tx, _) = broadcast::channel(1000);
        
        let initial_state = StateSnapshot {
            snapshot_id: generate_snapshot_id(),
            timestamp: get_timestamp().unwrap_or(0),
            state_data: HashMap::new(),
            checksum: "".to_string(),
            version: 0,
            parent_id: None,
            metadata: HashMap::new(),
        };

        let manager = Self {
            current_state: Arc::new(RwLock::new(initial_state)),
            history: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_HISTORY_LENGTH))),
            transitions: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            transition_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_TRANSITIONS)),
            notification_tx: Arc::new(notification_tx),
            validation_rules: Arc::new(DashMap::new()),
        };

        manager.start_maintenance_tasks();
        manager
    }

    #[wasm_bindgen]
    pub async fn transition_state(
        &self,
        changes: JsValue,
    ) -> Result<String, JsValue> {
        let changes: Vec<StateChange> = serde_wasm_bindgen::from_value(changes)?;
        let _permit = self.transition_semaphore.acquire().await.map_err(|e| {
            JsValue::from_str(&format!("Failed to acquire transition permit: {}", e))
        })?;

        let transition_id = generate_transition_id();
        let current_state = self.current_state.read().await;
        let from_state = current_state.snapshot_id.clone();
        
        // Validate changes
        let validation_result = self.validate_changes(&changes).await?;
        if !validation_result.is_valid {
            return Err(JsValue::from_str("Invalid state transition"));
        }

        // Create new state
        let mut new_state = current_state.clone();
        new_state.snapshot_id = generate_snapshot_id();
        new_state.timestamp = get_timestamp()?;
        new_state.version += 1;
        new_state.parent_id = Some(from_state.clone());

        // Apply changes
        for change in &changes {
            match change.change_type {
                ChangeType::Create | ChangeType::Update => {
                    if let Some(ref new_value) = change.new_value {
                        new_state.state_data.insert(change.key.clone(), new_value.clone());
                    }
                }
                ChangeType::Delete => {
                    new_state.state_data.remove(&change.key);
                }
                ChangeType::Merge => {
                    if let Some(StateValue::Object(ref new_obj)) = change.new_value {
                        if let Some(StateValue::Object(ref mut existing_obj)) = new_state.state_data.get_mut(&change.key) {
                            existing_obj.extend(new_obj.clone());
                        } else {
                            new_state.state_data.insert(change.key.clone(), StateValue::Object(new_obj.clone()));
                        }
                    }
                }
            }
        }

        // Update checksum
        new_state.checksum = self.calculate_checksum(&new_state)?;

        // Create transition record
        let transition = StateTransition {
            transition_id: transition_id.clone(),
            from_state,
            to_state: new_state.snapshot_id.clone(),
            changes,
            timestamp: get_timestamp()?,
            status: TransitionStatus::Completed,
            validation_result: Some(validation_result),
        };

        // Update state and history
        {
            let mut history = self.history.write().await;
            history.push_back(current_state.clone());
            while history.len() > MAX_HISTORY_LENGTH {
                history.pop_front();
            }
        }

        *self.current_state.write().await = new_state;
        self.transitions.insert(transition_id.clone(), transition.clone());
        self.notify_transition(transition).await?;

        Ok(transition_id)
    }

    async fn validate_changes(&self, changes: &[StateChange]) -> Result<ValidationResult, JsValue> {
        let mut errors = Vec::new();
        let mut warnings = Vec::new();

        for change in changes {
            if let Some(rules) = self.validation_rules.get(&change.key) {
                for rule in rules.iter() {
                    if let Some(ref new_value) = change.new_value {
                        match self.validate_value(new_value, rule) {
                            Ok(_) => continue,
                            Err(error) => {
                                errors.push(ValidationError {
                                    error_code: "VALIDATION_ERROR".to_string(),
                                    message: error,
                                    field: Some(change.key.clone()),
                                    severity: ValidationSeverity::Error,
                                });
                            }
                        }
                    }
                }
            }
        }

        Ok(ValidationResult {
            is_valid: errors.is_empty(),
            errors,
            warnings,
            timestamp: get_timestamp()?,
        })
    }

    fn validate_value(&self, value: &StateValue, rule: &ValidationRule) -> Result<(), String> {
        match rule {
            ValidationRule::Required => {
                if matches!(value, StateValue::Null) {
                    return Err("Value is required".to_string());
                }
            }
            ValidationRule::Type(expected_type) => {
                match (expected_type.as_str(), value) {
                    ("string", StateValue::String(_)) => {}
                    ("number", StateValue::Number(_)) => {}
                    ("boolean", StateValue::Boolean(_)) => {}
                    ("array", StateValue::Array(_)) => {}
                    ("object", StateValue::Object(_)) => {}
                    _ => return Err(format!("Invalid type, expected {}", expected_type)),
                }
            }
            ValidationRule::Range { min, max } => {
                if let StateValue::Number(n) = value {
                    if *n < *min || *n > *max {
                        return Err(format!("Value must be between {} and {}", min, max));
                    }
                }
            }
            ValidationRule::Length { min, max } => {
                match value {
                    StateValue::String(s) => {
                        if s.len() < *min || s.len() > *max {
                            return Err(format!("Length must be between {} and {}", min, max));
                        }
                    }
                    StateValue::Array(arr) => {
                        if arr.len() < *min || arr.len() > *max {
                            return Err(format!("Array length must be between {} and {}", min, max));
                        }
                    }
                    _ => {}
                }
            }
            ValidationRule::Pattern(pattern) => {
                if let StateValue::String(s) = value {
                    // Implement pattern matching
                }
            }
            ValidationRule::Custom(rule_name) => {
                // Implement custom validation
            }
        }
        Ok(())
    }

    fn calculate_checksum(&self, state: &StateSnapshot) -> Result<String, JsValue> {
        let serialized = serde_json::to_string(&state.state_data)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {}", e)))?;
        
        let mut hasher = Sha3_512::new();
        hasher.update(serialized.as_bytes());
        Ok(format!("{:x}", hasher.finalize()))
    }

    async fn notify_transition(&self, transition: StateTransition) -> Result<(), JsValue> {
        if let Err(e) = self.notification_tx.send(transition) {
            return Err(JsValue::from_str(&format!("Notification error: {}", e)));
        }
        Ok(())
    }

    fn start_maintenance_tasks(&self) {
        let manager = Arc::new(self.clone());

        // State check task
        tokio::spawn({
            let manager = manager.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(STATE_CHECK_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    manager.verify_state_integrity().await;
                }
            }
        });
    }

    async fn verify_state_integrity(&self) {
        let current_state = self.current_state.read().await;
        let calculated_checksum = self.calculate_checksum(&current_state).unwrap_or_default();
        
        if calculated_checksum != current_state.checksum {
            // Handle integrity violation
        }
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&StateMetrics {
                total_transitions: 0,
                successful_transitions: 0,
                failed_transitions: 0,
                average_transition_time_ms: 0.0,
                state_size_bytes: 0,
                validation_success_rate: 0.0,
                transition_patterns: Vec::new(),
                state_access_patterns: HashMap::new(),
            })?)
        }
    }
}

fn generate_snapshot_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("SNAPSHOT-{:016x}", rng.gen::<u64>())
}

fn generate_transition_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("TRANSITION-{:016x}", rng.gen::<u64>())
}

fn get_timestamp() -> Result<u64, JsValue> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for StateManager {
    fn drop(&mut self) {
        self.transitions.clear();
        self.metrics.clear();
        self.validation_rules.clear();
    }
}
