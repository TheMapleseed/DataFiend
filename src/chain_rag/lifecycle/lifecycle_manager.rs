use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, Semaphore};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque, HashSet, BTreeMap};
use tokio::time::sleep;

const MAX_LIFECYCLE_STATES: usize = 100;
const LIFECYCLE_CHECK_INTERVAL_MS: u64 = 100;
const MAX_CONCURRENT_TRANSITIONS: usize = 50;
const STATE_TIMEOUT_MS: u64 = 30000;

#[derive(Clone, Serialize, Deserialize)]
pub struct LifecycleManager {
    manager_id: String,
    state_machine: StateMachine,
    transition_rules: Vec<TransitionRule>,
    policies: Vec<LifecyclePolicy>,
    metrics: LifecycleMetrics,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StateMachine {
    states: HashMap<String, State>,
    transitions: Vec<Transition>,
    current_state: String,
    history: VecDeque<StateTransition>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct State {
    state_id: String,
    state_type: StateType,
    validators: Vec<StateValidator>,
    handlers: Vec<StateHandler>,
    timeout_ms: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Transition {
    transition_id: String,
    from_state: String,
    to_state: String,
    conditions: Vec<TransitionCondition>,
    actions: Vec<TransitionAction>,
    rollback: Option<RollbackStrategy>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TransitionRule {
    rule_id: String,
    conditions: Vec<RuleCondition>,
    actions: Vec<RuleAction>,
    priority: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LifecyclePolicy {
    policy_id: String,
    state_policies: HashMap<String, StatePolicy>,
    transition_policies: Vec<TransitionPolicy>,
    timeout_policy: TimeoutPolicy,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LifecycleMetrics {
    total_transitions: u64,
    failed_transitions: u64,
    average_transition_time_ms: f64,
    state_distribution: HashMap<String, u64>,
    timeout_events: u64,
    policy_violations: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StateTransition {
    transition_id: String,
    from_state: String,
    to_state: String,
    timestamp: u64,
    duration_ms: u64,
    result: TransitionResult,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StateValidator {
    validator_id: String,
    validation_type: ValidationType,
    parameters: HashMap<String, String>,
    error_message: String,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StateHandler {
    handler_id: String,
    handler_type: HandlerType,
    actions: Vec<HandlerAction>,
    error_handling: ErrorHandling,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RollbackStrategy {
    strategy_type: RollbackType,
    steps: Vec<RollbackStep>,
    cleanup_actions: Vec<CleanupAction>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct StatePolicy {
    max_duration_ms: u64,
    allowed_transitions: HashSet<String>,
    required_validations: Vec<ValidationRequirement>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TransitionPolicy {
    allowed_paths: Vec<Vec<String>>,
    forbidden_paths: Vec<Vec<String>>,
    max_retries: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TimeoutPolicy {
    default_timeout_ms: u64,
    state_timeouts: HashMap<String, u64>,
    timeout_actions: Vec<TimeoutAction>,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum StateType {
    Initial,
    Running,
    Paused,
    Error,
    Terminal,
    Custom(String),
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum TransitionResult {
    Success,
    Failure,
    Timeout,
    Cancelled,
    Custom(String),
}

#[wasm_bindgen]
pub struct LifecycleController {
    managers: Arc<DashMap<String, LifecycleManager>>,
    metrics: Arc<DashMap<String, LifecycleMetrics>>,
    operation_semaphore: Arc<Semaphore>,
    notification_tx: Arc<broadcast::Sender<LifecycleEvent>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct LifecycleEvent {
    event_id: String,
    manager_id: String,
    event_type: LifecycleEventType,
    timestamp: u64,
    details: HashMap<String, String>,
}

impl LifecycleController {
    async fn transition_state(
        &self,
        manager_id: &str,
        transition_id: &str,
    ) -> Result<(), JsValue> {
        let _permit = self.operation_semaphore.acquire().await;
        
        if let Some(mut manager) = self.managers.get_mut(manager_id) {
            let transition = self.get_transition(&manager, transition_id)?;
            
            // Validate transition
            self.validate_transition(&manager, &transition).await?;
            
            // Execute pre-transition actions
            self.execute_pre_transition_actions(&manager, &transition).await?;
            
            let start_time = Instant::now();
            
            // Perform transition
            match self.execute_transition(&mut manager, &transition).await {
                Ok(_) => {
                    // Update state
                    manager.state_machine.current_state = transition.to_state.clone();
                    
                    // Record transition
                    self.record_transition(
                        &mut manager,
                        &transition,
                        TransitionResult::Success,
                        start_time.elapsed().as_millis() as u64,
                    ).await?;
                    
                    // Execute post-transition actions
                    self.execute_post_transition_actions(&manager, &transition).await?;
                }
                Err(e) => {
                    // Handle failure
                    self.handle_transition_failure(
                        &mut manager,
                        &transition,
                        &e,
                        start_time.elapsed().as_millis() as u64,
                    ).await?;
                }
            }
        }
        
        Ok(())
    }

    async fn validate_transition(
        &self,
        manager: &LifecycleManager,
        transition: &Transition,
    ) -> Result<(), JsValue> {
        // Check if transition is allowed
        if !self.is_transition_allowed(manager, transition)? {
            return Err(JsValue::from_str("Transition not allowed"));
        }
        
        // Validate conditions
        for condition in &transition.conditions {
            if !self.evaluate_condition(manager, condition).await? {
                return Err(JsValue::from_str("Transition conditions not met"));
            }
        }
        
        // Check policies
        for policy in &manager.policies {
            self.validate_transition_policy(policy, transition)?;
        }
        
        Ok(())
    }

    async fn execute_transition(
        &self,
        manager: &mut LifecycleManager,
        transition: &Transition,
    ) -> Result<(), JsValue> {
        // Execute transition actions
        for action in &transition.actions {
            if let Err(e) = self.execute_action(manager, action).await {
                // Attempt rollback
                if let Some(rollback) = &transition.rollback {
                    self.execute_rollback(manager, rollback).await?;
                }
                return Err(e);
            }
        }
        
        Ok(())
    }

    async fn handle_transition_failure(
        &self,
        manager: &mut LifecycleManager,
        transition: &Transition,
        error: &JsValue,
        duration_ms: u64,
    ) -> Result<(), JsValue> {
        // Record failed transition
        self.record_transition(
            manager,
            transition,
            TransitionResult::Failure,
            duration_ms,
        ).await?;
        
        // Update metrics
        if let Some(mut metrics) = self.metrics.get_mut(&manager.manager_id) {
            metrics.failed_transitions += 1;
        }
        
        // Notify about failure
        self.notify_transition_failure(manager, transition, error).await?;
        
        Ok(())
    }

    fn start_lifecycle_tasks(&self) {
        let controller = Arc::new(self.clone());

        // State monitoring task
        tokio::spawn({
            let controller = controller.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(LIFECYCLE_CHECK_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    controller.monitor_states().await;
                }
            }
        });

        // Metrics update task
        tokio::spawn({
            let controller = controller.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(1));
                loop {
                    interval.tick().await;
                    controller.update_metrics().await;
                }
            }
        });
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&LifecycleMetrics {
                total_transitions: 0,
                failed_transitions: 0,
                average_transition_time_ms: 0.0,
                state_distribution: HashMap::new(),
                timeout_events: 0,
                policy_violations: 0,
            })?)
        }
    }
}

fn generate_event_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("EVENT-{:016x}", rng.gen::<u64>())
}

impl Drop for LifecycleController {
    fn drop(&mut self) {
        self.managers.clear();
        self.metrics.clear();
    }
} 
