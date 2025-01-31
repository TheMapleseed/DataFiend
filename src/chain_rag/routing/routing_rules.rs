use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, Semaphore};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque, HashSet, BTreeMap};
use regex::Regex;

const MAX_RULES: usize = 10000;
const MAX_RULE_CHAIN_LENGTH: usize = 100;
const RULE_CHECK_INTERVAL_MS: u64 = 100;
const MAX_CONCURRENT_EVALUATIONS: usize = 50;

#[derive(Clone, Serialize, Deserialize)]
pub struct RoutingRule {
    rule_id: String,
    priority: u32,
    conditions: Vec<RuleCondition>,
    actions: Vec<RuleAction>,
    metadata: HashMap<String, String>,
    enabled: bool,
    metrics: RuleMetrics,
    chain_refs: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RuleCondition {
    condition_type: ConditionType,
    parameters: HashMap<String, String>,
    operator: ConditionOperator,
    value: ConditionValue,
    weight: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RuleAction {
    action_type: ActionType,
    parameters: HashMap<String, String>,
    fallback: Option<Box<RuleAction>>,
    timeout_ms: u64,
    retry_policy: Option<RetryPolicy>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RuleMetrics {
    total_evaluations: u64,
    successful_matches: u64,
    failed_matches: u64,
    average_evaluation_time_ms: f64,
    action_success_rate: f64,
    last_matched: Option<u64>,
    pattern_matches: HashMap<String, u64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RuleChain {
    chain_id: String,
    rules: Vec<String>,
    execution_mode: ChainExecutionMode,
    fallback_chain: Option<String>,
    metrics: ChainMetrics,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainMetrics {
    total_executions: u64,
    successful_executions: u64,
    failed_executions: u64,
    average_chain_time_ms: f64,
    rule_hit_distribution: HashMap<String, u64>,
    pattern_effectiveness: f64,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ConditionType {
    Path,
    Header,
    Query,
    Method,
    Body,
    Time,
    Load,
    Custom,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    Contains,
    StartsWith,
    EndsWith,
    Regex,
    GreaterThan,
    LessThan,
    Between,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(untagged)]
pub enum ConditionValue {
    String(String),
    Number(f64),
    Boolean(bool),
    Array(Vec<String>),
    Pattern(String),
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ActionType {
    Forward,
    Redirect,
    Transform,
    Split,
    Aggregate,
    Cache,
    RateLimit,
    LoadBalance,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ChainExecutionMode {
    Sequential,
    Parallel,
    FirstMatch,
    AllMatch,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RetryPolicy {
    max_attempts: u32,
    backoff_base_ms: u64,
    backoff_factor: f64,
    jitter: bool,
}

#[wasm_bindgen]
pub struct RoutingRuleManager {
    rules: Arc<DashMap<String, RoutingRule>>,
    chains: Arc<DashMap<String, RuleChain>>,
    metrics: Arc<DashMap<String, ChainMetrics>>,
    evaluation_semaphore: Arc<Semaphore>,
    notification_tx: Arc<broadcast::Sender<RuleEvent>>,
    active_rules: Arc<RwLock<BTreeMap<u32, HashSet<String>>>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RuleEvent {
    event_id: String,
    rule_id: String,
    event_type: RuleEventType,
    timestamp: u64,
    details: HashMap<String, String>,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RuleEventType {
    Matched,
    ActionExecuted,
    ChainCompleted,
    RuleDisabled,
    Error,
}

#[wasm_bindgen]
impl RoutingRuleManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let (notification_tx, _) = broadcast::channel(1000);
        
        let manager = Self {
            rules: Arc::new(DashMap::new()),
            chains: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            evaluation_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_EVALUATIONS)),
            notification_tx: Arc::new(notification_tx),
            active_rules: Arc::new(RwLock::new(BTreeMap::new())),
        };

        manager.start_rule_tasks();
        manager
    }

    #[wasm_bindgen]
    pub async fn evaluate_request(
        &self,
        request_data: JsValue,
    ) -> Result<JsValue, JsValue> {
        let _permit = self.evaluation_semaphore.acquire().await
            .map_err(|e| JsValue::from_str(&format!("Failed to acquire permit: {}", e)))?;

        let request: HashMap<String, String> = serde_wasm_bindgen::from_value(request_data)?;
        
        // Get active rules in priority order
        let active_rules = self.active_rules.read().await;
        let mut matched_actions = Vec::new();

        // Evaluate rules in priority order
        for rules in active_rules.values() {
            for rule_id in rules {
                if let Some(rule) = self.rules.get(rule_id) {
                    if self.evaluate_conditions(&rule, &request).await? {
                        matched_actions.extend(rule.actions.clone());
                        self.update_rule_metrics(&rule, true).await?;
                    }
                }
            }
        }

        // Execute matched actions
        let result = self.execute_actions(&matched_actions, &request).await?;
        Ok(serde_wasm_bindgen::to_value(&result)?)
    }

    async fn evaluate_conditions(
        &self,
        rule: &RoutingRule,
        request: &HashMap<String, String>,
    ) -> Result<bool, JsValue> {
        for condition in &rule.conditions {
            match condition.condition_type {
                ConditionType::Path => {
                    if !self.evaluate_path_condition(condition, request)? {
                        return Ok(false);
                    }
                }
                ConditionType::Header => {
                    if !self.evaluate_header_condition(condition, request)? {
                        return Ok(false);
                    }
                }
                // ... other condition types
            }
        }
        Ok(true)
    }

    fn evaluate_path_condition(
        &self,
        condition: &RuleCondition,
        request: &HashMap<String, String>,
    ) -> Result<bool, JsValue> {
        let path = request.get("path").ok_or_else(|| JsValue::from_str("Path not found"))?;
        
        match &condition.value {
            ConditionValue::String(pattern) => {
                match condition.operator {
                    ConditionOperator::Equals => Ok(path == pattern),
                    ConditionOperator::Contains => Ok(path.contains(pattern)),
                    ConditionOperator::StartsWith => Ok(path.starts_with(pattern)),
                    ConditionOperator::EndsWith => Ok(path.ends_with(pattern)),
                    ConditionOperator::Regex => {
                        let regex = Regex::new(pattern)
                            .map_err(|e| JsValue::from_str(&format!("Invalid regex: {}", e)))?;
                        Ok(regex.is_match(path))
                    }
                    _ => Ok(false),
                }
            }
            _ => Ok(false),
        }
    }

    async fn execute_actions(
        &self,
        actions: &[RuleAction],
        request: &HashMap<String, String>,
    ) -> Result<Vec<String>, JsValue> {
        let mut results = Vec::new();
        
        for action in actions {
            match action.action_type {
                ActionType::Forward => {
                    results.push(self.execute_forward_action(action, request).await?);
                }
                ActionType::Transform => {
                    results.push(self.execute_transform_action(action, request).await?);
                }
                // ... other action types
            }
        }
        
        Ok(results)
    }

    async fn update_rule_metrics(
        &self,
        rule: &RoutingRule,
        matched: bool,
    ) -> Result<(), JsValue> {
        if let Some(mut metrics) = self.metrics.get_mut(&rule.rule_id) {
            metrics.total_executions += 1;
            if matched {
                metrics.successful_executions += 1;
            } else {
                metrics.failed_executions += 1;
            }
        }
        Ok(())
    }

    fn start_rule_tasks(&self) {
        let manager = Arc::new(self.clone());

        // Metrics update task
        tokio::spawn({
            let manager = manager.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(RULE_CHECK_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    manager.update_rule_metrics().await;
                }
            }
        });
    }

    async fn update_rule_metrics(&self) {
        // Update metrics for all rules and chains
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&ChainMetrics {
                total_executions: 0,
                successful_executions: 0,
                failed_executions: 0,
                average_chain_time_ms: 0.0,
                rule_hit_distribution: HashMap::new(),
                pattern_effectiveness: 0.0,
            })?)
        }
    }
}

fn generate_rule_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("RULE-{:016x}", rng.gen::<u64>())
}

fn generate_event_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("EVENT-{:016x}", rng.gen::<u64>())
}

fn get_timestamp() -> Result<u64, JsValue> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for RoutingRuleManager {
    fn drop(&mut self) {
        self.rules.clear();
        self.chains.clear();
        self.metrics.clear();
    }
}
