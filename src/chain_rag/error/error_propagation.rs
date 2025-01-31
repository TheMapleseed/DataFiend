use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque};
use crate::error::error_codes::{ErrorCode, ErrorSeverity, ErrorCategory};

const MAX_ERROR_CHAIN: usize = 10;
const ERROR_HISTORY_SIZE: usize = 1000;
const PROPAGATION_TIMEOUT_MS: u64 = 5000;

#[derive(Clone, Serialize, Deserialize)]
pub struct ErrorTrace {
    trace_id: String,
    timestamp: u64,
    origin: String,
    error_chain: Vec<PropagatedError>,
    affected_components: Vec<String>,
    resolution_status: ResolutionStatus,
    propagation_path: Vec<String>,
    recovery_attempts: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PropagatedError {
    code: ErrorCode,
    component: String,
    timestamp: u64,
    context: HashMap<String, String>,
    handled: bool,
    recovery_action: Option<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum ResolutionStatus {
    Unresolved,
    InProgress,
    Resolved,
    RequiresEscalation,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct PropagationMetrics {
    total_errors: u64,
    propagated_errors: u64,
    resolution_rate: f64,
    average_propagation_depth: f64,
    error_chains: u32,
    affected_services: Vec<String>,
    recovery_success_rate: f64,
    propagation_patterns: Vec<PropagationPattern>,
}

#[derive(Clone, Serialize, Deserialize)]
struct PropagationPattern {
    pattern_id: String,
    frequency: u32,
    components: Vec<String>,
    average_resolution_time: f64,
    impact_score: f64,
}

#[wasm_bindgen]
pub struct ErrorPropagator {
    traces: Arc<DashMap<String, ErrorTrace>>,
    metrics: Arc<DashMap<String, PropagationMetrics>>,
    active_traces: Arc<RwLock<VecDeque<String>>>,
    error_tx: Arc<broadcast::Sender<PropagatedError>>,
    component_dependencies: Arc<DashMap<String, Vec<String>>>,
}

#[wasm_bindgen]
impl ErrorPropagator {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let (error_tx, _) = broadcast::channel(1000);
        
        let propagator = Self {
            traces: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            active_traces: Arc::new(RwLock::new(VecDeque::new())),
            error_tx: Arc::new(error_tx),
            component_dependencies: Arc::new(DashMap::new()),
        };

        propagator.start_maintenance_tasks();
        propagator
    }

    #[wasm_bindgen]
    pub async fn propagate_error(
        &self,
        component: String,
        error_code: u32,
        context: JsValue,
    ) -> Result<String, JsValue> {
        let error_code = unsafe { std::mem::transmute(error_code) };
        let context: HashMap<String, String> = serde_wasm_bindgen::from_value(context)?;
        let timestamp = get_timestamp()?;

        let error = PropagatedError {
            code: error_code,
            component: component.clone(),
            timestamp,
            context,
            handled: false,
            recovery_action: None,
        };

        let trace_id = generate_trace_id();
        let affected = self.determine_affected_components(&component).await;

        let trace = ErrorTrace {
            trace_id: trace_id.clone(),
            timestamp,
            origin: component,
            error_chain: vec![error.clone()],
            affected_components: affected,
            resolution_status: ResolutionStatus::Unresolved,
            propagation_path: Vec::new(),
            recovery_attempts: 0,
        };

        self.traces.insert(trace_id.clone(), trace);
        self.notify_affected_components(error).await?;
        
        Ok(trace_id)
    }

    async fn determine_affected_components(&self, source: &str) -> Vec<String> {
        let mut affected = Vec::new();
        let mut visited = std::collections::HashSet::new();
        let mut queue = VecDeque::new();

        queue.push_back(source.to_string());
        visited.insert(source.to_string());

        while let Some(component) = queue.pop_front() {
            if let Some(dependencies) = self.component_dependencies.get(&component) {
                for dep in dependencies.iter() {
                    if !visited.contains(dep) {
                        visited.insert(dep.clone());
                        queue.push_back(dep.clone());
                        affected.push(dep.clone());
                    }
                }
            }
        }

        affected
    }

    async fn notify_affected_components(
        &self,
        error: PropagatedError,
    ) -> Result<(), JsValue> {
        if let Err(e) = self.error_tx.send(error.clone()) {
            return Err(JsValue::from_str(&format!("Notification error: {}", e)));
        }

        Ok(())
    }

    #[wasm_bindgen]
    pub async fn handle_error(
        &self,
        trace_id: String,
        component: String,
        resolution: Option<String>,
    ) -> Result<(), JsValue> {
        let timestamp = get_timestamp()?;

        if let Some(mut trace) = self.traces.get_mut(&trace_id) {
            // Update error chain
            if let Some(error) = trace.error_chain.iter_mut()
                .find(|e| e.component == component) {
                error.handled = true;
                error.recovery_action = resolution.clone();
            }

            // Update propagation path
            if !trace.propagation_path.contains(&component) {
                trace.propagation_path.push(component);
            }

            // Check if all errors are handled
            let all_handled = trace.error_chain
                .iter()
                .all(|e| e.handled);

            if all_handled {
                trace.resolution_status = ResolutionStatus::Resolved;
            }

            self.update_metrics(&trace).await;
        }

        Ok(())
    }

    async fn update_metrics(&self, trace: &ErrorTrace) {
        let resolved = matches!(trace.resolution_status, ResolutionStatus::Resolved);
        
        self.metrics
            .entry("global".to_string())
            .and_modify(|m| {
                m.total_errors += 1;
                m.propagated_errors += trace.error_chain.len() as u64;
                m.resolution_rate = if resolved { 1.0 } else { 0.0 };
                m.average_propagation_depth = trace.propagation_path.len() as f64;
                m.error_chains += 1;
                m.affected_services = trace.affected_components.clone();
                
                // Update patterns
                if resolved {
                    let pattern = PropagationPattern {
                        pattern_id: generate_pattern_id(),
                        frequency: 1,
                        components: trace.propagation_path.clone(),
                        average_resolution_time: 0.0,
                        impact_score: trace.error_chain.len() as f64,
                    };
                    m.propagation_patterns.push(pattern);
                }
            })
            .or_insert_with(|| PropagationMetrics {
                total_errors: 1,
                propagated_errors: trace.error_chain.len() as u64,
                resolution_rate: if resolved { 1.0 } else { 0.0 },
                average_propagation_depth: trace.propagation_path.len() as f64,
                error_chains: 1,
                affected_services: trace.affected_components.clone(),
                recovery_success_rate: if resolved { 1.0 } else { 0.0 },
                propagation_patterns: Vec::new(),
            });
    }

    fn start_maintenance_tasks(&self) {
        let propagator = Arc::new(self.clone());

        // Cleanup task
        tokio::spawn({
            let propagator = propagator.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    propagator.cleanup_old_traces().await;
                }
            }
        });
    }

    async fn cleanup_old_traces(&self) {
        let cutoff = get_timestamp().unwrap_or(0) - 86400; // 24 hours
        self.traces.retain(|_, trace| trace.timestamp > cutoff);
        
        let mut active_traces = self.active_traces.write().await;
        active_traces.retain(|trace_id| {
            self.traces.contains_key(trace_id)
        });
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&PropagationMetrics {
                total_errors: 0,
                propagated_errors: 0,
                resolution_rate: 0.0,
                average_propagation_depth: 0.0,
                error_chains: 0,
                affected_services: Vec::new(),
                recovery_success_rate: 0.0,
                propagation_patterns: Vec::new(),
            })?)
        }
    }
}

fn generate_trace_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("TRACE-{:016x}", rng.gen::<u64>())
}

fn generate_pattern_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("PAT-{:016x}", rng.gen::<u64>())
}

fn get_timestamp() -> Result<u64, JsValue> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for ErrorPropagator {
    fn drop(&mut self) {
        self.traces.clear();
        self.metrics.clear();
        self.component_dependencies.clear();
    }
} 