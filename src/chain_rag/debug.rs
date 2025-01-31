use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn, error, Level};
use serde::{Serialize, Deserialize};
use std::collections::VecDeque;

const DEBUG_HISTORY_SIZE: usize = 1000;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugEvent {
    timestamp: u64,
    component: SystemComponent,
    event_type: EventType,
    details: String,
    metrics: Option<ComponentMetrics>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemComponent {
    VM,
    Model,
    Database,
    WASM,
    Learning,
    Coordinator,
    Metrics,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventType {
    Request,
    Response,
    Error,
    Metric,
    StateChange,
    Learning,
}

pub struct DebugSystem {
    history: Arc<RwLock<VecDeque<DebugEvent>>>,
    metrics: Arc<MetricsStore>,
    active_traces: Arc<RwLock<HashMap<String, TraceContext>>>,
}

impl DebugSystem {
    pub fn new(metrics: Arc<MetricsStore>) -> Self {
        let history = VecDeque::with_capacity(DEBUG_HISTORY_SIZE);
        
        Self {
            history: Arc::new(RwLock::new(history)),
            metrics,
            active_traces: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub async fn trace_request(&self, request_id: &str) -> TraceGuard {
        let mut traces = self.active_traces.write().await;
        let context = TraceContext::new(request_id);
        traces.insert(request_id.to_string(), context.clone());
        
        TraceGuard {
            request_id: request_id.to_string(),
            traces: self.active_traces.clone(),
        }
    }

    pub async fn record_event(&self, event: DebugEvent) {
        // Record in history
        let mut history = self.history.write().await;
        if history.len() >= DEBUG_HISTORY_SIZE {
            history.pop_front();
        }
        history.push_back(event.clone());

        // Update metrics
        self.metrics.record_debug_event(&event).await;

        // Log based on event type
        match event.event_type {
            EventType::Error => {
                error!(
                    component = ?event.component,
                    details = %event.details,
                    "Error in system"
                );
            }
            EventType::StateChange => {
                info!(
                    component = ?event.component,
                    details = %event.details,
                    "State changed"
                );
            }
            _ => {
                info!(
                    component = ?event.component,
                    event_type = ?event.event_type,
                    "Event recorded"
                );
            }
        }
    }

    pub async fn analyze_system_health(&self) -> SystemHealth {
        let history = self.history.read().await;
        let recent_events: Vec<_> = history.iter()
            .filter(|e| e.event_type == EventType::Error)
            .collect();

        SystemHealth {
            error_rate: self.calculate_error_rate(&recent_events),
            component_status: self.analyze_components(&recent_events),
            performance_metrics: self.metrics.get_performance_metrics().await,
        }
    }

    pub async fn get_component_trace(&self, component: SystemComponent) -> Vec<DebugEvent> {
        let history = self.history.read().await;
        history.iter()
            .filter(|e| e.component == component)
            .cloned()
            .collect()
    }

    pub async fn dump_debug_state(&self) -> DebugState {
        DebugState {
            history: self.history.read().await.clone(),
            active_traces: self.active_traces.read().await.clone(),
            metrics: self.metrics.get_current().await,
        }
    }
}

// Trace guard for automatic cleanup
pub struct TraceGuard {
    request_id: String,
    traces: Arc<RwLock<HashMap<String, TraceContext>>>,
}

impl Drop for TraceGuard {
    fn drop(&mut self) {
        let traces = self.traces.clone();
        let request_id = self.request_id.clone();
        
        tokio::spawn(async move {
            let mut traces = traces.write().await;
            traces.remove(&request_id);
        });
    }
}

// Debug commands for live system inspection
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum DebugCommand {
    DumpState,
    TraceComponent(SystemComponent),
    AnalyzeHealth,
    ClearHistory,
    InspectRequest(String),
}

impl DebugCommand {
    pub async fn execute(&self, debug: &DebugSystem) -> Result<DebugResponse> {
        match self {
            DebugCommand::DumpState => {
                Ok(DebugResponse::State(debug.dump_debug_state().await))
            }
            DebugCommand::TraceComponent(component) => {
                Ok(DebugResponse::ComponentTrace(
                    debug.get_component_trace(*component).await
                ))
            }
            DebugCommand::AnalyzeHealth => {
                Ok(DebugResponse::Health(debug.analyze_system_health().await))
            }
            DebugCommand::ClearHistory => {
                debug.history.write().await.clear();
                Ok(DebugResponse::Acknowledged)
            }
            DebugCommand::InspectRequest(request_id) => {
                let traces = debug.active_traces.read().await;
                if let Some(trace) = traces.get(request_id) {
                    Ok(DebugResponse::RequestTrace(trace.clone()))
                } else {
                    Err(Error::RequestNotFound)
                }
            }
        }
    }
}

// WASM debug interface
#[wasm_bindgen]
impl WASMInterface {
    #[wasm_bindgen]
    pub async fn debug_command(&self, command: JsValue) -> Result<JsValue, JsValue> {
        let command: DebugCommand = serde_wasm_bindgen::from_value(command)?;
        let response = command.execute(&self.bridge.system.debug).await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&response)?)
    }
} 