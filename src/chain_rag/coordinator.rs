use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

#[derive(Debug, Serialize, Deserialize)]
pub struct CoordinatedMetrics {
    corag_metrics: CoRAGMetrics,
    model_metrics: ModelMetrics,
    system_metrics: SystemMetrics,
}

pub struct UnifiedCoordinator {
    // Shared metrics and error reporting
    metrics_store: Arc<MetricsStore>,
    error_store: Arc<ErrorStore>,
    
    // CoRAG Database System
    corag: Arc<CoRAGSystem>,
    
    // Heimdal Model System
    heimdal: Arc<RwLock<HeimdallModel>>,
    
    // Coordination state
    state: Arc<RwLock<CoordinationState>>,
}

impl UnifiedCoordinator {
    pub async fn new() -> Result<Self> {
        let metrics_store = Arc::new(MetricsStore::new()?);
        let error_store = Arc::new(ErrorStore::new()?);

        // Initialize both systems with shared metrics
        let corag = CoRAGSystem::new(metrics_store.clone(), error_store.clone());
        let heimdal = HeimdallModel::new(metrics_store.clone(), error_store.clone());

        Ok(Self {
            metrics_store,
            error_store,
            corag: Arc::new(corag),
            heimdal: Arc::new(RwLock::new(heimdal)),
            state: Arc::new(RwLock::new(CoordinationState::new())),
        })
    }

    pub async fn process_event(&self, event: SystemEvent) -> Result<EventResponse> {
        // Acquire state lock first
        let _guard = self.state.read().await;
        
        // Record event with state context
        self.metrics_store.record_event_with_state(&event, &self.state).await?;
        
        match event {
            SystemEvent::CoRAGQuery(query) => {
                let result = self.corag.process_query(query).await?;
                {
                    let mut heimdal = self.heimdal.write().await;
                    heimdal.learn_from_query(&result);
                }
                Ok(EventResponse::Query(result))
            },
            SystemEvent::ModelRequest(request) => {
                let result = self.heimdal.read().await.process_request(request).await?;
                // Update CoRAG with model insights
                self.corag.update_from_model(&result).await?;
                Ok(EventResponse::Model(result))
            },
            SystemEvent::SystemMetrics => {
                let metrics = self.collect_unified_metrics().await?;
                Ok(EventResponse::Metrics(metrics))
            }
        }
    }

    async fn collect_unified_metrics(&self) -> Result<CoordinatedMetrics> {
        Ok(CoordinatedMetrics {
            corag_metrics: self.corag.get_metrics().await?,
            model_metrics: self.heimdal.read().await.get_metrics().await?,
            system_metrics: self.metrics_store.get_system_metrics().await?,
        })
    }

    pub async fn handle_error(&self, error: SystemError) {
        // Record error
        self.error_store.record_error(&error);

        // Let both systems learn from the error
        self.corag.learn_from_error(&error).await;
        self.heimdal.write().await.learn_from_error(&error).await;

        // Update coordination state
        self.state.write().await.update_from_error(&error);
    }
}

#[derive(Debug)]
struct CoordinationState {
    corag_health: SystemHealth,
    model_health: SystemHealth,
    learning_state: LearningState,
}

impl CoordinationState {
    fn new() -> Self {
        Self {
            corag_health: SystemHealth::default(),
            model_health: SystemHealth::default(),
            learning_state: LearningState::default(),
        }
    }

    fn update_from_error(&mut self, error: &SystemError) {
        match error {
            SystemError::CoRAG(_) => self.corag_health.record_error(),
            SystemError::Model(_) => self.model_health.record_error(),
            SystemError::Coordination(_) => {
                self.corag_health.record_error();
                self.model_health.record_error();
            }
        }

        self.learning_state.update_from_error(error);
    }
}

#[derive(Debug, Default)]
struct SystemHealth {
    error_count: u64,
    last_error: Option<SystemTime>,
    status: HealthStatus,
}

impl SystemHealth {
    fn record_error(&mut self) {
        self.error_count += 1;
        self.last_error = Some(SystemTime::now());
        self.update_status();
    }

    fn update_status(&mut self) {
        self.status = match self.error_count {
            0 => HealthStatus::Healthy,
            1..=3 => HealthStatus::Warning,
            _ => HealthStatus::Critical,
        };
    }
}

#[derive(Debug)]
enum HealthStatus {
    Healthy,
    Warning,
    Critical,
}

impl Default for HealthStatus {
    fn default() -> Self {
        HealthStatus::Healthy
    }
} 