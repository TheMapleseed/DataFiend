use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use crate::error::error_system::SystemError;
use crate::metrics::collector::MetricsCollector;
use crate::security::validation::{DataValidator, ResourceLimiter};
use crate::security::ecc::ECCHandler;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TrainingConfig {
    batch_size: usize,
    learning_rate: f64,
    epochs: usize,
    validation_split: f64,
    early_stopping_patience: usize,
}

#[derive(Debug)]
pub struct TrainingSystem {
    config: Arc<RwLock<TrainingConfig>>,
    metrics: Arc<MetricsCollector>,
    validator: DataValidator,
    resource_limiter: ResourceLimiter,
    ecc_handler: Arc<ECCHandler>,
} 