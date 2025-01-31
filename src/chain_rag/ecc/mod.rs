use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use crate::corag::CoRAG;
use crate::resource::resource_limits::ResourceLimiter;
use crate::error::error_system::SystemError;

pub mod testing;
pub mod validation;
pub mod correction;
pub mod monitoring;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ECCConfig {
    correction_threshold: f64,
    validation_frequency: u32,
    monitoring_interval: u64,
    test_coverage_target: f64,
}

pub struct ECCSystem {
    corag: Arc<CoRAG>,
    resource_limiter: Arc<ResourceLimiter>,
    config: Arc<RwLock<ECCConfig>>,
    test_suite: Arc<testing::TestSuite>,
    validator: Arc<validation::Validator>,
    corrector: Arc<correction::Corrector>,
    monitor: Arc<monitoring::Monitor>,
}

impl ECCSystem {
    pub fn new(corag: Arc<CoRAG>, resource_limiter: Arc<ResourceLimiter>) -> Self {
        let config = Arc::new(RwLock::new(ECCConfig {
            correction_threshold: 0.85,
            validation_frequency: 100,
            monitoring_interval: 1000,
            test_coverage_target: 0.95,
        }));

        Self {
            corag: corag.clone(),
            resource_limiter: resource_limiter.clone(),
            config: config.clone(),
            test_suite: Arc::new(testing::TestSuite::new(corag.clone(), config.clone())),
            validator: Arc::new(validation::Validator::new(corag.clone(), config.clone())),
            corrector: Arc::new(correction::Corrector::new(corag.clone(), config.clone())),
            monitor: Arc::new(monitoring::Monitor::new(corag, config)),
        }
    }

    pub async fn run_test_suite(&self) -> Result<testing::TestResults, SystemError> {
        self.test_suite.run_all_tests().await
    }

    pub async fn validate_system(&self) -> Result<validation::ValidationReport, SystemError> {
        self.validator.validate_system_state().await
    }

    pub async fn apply_corrections(&self, report: &validation::ValidationReport) -> Result<(), SystemError> {
        self.corrector.apply_corrections(report).await
    }

    pub async fn monitor_system(&self) -> Result<monitoring::SystemMetrics, SystemError> {
        self.monitor.collect_metrics().await
    }

    pub async fn continuous_monitoring(&self) -> Result<(), SystemError> {
        loop {
            // Run test suite
            let test_results = self.run_test_suite().await?;
            
            // Validate system
            let validation_report = self.validate_system().await?;
            
            // Apply corrections if needed
            if validation_report.needs_correction() {
                self.apply_corrections(&validation_report).await?;
            }
            
            // Collect metrics
            let metrics = self.monitor_system().await?;
            
            // Update CoRAG with results
            self.corag.process_ecc_results(test_results, validation_report, metrics).await?;
            
            // Wait for next interval
            tokio::time::sleep(tokio::time::Duration::from_millis(
                self.config.read().await.monitoring_interval
            )).await;
        }
    }
} 