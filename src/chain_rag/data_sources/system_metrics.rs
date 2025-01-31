use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use metrics::{counter, gauge, histogram};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemMetricsSource {
    metrics_buffer: Arc<RwLock<Vec<MetricPoint>>>,
    error_buffer: Arc<RwLock<Vec<ErrorPoint>>>,
    alert_buffer: Arc<RwLock<Vec<AlertPoint>>>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MetricPoint {
    timestamp: DateTime<Utc>,
    metric_type: MetricType,
    value: f64,
    context: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ErrorPoint {
    timestamp: DateTime<Utc>,
    error_type: String,
    severity: u8,
    context: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AlertPoint {
    timestamp: DateTime<Utc>,
    alert_type: String,
    priority: u8,
    data: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum MetricType {
    Memory,
    CPU,
    Latency,
    Throughput,
    ErrorRate,
    ResourceUtilization,
}

impl SystemMetricsSource {
    pub fn new() -> Self {
        Self {
            metrics_buffer: Arc::new(RwLock::new(Vec::with_capacity(1000))),
            error_buffer: Arc::new(RwLock::new(Vec::with_capacity(100))),
            alert_buffer: Arc::new(RwLock::new(Vec::with_capacity(50))),
        }
    }

    pub async fn record_metric(&self, metric_type: MetricType, value: f64, context: serde_json::Value) {
        let point = MetricPoint {
            timestamp: Utc::now(),
            metric_type,
            value,
            context,
        };

        let mut buffer = self.metrics_buffer.write().await;
        buffer.push(point);

        // Update real-time metrics for WASM frontend
        match metric_type {
            MetricType::Memory => gauge!("system.memory", value),
            MetricType::CPU => gauge!("system.cpu", value),
            MetricType::Latency => histogram!("system.latency", value),
            MetricType::Throughput => counter!("system.throughput", value as u64),
            MetricType::ErrorRate => gauge!("system.error_rate", value),
            MetricType::ResourceUtilization => gauge!("system.resource_utilization", value),
        }

        // Trim buffer if needed
        if buffer.len() > 1000 {
            buffer.drain(0..100);
        }
    }

    pub async fn record_error(&self, error_type: String, severity: u8, context: serde_json::Value) {
        let point = ErrorPoint {
            timestamp: Utc::now(),
            error_type,
            severity,
            context,
        };

        let mut buffer = self.error_buffer.write().await;
        buffer.push(point);

        // Trim buffer if needed
        if buffer.len() > 100 {
            buffer.drain(0..10);
        }
    }

    pub async fn record_alert(&self, alert_type: String, priority: u8, data: serde_json::Value) {
        let point = AlertPoint {
            timestamp: Utc::now(),
            alert_type,
            priority,
            data,
        };

        let mut buffer = self.alert_buffer.write().await;
        buffer.push(point);

        // Trim buffer if needed
        if buffer.len() > 50 {
            buffer.drain(0..5);
        }
    }

    pub async fn get_recent_metrics(&self, duration: chrono::Duration) -> Vec<MetricPoint> {
        let cutoff = Utc::now() - duration;
        let buffer = self.metrics_buffer.read().await;
        
        buffer.iter()
            .filter(|point| point.timestamp > cutoff)
            .cloned()
            .collect()
    }

    pub async fn get_recent_errors(&self, duration: chrono::Duration) -> Vec<ErrorPoint> {
        let cutoff = Utc::now() - duration;
        let buffer = self.error_buffer.read().await;
        
        buffer.iter()
            .filter(|point| point.timestamp > cutoff)
            .cloned()
            .collect()
    }

    pub async fn get_metrics_for_learning(&self) -> (Vec<MetricPoint>, Vec<ErrorPoint>, Vec<AlertPoint>) {
        (
            self.metrics_buffer.read().await.clone(),
            self.error_buffer.read().await.clone(),
            self.alert_buffer.read().await.clone(),
        )
    }
}

// Implementation for CoRAG to consume the metrics
impl crate::corag::CoRAG {
    pub async fn process_system_metrics(&self) -> Result<(), crate::error::error_system::SystemError> {
        let metrics_source = self.get_metrics_source();
        let (metrics, errors, alerts) = metrics_source.get_metrics_for_learning().await;

        // Process metrics for pattern recognition
        self.learn_from_metrics(&metrics).await?;

        // Analyze errors for pattern detection
        self.analyze_error_patterns(&errors).await?;

        // Process alerts for system optimization
        self.optimize_from_alerts(&alerts).await?;

        Ok(())
    }
}

// Implementation for WASM frontend to consume the metrics
#[wasm_bindgen]
impl crate::wasm::WasmInterface {
    pub async fn get_system_metrics(&self) -> Result<JsValue, JsError> {
        let metrics_source = self.get_metrics_source();
        let recent_metrics = metrics_source.get_recent_metrics(chrono::Duration::minutes(5)).await;
        
        Ok(serde_wasm_bindgen::to_value(&recent_metrics)?)
    }
} 