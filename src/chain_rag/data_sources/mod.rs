use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};

pub mod system_metrics;
pub mod user_interactions;
pub mod network_traffic;
pub mod security_events;
pub mod resource_usage;
pub mod application_logs;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DataSourceManager {
    system_metrics: Arc<system_metrics::SystemMetricsSource>,
    user_interactions: Arc<user_interactions::UserInteractionSource>,
    network_traffic: Arc<network_traffic::NetworkTrafficSource>,
    security_events: Arc<security_events::SecurityEventSource>,
    resource_usage: Arc<resource_usage::ResourceUsageSource>,
    application_logs: Arc<application_logs::ApplicationLogSource>,
}

impl DataSourceManager {
    pub fn new() -> Self {
        Self {
            system_metrics: Arc::new(system_metrics::SystemMetricsSource::new()),
            user_interactions: Arc::new(user_interactions::UserInteractionSource::new()),
            network_traffic: Arc::new(network_traffic::NetworkTrafficSource::new()),
            security_events: Arc::new(security_events::SecurityEventSource::new()),
            resource_usage: Arc::new(resource_usage::ResourceUsageSource::new()),
            application_logs: Arc::new(application_logs::ApplicationLogSource::new()),
        }
    }

    // CoRAG uses this to get all available data streams
    pub async fn get_data_streams(&self) -> Vec<DataStream> {
        vec![
            DataStream::SystemMetrics(self.system_metrics.clone()),
            DataStream::UserInteractions(self.user_interactions.clone()),
            DataStream::NetworkTraffic(self.network_traffic.clone()),
            DataStream::SecurityEvents(self.security_events.clone()),
            DataStream::ResourceUsage(self.resource_usage.clone()),
            DataStream::ApplicationLogs(self.application_logs.clone()),
        ]
    }
}

// CoRAG can focus on any combination of these streams as needed
pub enum DataStream {
    SystemMetrics(Arc<system_metrics::SystemMetricsSource>),
    UserInteractions(Arc<user_interactions::UserInteractionSource>),
    NetworkTraffic(Arc<network_traffic::NetworkTrafficSource>),
    SecurityEvents(Arc<security_events::SecurityEventSource>),
    ResourceUsage(Arc<resource_usage::ResourceUsageSource>),
    ApplicationLogs(Arc<application_logs::ApplicationLogSource>),
} 
