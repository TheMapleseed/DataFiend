use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use tokio::sync::RwLock;

// Public WASM Interface
#[wasm_bindgen]
pub struct CoRAGInterface {
    #[wasm_bindgen(skip)]
    inner: Arc<CoRAGSystem>,
    #[wasm_bindgen(skip)]
    security: Arc<InterfaceSecurity>,
}

#[wasm_bindgen]
impl CoRAGInterface {
    // Public API for web access
    #[wasm_bindgen]
    pub async fn query_system_status(&self) -> Result<JsValue, JsValue> {
        // Validate web request
        self.security.validate_request()?;
        
        // Get status through VM layers
        let status = self.inner.get_system_status().await?;
        
        // Convert to JS-safe format
        Ok(serde_wasm_bindgen::to_value(&status)?)
    }

    #[wasm_bindgen]
    pub async fn get_metrics(&self, filter: JsValue) -> Result<JsValue, JsValue> {
        self.security.validate_request()?;
        
        let filter: MetricsFilter = serde_wasm_bindgen::from_value(filter)?;
        let metrics = self.inner.get_filtered_metrics(filter).await?;
        
        Ok(serde_wasm_bindgen::to_value(&metrics)?)
    }

    #[wasm_bindgen]
    pub async fn get_error_report(&self, query: JsValue) -> Result<JsValue, JsValue> {
        self.security.validate_request()?;
        
        let query: ErrorQuery = serde_wasm_bindgen::from_value(query)?;
        let report = self.inner.get_error_report(query).await?;
        
        Ok(serde_wasm_bindgen::to_value(&report)?)
    }

    #[wasm_bindgen]
    pub async fn subscribe_to_updates(&self, config: JsValue) -> Result<UpdateStream, JsValue> {
        self.security.validate_subscription(&config)?;
        
        let config: SubscriptionConfig = serde_wasm_bindgen::from_value(config)?;
        let stream = self.inner.create_update_stream(config).await?;
        
        Ok(UpdateStream::new(stream))
    }
}

// Update Stream for Web Clients
#[wasm_bindgen]
pub struct UpdateStream {
    #[wasm_bindgen(skip)]
    stream: Arc<SystemStream>,
}

#[wasm_bindgen]
impl UpdateStream {
    #[wasm_bindgen]
    pub async fn next_update(&self) -> Result<JsValue, JsValue> {
        let update = self.stream.next().await?;
        Ok(serde_wasm_bindgen::to_value(&update)?)
    }
}

// Internal System Interface
struct CoRAGSystem {
    corag_space: Arc<CoRAGMemorySpace>,
    slm_space: Arc<SLMMemorySpace>,
    interface_metrics: Arc<RwLock<InterfaceMetrics>>,
}

impl CoRAGSystem {
    async fn get_system_status(&self) -> Result<SystemStatus, SystemError> {
        // Get status through VM isolation
        let corag_status = self.corag_space
            .get_status()
            .await?;
            
        let slm_status = self.slm_space
            .get_restricted_status()
            .await?;
            
        // Combine status safely
        Ok(SystemStatus {
            corag: corag_status,
            slm: slm_status,
            timestamp: chrono::Utc::now(),
        })
    }

    async fn get_filtered_metrics(
        &self,
        filter: MetricsFilter
    ) -> Result<SystemMetrics, SystemError> {
        // Apply filter through VM boundaries
        let corag_metrics = self.corag_space
            .get_metrics(filter.clone())
            .await?;
            
        let slm_metrics = self.slm_space
            .get_restricted_metrics(filter)
            .await?;
            
        // Combine metrics safely
        Ok(SystemMetrics {
            corag: corag_metrics,
            slm: slm_metrics,
            timestamp: chrono::Utc::now(),
        })
    }

    async fn create_update_stream(
        &self,
        config: SubscriptionConfig
    ) -> Result<SystemStream, SystemError> {
        // Create restricted stream
        let stream = SystemStream::new(
            self.corag_space.clone(),
            self.slm_space.clone(),
            config,
        );
        
        // Track subscription
        self.interface_metrics
            .write()
            .await
            .track_subscription(&stream);
            
        Ok(stream)
    }
}

// Security Layer
struct InterfaceSecurity {
    rate_limiter: Arc<RateLimiter>,
    access_control: Arc<AccessControl>,
    threat_detection: Arc<ThreatDetection>,
}

impl InterfaceSecurity {
    fn validate_request(&self) -> Result<(), JsValue> {
        // Rate limiting
        self.rate_limiter.check_limit()?;
        
        // Access control
        self.access_control.validate_access()?;
        
        // Threat detection
        self.threat_detection.scan_request()?;
        
        Ok(())
    }
}
