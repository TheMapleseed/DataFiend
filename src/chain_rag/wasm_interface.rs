use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::sync::Arc;
use validator::{Validate, ValidationError};
use regex::Regex;
use thiserror::Error;

// Input validation constants
const MAX_QUERY_LENGTH: usize = 4096;
const MAX_BATCH_SIZE: usize = 100;
const MAX_FIELD_LENGTH: usize = 256;
const ALLOWED_CHARS_PATTERN: &str = r"^[\w\s\-\.,:;?!()\[\]{}\"']+$";

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Input too long: {field} ({length} > {max})")]
    InputTooLong {
        field: String,
        length: usize,
        max: usize,
    },
    
    #[error("Invalid characters in {field}")]
    InvalidCharacters { field: String },
    
    #[error("Batch size too large: {size} > {max}")]
    BatchTooLarge { size: usize, max: usize },
    
    #[error("Required field missing: {0}")]
    MissingField(String),
    
    #[error("Invalid format: {0}")]
    InvalidFormat(String),
}

#[derive(Debug, Validate, Serialize, Deserialize)]
pub struct DatabaseRequest {
    #[validate(length(max = "MAX_QUERY_LENGTH"))]
    #[validate(regex = "ALLOWED_CHARS_PATTERN")]
    query: String,
    
    #[validate(range(max = "MAX_BATCH_SIZE"))]
    batch_size: usize,
    
    #[validate(length(max = "MAX_FIELD_LENGTH"))]
    namespace: String,
}

#[wasm_bindgen]
pub struct WASMInterface {
    system: Arc<IntegratedSystem>,
    bridge: Arc<WASMBridge>,
    input_validator: InputValidator,
    metrics: Arc<MetricsStore>,
}

struct InputValidator {
    allowed_chars: Regex,
    sanitizer: html_escape::HtmlEscape,
}

impl InputValidator {
    fn new() -> Self {
        Self {
            allowed_chars: Regex::new(ALLOWED_CHARS_PATTERN).unwrap(),
            sanitizer: html_escape::HtmlEscape::new(),
        }
    }

    fn validate_and_sanitize(&self, input: &str, field: &str) -> Result<String, ValidationError> {
        // Check length
        if input.len() > MAX_FIELD_LENGTH {
            return Err(ValidationError::InputTooLong {
                field: field.to_string(),
                length: input.len(),
                max: MAX_FIELD_LENGTH,
            });
        }

        // Check characters
        if !self.allowed_chars.is_match(input) {
            return Err(ValidationError::InvalidCharacters {
                field: field.to_string(),
            });
        }

        // Sanitize HTML/JS
        let sanitized = self.sanitizer.escape(input);
        
        Ok(sanitized.to_string())
    }
}

#[wasm_bindgen]
impl WASMInterface {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WASMInterface, JsValue> {
        let system = Arc::new(IntegratedSystem::new().await.map_err(|e| JsValue::from_str(&e.to_string()))?);
        let bridge = Arc::new(WASMBridge::new(system.clone()));
        
        Ok(Self { system, bridge, input_validator: InputValidator::new(), metrics: Arc::new(MetricsStore::new()) })
    }

    #[wasm_bindgen]
    pub async fn query_model(&self, input: JsValue) -> Result<JsValue, JsValue> {
        let request: ModelRequest = serde_wasm_bindgen::from_value(input)?;
        let response = self.bridge.handle_model_request(request).await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        Ok(serde_wasm_bindgen::to_value(&response)?)
    }

    #[wasm_bindgen]
    pub async fn query_database(&self, request: JsValue) -> Result<JsValue, JsValue> {
        // Deserialize and validate request
        let request: DatabaseRequest = self.deserialize_and_validate(request)?;
        
        // Sanitize inputs
        let sanitized_request = self.sanitize_request(request)?;
        
        // Record metrics
        self.metrics.record_wasm_request().await;
        
        // Process request
        let response = self.bridge.system
            .process_database_query(sanitized_request)
            .await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            
        // Serialize response
        Ok(serde_wasm_bindgen::to_value(&response)?)
    }

    fn deserialize_and_validate(&self, value: JsValue) -> Result<DatabaseRequest, JsValue> {
        let request: DatabaseRequest = serde_wasm_bindgen::from_value(value)
            .map_err(|e| JsValue::from_str(&format!("Invalid request format: {}", e)))?;
            
        // Validate using derive(Validate)
        request.validate()
            .map_err(|e| JsValue::from_str(&format!("Validation failed: {}", e)))?;
            
        Ok(request)
    }

    fn sanitize_request(&self, request: DatabaseRequest) -> Result<DatabaseRequest, JsValue> {
        // Sanitize each field
        let sanitized_query = self.input_validator
            .validate_and_sanitize(&request.query, "query")
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            
        let sanitized_namespace = self.input_validator
            .validate_and_sanitize(&request.namespace, "namespace")
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            
        Ok(DatabaseRequest {
            query: sanitized_query,
            batch_size: request.batch_size,
            namespace: sanitized_namespace,
        })
    }

    #[wasm_bindgen]
    pub async fn get_metrics(&self) -> Result<JsValue, JsValue> {
        let metrics = self.metrics.get_wasm_metrics().await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
            
        Ok(serde_wasm_bindgen::to_value(&metrics)?)
    }
}

struct WASMBridge {
    system: Arc<IntegratedSystem>,
    metrics_cache: Arc<RwLock<MetricsCache>>,
}

impl WASMBridge {
    fn new(system: Arc<IntegratedSystem>) -> Self {
        let metrics_cache = Arc::new(RwLock::new(MetricsCache::new()));
        
        // Start metrics cache updater
        Self::start_metrics_cache_updater(system.clone(), metrics_cache.clone());
        
        Self {
            system,
            metrics_cache,
        }
    }

    async fn handle_model_request(&self, request: ModelRequest) -> Result<ModelResponse> {
        let system_request = SystemRequest::from_wasm_model(request);
        let system_response = self.system.handle_request(system_request).await?;
        Ok(ModelResponse::from_system(system_response))
    }

    async fn handle_database_request(&self, request: DatabaseRequest) -> Result<DatabaseResponse> {
        let system_request = SystemRequest::from_wasm_database(request);
        let system_response = self.system.handle_request(system_request).await?;
        Ok(DatabaseResponse::from_system(system_response))
    }

    async fn get_system_metrics(&self) -> Result<SystemMetrics> {
        Ok(self.metrics_cache.read().await.clone())
    }

    fn start_metrics_cache_updater(
        system: Arc<IntegratedSystem>,
        cache: Arc<RwLock<MetricsCache>>,
    ) {
        tokio::spawn(async move {
            loop {
                if let Ok(metrics) = system.metrics.get_current().await {
                    let mut cache_write = cache.write().await;
                    *cache_write = MetricsCache::from_system_metrics(metrics);
                }
                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct MetricsCache {
    timestamp: u64,
    metrics: SystemMetrics,
}

impl MetricsCache {
    fn new() -> Self {
        Self {
            timestamp: 0,
            metrics: SystemMetrics::default(),
        }
    }

    fn from_system_metrics(metrics: SystemMetrics) -> Self {
        Self {
            timestamp: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
            metrics,
        }
    }
}

// JavaScript bindings
#[wasm_bindgen]
pub fn init_panic_hook() {
    console_error_panic_hook::set_once();
}

// Export types for JavaScript
#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct ModelRequest {
    query: String,
    parameters: JsValue,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct ModelResponse {
    result: String,
    confidence: f32,
    metrics: JsValue,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct DatabaseResponse {
    results: JsValue,
    timing: f32,
}

// Response sanitization
impl DatabaseResponse {
    fn sanitize(&self) -> Result<Self, ValidationError> {
        // Implement response sanitization if needed
        Ok(self.clone())
    }
}

// Safe cleanup
impl Drop for WASMInterface {
    fn drop(&mut self) {
        // Cleanup any resources
        self.metrics.record_wasm_interface_dropped().await;
    }
} 