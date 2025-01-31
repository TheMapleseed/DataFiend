use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use lazy_static::lazy_static;
use std::sync::Arc;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Hash, Serialize, Deserialize)]
#[repr(u32)]
pub enum ErrorCode {
    // System Level: 1000-1999
    SystemStartupFailure = 1000,
    SystemShutdownFailure = 1001,
    SystemOverload = 1002,
    SystemOutOfMemory = 1003,
    SystemDiskFull = 1004,
    SystemNetworkFailure = 1005,
    SystemConfigError = 1006,
    SystemStateCorruption = 1007,
    SystemMaintenanceRequired = 1008,
    SystemVersionMismatch = 1009,

    // Security: 2000-2999
    SecurityAuthenticationFailed = 2000,
    SecurityAuthorizationFailed = 2001,
    SecurityInvalidToken = 2002,
    SecurityExpiredToken = 2003,
    SecurityInvalidSignature = 2004,
    SecurityRateLimitExceeded = 2005,
    SecurityInvalidCertificate = 2006,
    SecurityEncryptionFailure = 2007,
    SecurityDecryptionFailure = 2008,
    SecurityTamperedData = 2009,

    // Resource Management: 3000-3999
    ResourceAllocationFailed = 3000,
    ResourceDeallocationFailed = 3001,
    ResourceLimitExceeded = 3002,
    ResourceNotFound = 3003,
    ResourceBusy = 3004,
    ResourceDeadlock = 3005,
    ResourceTimeout = 3006,
    ResourceCorrupted = 3007,
    ResourceVersionMismatch = 3008,
    ResourceInvalidState = 3009,

    // Cache Operations: 4000-4999
    CacheInitializationFailed = 4000,
    CacheWriteFailed = 4001,
    CacheReadFailed = 4002,
    CacheInvalidation = 4003,
    CacheEvictionFailed = 4004,
    CacheFullError = 4005,
    CacheKeyNotFound = 4006,
    CacheKeyCollision = 4007,
    CacheVersionMismatch = 4008,
    CacheConsistencyError = 4009,

    // Network Operations: 5000-5999
    NetworkConnectionFailed = 5000,
    NetworkTimeout = 5001,
    NetworkInvalidAddress = 5002,
    NetworkDataCorruption = 5003,
    NetworkProtocolError = 5004,
    NetworkSegmentationError = 5005,
    NetworkRoutingError = 5006,
    NetworkBandwidthExceeded = 5007,
    NetworkLatencyError = 5008,
    NetworkPartitionDetected = 5009,

    // Data Operations: 6000-6999
    DataValidationFailed = 6000,
    DataSerializationFailed = 6001,
    DataDeserializationFailed = 6002,
    DataInconsistency = 6003,
    DataCorruption = 6004,
    DataTypeMismatch = 6005,
    DataSizeLimitExceeded = 6006,
    DataNotFound = 6007,
    DataAlreadyExists = 6008,
    DataVersionConflict = 6009,

    // Chain Operations: 7000-7999
    ChainSyncFailed = 7000,
    ChainValidationFailed = 7001,
    ChainConsensusError = 7002,
    ChainForkDetected = 7003,
    ChainBlockRejected = 7004,
    ChainStateError = 7005,
    ChainProofInvalid = 7006,
    ChainSignatureInvalid = 7007,
    ChainNonceMismatch = 7008,
    ChainReorgDetected = 7009,

    // RAG Operations: 8000-8999
    RagQueryFailed = 8000,
    RagEmbeddingError = 8001,
    RagRetrievalError = 8002,
    RagGenerationError = 8003,
    RagContextLimitExceeded = 8004,
    RagInvalidPrompt = 8005,
    RagModelError = 8006,
    RagTokenLimitExceeded = 8007,
    RagInvalidResponse = 8008,
    RagProcessingTimeout = 8009,

    // Monitoring: 9000-9999
    MonitoringInitFailed = 9000,
    MonitoringMetricError = 9001,
    MonitoringAlertFailed = 9002,
    MonitoringThresholdExceeded = 9003,
    MonitoringDataLoss = 9004,
    MonitoringServiceDown = 9005,
    MonitoringHighLatency = 9006,
    MonitoringResourceExhaustion = 9007,
    MonitoringSystemDegraded = 9008,
    MonitoringHealthCheckFailed = 9009,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ErrorContext {
    pub code: ErrorCode,
    pub severity: ErrorSeverity,
    pub category: ErrorCategory,
    pub description: String,
    pub resolution: String,
    pub requires_immediate_action: bool,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum ErrorSeverity {
    Critical,
    High,
    Medium,
    Low,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize)]
pub enum ErrorCategory {
    System,
    Security,
    Resource,
    Cache,
    Network,
    Data,
    Chain,
    Rag,
    Monitoring,
}

lazy_static! {
    static ref ERROR_CONTEXTS: HashMap<ErrorCode, ErrorContext> = {
        let mut m = HashMap::new();
        
        // System Errors
        m.insert(ErrorCode::SystemOutOfMemory, ErrorContext {
            code: ErrorCode::SystemOutOfMemory,
            severity: ErrorSeverity::Critical,
            category: ErrorCategory::System,
            description: "System has exhausted available memory".to_string(),
            resolution: "Free up memory resources or scale system".to_string(),
            requires_immediate_action: true,
        });

        // Add all other error contexts...
        // Security Errors
        m.insert(ErrorCode::SecurityAuthenticationFailed, ErrorContext {
            code: ErrorCode::SecurityAuthenticationFailed,
            severity: ErrorSeverity::High,
            category: ErrorCategory::Security,
            description: "Authentication attempt failed".to_string(),
            resolution: "Verify credentials and retry".to_string(),
            requires_immediate_action: true,
        });

        m
    };
}

#[wasm_bindgen]
pub struct ErrorRegistry {
    contexts: Arc<HashMap<ErrorCode, ErrorContext>>,
}

#[wasm_bindgen]
impl ErrorRegistry {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            contexts: Arc::new(ERROR_CONTEXTS.clone()),
        }
    }

    #[wasm_bindgen]
    pub fn get_error_context(&self, code: u32) -> Result<JsValue, JsValue> {
        let error_code = unsafe { std::mem::transmute(code) };
        if let Some(context) = self.contexts.get(&error_code) {
            Ok(serde_wasm_bindgen::to_value(context)?)
        } else {
            Err(JsValue::from_str("Unknown error code"))
        }
    }

    #[wasm_bindgen]
    pub fn is_critical(&self, code: u32) -> bool {
        let error_code = unsafe { std::mem::transmute(code) };
        self.contexts.get(&error_code)
            .map(|ctx| matches!(ctx.severity, ErrorSeverity::Critical))
            .unwrap_or(false)
    }

    #[wasm_bindgen]
    pub fn requires_immediate_action(&self, code: u32) -> bool {
        let error_code = unsafe { std::mem::transmute(code) };
        self.contexts.get(&error_code)
            .map(|ctx| ctx.requires_immediate_action)
            .unwrap_or(false)
    }
}

// Helper function for other components
pub fn get_error_code(error: &ErrorCode) -> u32 {
    *error as u32
}

// Helper function to get description
pub fn get_error_description(code: ErrorCode) -> String {
    ERROR_CONTEXTS.get(&code)
        .map(|ctx| ctx.description.clone())
        .unwrap_or_else(|| "Unknown error".to_string())
} 