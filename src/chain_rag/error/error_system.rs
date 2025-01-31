use wasm_bindgen::prelude::*;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use crate::chain_rag::CoRAG;
use crate::security::wasm_protection::SecurityError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SystemError {
    ResourceError(ResourceError),
    SecurityError(SecurityError),
    RuntimeError(RuntimeError),
    ValidationError(ValidationError),
    WasmError(String),
    TimeoutError,
    MemoryError(String),
    ConcurrencyError(String),
    StateError(String),
    DataError(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ResourceError {
    MemoryLimitExceeded { limit: usize, requested: usize },
    ConcurrencyLimitExceeded { limit: u32, requested: u32 },
    ThroughputExceeded { limit: u32, current: u32 },
    ResourceExhausted { resource_type: String, details: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SecurityError {
    AccessDenied { reason: String },
    InvalidToken { details: String },
    EncryptionError { details: String },
    IntegrityViolation { details: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuntimeError {
    OperationTimeout { operation: String, timeout: u64 },
    SystemOverload { component: String, metrics: String },
    StateError { expected: String, actual: String },
    ComponentFailure { component: String, reason: String },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum ValidationError {
    InvalidInput { field: String, reason: String },
    ConstraintViolation { constraint: String, details: String },
    StateValidation { check: String, details: String },
    FormatError { expected: String, received: String },
}

pub struct ErrorSystem {
    corag: Arc<CoRAG>,
}

impl ErrorSystem {
    pub fn new(corag: Arc<CoRAG>) -> Self {
        Self { corag }
    }

    pub async fn handle_error(&self, error: SystemError) -> Result<(), JsValue> {
        // Log the error
        self.log_error(&error).await?;

        // Forward to CoRAG for pattern analysis and learning
        self.corag.process_error(&error).await?;

        // Apply any immediate necessary corrections
        self.apply_immediate_corrections(&error).await?;

        Ok(())
    }

    async fn log_error(&self, error: &SystemError) -> Result<(), JsValue> {
        // Structured error logging
        let error_log = self.create_error_log(error);
        self.corag.log_event("error", &error_log).await?;
        Ok(())
    }

    async fn apply_immediate_corrections(&self, error: &SystemError) -> Result<(), JsValue> {
        match error {
            SystemError::ResourceError(resource_error) => {
                self.handle_resource_error(resource_error).await?;
            },
            SystemError::SecurityError(security_error) => {
                self.handle_security_error(security_error).await?;
            },
            SystemError::RuntimeError(runtime_error) => {
                self.handle_runtime_error(runtime_error).await?;
            },
            SystemError::ValidationError(validation_error) => {
                self.handle_validation_error(validation_error).await?;
            },
            SystemError::MemoryError(memory_error) => {
                self.handle_memory_error(memory_error).await?;
            },
            SystemError::ConcurrencyError(concurrency_error) => {
                self.handle_concurrency_error(concurrency_error).await?;
            },
            SystemError::StateError(state_error) => {
                self.handle_state_error(state_error).await?;
            },
            SystemError::DataError(data_error) => {
                self.handle_data_error(data_error).await?;
            },
            SystemError::TimeoutError => {
                self.handle_timeout_error().await?;
            },
            SystemError::WasmError(wasm_error) => {
                self.handle_wasm_error(wasm_error).await?;
            },
        }
        Ok(())
    }

    fn create_error_log(&self, error: &SystemError) -> serde_json::Value {
        // Create structured error log
        json!({
            "timestamp": chrono::Utc::now().to_rfc3339(),
            "error_type": format!("{:?}", error),
            "details": self.error_details(error),
            "severity": self.determine_severity(error),
        })
    }

    pub fn is_security_related(&self, error: &SystemError) -> bool {
        matches!(
            error,
            SystemError::SecurityError(_) |
            SystemError::ValidationError(_) |
            SystemError::MemoryError(_)
        )
    }

    pub fn requires_immediate_action(&self, error: &SystemError) -> bool {
        matches!(
            error,
            SystemError::SecurityError(_) |
            SystemError::MemoryError(_)
        )
    }

    pub fn get_severity(&self, error: &SystemError) -> ErrorSeverity {
        match error {
            SystemError::SecurityError(_) => ErrorSeverity::Critical,
            SystemError::MemoryError(_) => ErrorSeverity::Critical,
            SystemError::ValidationError(_) => ErrorSeverity::High,
            SystemError::ResourceError(_) => ErrorSeverity::High,
            _ => ErrorSeverity::Medium,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum ErrorSeverity {
    Low,
    Medium,
    High,
    Critical,
}

impl From<SecurityError> for SystemError {
    fn from(error: SecurityError) -> Self {
        SystemError::SecurityError(error)
    }
}

// CoRAG integration for error handling
impl crate::corag::CoRAG {
    pub async fn handle_security_error(&self, error: SecurityError) -> Result<(), SystemError> {
        // Log security incident
        self.log_security_incident(&error).await?;

        // Notify security monitoring
        self.notify_security_monitor(&error).await?;

        // Take protective action
        self.handle_security_breach(&error).await?;

        Ok(())
    }
} 