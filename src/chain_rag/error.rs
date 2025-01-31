use std::sync::Arc;
use thiserror::Error;
use std::fmt;
use serde::{Serialize, Deserialize};
use uuid::Uuid;

// Public error types (safe to expose)
#[derive(Debug, Error, Serialize, Deserialize)]
#[serde(tag = "type", content = "details")]
pub enum PublicError {
    #[error("Request failed: {code}")]
    RequestFailed {
        code: ErrorCode,
        error_id: Uuid,
    },
    
    #[error("Invalid input")]
    ValidationFailed {
        code: ErrorCode,
        error_id: Uuid,
    },
    
    #[error("Operation not permitted")]
    PermissionDenied {
        code: ErrorCode,
        error_id: Uuid,
    },
    
    #[error("Resource not found")]
    NotFound {
        code: ErrorCode,
        error_id: Uuid,
    },
    
    #[error("Service temporarily unavailable")]
    ServiceUnavailable {
        code: ErrorCode,
        error_id: Uuid,
    },
}

// Internal error types (not exposed)
#[derive(Debug, Error)]
pub(crate) enum InternalError {
    #[error("Database error: {0}")]
    Database(#[source] DatabaseError),
    
    #[error("Crypto error: {0}")]
    Crypto(#[source] CryptoError),
    
    #[error("Authentication error: {0}")]
    Auth(#[source] AuthError),
    
    #[error("Network error: {0}")]
    Network(#[source] NetworkError),
    
    #[error("System error: {0}")]
    System(#[source] SystemError),
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[repr(u16)]
pub enum ErrorCode {
    // Generic errors (1000-1999)
    Unknown = 1000,
    InvalidInput = 1001,
    NotFound = 1002,
    PermissionDenied = 1003,
    
    // Authentication errors (2000-2999)
    AuthenticationFailed = 2000,
    SessionExpired = 2001,
    InvalidToken = 2002,
    
    // Request errors (3000-3999)
    InvalidRequest = 3000,
    RateLimitExceeded = 3001,
    RequestTimeout = 3002,
    
    // Service errors (4000-4999)
    ServiceUnavailable = 4000,
    DatabaseError = 4001,
    NetworkError = 4002,
}

pub struct ErrorManager {
    metrics: Arc<MetricsStore>,
    logger: Arc<Logger>,
}

impl ErrorManager {
    pub fn new(metrics: Arc<MetricsStore>, logger: Arc<Logger>) -> Self {
        Self {
            metrics,
            logger,
        }
    }

    // Convert internal errors to public errors
    pub async fn handle_error(&self, error: InternalError) -> PublicError {
        let error_id = Uuid::new_v4();
        
        // Log internal error details securely
        self.log_internal_error(&error, error_id).await;
        
        // Convert to public error
        match error {
            InternalError::Database(e) => {
                self.metrics.record_database_error().await;
                PublicError::ServiceUnavailable {
                    code: ErrorCode::DatabaseError,
                    error_id,
                }
            }
            InternalError::Crypto(e) => {
                self.metrics.record_crypto_error().await;
                PublicError::RequestFailed {
                    code: ErrorCode::Unknown,
                    error_id,
                }
            }
            InternalError::Auth(e) => {
                self.metrics.record_auth_error().await;
                PublicError::PermissionDenied {
                    code: ErrorCode::AuthenticationFailed,
                    error_id,
                }
            }
            InternalError::Network(e) => {
                self.metrics.record_network_error().await;
                PublicError::ServiceUnavailable {
                    code: ErrorCode::NetworkError,
                    error_id,
                }
            }
            InternalError::System(e) => {
                self.metrics.record_system_error().await;
                PublicError::ServiceUnavailable {
                    code: ErrorCode::ServiceUnavailable,
                    error_id,
                }
            }
        }
    }

    async fn log_internal_error(&self, error: &InternalError, error_id: Uuid) {
        let log_entry = SecureLogEntry {
            error_id,
            timestamp: chrono::Utc::now(),
            error_type: format!("{:?}", error),
            details: error.to_string(),
            stack_trace: std::backtrace::Backtrace::capture().to_string(),
        };
        
        self.logger.log_error(log_entry).await;
    }

    pub async fn validate_error_response(&self, error: &PublicError) -> bool {
        // Ensure error doesn't contain sensitive data
        !error.to_string().contains_sensitive_data()
    }
}

// Secure logging
#[derive(Serialize)]
struct SecureLogEntry {
    error_id: Uuid,
    timestamp: chrono::DateTime<chrono::Utc>,
    error_type: String,
    details: String,
    stack_trace: String,
}

// Custom Display implementation to prevent leaking sensitive data
impl fmt::Display for PublicError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PublicError::RequestFailed { code, error_id } => {
                write!(f, "Request failed (ID: {})", error_id)
            }
            PublicError::ValidationFailed { code, error_id } => {
                write!(f, "Invalid input (ID: {})", error_id)
            }
            PublicError::PermissionDenied { code, error_id } => {
                write!(f, "Operation not permitted (ID: {})", error_id)
            }
            PublicError::NotFound { code, error_id } => {
                write!(f, "Resource not found (ID: {})", error_id)
            }
            PublicError::ServiceUnavailable { code, error_id } => {
                write!(f, "Service temporarily unavailable (ID: {})", error_id)
            }
        }
    }
}

// Helper trait for sensitive data detection
trait ContainsSensitiveData {
    fn contains_sensitive_data(&self) -> bool;
}

impl ContainsSensitiveData for String {
    fn contains_sensitive_data(&self) -> bool {
        // Check for common sensitive patterns
        let patterns = [
            "password", "key", "token", "secret", "credential",
            "api_key", "private", "auth", "session", "hash",
        ];
        
        patterns.iter().any(|&pattern| {
            self.to_lowercase().contains(pattern)
        })
    }
} 