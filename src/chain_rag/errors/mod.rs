use std::sync::Arc;
use thiserror::Error;
use serde::{Serialize, Deserialize};
use uuid::Uuid;
use std::fmt;

// Root error type for the entire system
#[derive(Debug, Error)]
pub enum ChainRAGError {
    #[error(transparent)]
    Database(#[from] DatabaseError),
    
    #[error(transparent)]
    Auth(#[from] AuthError),
    
    #[error(transparent)]
    Crypto(#[from] CryptoError),
    
    #[error(transparent)]
    Network(#[from] NetworkError),
    
    #[error(transparent)]
    Validation(#[from] ValidationError),
    
    #[error(transparent)]
    Storage(#[from] StorageError),
    
    #[error(transparent)]
    Processing(#[from] ProcessingError),
    
    #[error("Internal error: {0}")]
    Internal(InternalError),
}

// Component-specific errors
#[derive(Debug, Error)]
pub enum DatabaseError {
    #[error("Connection failed: {0}")]
    ConnectionFailed(String),
    
    #[error("Query failed: {0}")]
    QueryFailed(String),
    
    #[error("Transaction failed: {0}")]
    TransactionFailed(String),
    
    #[error("Deadlock detected")]
    DeadlockDetected,
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("Invalid credentials")]
    InvalidCredentials,
    
    #[error("Session expired")]
    SessionExpired,
    
    #[error("Token invalid")]
    InvalidToken,
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
}

#[derive(Debug, Error)]
pub enum ValidationError {
    #[error("Invalid input: {0}")]
    InvalidInput(String),
    
    #[error("Missing field: {0}")]
    MissingField(String),
    
    #[error("Value out of range: {0}")]
    OutOfRange(String),
}

// Error context for tracking and correlation
#[derive(Debug, Clone, Serialize)]
pub struct ErrorContext {
    error_id: Uuid,
    component: String,
    operation: String,
    timestamp: chrono::DateTime<chrono::Utc>,
    trace_id: Option<String>,
    user_id: Option<String>,
}

// Unified error handler
pub struct ErrorHandler {
    metrics: Arc<MetricsStore>,
    logger: Arc<Logger>,
    alert_system: Arc<AlertSystem>,
}

impl ErrorHandler {
    pub fn new(
        metrics: Arc<MetricsStore>,
        logger: Arc<Logger>,
        alert_system: Arc<AlertSystem>,
    ) -> Self {
        Self {
            metrics,
            logger,
            alert_system,
        }
    }

    pub async fn handle_error(
        &self,
        error: ChainRAGError,
        context: ErrorContext,
    ) -> PublicError {
        // Log error with context
        self.log_error(&error, &context).await;
        
        // Update metrics
        self.update_metrics(&error, &context).await;
        
        // Check if alert needed
        self.check_alert_threshold(&error, &context).await;
        
        // Convert to public error
        self.to_public_error(error, context)
    }

    async fn log_error(&self, error: &ChainRAGError, context: &ErrorContext) {
        let log_entry = ErrorLogEntry {
            error: error.to_string(),
            context: context.clone(),
            stack_trace: std::backtrace::Backtrace::capture().to_string(),
            severity: self.determine_severity(error),
        };
        
        self.logger.log_error(log_entry).await;
    }

    async fn update_metrics(&self, error: &ChainRAGError, context: &ErrorContext) {
        let labels = MetricLabels {
            component: context.component.clone(),
            error_type: error.type_name(),
            severity: self.determine_severity(error),
        };
        
        self.metrics.increment_error_counter(labels).await;
    }

    async fn check_alert_threshold(&self, error: &ChainRAGError, context: &ErrorContext) {
        if self.should_alert(error) {
            let alert = Alert {
                error_id: context.error_id,
                severity: self.determine_severity(error),
                message: error.to_string(),
                context: context.clone(),
            };
            
            self.alert_system.send_alert(alert).await;
        }
    }

    fn to_public_error(&self, error: ChainRAGError, context: ErrorContext) -> PublicError {
        match error {
            ChainRAGError::Database(_) => PublicError::ServiceUnavailable {
                code: ErrorCode::DatabaseError,
                error_id: context.error_id,
            },
            ChainRAGError::Auth(auth_error) => match auth_error {
                AuthError::InvalidCredentials | AuthError::InvalidToken => {
                    PublicError::AuthenticationFailed {
                        code: ErrorCode::AuthenticationFailed,
                        error_id: context.error_id,
                    }
                }
                AuthError::SessionExpired => PublicError::SessionExpired {
                    code: ErrorCode::SessionExpired,
                    error_id: context.error_id,
                },
                AuthError::PermissionDenied(_) => PublicError::PermissionDenied {
                    code: ErrorCode::PermissionDenied,
                    error_id: context.error_id,
                },
            },
            ChainRAGError::Validation(_) => PublicError::ValidationFailed {
                code: ErrorCode::InvalidInput,
                error_id: context.error_id,
            },
            _ => PublicError::InternalError {
                code: ErrorCode::Unknown,
                error_id: context.error_id,
            },
        }
    }

    fn determine_severity(&self, error: &ChainRAGError) -> ErrorSeverity {
        match error {
            ChainRAGError::Database(_) | ChainRAGError::Internal(_) => ErrorSeverity::Critical,
            ChainRAGError::Auth(_) => ErrorSeverity::Warning,
            ChainRAGError::Validation(_) => ErrorSeverity::Info,
            _ => ErrorSeverity::Error,
        }
    }

    fn should_alert(&self, error: &ChainRAGError) -> bool {
        matches!(
            self.determine_severity(error),
            ErrorSeverity::Critical | ErrorSeverity::Error
        )
    }
}

// Helper types
#[derive(Debug, Clone, Copy, Serialize)]
pub enum ErrorSeverity {
    Critical,
    Error,
    Warning,
    Info,
}

#[derive(Debug, Serialize)]
struct ErrorLogEntry {
    error: String,
    context: ErrorContext,
    stack_trace: String,
    severity: ErrorSeverity,
}

#[derive(Debug)]
struct MetricLabels {
    component: String,
    error_type: String,
    severity: ErrorSeverity,
}

#[derive(Debug)]
struct Alert {
    error_id: Uuid,
    severity: ErrorSeverity,
    message: String,
    context: ErrorContext,
}

// Extension trait for error type information
trait ErrorType {
    fn type_name(&self) -> String;
}

impl ErrorType for ChainRAGError {
    fn type_name(&self) -> String {
        match self {
            ChainRAGError::Database(_) => "database",
            ChainRAGError::Auth(_) => "auth",
            ChainRAGError::Crypto(_) => "crypto",
            ChainRAGError::Network(_) => "network",
            ChainRAGError::Validation(_) => "validation",
            ChainRAGError::Storage(_) => "storage",
            ChainRAGError::Processing(_) => "processing",
            ChainRAGError::Internal(_) => "internal",
        }.to_string()
    }
}
