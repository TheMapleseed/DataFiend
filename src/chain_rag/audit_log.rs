use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};
use thiserror::Error;
use uuid::Uuid;
use std::collections::HashMap;
use dashmap::DashMap;
use std::time::Duration;

// Audit constants
const MAX_LOG_SIZE: usize = 10_000;
const RETENTION_DAYS: i64 = 365;
const BATCH_SIZE: usize = 100;
const FLUSH_INTERVAL: Duration = Duration::from_secs(30);
const MAX_BATCH_AGE: Duration = Duration::from_secs(300);

#[derive(Debug, Error)]
pub enum AuditError {
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Log buffer full")]
    BufferFull,
    
    #[error("Invalid event data: {0}")]
    InvalidData(String),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub id: Uuid,
    pub timestamp: DateTime<Utc>,
    pub event_type: EventType,
    pub severity: EventSeverity,
    pub user_id: Option<String>,
    pub resource_id: Option<String>,
    pub action: String,
    pub status: EventStatus,
    pub client_ip: Option<String>,
    pub user_agent: Option<String>,
    pub details: HashMap<String, String>,
    pub trace_id: Option<String>,
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub enum EventType {
    Authentication,
    Authorization,
    Configuration,
    DataAccess,
    SystemChange,
    Security,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Ord, PartialOrd, Eq)]
pub enum EventSeverity {
    Critical,
    High,
    Medium,
    Low,
    Info,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum EventStatus {
    Success,
    Failure,
    Denied,
    Error,
}

pub struct AuditLogger {
    buffer: Arc<DashMap<Uuid, AuditEvent>>,
    db_pool: Arc<sqlx::PgPool>,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
    flush_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
    retention_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl AuditLogger {
    pub async fn new(
        db_pool: Arc<sqlx::PgPool>,
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Result<Self, AuditError> {
        let logger = Self {
            buffer: Arc::new(DashMap::with_capacity(MAX_LOG_SIZE)),
            db_pool,
            metrics,
            error_handler,
            flush_task: Arc::new(tokio::sync::Mutex::new(None)),
            retention_task: Arc::new(tokio::sync::Mutex::new(None)),
        };
        
        logger.initialize_database().await?;
        logger.start_flush_task();
        logger.start_retention_task();
        
        Ok(logger)
    }

    pub async fn log_event(
        &self,
        event_type: EventType,
        severity: EventSeverity,
        action: &str,
        status: EventStatus,
        context: &SecurityContext,
        details: HashMap<String, String>,
    ) -> Result<(), AuditError> {
        // Validate event data
        self.validate_event_data(&details)?;
        
        let event = AuditEvent {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            event_type,
            severity,
            user_id: context.user_id.clone(),
            resource_id: context.resource_id.clone(),
            action: action.to_string(),
            status,
            client_ip: context.client_ip.clone(),
            user_agent: context.user_agent.clone(),
            details,
            trace_id: context.trace_id.clone(),
            session_id: context.session_id.clone(),
        };

        // Check buffer capacity
        if self.buffer.len() >= MAX_LOG_SIZE {
            self.metrics.record_audit_buffer_full().await;
            return Err(AuditError::BufferFull);
        }

        // Store event in buffer
        self.buffer.insert(event.id, event.clone());
        
        // Trigger immediate flush for critical events
        if severity == EventSeverity::Critical {
            self.flush_events().await?;
        }

        self.metrics.record_audit_event(&event).await;
        Ok(())
    }

    async fn flush_events(&self) -> Result<(), AuditError> {
        let mut batch = Vec::with_capacity(BATCH_SIZE);
        let mut to_remove = Vec::new();
        
        // Collect events for flushing
        for entry in self.buffer.iter() {
            batch.push(entry.value().clone());
            to_remove.push(*entry.key());
            
            if batch.len() >= BATCH_SIZE {
                break;
            }
        }

        if batch.is_empty() {
            return Ok(());
        }

        // Store events in database
        let mut tx = self.db_pool.begin().await?;
        
        for event in &batch {
            sqlx::query!(
                r#"
                INSERT INTO audit_events (
                    id, timestamp, event_type, severity, user_id, resource_id,
                    action, status, client_ip, user_agent, details, trace_id, session_id
                )
                VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13)
                "#,
                event.id,
                event.timestamp,
                event.event_type as _,
                event.severity as _,
                event.user_id,
                event.resource_id,
                event.action,
                event.status as _,
                event.client_ip,
                event.user_agent,
                serde_json::to_value(&event.details)?,
                event.trace_id,
                event.session_id,
            )
            .execute(&mut *tx)
            .await?;
        }

        tx.commit().await?;

        // Remove flushed events from buffer
        for id in to_remove {
            self.buffer.remove(&id);
        }

        self.metrics.record_audit_flush(batch.len()).await;
        Ok(())
    }

    async fn initialize_database(&self) -> Result<(), AuditError> {
        sqlx::query!(
            r#"
            CREATE TABLE IF NOT EXISTS audit_events (
                id UUID PRIMARY KEY,
                timestamp TIMESTAMPTZ NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT NOT NULL,
                user_id TEXT,
                resource_id TEXT,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                client_ip TEXT,
                user_agent TEXT,
                details JSONB NOT NULL,
                trace_id TEXT,
                session_id TEXT,
                
                -- Indexes for common queries
                INDEX idx_audit_timestamp (timestamp),
                INDEX idx_audit_user_id (user_id),
                INDEX idx_audit_severity (severity),
                INDEX idx_audit_type (event_type)
            )
            "#
        )
        .execute(&*self.db_pool)
        .await?;

        Ok(())
    }

    fn validate_event_data(&self, details: &HashMap<String, String>) -> Result<(), AuditError> {
        for (key, value) in details {
            if key.is_empty() || value.is_empty() {
                return Err(AuditError::InvalidData(
                    "Empty keys or values not allowed".to_string()
                ));
            }
            
            if key.len() > 255 || value.len() > 1024 {
                return Err(AuditError::InvalidData(
                    "Key or value exceeds maximum length".to_string()
                ));
            }
        }
        
        Ok(())
    }

    fn start_flush_task(&self) {
        let buffer = self.buffer.clone();
        let db_pool = self.db_pool.clone();
        let metrics = self.metrics.clone();
        let error_handler = self.error_handler.clone();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(FLUSH_INTERVAL);
            
            loop {
                interval.tick().await;
                
                if let Err(e) = Self::flush_batch(&buffer, &db_pool, &metrics).await {
                    error_handler.handle_error(
                        e.into(),
                        "audit_flush".to_string(),
                    ).await;
                }
            }
        });

        *self.flush_task.lock().unwrap() = Some(handle);
    }

    fn start_retention_task(&self) {
        let db_pool = self.db_pool.clone();
        let metrics = self.metrics.clone();
        let error_handler = self.error_handler.clone();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(Duration::from_secs(86400)); // Daily
            
            loop {
                interval.tick().await;
                
                if let Err(e) = Self::cleanup_old_events(&db_pool, &metrics).await {
                    error_handler.handle_error(
                        e.into(),
                        "audit_retention".to_string(),
                    ).await;
                }
            }
        });

        *self.retention_task.lock().unwrap() = Some(handle);
    }

    async fn cleanup_old_events(
        db_pool: &sqlx::PgPool,
        metrics: &MetricsStore,
    ) -> Result<(), AuditError> {
        let cutoff = Utc::now() - chrono::Duration::days(RETENTION_DAYS);
        
        let result = sqlx::query!(
            r#"
            DELETE FROM audit_events
            WHERE timestamp < $1
            "#,
            cutoff,
        )
        .execute(db_pool)
        .await?;

        metrics.record_audit_cleanup(result.rows_affected() as usize).await;
        Ok(())
    }
}

// Safe cleanup
impl Drop for AuditLogger {
    fn drop(&mut self) {
        if let Some(handle) = self.flush_task.lock().unwrap().take() {
            handle.abort();
        }
        
        if let Some(handle) = self.retention_task.lock().unwrap().take() {
            handle.abort();
        }
    }
} 