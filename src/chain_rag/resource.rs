use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use std::collections::HashMap;
use uuid::Uuid;
use thiserror::Error;
use std::time::{Duration, Instant};
use async_trait::async_trait;

// Resource management constants
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const MAX_RESOURCE_AGE: Duration = Duration::from_secs(3600);
const MAX_RETRIES: u32 = 3;

#[derive(Debug, Error)]
pub enum ResourceError {
    #[error("Resource allocation failed: {0}")]
    AllocationFailed(String),
    
    #[error("Resource not found: {0}")]
    NotFound(String),
    
    #[error("Resource cleanup failed: {0}")]
    CleanupFailed(String),
    
    #[error("Resource locked: {0}")]
    Locked(String),
}

#[async_trait]
pub trait ManagedResource: Send + Sync {
    async fn cleanup(&mut self) -> Result<(), ResourceError>;
    async fn is_valid(&self) -> bool;
    fn last_accessed(&self) -> Instant;
    fn resource_type(&self) -> &'static str;
}

pub struct ResourceManager {
    resources: Arc<RwLock<HashMap<Uuid, ResourceEntry>>>,
    error_handler: Arc<ErrorHandler>,
    metrics: Arc<MetricsStore>,
    cleanup_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

struct ResourceEntry {
    resource: Box<dyn ManagedResource>,
    created_at: Instant,
    last_accessed: Arc<RwLock<Instant>>,
    cleanup_lock: Arc<tokio::sync::Mutex<()>>,
}

impl ResourceManager {
    pub fn new(
        error_handler: Arc<ErrorHandler>,
        metrics: Arc<MetricsStore>,
    ) -> Self {
        let manager = Self {
            resources: Arc::new(RwLock::new(HashMap::new())),
            error_handler,
            metrics,
            cleanup_task: Arc::new(Mutex::new(None)),
        };
        
        manager.start_cleanup_task();
        manager
    }

    pub async fn allocate_resource<T: ManagedResource + 'static>(
        &self,
        resource: T
    ) -> Result<Uuid, ChainRAGError> {
        let context = ErrorContext {
            error_id: Uuid::new_v4(),
            component: "resource_manager".to_string(),
            operation: "allocate_resource".to_string(),
            timestamp: chrono::Utc::now(),
            trace_id: Some(opentelemetry::trace::current_span_context().trace_id().to_string()),
            user_id: None,
        };

        let resource_id = Uuid::new_v4();
        let entry = ResourceEntry {
            resource: Box::new(resource),
            created_at: Instant::now(),
            last_accessed: Arc::new(RwLock::new(Instant::now())),
            cleanup_lock: Arc::new(tokio::sync::Mutex::new(())),
        };

        let mut resources = self.resources.write().await;
        resources.insert(resource_id, entry);
        
        self.metrics.record_resource_allocation(resource_id).await;
        Ok(resource_id)
    }

    pub async fn get_resource<T: 'static>(
        &self,
        resource_id: Uuid
    ) -> Result<impl std::ops::Deref<Target = T>, ChainRAGError> {
        let context = ErrorContext {
            error_id: Uuid::new_v4(),
            component: "resource_manager".to_string(),
            operation: "get_resource".to_string(),
            timestamp: chrono::Utc::now(),
            trace_id: Some(opentelemetry::trace::current_span_context().trace_id().to_string()),
            user_id: None,
        };

        let resources = self.resources.read().await;
        if let Some(entry) = resources.get(&resource_id) {
            *entry.last_accessed.write().await = Instant::now();
            // Type-safe resource access
            if let Some(resource) = entry.resource.as_any().downcast_ref::<T>() {
                return Ok(ResourceGuard::new(resource, entry.cleanup_lock.clone()));
            }
        }
        
        Err(ChainRAGError::Resource(ResourceError::NotFound(
            resource_id.to_string()
        )))
    }

    pub async fn cleanup_resource(
        &self,
        resource_id: Uuid
    ) -> Result<(), ChainRAGError> {
        let context = ErrorContext {
            error_id: Uuid::new_v4(),
            component: "resource_manager".to_string(),
            operation: "cleanup_resource".to_string(),
            timestamp: chrono::Utc::now(),
            trace_id: Some(opentelemetry::trace::current_span_context().trace_id().to_string()),
            user_id: None,
        };

        let mut resources = self.resources.write().await;
        if let Some(mut entry) = resources.remove(&resource_id) {
            // Acquire cleanup lock
            let _lock = entry.cleanup_lock.lock().await;
            
            match entry.resource.cleanup().await {
                Ok(()) => {
                    self.metrics.record_resource_cleanup_success(resource_id).await;
                    Ok(())
                }
                Err(e) => {
                    let error = ChainRAGError::Resource(e);
                    self.error_handler.handle_error(error.clone(), context).await;
                    Err(error)
                }
            }
        } else {
            Ok(()) // Resource already cleaned up
        }
    }

    fn start_cleanup_task(&self) {
        let resources = self.resources.clone();
        let error_handler = self.error_handler.clone();
        let metrics = self.metrics.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(CLEANUP_INTERVAL).await;
                
                let mut to_cleanup = Vec::new();
                let now = Instant::now();
                
                // Identify resources to clean up
                {
                    let resources_read = resources.read().await;
                    for (id, entry) in resources_read.iter() {
                        if now.duration_since(*entry.last_accessed.read().await) > MAX_RESOURCE_AGE {
                            to_cleanup.push(*id);
                        }
                    }
                }
                
                // Clean up identified resources
                for resource_id in to_cleanup {
                    let context = ErrorContext {
                        error_id: Uuid::new_v4(),
                        component: "resource_manager".to_string(),
                        operation: "auto_cleanup".to_string(),
                        timestamp: chrono::Utc::now(),
                        trace_id: Some(opentelemetry::trace::current_span_context().trace_id().to_string()),
                        user_id: None,
                    };

                    let mut retry_count = 0;
                    while retry_count < MAX_RETRIES {
                        match resources.write().await.remove(&resource_id) {
                            Some(mut entry) => {
                                let _lock = entry.cleanup_lock.lock().await;
                                if let Err(e) = entry.resource.cleanup().await {
                                    retry_count += 1;
                                    if retry_count == MAX_RETRIES {
                                        let error = ChainRAGError::Resource(e);
                                        error_handler.handle_error(error, context.clone()).await;
                                    }
                                    continue;
                                }
                                metrics.record_resource_cleanup_success(resource_id).await;
                                break;
                            }
                            None => break, // Already cleaned up
                        }
                    }
                }
            }
        });

        *self.cleanup_task.lock().unwrap() = Some(handle);
    }
}

// Resource guard for safe access
struct ResourceGuard<'a, T> {
    resource: &'a T,
    _lock: Arc<tokio::sync::Mutex<()>>,
}

impl<'a, T> ResourceGuard<'a, T> {
    fn new(resource: &'a T, lock: Arc<tokio::sync::Mutex<()>>) -> Self {
        Self {
            resource,
            _lock: lock,
        }
    }
}

impl<'a, T> std::ops::Deref for ResourceGuard<'a, T> {
    type Target = T;
    
    fn deref(&self) -> &Self::Target {
        self.resource
    }
}

// Safe cleanup
impl Drop for ResourceManager {
    fn drop(&mut self) {
        if let Some(handle) = self.cleanup_task.lock().unwrap().take() {
            handle.abort();
        }
    }
} 