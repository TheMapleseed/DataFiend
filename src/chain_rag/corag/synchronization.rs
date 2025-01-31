use std::sync::Arc;
use tokio::sync::{RwLock, Semaphore, Mutex};
use dashmap::DashMap;
use futures::stream::{self, StreamExt};
use crate::error::error_system::SystemError;

pub struct SyncManager {
    operation_locks: DashMap<String, Arc<Mutex<()>>>,
    resource_semaphores: DashMap<String, Arc<Semaphore>>,
    state_lock: Arc<RwLock<()>>,
    batch_processor: Arc<BatchProcessor>,
}

struct BatchProcessor {
    queue: Arc<Mutex<Vec<Operation>>>,
    max_concurrent: usize,
    processing_semaphore: Arc<Semaphore>,
}

impl SyncManager {
    pub fn new(max_concurrent: usize) -> Self {
        Self {
            operation_locks: DashMap::new(),
            resource_semaphores: DashMap::new(),
            state_lock: Arc::new(RwLock::new(())),
            batch_processor: Arc::new(BatchProcessor::new(max_concurrent)),
        }
    }

    pub async fn synchronize_operation<F, T>(&self, operation_id: &str, f: F) -> Result<T, SystemError>
    where
        F: Future<Output = Result<T, SystemError>> + Send + 'static,
        T: Send + 'static,
    {
        // Get or create operation lock
        let lock = self.operation_locks
            .entry(operation_id.to_string())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone();

        // Acquire operation lock
        let _guard = lock.lock().await;

        // Execute operation
        f.await
    }

    pub async fn process_batch<T, F>(&self, items: Vec<T>, processor: F) -> Result<Vec<Result<T, SystemError>>, SystemError>
    where
        T: Send + 'static,
        F: Fn(T) -> Future<Output = Result<T, SystemError>> + Send + Sync + 'static,
    {
        let processor = Arc::new(processor);
        
        stream::iter(items)
            .map(|item| {
                let processor = processor.clone();
                async move {
                    let _permit = self.batch_processor.processing_semaphore.acquire().await
                        .map_err(|_| SystemError::ConcurrencyError("Failed to acquire processing permit".into()))?;
                    processor(item).await
                }
            })
            .buffer_unordered(self.batch_processor.max_concurrent)
            .collect()
            .await
    }

    pub async fn acquire_resource(&self, resource_id: &str, amount: usize) -> Result<(), SystemError> {
        let semaphore = self.resource_semaphores
            .entry(resource_id.to_string())
            .or_insert_with(|| Arc::new(Semaphore::new(amount)))
            .clone();

        semaphore.acquire_many(amount as u32).await
            .map_err(|_| SystemError::ResourceError("Failed to acquire resource".into()))?;

        Ok(())
    }

    pub async fn with_state_lock<F, T>(&self, f: F) -> Result<T, SystemError>
    where
        F: Future<Output = Result<T, SystemError>> + Send + 'static,
        T: Send + 'static,
    {
        let _guard = self.state_lock.write().await;
        f.await
    }

    pub async fn coordinate_operations<T, F>(&self, operations: Vec<Operation<T>>, executor: F) -> Result<Vec<T>, SystemError>
    where
        T: Send + 'static,
        F: Fn(Operation<T>) -> Future<Output = Result<T, SystemError>> + Send + Sync + 'static,
    {
        let executor = Arc::new(executor);
        let results = Vec::with_capacity(operations.len());
        let results_lock = Arc::new(Mutex::new(results));

        let futures = operations.into_iter().map(|op| {
            let executor = executor.clone();
            let results = results_lock.clone();
            
            async move {
                let result = self.synchronize_operation(&op.id, async {
                    executor(op).await
                }).await?;

                let mut results = results.lock().await;
                results.push(result);
                Ok(())
            }
        });

        futures::future::try_join_all(futures).await?;
        
        Ok(Arc::try_unwrap(results_lock)
            .map_err(|_| SystemError::ConcurrencyError("Failed to unwrap results".into()))?
            .into_inner())
    }
}

impl BatchProcessor {
    fn new(max_concurrent: usize) -> Self {
        Self {
            queue: Arc::new(Mutex::new(Vec::new())),
            max_concurrent,
            processing_semaphore: Arc::new(Semaphore::new(max_concurrent)),
        }
    }

    async fn enqueue(&self, operation: Operation) -> Result<(), SystemError> {
        let mut queue = self.queue.lock().await;
        queue.push(operation);
        Ok(())
    }

    async fn process_queue<F>(&self, processor: F) -> Result<(), SystemError>
    where
        F: Fn(Operation) -> Future<Output = Result<(), SystemError>> + Send + Sync + 'static,
    {
        let processor = Arc::new(processor);
        let mut queue = self.queue.lock().await;
        
        let futures = queue.drain(..).map(|op| {
            let processor = processor.clone();
            async move {
                let _permit = self.processing_semaphore.acquire().await
                    .map_err(|_| SystemError::ConcurrencyError("Failed to acquire permit".into()))?;
                processor(op).await
            }
        });

        futures::future::try_join_all(futures).await?;
        Ok(())
    }
}

#[derive(Debug)]
pub struct Operation<T = ()> {
    id: String,
    priority: u32,
    data: T,
}

impl<T> Operation<T> {
    pub fn new(id: String, priority: u32, data: T) -> Self {
        Self {
            id,
            priority,
            data,
        }
    }
} 