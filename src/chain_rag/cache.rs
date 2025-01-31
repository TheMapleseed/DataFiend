use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use dashmap::DashMap;
use std::time::{Duration, Instant};
use std::collections::HashMap;
use thiserror::Error;
use futures::future::join_all;
use tokio::time::interval;

// Cache constants
const MAX_CACHE_SIZE: usize = 10_000;
const DEFAULT_TTL: Duration = Duration::from_secs(3600);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(60);
const WRITE_LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_BATCH_SIZE: usize = 100;

#[derive(Debug, Error)]
pub enum CacheError {
    #[error("Cache entry not found: {0}")]
    NotFound(String),
    
    #[error("Cache write failed: {0}")]
    WriteFailed(String),
    
    #[error("Lock acquisition timeout")]
    LockTimeout,
    
    #[error("Cache capacity exceeded")]
    CapacityExceeded,
    
    #[error("Invalid operation: {0}")]
    InvalidOperation(String),
}

pub struct CacheManager<K, V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    entries: Arc<DashMap<K, CacheEntry<V>>>,
    write_locks: Arc<DashMap<K, Arc<Mutex<()>>>>,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
    cleanup_task: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
    max_size: usize,
}

#[derive(Clone)]
struct CacheEntry<V> {
    value: V,
    created_at: Instant,
    last_accessed: Arc<RwLock<Instant>>,
    ttl: Duration,
    version: u64,
}

impl<K, V> CacheManager<K, V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    pub fn new(
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Self {
        let manager = Self {
            entries: Arc::new(DashMap::with_capacity(MAX_CACHE_SIZE)),
            write_locks: Arc::new(DashMap::new()),
            metrics,
            error_handler,
            cleanup_task: Arc::new(Mutex::new(None)),
            max_size: MAX_CACHE_SIZE,
        };
        
        manager.start_cleanup_task();
        manager
    }

    pub async fn get(&self, key: &K) -> Result<V, CacheError> {
        let context = self.create_error_context("get");
        
        if let Some(entry) = self.entries.get(key) {
            // Update last accessed time
            *entry.last_accessed.write().await = Instant::now();
            
            // Check if entry is still valid
            if entry.is_expired() {
                self.remove(key).await?;
                return Err(CacheError::NotFound(format!("{:?}", key)));
            }
            
            self.metrics.record_cache_hit().await;
            Ok(entry.value.clone())
        } else {
            self.metrics.record_cache_miss().await;
            Err(CacheError::NotFound(format!("{:?}", key)))
        }
    }

    pub async fn set(
        &self,
        key: K,
        value: V,
        ttl: Option<Duration>,
    ) -> Result<(), CacheError> {
        let context = self.create_error_context("set");
        
        // Check cache size before acquiring lock
        if self.entries.len() >= self.max_size {
            return Err(CacheError::CapacityExceeded);
        }

        // Get or create write lock for this key
        let lock = self.get_write_lock(&key);
        
        // Acquire lock with timeout
        let _guard = tokio::time::timeout(
            WRITE_LOCK_TIMEOUT,
            lock.lock()
        ).await.map_err(|_| CacheError::LockTimeout)?;

        let entry = CacheEntry {
            value,
            created_at: Instant::now(),
            last_accessed: Arc::new(RwLock::new(Instant::now())),
            ttl: ttl.unwrap_or(DEFAULT_TTL),
            version: 0,
        };

        // Atomic insert
        self.entries.insert(key.clone(), entry);
        self.metrics.record_cache_set().await;
        
        Ok(())
    }

    pub async fn remove(&self, key: &K) -> Result<(), CacheError> {
        let context = self.create_error_context("remove");
        
        let lock = self.get_write_lock(key);
        let _guard = tokio::time::timeout(
            WRITE_LOCK_TIMEOUT,
            lock.lock()
        ).await.map_err(|_| CacheError::LockTimeout)?;

        self.entries.remove(key);
        self.metrics.record_cache_remove().await;
        
        Ok(())
    }

    pub async fn batch_get(
        &self,
        keys: &[K],
    ) -> Result<HashMap<K, V>, CacheError> {
        let context = self.create_error_context("batch_get");
        
        if keys.len() > MAX_BATCH_SIZE {
            return Err(CacheError::InvalidOperation(
                format!("Batch size exceeds maximum: {}", keys.len())
            ));
        }

        let mut results = HashMap::with_capacity(keys.len());
        let mut futures = Vec::with_capacity(keys.len());

        // Create futures for all gets
        for key in keys {
            let key_clone = key.clone();
            futures.push(async move {
                (key_clone.clone(), self.get(&key_clone).await)
            });
        }

        // Execute all gets concurrently
        let results_vec = join_all(futures).await;
        
        // Process results
        for (key, result) in results_vec {
            if let Ok(value) = result {
                results.insert(key, value);
            }
        }

        Ok(results)
    }

    pub async fn batch_set(
        &self,
        entries: HashMap<K, V>,
        ttl: Option<Duration>,
    ) -> Result<(), CacheError> {
        let context = self.create_error_context("batch_set");
        
        if entries.len() > MAX_BATCH_SIZE {
            return Err(CacheError::InvalidOperation(
                format!("Batch size exceeds maximum: {}", entries.len())
            ));
        }

        let mut futures = Vec::with_capacity(entries.len());

        // Create futures for all sets
        for (key, value) in entries {
            futures.push(self.set(key, value, ttl));
        }

        // Execute all sets concurrently
        join_all(futures).await
            .into_iter()
            .collect::<Result<Vec<_>, _>>()?;

        Ok(())
    }

    fn start_cleanup_task(&self) {
        let entries = self.entries.clone();
        let metrics = self.metrics.clone();
        
        let handle = tokio::spawn(async move {
            let mut interval = interval(CLEANUP_INTERVAL);
            
            loop {
                interval.tick().await;
                
                let mut removed_count = 0;
                entries.retain(|_, entry| {
                    if entry.is_expired() {
                        removed_count += 1;
                        false
                    } else {
                        true
                    }
                });
                
                if removed_count > 0 {
                    metrics.record_cache_cleanup(removed_count).await;
                }
            }
        });

        *self.cleanup_task.lock().unwrap() = Some(handle);
    }

    fn get_write_lock(&self, key: &K) -> Arc<Mutex<()>> {
        self.write_locks
            .entry(key.clone())
            .or_insert_with(|| Arc::new(Mutex::new(())))
            .clone()
    }

    fn create_error_context(&self, operation: &str) -> ErrorContext {
        ErrorContext {
            error_id: Uuid::new_v4(),
            component: "cache_manager".to_string(),
            operation: operation.to_string(),
            timestamp: chrono::Utc::now(),
            trace_id: Some(opentelemetry::trace::current_span_context().trace_id().to_string()),
            user_id: None,
        }
    }
}

impl<V> CacheEntry<V> {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() >= self.ttl
    }
}

// Safe cleanup
impl<K, V> Drop for CacheManager<K, V>
where
    K: Clone + Eq + std::hash::Hash + Send + Sync + 'static,
    V: Clone + Send + Sync + 'static,
{
    fn drop(&mut self) {
        if let Some(handle) = self.cleanup_task.lock().unwrap().take() {
            handle.abort();
        }
    }
} 