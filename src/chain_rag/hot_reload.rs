use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use notify::{Watcher, RecursiveMode, Event};
use sha2::{Sha256, Digest};
use thiserror::Error;
use std::time::{Duration, Instant};
use dashmap::DashMap;
use tokio::fs;
use async_trait::async_trait;

// Constants for hot reload management
const MIN_RELOAD_INTERVAL: Duration = Duration::from_secs(1);
const MAX_RETRIES: u32 = 3;
const LOCK_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_RELOAD_ATTEMPTS: usize = 3;
const COOLDOWN_PERIOD: Duration = Duration::from_secs(60);
const MAX_FILE_SIZE: u64 = 10 * 1024 * 1024; // 10MB
const HASH_CACHE_TTL: Duration = Duration::from_secs(300);
const RELOAD_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum HotReloadError {
    #[error("File access error: {0}")]
    FileAccess(#[from] std::io::Error),
    
    #[error("File watch error: {0}")]
    FileWatch(String),
    
    #[error("Reload failed: {0}")]
    ReloadFailed(String),
    
    #[error("Lock timeout")]
    LockTimeout,
    
    #[error("Invalid state: {0}")]
    InvalidState(String),
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Invalid file: {0}")]
    InvalidFile(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Watch error: {0}")]
    Watch(#[from] notify::Error),
    
    #[error("Validation error: {0}")]
    Validation(String),
}

#[derive(Debug, Clone)]
struct FileState {
    path: PathBuf,
    hash: String,
    last_modified: std::time::SystemTime,
    permissions: u32,
    reload_count: usize,
    last_reload: Instant,
    validated: bool,
}

pub struct HotReloadManager {
    configs: Arc<RwLock<HashMap<PathBuf, ConfigState>>>,
    file_hashes: Arc<RwLock<HashMap<PathBuf, Vec<u8>>>>,
    watcher: Arc<Mutex<notify::RecommendedWatcher>>,
    error_handler: Arc<ErrorHandler>,
    metrics: Arc<MetricsStore>,
    reload_locks: Arc<DashMap<PathBuf, Arc<tokio::sync::Mutex<()>>>>,
    watched_files: Arc<DashMap<PathBuf, FileState>>,
    file_validators: Arc<DashMap<String, Box<dyn FileValidator + Send + Sync>>>,
    reload_handlers: Arc<DashMap<String, Box<dyn ReloadHandler + Send + Sync>>>,
    permission_checker: Arc<PermissionChecker>,
    hash_cache: Arc<DashMap<PathBuf, (String, Instant)>>,
}

#[derive(Clone)]
struct ConfigState {
    content: Vec<u8>,
    last_modified: std::time::SystemTime,
    last_reload: Instant,
    version: u64,
}

#[async_trait::async_trait]
pub trait FileValidator: Send + Sync {
    async fn validate(&self, path: &Path, content: &[u8]) -> Result<(), HotReloadError>;
}

#[async_trait::async_trait]
pub trait ReloadHandler: Send + Sync {
    async fn handle_reload(&self, path: &Path, content: &[u8]) -> Result<(), HotReloadError>;
}

impl HotReloadManager {
    pub async fn new(
        error_handler: Arc<ErrorHandler>,
        metrics: Arc<MetricsStore>,
        permission_checker: Arc<PermissionChecker>,
    ) -> Result<Self, HotReloadError> {
        let (tx, rx) = std::sync::mpsc::channel();
        
        let watcher = notify::recommended_watcher(move |res| {
            if let Ok(event) = res {
                let _ = tx.send(event);
            }
        })?;

        let manager = Self {
            configs: Arc::new(RwLock::new(HashMap::new())),
            file_hashes: Arc::new(RwLock::new(HashMap::new())),
            watcher: Arc::new(Mutex::new(watcher)),
            error_handler,
            metrics,
            reload_locks: Arc::new(DashMap::new()),
            watched_files: Arc::new(DashMap::new()),
            file_validators: Arc::new(DashMap::new()),
            reload_handlers: Arc::new(DashMap::new()),
            permission_checker,
            hash_cache: Arc::new(DashMap::new()),
        };

        manager.start_watch_handler(rx);
        Ok(manager)
    }

    pub async fn register_config<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<(), HotReloadError> {
        let path = path.as_ref().to_owned();
        let context = self.create_error_context("register_config");

        // Acquire exclusive lock for registration
        let lock = self.get_or_create_lock(&path);
        let _guard = lock.lock().await;

        // Verify file exists and calculate initial hash
        let metadata = tokio::fs::metadata(&path).await?;
        let content = tokio::fs::read(&path).await?;
        let hash = self.calculate_hash(&content);

        // Update state atomically
        {
            let mut configs = self.configs.write().await;
            let mut hashes = self.file_hashes.write().await;
            
            configs.insert(path.clone(), ConfigState {
                content,
                last_modified: metadata.modified()?,
                last_reload: Instant::now(),
                version: 0,
            });
            
            hashes.insert(path.clone(), hash);
        }

        // Start watching file
        self.watcher
            .lock()
            .await
            .watch(&path, RecursiveMode::NonRecursive)
            .map_err(|e| HotReloadError::FileWatch(e.to_string()))?;

        self.metrics.record_config_registration(&path).await;
        Ok(())
    }

    pub async fn get_config<P: AsRef<Path>>(
        &self,
        path: P,
    ) -> Result<Vec<u8>, HotReloadError> {
        let path = path.as_ref();
        let context = self.create_error_context("get_config");

        // Use read lock for concurrent access
        let configs = self.configs.read().await;
        if let Some(state) = configs.get(path) {
            Ok(state.content.clone())
        } else {
            Err(HotReloadError::InvalidState(format!(
                "Config not registered: {:?}",
                path
            )))
        }
    }

    async fn handle_file_change(
        &self,
        path: PathBuf,
        event_type: notify::EventKind,
    ) -> Result<(), HotReloadError> {
        let context = self.create_error_context("handle_file_change");

        // Acquire exclusive lock with timeout
        let lock = self.get_or_create_lock(&path);
        let guard = tokio::time::timeout(
            LOCK_TIMEOUT,
            lock.lock()
        ).await.map_err(|_| HotReloadError::LockTimeout)?;

        // Verify file still exists and read new content
        let content = match tokio::fs::read(&path).await {
            Ok(content) => content,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                // Handle file deletion
                self.handle_config_removal(&path).await?;
                return Ok(());
            }
            Err(e) => return Err(e.into()),
        };

        // Calculate and verify hash
        let new_hash = self.calculate_hash(&content);
        let should_reload = {
            let hashes = self.file_hashes.read().await;
            !hashes.get(&path).map_or(true, |old_hash| old_hash == &new_hash)
        };

        if should_reload {
            self.reload_config(&path, content, new_hash).await?;
        }

        Ok(())
    }

    async fn reload_config(
        &self,
        path: &Path,
        content: Vec<u8>,
        new_hash: Vec<u8>,
    ) -> Result<(), HotReloadError> {
        let mut retry_count = 0;
        let mut last_error = None;

        while retry_count < MAX_RETRIES {
            match self.try_reload_config(path, content.clone(), new_hash.clone()).await {
                Ok(()) => {
                    self.metrics.record_config_reload_success(path).await;
                    return Ok(());
                }
                Err(e) => {
                    retry_count += 1;
                    last_error = Some(e);
                    tokio::time::sleep(Duration::from_millis(100 * retry_count)).await;
                }
            }
        }

        let error = last_error.unwrap_or_else(|| {
            HotReloadError::ReloadFailed("Maximum retries exceeded".to_string())
        });
        
        self.metrics.record_config_reload_failure(path).await;
        Err(error)
    }

    async fn try_reload_config(
        &self,
        path: &Path,
        content: Vec<u8>,
        new_hash: Vec<u8>,
    ) -> Result<(), HotReloadError> {
        let now = Instant::now();
        
        // Update state atomically
        {
            let mut configs = self.configs.write().await;
            let mut hashes = self.file_hashes.write().await;
            
            if let Some(state) = configs.get_mut(path) {
                if now.duration_since(state.last_reload) < MIN_RELOAD_INTERVAL {
                    return Ok(());
                }
                
                state.content = content;
                state.last_reload = now;
                state.version += 1;
                
                hashes.insert(path.to_owned(), new_hash);
            }
        }

        Ok(())
    }

    async fn handle_config_removal(
        &self,
        path: &Path,
    ) -> Result<(), HotReloadError> {
        let mut configs = self.configs.write().await;
        let mut hashes = self.file_hashes.write().await;
        
        configs.remove(path);
        hashes.remove(path);
        
        self.metrics.record_config_removal(path).await;
        Ok(())
    }

    fn calculate_hash(&self, content: &[u8]) -> Vec<u8> {
        let mut hasher = Sha256::new();
        hasher.update(content);
        hasher.finalize().to_vec()
    }

    fn get_or_create_lock(&self, path: &Path) -> Arc<tokio::sync::Mutex<()>> {
        self.reload_locks
            .entry(path.to_owned())
            .or_insert_with(|| Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    fn create_error_context(&self, operation: &str) -> ErrorContext {
        ErrorContext {
            error_id: Uuid::new_v4(),
            component: "hot_reload_manager".to_string(),
            operation: operation.to_string(),
            timestamp: chrono::Utc::now(),
            trace_id: Some(opentelemetry::trace::current_span_context().trace_id().to_string()),
            user_id: None,
        }
    }

    pub async fn watch_file(
        &self,
        path: PathBuf,
        file_type: String,
        validator: Box<dyn FileValidator + Send + Sync>,
        handler: Box<dyn ReloadHandler + Send + Sync>,
    ) -> Result<(), HotReloadError> {
        // Validate initial file state
        self.validate_file(&path).await?;

        // Check permissions
        self.permission_checker.check_file_permissions(&path).await?;

        // Calculate initial hash
        let hash = self.calculate_file_hash(&path).await?;

        let state = FileState {
            path: path.clone(),
            hash,
            last_modified: fs::metadata(&path).await?.modified()?,
            permissions: fs::metadata(&path).await?.permissions().mode(),
            reload_count: 0,
            last_reload: Instant::now(),
            validated: true,
        };

        self.watched_files.insert(path.clone(), state);
        self.file_validators.insert(file_type.clone(), validator);
        self.reload_handlers.insert(file_type, handler);

        // Start watching file
        self.watcher
            .lock()
            .await
            .watch(&path, RecursiveMode::NonRecursive)?;
        
        self.metrics.record_file_watched().await;
        Ok(())
    }

    async fn validate_file(&self, path: &Path) -> Result<(), HotReloadError> {
        // Check file size
        let metadata = fs::metadata(path).await?;
        if metadata.len() > MAX_FILE_SIZE {
            return Err(HotReloadError::InvalidFile(
                "File exceeds maximum size".to_string()
            ));
        }

        // Validate file permissions
        let permissions = metadata.permissions();
        if permissions.mode() & 0o777 != 0o600 {
            return Err(HotReloadError::PermissionDenied(
                "Invalid file permissions".to_string()
            ));
        }

        // Validate file owner
        if !self.permission_checker.validate_file_owner(path).await? {
            return Err(HotReloadError::PermissionDenied(
                "Invalid file owner".to_string()
            ));
        }

        Ok(())
    }

    async fn calculate_file_hash(&self, path: &Path) -> Result<String, HotReloadError> {
        // Check cache first
        if let Some((hash, timestamp)) = self.hash_cache.get(path) {
            if timestamp.elapsed() < HASH_CACHE_TTL {
                return Ok(hash.clone());
            }
        }

        let content = fs::read(path).await?;
        let mut hasher = Sha256::new();
        hasher.update(&content);
        let hash = format!("{:x}", hasher.finalize());

        // Update cache
        self.hash_cache.insert(
            path.to_path_buf(),
            (hash.clone(), Instant::now()),
        );

        Ok(hash)
    }

    pub async fn handle_file_change(
        &self,
        path: &Path,
    ) -> Result<(), HotReloadError> {
        let mut state = self.watched_files.get_mut(path)
            .ok_or_else(|| HotReloadError::InvalidFile(
                "File not watched".to_string()
            ))?;

        // Check cooldown period
        if state.last_reload.elapsed() < COOLDOWN_PERIOD {
            return Err(HotReloadError::ReloadFailed(
                "Cooldown period not elapsed".to_string()
            ));
        }

        // Check reload attempts
        if state.reload_count >= MAX_RELOAD_ATTEMPTS {
            return Err(HotReloadError::ReloadFailed(
                "Maximum reload attempts exceeded".to_string()
            ));
        }

        // Validate file state
        self.validate_file(path).await?;

        // Calculate new hash
        let new_hash = self.calculate_file_hash(path).await?;
        if new_hash == state.hash {
            return Ok(());
        }

        // Read file content
        let content = fs::read(path).await?;

        // Validate content
        let file_type = path.extension()
            .and_then(|ext| ext.to_str())
            .ok_or_else(|| HotReloadError::InvalidFile("Invalid file type".to_string()))?;

        if let Some(validator) = self.file_validators.get(file_type) {
            validator.validate(path, &content).await?;
        }

        // Handle reload
        if let Some(handler) = self.reload_handlers.get(file_type) {
            handler.handle_reload(path, &content).await?;
        }

        // Update state
        state.hash = new_hash;
        state.last_modified = fs::metadata(path).await?.modified()?;
        state.reload_count += 1;
        state.last_reload = Instant::now();

        self.metrics.record_file_reloaded().await;
        Ok(())
    }

    pub async fn cleanup_cache(&self) {
        let now = Instant::now();
        self.hash_cache.retain(|_, (_, timestamp)| {
            timestamp.elapsed() < HASH_CACHE_TTL
        });
    }
}

// Safe cleanup
impl Drop for HotReloadManager {
    fn drop(&mut self) {
        // Stop file watcher and clean up resources
        if let Ok(mut watcher) = self.watcher.try_lock() {
            let _ = watcher.unwatch(Path::new("."));
        }
    }
} 