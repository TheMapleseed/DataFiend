use std::sync::Arc;
use tokio::sync::RwLock;
use std::path::{Path, PathBuf};
use chrono::{DateTime, Utc};
use thiserror::Error;
use zstd::stream::copy_encode;
use std::time::Duration;
use dashmap::DashMap;
use tokio::fs;
use std::collections::BinaryHeap;
use std::cmp::Reverse;

// Log rotation constants
const MAX_LOG_SIZE_BYTES: u64 = 100 * 1024 * 1024; // 100MB
const MAX_LOG_AGE_DAYS: i64 = 90;
const MAX_LOG_FILES: usize = 1000;
const ROTATION_CHECK_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes
const COMPRESSION_LEVEL: i32 = 19; // Maximum ZSTD compression
const MAX_COMPRESSION_THREADS: usize = 4;
const ROTATION_LOCK_TIMEOUT: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum LogRotationError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Compression error: {0}")]
    Compression(String),
    
    #[error("Lock timeout")]
    LockTimeout,
    
    #[error("Max files exceeded")]
    MaxFilesExceeded,
    
    #[error("Invalid path: {0}")]
    InvalidPath(String),
}

pub struct LogRotationManager {
    base_path: PathBuf,
    active_logs: Arc<DashMap<PathBuf, LogFileInfo>>,
    compression_pool: Arc<ThreadPool>,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
    rotation_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

#[derive(Clone)]
struct LogFileInfo {
    path: PathBuf,
    size: u64,
    created_at: DateTime<Utc>,
    last_write: DateTime<Utc>,
    rotation_count: u32,
}

impl LogRotationManager {
    pub async fn new(
        base_path: PathBuf,
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Result<Self, LogRotationError> {
        // Validate and create base directory
        if !base_path.exists() {
            fs::create_dir_all(&base_path).await?;
        }

        let manager = Self {
            base_path,
            active_logs: Arc::new(DashMap::new()),
            compression_pool: Arc::new(ThreadPool::new(MAX_COMPRESSION_THREADS)),
            metrics,
            error_handler,
            rotation_task: Arc::new(tokio::sync::Mutex::new(None)),
        };
        
        manager.start_rotation_task();
        manager.recover_existing_logs().await?;
        
        Ok(manager)
    }

    pub async fn register_log_file(
        &self,
        path: PathBuf,
    ) -> Result<(), LogRotationError> {
        // Validate path
        if !path.starts_with(&self.base_path) {
            return Err(LogRotationError::InvalidPath(
                "Log file must be within base directory".to_string()
            ));
        }

        let metadata = fs::metadata(&path).await?;
        
        let info = LogFileInfo {
            path: path.clone(),
            size: metadata.len(),
            created_at: chrono::DateTime::from(metadata.created()?),
            last_write: chrono::DateTime::from(metadata.modified()?),
            rotation_count: 0,
        };

        self.active_logs.insert(path, info);
        self.metrics.record_log_file_registered().await;
        
        Ok(())
    }

    pub async fn update_file_size(
        &self,
        path: &Path,
        additional_bytes: u64,
    ) -> Result<bool, LogRotationError> {
        let mut needs_rotation = false;
        
        if let Some(mut entry) = self.active_logs.get_mut(path) {
            entry.size += additional_bytes;
            entry.last_write = Utc::now();
            
            needs_rotation = entry.size >= MAX_LOG_SIZE_BYTES;
        }
        
        Ok(needs_rotation)
    }

    pub async fn rotate_log(
        &self,
        path: &Path,
    ) -> Result<(), LogRotationError> {
        let lock = tokio::sync::Mutex::new(());
        let _guard = lock.try_lock_for(ROTATION_LOCK_TIMEOUT)
            .map_err(|_| LogRotationError::LockTimeout)?;

        if let Some(mut info) = self.active_logs.get_mut(path) {
            // Generate rotation path
            let timestamp = chrono::Local::now().format("%Y%m%d_%H%M%S");
            let rotated_path = path.with_extension(
                format!("{}.{}.log", timestamp, info.rotation_count)
            );
            
            // Rotate the file
            fs::rename(path, &rotated_path).await?;
            
            // Create new empty log file
            fs::File::create(path).await?;
            
            // Update info
            info.size = 0;
            info.rotation_count += 1;
            info.last_write = Utc::now();
            
            // Compress in background
            self.compress_rotated_log(rotated_path);
            
            self.metrics.record_log_rotation().await;
        }
        
        Ok(())
    }

    fn compress_rotated_log(&self, path: PathBuf) {
        let compressed_path = path.with_extension("log.zst");
        let metrics = self.metrics.clone();
        let error_handler = self.error_handler.clone();
        
        self.compression_pool.spawn(move || {
            let result = || -> Result<(), LogRotationError> {
                let input = std::fs::File::open(&path)?;
                let output = std::fs::File::create(&compressed_path)?;
                
                copy_encode(
                    input,
                    output,
                    COMPRESSION_LEVEL,
                ).map_err(|e| LogRotationError::Compression(e.to_string()))?;
                
                // Remove original file after successful compression
                std::fs::remove_file(&path)?;
                
                Ok(())
            }();

            if let Err(e) = result {
                error_handler.handle_error(
                    e.into(),
                    "log_compression".to_string(),
                );
            } else {
                metrics.record_log_compressed();
            }
        });
    }

    async fn cleanup_old_logs(&self) -> Result<(), LogRotationError> {
        let mut files_to_remove = BinaryHeap::new();
        let cutoff = Utc::now() - chrono::Duration::days(MAX_LOG_AGE_DAYS);
        
        // Collect files for potential removal
        for entry in fs::read_dir(&self.base_path).await? {
            let entry = entry?;
            let metadata = entry.metadata().await?;
            
            if metadata.is_file() {
                let modified = chrono::DateTime::from(metadata.modified()?);
                
                if modified < cutoff {
                    files_to_remove.push(Reverse((modified, entry.path())));
                }
            }
        }

        // Remove oldest files if we exceed MAX_LOG_FILES
        while self.active_logs.len() + files_to_remove.len() > MAX_LOG_FILES {
            if let Some(Reverse((_, path))) = files_to_remove.pop() {
                fs::remove_file(path).await?;
                self.metrics.record_log_removed().await;
            }
        }

        // Remove files beyond retention period
        while let Some(Reverse((modified, path))) = files_to_remove.pop() {
            if modified < cutoff {
                fs::remove_file(path).await?;
                self.metrics.record_log_removed().await;
            }
        }

        Ok(())
    }

    async fn recover_existing_logs(&self) -> Result<(), LogRotationError> {
        let mut entries = fs::read_dir(&self.base_path).await?;
        
        while let Some(entry) = entries.next_entry().await? {
            let path = entry.path();
            if path.extension().and_then(|s| s.to_str()) == Some("log") {
                self.register_log_file(path).await?;
            }
        }
        
        Ok(())
    }

    fn start_rotation_task(&self) {
        let active_logs = self.active_logs.clone();
        let metrics = self.metrics.clone();
        let error_handler = self.error_handler.clone();
        let manager = self.clone();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(ROTATION_CHECK_INTERVAL);
            
            loop {
                interval.tick().await;
                
                // Check all active logs
                for entry in active_logs.iter() {
                    let path = entry.path();
                    let info = entry.value();
                    
                    // Check size and age
                    if info.size >= MAX_LOG_SIZE_BYTES {
                        if let Err(e) = manager.rotate_log(path).await {
                            error_handler.handle_error(
                                e.into(),
                                "log_rotation".to_string(),
                            ).await;
                        }
                    }
                }
                
                // Cleanup old logs
                if let Err(e) = manager.cleanup_old_logs().await {
                    error_handler.handle_error(
                        e.into(),
                        "log_cleanup".to_string(),
                    ).await;
                }
                
                metrics.record_rotation_check().await;
            }
        });

        *self.rotation_task.lock().unwrap() = Some(handle);
    }
}

impl Clone for LogRotationManager {
    fn clone(&self) -> Self {
        Self {
            base_path: self.base_path.clone(),
            active_logs: self.active_logs.clone(),
            compression_pool: self.compression_pool.clone(),
            metrics: self.metrics.clone(),
            error_handler: self.error_handler.clone(),
            rotation_task: self.rotation_task.clone(),
        }
    }
}

// Safe cleanup
impl Drop for LogRotationManager {
    fn drop(&mut self) {
        if let Some(handle) = self.rotation_task.lock().unwrap().take() {
            handle.abort();
        }
    }
} 