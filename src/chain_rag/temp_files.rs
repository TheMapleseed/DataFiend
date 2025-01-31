use std::sync::Arc;
use tokio::sync::RwLock;
use std::path::{Path, PathBuf};
use std::collections::HashMap;
use tokio::fs;
use uuid::Uuid;
use thiserror::Error;
use std::time::{Duration, Instant};
use dashmap::DashMap;

// Constants for temp file management
const MAX_TEMP_FILE_SIZE: u64 = 100 * 1024 * 1024; // 100MB
const MAX_TOTAL_TEMP_SIZE: u64 = 1024 * 1024 * 1024; // 1GB
const TEMP_FILE_TTL: Duration = Duration::from_secs(3600); // 1 hour
const CLEANUP_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes
const MAX_TEMP_FILES: usize = 1000;

#[derive(Debug, Error)]
pub enum TempFileError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("File size exceeds limit: {size} > {limit}")]
    FileTooLarge { size: u64, limit: u64 },
    
    #[error("Total temp size exceeds limit: {size} > {limit}")]
    TotalSizeTooLarge { size: u64, limit: u64 },
    
    #[error("Max temp files exceeded: {count} > {limit}")]
    TooManyFiles { count: usize, limit: usize },
    
    #[error("File not found: {0}")]
    NotFound(PathBuf),
    
    #[error("File expired")]
    Expired,
}

pub struct TempFileManager {
    base_path: PathBuf,
    files: Arc<DashMap<PathBuf, TempFileInfo>>,
    total_size: Arc<std::sync::atomic::AtomicU64>,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
    cleanup_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

#[derive(Clone)]
struct TempFileInfo {
    id: Uuid,
    size: u64,
    created_at: Instant,
    last_accessed: Arc<RwLock<Instant>>,
    path: PathBuf,
}

impl TempFileManager {
    pub async fn new(
        base_path: PathBuf,
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Result<Self, TempFileError> {
        // Ensure base temp directory exists
        fs::create_dir_all(&base_path).await?;
        
        let manager = Self {
            base_path,
            files: Arc::new(DashMap::new()),
            total_size: Arc::new(std::sync::atomic::AtomicU64::new(0)),
            metrics,
            error_handler,
            cleanup_task: Arc::new(tokio::sync::Mutex::new(None)),
        };
        
        manager.start_cleanup_task();
        manager.recover_existing_files().await?;
        
        Ok(manager)
    }

    pub async fn create_temp_file(
        &self,
        prefix: Option<&str>,
        extension: Option<&str>,
    ) -> Result<PathBuf, TempFileError> {
        // Check file count limit
        if self.files.len() >= MAX_TEMP_FILES {
            return Err(TempFileError::TooManyFiles {
                count: self.files.len(),
                limit: MAX_TEMP_FILES,
            });
        }

        let file_id = Uuid::new_v4();
        let filename = format!(
            "{}{}.{}",
            prefix.unwrap_or("temp"),
            file_id,
            extension.unwrap_or("tmp")
        );
        
        let path = self.base_path.join(filename);
        
        // Create empty file
        fs::File::create(&path).await?;
        
        let info = TempFileInfo {
            id: file_id,
            size: 0,
            created_at: Instant::now(),
            last_accessed: Arc::new(RwLock::new(Instant::now())),
            path: path.clone(),
        };
        
        self.files.insert(path.clone(), info);
        self.metrics.record_temp_file_created().await;
        
        Ok(path)
    }

    pub async fn write_temp_file(
        &self,
        path: &Path,
        data: &[u8],
    ) -> Result<(), TempFileError> {
        let size = data.len() as u64;
        
        // Check file size limit
        if size > MAX_TEMP_FILE_SIZE {
            return Err(TempFileError::FileTooLarge {
                size,
                limit: MAX_TEMP_FILE_SIZE,
            });
        }
        
        // Check total size limit
        let new_total = self.total_size.load(std::sync::atomic::Ordering::Relaxed) + size;
        if new_total > MAX_TOTAL_TEMP_SIZE {
            return Err(TempFileError::TotalSizeTooLarge {
                size: new_total,
                limit: MAX_TOTAL_TEMP_SIZE,
            });
        }

        // Update file info
        if let Some(mut info) = self.files.get_mut(path) {
            // Check if file has expired
            if info.is_expired() {
                return Err(TempFileError::Expired);
            }
            
            // Update size and access time
            self.total_size.fetch_add(
                size.saturating_sub(info.size),
                std::sync::atomic::Ordering::Relaxed
            );
            info.size = size;
            *info.last_accessed.write().await = Instant::now();
        } else {
            return Err(TempFileError::NotFound(path.to_owned()));
        }

        // Write file
        fs::write(path, data).await?;
        self.metrics.record_temp_file_write().await;
        
        Ok(())
    }

    pub async fn read_temp_file(&self, path: &Path) -> Result<Vec<u8>, TempFileError> {
        // Update access time
        if let Some(info) = self.files.get(path) {
            // Check if file has expired
            if info.is_expired() {
                return Err(TempFileError::Expired);
            }
            
            *info.last_accessed.write().await = Instant::now();
        } else {
            return Err(TempFileError::NotFound(path.to_owned()));
        }

        let data = fs::read(path).await?;
        self.metrics.record_temp_file_read().await;
        
        Ok(data)
    }

    pub async fn cleanup_temp_file(&self, path: &Path) -> Result<(), TempFileError> {
        if let Some((_, info)) = self.files.remove(path) {
            // Update total size
            self.total_size.fetch_sub(info.size, std::sync::atomic::Ordering::Relaxed);
            
            // Remove file
            if let Err(e) = fs::remove_file(path).await {
                if e.kind() != std::io::ErrorKind::NotFound {
                    return Err(e.into());
                }
            }
            
            self.metrics.record_temp_file_cleaned().await;
        }
        
        Ok(())
    }

    async fn recover_existing_files(&self) -> Result<(), TempFileError> {
        let mut dir = fs::read_dir(&self.base_path).await?;
        
        while let Some(entry) = dir.next_entry().await? {
            let path = entry.path();
            if path.is_file() {
                let metadata = fs::metadata(&path).await?;
                
                let info = TempFileInfo {
                    id: Uuid::new_v4(),
                    size: metadata.len(),
                    created_at: Instant::now(),
                    last_accessed: Arc::new(RwLock::new(Instant::now())),
                    path: path.clone(),
                };
                
                self.files.insert(path, info);
                self.total_size.fetch_add(metadata.len(), std::sync::atomic::Ordering::Relaxed);
            }
        }
        
        Ok(())
    }

    fn start_cleanup_task(&self) {
        let files = self.files.clone();
        let total_size = self.total_size.clone();
        let base_path = self.base_path.clone();
        let metrics = self.metrics.clone();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            
            loop {
                interval.tick().await;
                
                let mut to_remove = Vec::new();
                
                // Identify expired files
                for entry in files.iter() {
                    if entry.is_expired() {
                        to_remove.push(entry.path.clone());
                    }
                }
                
                // Clean up expired files
                for path in to_remove {
                    if let Some((_, info)) = files.remove(&path) {
                        total_size.fetch_sub(info.size, std::sync::atomic::Ordering::Relaxed);
                        
                        let _ = fs::remove_file(&path).await;
                        metrics.record_temp_file_expired().await;
                    }
                }
            }
        });

        *self.cleanup_task.lock().unwrap() = Some(handle);
    }
}

impl TempFileInfo {
    fn is_expired(&self) -> bool {
        self.created_at.elapsed() > TEMP_FILE_TTL
    }
}

// Safe cleanup
impl Drop for TempFileManager {
    fn drop(&mut self) {
        // Stop cleanup task
        if let Some(handle) = self.cleanup_task.lock().unwrap().take() {
            handle.abort();
        }
        
        // Clean up remaining files
        let runtime = tokio::runtime::Runtime::new().unwrap();
        runtime.block_on(async {
            let base_path = self.base_path.clone();
            
            // Remove all tracked files
            for entry in self.files.iter() {
                let _ = fs::remove_file(&entry.path).await;
            }
            
            // Remove base directory if empty
            let _ = fs::remove_dir(&base_path).await;
        });
    }
} 