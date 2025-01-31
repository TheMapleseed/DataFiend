use std::sync::Arc;
use std::path::{Path, PathBuf};
use std::os::unix::fs::PermissionsExt;
use thiserror::Error;
use tokio::fs;
use std::collections::HashSet;
use dashmap::DashMap;
use std::time::{Duration, Instant};

// Permission constants
const MAX_PERMS_REGULAR: u32 = 0o600; // rw-------
const MAX_PERMS_DIRECTORY: u32 = 0o700; // rwx------
const VALIDATION_INTERVAL: Duration = Duration::from_secs(300); // 5 minutes
const MAX_SYMLINK_DEPTH: u32 = 8;
const SECURE_PATHS: &[&str] = &["/etc/chain_rag", "/var/lib/chain_rag"];

#[derive(Debug, Error)]
pub enum PermissionError {
    #[error("Invalid permissions: path={path}, current={current:o}, maximum={maximum:o}")]
    InvalidPermissions {
        path: PathBuf,
        current: u32,
        maximum: u32,
    },
    
    #[error("Invalid owner: path={path}, current={current}, required={required}")]
    InvalidOwner {
        path: PathBuf,
        current: u32,
        required: u32,
    },
    
    #[error("Invalid group: path={path}, current={current}, required={required}")]
    InvalidGroup {
        path: PathBuf,
        current: u32,
        required: u32,
    },
    
    #[error("Symlink depth exceeded: {0}")]
    SymlinkDepthExceeded(PathBuf),
    
    #[error("Path traversal attempt: {0}")]
    PathTraversal(PathBuf),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
}

pub struct ConfigPermissionManager {
    base_paths: HashSet<PathBuf>,
    required_owner: u32,
    required_group: u32,
    validated_paths: Arc<DashMap<PathBuf, Instant>>,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
    validation_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl ConfigPermissionManager {
    pub fn new(
        required_owner: u32,
        required_group: u32,
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Self {
        let mut base_paths = HashSet::new();
        for path in SECURE_PATHS {
            base_paths.insert(PathBuf::from(path));
        }

        let manager = Self {
            base_paths,
            required_owner,
            required_group,
            validated_paths: Arc::new(DashMap::new()),
            metrics,
            error_handler,
            validation_task: Arc::new(tokio::sync::Mutex::new(None)),
        };
        
        manager.start_validation_task();
        manager
    }

    pub async fn validate_path(
        &self,
        path: impl AsRef<Path>,
    ) -> Result<(), PermissionError> {
        let path = path.as_ref();
        
        // Validate path is within allowed base paths
        self.validate_path_security(path)?;
        
        // Resolve and validate symlinks
        let real_path = self.resolve_symlinks(path, 0).await?;
        
        // Validate directory tree permissions
        self.validate_directory_tree(&real_path).await?;
        
        // Record successful validation
        self.validated_paths.insert(real_path.to_path_buf(), Instant::now());
        self.metrics.record_permission_validation_success().await;
        
        Ok(())
    }

    fn validate_path_security(&self, path: &Path) -> Result<(), PermissionError> {
        let canonical = path.canonicalize()?;
        
        // Check if path is within allowed base paths
        if !self.base_paths.iter().any(|base| canonical.starts_with(base)) {
            return Err(PermissionError::PathTraversal(path.to_path_buf()));
        }
        
        // Check for path traversal attempts
        if path.components().any(|c| c.as_os_str() == "..") {
            return Err(PermissionError::PathTraversal(path.to_path_buf()));
        }
        
        Ok(())
    }

    async fn resolve_symlinks(
        &self,
        path: &Path,
        depth: u32,
    ) -> Result<PathBuf, PermissionError> {
        if depth > MAX_SYMLINK_DEPTH {
            return Err(PermissionError::SymlinkDepthExceeded(path.to_path_buf()));
        }

        let metadata = fs::symlink_metadata(path).await?;
        
        if metadata.file_type().is_symlink() {
            let target = fs::read_link(path)?;
            self.resolve_symlinks(&target, depth + 1).await
        } else {
            Ok(path.to_path_buf())
        }
    }

    async fn validate_directory_tree(
        &self,
        path: &Path,
    ) -> Result<(), PermissionError> {
        let mut current = Some(path.to_path_buf());
        
        while let Some(check_path) = current {
            self.validate_single_path(&check_path).await?;
            current = check_path.parent().map(|p| p.to_path_buf());
        }
        
        Ok(())
    }

    async fn validate_single_path(
        &self,
        path: &Path,
    ) -> Result<(), PermissionError> {
        let metadata = fs::metadata(path).await?;
        let permissions = metadata.permissions();
        let mode = permissions.mode();

        // Validate owner
        if metadata.uid() != self.required_owner {
            return Err(PermissionError::InvalidOwner {
                path: path.to_path_buf(),
                current: metadata.uid(),
                required: self.required_owner,
            });
        }

        // Validate group
        if metadata.gid() != self.required_group {
            return Err(PermissionError::InvalidGroup {
                path: path.to_path_buf(),
                current: metadata.gid(),
                required: self.required_group,
            });
        }

        // Validate permissions
        let max_perms = if metadata.is_dir() {
            MAX_PERMS_DIRECTORY
        } else {
            MAX_PERMS_REGULAR
        };

        if mode & !max_perms != 0 {
            return Err(PermissionError::InvalidPermissions {
                path: path.to_path_buf(),
                current: mode,
                maximum: max_perms,
            });
        }

        Ok(())
    }

    fn start_validation_task(&self) {
        let validated_paths = self.validated_paths.clone();
        let metrics = self.metrics.clone();
        let error_handler = self.error_handler.clone();
        let manager = self.clone();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(VALIDATION_INTERVAL);
            
            loop {
                interval.tick().await;
                
                // Revalidate all paths
                let paths: Vec<PathBuf> = validated_paths.iter()
                    .map(|entry| entry.key().clone())
                    .collect();
                
                for path in paths {
                    if let Err(e) = manager.validate_path(&path).await {
                        error_handler.handle_error(
                            e.into(),
                            "permission_validation".to_string(),
                        ).await;
                        metrics.record_permission_validation_failure().await;
                    }
                }
            }
        });

        *self.validation_task.lock().unwrap() = Some(handle);
    }
}

impl Clone for ConfigPermissionManager {
    fn clone(&self) -> Self {
        Self {
            base_paths: self.base_paths.clone(),
            required_owner: self.required_owner,
            required_group: self.required_group,
            validated_paths: self.validated_paths.clone(),
            metrics: self.metrics.clone(),
            error_handler: self.error_handler.clone(),
            validation_task: self.validation_task.clone(),
        }
    }
}

// Safe cleanup
impl Drop for ConfigPermissionManager {
    fn drop(&mut self) {
        if let Some(handle) = self.validation_task.lock().unwrap().take() {
            handle.abort();
        }
    }
} 