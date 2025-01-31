use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use futures::future::{self, Future};
use tracing::{error, warn, info, debug};
use anyhow::{Context, Result};
use dashmap::DashMap;
use std::time::{SystemTime, Duration};
use std::net::IpAddr;
use uuid::Uuid;
use chrono::{DateTime, Utc};

// Fixed Key Rotation
pub struct EnhancedKeyRotator {
    current_key: Arc<RwLock<RotatingKey>>,
    entropy_pool: Arc<EntropyPool>,
    system_lock: Arc<tokio::sync::Mutex<()>>,
    metrics: Arc<MetricsStore>,
}

impl EnhancedKeyRotator {
    pub async fn rotate_key(&self) -> Result<()> {
        let _lock = self.system_lock.lock().await;
        
        let entropy = self.entropy_pool.get_mixed_entropy().await?;
        let new_key = self.generate_key_with_entropy(&entropy).await?;
        
        {
            let mut current = self.current_key.write().await;
            *current = new_key;
            
            // Record metrics atomically
            self.metrics.record_key_rotation(&new_key.metadata).await?;
        }
        
        debug!("Key rotation completed with new generation: {}", new_key.generation);
        Ok(())
    }

    async fn generate_key_with_entropy(&self, entropy: &[u8]) -> Result<RotatingKey> {
        let mut rng = thread_rng();
        let mut hasher = blake3::Hasher::new();
        
        // Mix multiple entropy sources
        hasher.update(entropy);
        hasher.update(&rng.gen::<[u8; 32]>());
        hasher.update(&SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
            .to_le_bytes());
            
        let key_bytes = hasher.finalize().as_bytes();
        
        Ok(RotatingKey {
            key: Key::from_slice(key_bytes),
            generation: rng.gen(),
            metadata: KeyMetadata::new(entropy),
        })
    }
}

// Fixed Metrics Store
pub struct EnhancedMetricsStore {
    events: Arc<RwLock<VecDeque<MetricEvent>>>,
    collectors: Vec<Arc<dyn MetricCollector>>,
    pruning_lock: Arc<Mutex<()>>,
}

impl EnhancedMetricsStore {
    pub async fn record_event(&self, event: MetricEvent) -> Result<()> {
        let _lock = self.pruning_lock.lock().await;
        
        let mut events = self.events.write().await;
        events.push_back(event);
        
        // Efficient pruning
        if events.len() > MAX_EVENTS {
            let to_remove = events.len() - MAX_EVENTS;
            events.drain(0..to_remove);
        }
        
        Ok(())
    }

    pub async fn collect_metrics(&self) -> Result<()> {
        // Parallel collection with timeout
        let collectors: Vec<_> = self.collectors.iter()
            .map(|c| {
                tokio::time::timeout(
                    Duration::from_secs(5),
                    c.collect()
                )
            })
            .collect();
            
        let results = future::join_all(collectors).await;
        
        // Process results and handle timeouts
        for (idx, result) in results.into_iter().enumerate() {
            match result {
                Ok(Ok(_)) => debug!("Collector {} succeeded", idx),
                Ok(Err(e)) => warn!("Collector {} failed: {}", idx, e),
                Err(_) => error!("Collector {} timed out", idx),
            }
        }
        
        Ok(())
    }
}

// Fixed Hot Reload
pub struct EnhancedHotReloadManager {
    vm: Arc<RwLock<UnifiedVMSystem>>,
    coordinator: Arc<RwLock<UnifiedCoordinator>>,
    system_lock: Arc<tokio::sync::Mutex<()>>,
    state_validator: Arc<StateValidator>,
}

impl EnhancedHotReloadManager {
    pub async fn hot_swap_component<T: Component>(&self, component: T, state: ComponentState) -> Result<()> {
        // Acquire system-wide lock
        let _lock = self.system_lock.lock().await;
        
        // Validate state before swap
        self.state_validator.validate(&state).await?;
        
        // Perform atomic swap
        {
            let mut vm = self.vm.write().await;
            let mut coordinator = self.coordinator.write().await;
            
            vm.swap_component(component, state.clone()).await
                .context("Failed to swap component")?;
                
            coordinator.update_references(&vm)
                .context("Failed to update coordinator references")?;
        }
        
        // Verify system integrity
        self.verify_system_state().await
            .context("System state verification failed after hot swap")?;
            
        Ok(())
    }
}

// Fixed Resource Management
pub struct EnhancedDeployment {
    config: DeployConfig,
    resource_manager: Arc<ResourceManager>,
}

impl EnhancedDeployment {
    pub async fn transfer_files(&self, sess: &Session) -> Result<()> {
        for file in &self.config.files {
            let mut remote_file = sess.scp_send(
                &file.remote_path,
                file.permissions,
                file.size,
                None
            )?;
            
            // Use resource manager to handle file transfer
            self.resource_manager.transfer_file(&mut remote_file, &file.local_path).await?;
            
            // Ensure proper cleanup
            remote_file.send_eof()?;
            remote_file.wait_eof()?;
            remote_file.close()?;
            remote_file.wait_close()?;
        }
        
        Ok(())
    }
}

// Resource Manager
pub struct ResourceManager {
    active_transfers: Arc<RwLock<HashMap<String, TransferState>>>,
    cleanup_scheduler: Arc<CleanupScheduler>,
}

impl ResourceManager {
    pub async fn transfer_file<W: Write>(&self, writer: &mut W, path: &Path) -> Result<()> {
        let transfer = TransferState::new(path);
        self.active_transfers.write().await.insert(path.to_string_lossy().into_owned(), transfer);
        
        let result = tokio::fs::read(path).await?;
        writer.write_all(&result)?;
        
        // Schedule cleanup
        self.cleanup_scheduler.schedule(path.to_string_lossy().into_owned());
        
        Ok(())
    }
}

// Enhanced Error Handling
pub struct ErrorContext {
    component: ComponentId,
    operation: OperationType,
    timestamp: SystemTime,
    state: SystemState,
}

impl std::error::Error for SystemError {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        self.source.as_ref().map(|e| &**e)
    }
}

impl SystemError {
    pub fn with_context(self, context: ErrorContext) -> Self {
        Self {
            context: Some(context),
            ..self
        }
    }
}

// Rate limiting configuration
const MAX_ATTEMPTS: u32 = 5;
const WINDOW_SECS: u64 = 300; // 5 minutes
const LOCKOUT_DURATION: u64 = 1800; // 30 minutes
const IP_BURST_LIMIT: u32 = 20;
const IP_BURST_WINDOW: u64 = 60; // 1 minute

pub struct RateLimiter {
    attempts: DashMap<String, Vec<SystemTime>>,
    lockouts: DashMap<String, SystemTime>,
    ip_attempts: DashMap<IpAddr, Vec<SystemTime>>,
    metrics: Arc<MetricsStore>,
}

impl RateLimiter {
    pub fn new(metrics: Arc<MetricsStore>) -> Self {
        Self {
            attempts: DashMap::new(),
            lockouts: DashMap::new(),
            ip_attempts: DashMap::new(),
            metrics,
        }
    }

    pub async fn check_rate_limit(&self, user_id: &str, ip: IpAddr) -> Result<(), AuthError> {
        // Check IP burst limit first
        self.check_ip_burst(ip).await?;
        
        // Check if user is locked out
        if let Some(lockout_time) = self.lockouts.get(user_id) {
            let elapsed = SystemTime::now()
                .duration_since(*lockout_time)
                .unwrap_or(Duration::from_secs(0));
                
            if elapsed.as_secs() < LOCKOUT_DURATION {
                self.metrics.record_lockout_rejection(user_id).await;
                return Err(AuthError::AccountLocked {
                    remaining: LOCKOUT_DURATION - elapsed.as_secs(),
                });
            }
            
            // Lockout expired, remove it
            self.lockouts.remove(user_id);
        }

        // Check attempt history
        let now = SystemTime::now();
        let mut attempts = self.attempts
            .entry(user_id.to_string())
            .or_insert_with(Vec::new);

        // Remove old attempts outside window
        attempts.retain(|time| {
            now.duration_since(*time)
                .unwrap_or(Duration::from_secs(0))
                .as_secs() < WINDOW_SECS
        });

        // Check if too many attempts
        if attempts.len() >= MAX_ATTEMPTS as usize {
            // Lock the account
            self.lockouts.insert(user_id.to_string(), now);
            self.metrics.record_account_lockout(user_id).await;
            
            return Err(AuthError::TooManyAttempts {
                wait_time: LOCKOUT_DURATION,
            });
        }

        Ok(())
    }

    async fn check_ip_burst(&self, ip: IpAddr) -> Result<(), AuthError> {
        let now = SystemTime::now();
        let mut attempts = self.ip_attempts
            .entry(ip)
            .or_insert_with(Vec::new);

        // Remove old attempts
        attempts.retain(|time| {
            now.duration_since(*time)
                .unwrap_or(Duration::from_secs(0))
                .as_secs() < IP_BURST_WINDOW
        });

        if attempts.len() >= IP_BURST_LIMIT as usize {
            self.metrics.record_ip_burst_limit(ip).await;
            return Err(AuthError::IpRateLimited {
                ip,
                wait_time: IP_BURST_WINDOW,
            });
        }

        attempts.push(now);
        Ok(())
    }

    pub async fn record_attempt(&self, user_id: &str, ip: IpAddr) {
        let now = SystemTime::now();
        
        // Record user attempt
        self.attempts
            .entry(user_id.to_string())
            .or_insert_with(Vec::new)
            .push(now);
            
        // Record IP attempt
        self.ip_attempts
            .entry(ip)
            .or_insert_with(Vec::new)
            .push(now);
    }

    pub async fn record_success(&self, user_id: &str) {
        // Clear attempt history on success
        self.attempts.remove(user_id);
        self.lockouts.remove(user_id);
    }
}

// Integration with authentication system
impl AuthenticationManager {
    pub async fn authenticate(&self, credentials: &Credentials, ip: IpAddr) -> Result<AuthToken> {
        // Check rate limits first
        self.rate_limiter.check_rate_limit(&credentials.user_id, ip).await?;
        
        // Record the attempt
        self.rate_limiter.record_attempt(&credentials.user_id, ip).await;
        
        // Perform actual authentication
        match self.verify_credentials(credentials).await {
            Ok(token) => {
                // Record successful attempt
                self.rate_limiter.record_success(&credentials.user_id).await;
                Ok(token)
            }
            Err(e) => {
                // Let rate limiter track failed attempt
                Err(e)
            }
        }
    }
}

// Error types
#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("Account is locked for {remaining} seconds")]
    AccountLocked { remaining: u64 },
    
    #[error("Too many attempts, try again in {wait_time} seconds")]
    TooManyAttempts { wait_time: u64 },
    
    #[error("IP {ip} is rate limited, try again in {wait_time} seconds")]
    IpRateLimited { ip: IpAddr, wait_time: u64 },
}

// Security constants
const SESSION_TIMEOUT: u64 = 3600; // 1 hour
const EXTENDED_SESSION_TIMEOUT: u64 = 86400; // 24 hours
const INACTIVE_TIMEOUT: u64 = 900; // 15 minutes
const MAX_SESSIONS_PER_USER: usize = 5;
const SESSION_CLEANUP_INTERVAL: u64 = 300; // 5 minutes

#[derive(Debug, Clone)]
pub struct Session {
    id: Uuid,
    user_id: String,
    created_at: DateTime<Utc>,
    last_activity: Arc<RwLock<DateTime<Utc>>>,
    expires_at: DateTime<Utc>,
    ip_address: std::net::IpAddr,
    device_info: DeviceInfo,
    permissions: Vec<String>,
    is_extended: bool,
}

#[derive(Debug, Clone)]
struct DeviceInfo {
    device_id: String,
    user_agent: String,
    fingerprint: String,
}

pub struct SessionManager {
    sessions: DashMap<Uuid, Session>,
    user_sessions: DashMap<String, Vec<Uuid>>,
    metrics: Arc<MetricsStore>,
    cleanup_handle: Arc<Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl SessionManager {
    pub fn new(metrics: Arc<MetricsStore>) -> Self {
        let manager = Self {
            sessions: DashMap::new(),
            user_sessions: DashMap::new(),
            metrics,
            cleanup_handle: Arc::new(Mutex::new(None)),
        };
        
        manager.start_cleanup_task();
        manager
    }

    pub async fn create_session(
        &self,
        user_id: &str,
        ip: std::net::IpAddr,
        device_info: DeviceInfo,
        permissions: Vec<String>,
    ) -> Result<Session, AuthError> {
        // Check existing sessions for user
        self.enforce_session_limits(user_id).await?;
        
        let now = Utc::now();
        let session = Session {
            id: Uuid::new_v4(),
            user_id: user_id.to_string(),
            created_at: now,
            last_activity: Arc::new(RwLock::new(now)),
            expires_at: now + chrono::Duration::seconds(SESSION_TIMEOUT as i64),
            ip_address: ip,
            device_info,
            permissions,
            is_extended: false,
        };

        // Store session
        self.sessions.insert(session.id, session.clone());
        
        // Update user sessions
        self.user_sessions
            .entry(user_id.to_string())
            .or_default()
            .push(session.id);
            
        // Record metrics
        self.metrics.record_session_created(&session).await;
        
        Ok(session)
    }

    pub async fn validate_session(&self, session_id: Uuid) -> Result<Session, AuthError> {
        let session = self.sessions
            .get(&session_id)
            .ok_or(AuthError::InvalidSession)?
            .clone();
            
        // Check expiration
        if Utc::now() > session.expires_at {
            self.terminate_session(session_id).await?;
            return Err(AuthError::SessionExpired);
        }

        // Check inactivity
        let last_activity = *session.last_activity.read().await;
        let inactive_duration = Utc::now() - last_activity;
        
        if inactive_duration > chrono::Duration::seconds(INACTIVE_TIMEOUT as i64) {
            self.terminate_session(session_id).await?;
            return Err(AuthError::SessionInactive);
        }

        // Update last activity
        *session.last_activity.write().await = Utc::now();
        
        Ok(session)
    }

    pub async fn extend_session(&self, session_id: Uuid) -> Result<(), AuthError> {
        let mut session = self.sessions
            .get_mut(&session_id)
            .ok_or(AuthError::InvalidSession)?;
            
        if !session.is_extended {
            session.expires_at = Utc::now() + 
                chrono::Duration::seconds(EXTENDED_SESSION_TIMEOUT as i64);
            session.is_extended = true;
            
            // Record extension
            self.metrics.record_session_extended(&session).await;
        }
        
        Ok(())
    }

    pub async fn terminate_session(&self, session_id: Uuid) -> Result<(), AuthError> {
        if let Some(session) = self.sessions.remove(&session_id) {
            // Remove from user sessions
            if let Some(mut user_sessions) = self.user_sessions.get_mut(&session.1.user_id) {
                user_sessions.retain(|&id| id != session_id);
            }
            
            // Record termination
            self.metrics.record_session_terminated(&session.1).await;
        }
        
        Ok(())
    }

    async fn enforce_session_limits(&self, user_id: &str) -> Result<(), AuthError> {
        if let Some(sessions) = self.user_sessions.get(user_id) {
            if sessions.len() >= MAX_SESSIONS_PER_USER {
                return Err(AuthError::TooManySessions);
            }
        }
        Ok(())
    }

    fn start_cleanup_task(&self) {
        let sessions = self.sessions.clone();
        let user_sessions = self.user_sessions.clone();
        let metrics = self.metrics.clone();

        let handle = tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(SESSION_CLEANUP_INTERVAL)).await;
                
                let now = Utc::now();
                let mut expired_count = 0;
                
                // Clean expired sessions
                sessions.retain(|_, session| {
                    let valid = now <= session.expires_at;
                    if !valid {
                        expired_count += 1;
                        // Clean user sessions
                        if let Some(mut user_sessions) = user_sessions.get_mut(&session.user_id) {
                            user_sessions.retain(|&id| id != session.id);
                        }
                    }
                    valid
                });
                
                // Record cleanup metrics
                if expired_count > 0 {
                    metrics.record_sessions_cleaned(expired_count).await;
                }
            }
        });

        *self.cleanup_handle.lock().unwrap() = Some(handle);
    }
}

// Safe cleanup
impl Drop for SessionManager {
    fn drop(&mut self) {
        if let Some(handle) = self.cleanup_handle.lock().unwrap().take() {
            handle.abort();
        }
    }
} 