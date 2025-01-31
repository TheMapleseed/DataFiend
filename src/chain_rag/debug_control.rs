use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use ring::{digest, pbkdf2};
use std::num::NonZeroU32;
use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::net::SocketAddr;
use thiserror::Error;
use dashmap::DashMap;
use std::time::{Duration, Instant};
use hmac::{Hmac, Mac};
use sha2::Sha256;
use rand::Rng;
use uuid::Uuid;
use std::collections::HashSet;

// Debug interface constants
const MAX_SESSIONS: usize = 10;
const SESSION_TIMEOUT: Duration = Duration::from_secs(1800); // 30 minutes
const MAX_FAILED_ATTEMPTS: usize = 3;
const LOCKOUT_DURATION: Duration = Duration::from_secs(1800);
const TOKEN_LENGTH: usize = 32;
const MAX_REQUEST_SIZE: usize = 1024 * 1024; // 1MB
const CLEANUP_INTERVAL: Duration = Duration::from_secs(300);

#[derive(Debug, Error)]
pub enum DebugControlError {
    #[error("Authentication failed: {0}")]
    AuthFailed(String),
    
    #[error("Access denied: {0}")]
    AccessDenied(String),
    
    #[error("Session error: {0}")]
    Session(String),
    
    #[error("Rate limit exceeded: {0}")]
    RateLimit(String),
    
    #[error("Invalid request: {0}")]
    InvalidRequest(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DebugSession {
    id: Uuid,
    user_id: String,
    token: String,
    created_at: chrono::DateTime<chrono::Utc>,
    expires_at: chrono::DateTime<chrono::Utc>,
    ip_address: SocketAddr,
    permissions: HashSet<String>,
    mfa_verified: bool,
}

pub struct DebugControlManager {
    active_sessions: Arc<DashMap<String, DebugSession>>,
    failed_attempts: Arc<DashMap<String, (usize, Instant)>>,
    blocked_ips: Arc<DashMap<SocketAddr, Instant>>,
    hmac_key: Arc<[u8; 32]>,
    rbac_manager: Arc<RbacManager>,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
    cleanup_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

impl DebugControlManager {
    pub async fn new(
        hmac_key: [u8; 32],
        rbac_manager: Arc<RbacManager>,
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Self {
        let manager = Self {
            active_sessions: Arc::new(DashMap::new()),
            failed_attempts: Arc::new(DashMap::new()),
            blocked_ips: Arc::new(DashMap::new()),
            hmac_key: Arc::new(hmac_key),
            rbac_manager,
            metrics,
            error_handler,
            cleanup_task: Arc::new(tokio::sync::Mutex::new(None)),
        };
        
        manager.start_cleanup_task();
        manager
    }

    pub async fn authenticate(
        &self,
        user_id: &str,
        credentials: &str,
        ip: SocketAddr,
        mfa_token: Option<&str>,
    ) -> Result<DebugSession, DebugControlError> {
        // Check IP blocks
        if let Some(blocked_until) = self.blocked_ips.get(&ip) {
            if blocked_until.elapsed() < LOCKOUT_DURATION {
                return Err(DebugControlError::AccessDenied(
                    "IP address is blocked".to_string()
                ));
            }
            self.blocked_ips.remove(&ip);
        }

        // Validate debug access permission
        if !self.rbac_manager.check_permission(
            user_id,
            "debug_interface",
            "system",
            "access",
            None,
        ).await? {
            self.record_failed_attempt(user_id).await?;
            return Err(DebugControlError::AccessDenied(
                "Insufficient permissions".to_string()
            ));
        }

        // Verify credentials
        if !self.verify_credentials(user_id, credentials).await? {
            self.record_failed_attempt(user_id).await?;
            return Err(DebugControlError::AuthFailed(
                "Invalid credentials".to_string()
            ));
        }

        // Check MFA requirement
        let requires_mfa = self.rbac_manager.user_requires_mfa(user_id).await?;
        if requires_mfa {
            if let Some(token) = mfa_token {
                if !self.verify_mfa_token(user_id, token).await? {
                    self.record_failed_attempt(user_id).await?;
                    return Err(DebugControlError::AuthFailed(
                        "Invalid MFA token".to_string()
                    ));
                }
            } else {
                return Err(DebugControlError::AuthFailed(
                    "MFA token required".to_string()
                ));
            }
        }

        // Create session
        let session = self.create_session(user_id, ip, requires_mfa).await?;
        
        self.metrics.record_debug_session_created().await;
        Ok(session)
    }

    async fn record_failed_attempt(&self, user_id: &str) -> Result<(), DebugControlError> {
        let now = Instant::now();
        self.failed_attempts
            .entry(user_id.to_string())
            .and_modify(|e| {
                e.0 += 1;
                e.1 = now;
            })
            .or_insert((1, now));

        if let Some(attempts) = self.failed_attempts.get(user_id) {
            if attempts.0 >= MAX_FAILED_ATTEMPTS {
                self.blocked_ips.insert(user_id.parse().unwrap(), Instant::now());
                self.failed_attempts.remove(user_id);
                
                self.metrics.record_ip_blocked().await;
            }
        }

        Ok(())
    }

    async fn create_session(
        &self,
        user_id: &str,
        ip: SocketAddr,
        mfa_verified: bool,
    ) -> Result<DebugSession, DebugControlError> {
        // Check session limit
        if self.active_sessions.len() >= MAX_SESSIONS {
            return Err(DebugControlError::Session(
                "Maximum sessions reached".to_string()
            ));
        }

        // Generate session token
        let token = self.generate_session_token();

        // Create session
        let session = DebugSession {
            id: Uuid::new_v4(),
            user_id: user_id.to_string(),
            token,
            created_at: chrono::Utc::now(),
            expires_at: chrono::Utc::now() + chrono::Duration::from_std(SESSION_TIMEOUT)?,
            ip_address: ip,
            permissions: self.rbac_manager.get_user_permissions(user_id).await?,
            mfa_verified,
        };

        self.active_sessions.insert(session.token.clone(), session.clone());
        Ok(session)
    }

    pub async fn validate_request(
        &self,
        token: &str,
        command: &str,
        args: &[String],
    ) -> Result<(), DebugControlError> {
        // Get session
        let session = self.active_sessions.get(token)
            .ok_or_else(|| DebugControlError::Session(
                "Invalid session".to_string()
            ))?;

        // Check session expiry
        if chrono::Utc::now() > session.expires_at {
            self.active_sessions.remove(token);
            return Err(DebugControlError::Session(
                "Session expired".to_string()
            ));
        }

        // Validate command permissions
        if !self.rbac_manager.check_permission(
            &session.user_id,
            "debug_command",
            command,
            "execute",
            Some(&serde_json::json!({ "args": args })),
        ).await? {
            return Err(DebugControlError::AccessDenied(
                "Insufficient permissions for command".to_string()
            ));
        }

        // Validate request size
        let request_size = command.len() + args.iter().map(|s| s.len()).sum::<usize>();
        if request_size > MAX_REQUEST_SIZE {
            return Err(DebugControlError::InvalidRequest(
                "Request too large".to_string()
            ));
        }

        self.metrics.record_debug_command_executed().await;
        Ok(())
    }

    fn generate_session_token(&self) -> String {
        let mut rng = rand::thread_rng();
        let mut token = vec![0u8; TOKEN_LENGTH];
        rng.fill(&mut token[..]);
        
        let mut mac = Hmac::<Sha256>::new_from_slice(&self.hmac_key)
            .expect("HMAC initialization failed");
        mac.update(&token);
        let result = mac.finalize();
        
        hex::encode(result.into_bytes())
    }

    async fn verify_credentials(
        &self,
        user_id: &str, 
        credentials: &str
    ) -> Result<bool, DebugControlError> {
        // Validate inputs
        if user_id.is_empty() || credentials.is_empty() {
            return Err(DebugControlError::AuthFailed("Empty credentials".into()));
        }

        // Rate limiting
        if let Some(attempts) = self.failed_attempts.get(user_id) {
            if attempts.0 >= MAX_FAILED_ATTEMPTS {
                let elapsed = attempts.1.elapsed();
                if elapsed < LOCKOUT_DURATION {
                    return Err(DebugControlError::AccessDenied(
                        format!("Account locked for {} more seconds", 
                            (LOCKOUT_DURATION - elapsed).as_secs()
                        )
                    ));
                }
                self.failed_attempts.remove(user_id);
            }
        }

        // Verify against secure credential store
        let result = match self.rbac_manager.verify_credentials(
            user_id,
            credentials,
            "debug_interface"
        ).await {
            Ok(valid) => valid,
            Err(e) => {
                // Record failed attempt
                self.record_failed_attempt(user_id).await;
                return Err(DebugControlError::AuthFailed(e.to_string()));
            }
        };

        if !result {
            self.record_failed_attempt(user_id).await;
            return Err(DebugControlError::AuthFailed("Invalid credentials".into()));
        }

        // Clear failed attempts on success
        self.failed_attempts.remove(user_id);
        
        Ok(true)
    }

    async fn verify_mfa_token(
        &self,
        user_id: &str,
        token: &str,
    ) -> Result<bool, DebugControlError> {
        // Implement MFA token verification
        Ok(true)
    }

    fn start_cleanup_task(&self) {
        let active_sessions = self.active_sessions.clone();
        let failed_attempts = self.failed_attempts.clone();
        let blocked_ips = self.blocked_ips.clone();
        let metrics = self.metrics.clone();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            
            loop {
                interval.tick().await;
                
                let now = Instant::now();
                let utc_now = chrono::Utc::now();
                
                // Cleanup expired sessions
                active_sessions.retain(|_, session| {
                    session.expires_at > utc_now
                });
                
                // Cleanup failed attempts
                failed_attempts.retain(|_, (_, timestamp)| {
                    timestamp.elapsed() < LOCKOUT_DURATION
                });
                
                // Cleanup blocked IPs
                blocked_ips.retain(|_, timestamp| {
                    timestamp.elapsed() < LOCKOUT_DURATION
                });
                
                metrics.record_cleanup().await;
            }
        });

        *self.cleanup_task.lock().unwrap() = Some(handle);
    }
}

// Safe cleanup
impl Drop for DebugControlManager {
    fn drop(&mut self) {
        if let Some(handle) = self.cleanup_task.lock().unwrap().take() {
            handle.abort();
        }
    }
}

#[derive(Serialize, Deserialize)]
pub enum SystemInterface {
    Metrics,
    Debug,
    Configuration,
    NetworkControl,
    ResourceManagement,
    CacheControl,
}

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct AdminSession {
    session_id: String,
    start_time: chrono::DateTime<chrono::Utc>,
    last_access: Arc<RwLock<chrono::DateTime<chrono::Utc>>>,
    active_interfaces: HashSet<SystemInterface>,
}

#[wasm_bindgen]
pub struct SystemControl {
    admin_hash: [u8; CREDENTIAL_LEN],
    admin_salt: [u8; SALT_LEN],
    active_session: Arc<RwLock<Option<AdminSession>>>,
    session_lock: Arc<Mutex<()>>,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
}

#[wasm_bindgen]
impl SystemControl {
    #[wasm_bindgen]
    pub async fn login(&self, password: &str) -> Result<JsValue, JsValue> {
        let _lock = self.session_lock.lock().await;
        
        // Single session check
        if self.active_session.read().await.is_some() {
            return Err(JsValue::from_str("System already has an active admin session"));
        }

        // Verify admin credentials
        self.verify_admin_password(password).await?;

        // Create new admin session with full system access
        let session = AdminSession {
            session_id: Uuid::new_v4().to_string(),
            start_time: chrono::Utc::now(),
            last_access: Arc::new(RwLock::new(chrono::Utc::now())),
            active_interfaces: HashSet::from_iter(vec![
                SystemInterface::Metrics,
                SystemInterface::Debug,
                SystemInterface::Configuration,
                SystemInterface::NetworkControl,
                SystemInterface::ResourceManagement,
                SystemInterface::CacheControl,
            ]),
        };

        *self.active_session.write().await = Some(session.clone());
        self.metrics.record_admin_login().await;

        Ok(serde_wasm_bindgen::to_value(&session)?)
    }

    #[wasm_bindgen]
    pub async fn access_interface(
        &self, 
        session_id: &str,
        interface: &str
    ) -> Result<JsValue, JsValue> {
        // Verify session
        let session = self.verify_session(session_id).await?;
        
        // Parse and verify interface access
        let interface_type = serde_json::from_str(interface)
            .map_err(|_| JsValue::from_str("Invalid interface type"))?;

        if !session.active_interfaces.contains(&interface_type) {
            return Err(JsValue::from_str("Access denied to requested interface"));
        }

        // Update last access time
        *session.last_access.write().await = chrono::Utc::now();

        // Return interface-specific data
        match interface_type {
            SystemInterface::Metrics => {
                let metrics_data = self.metrics.get_all_metrics().await;
                Ok(serde_wasm_bindgen::to_value(&metrics_data)?)
            },
            SystemInterface::Debug => {
                let debug_data = self.get_debug_info().await;
                Ok(serde_wasm_bindgen::to_value(&debug_data)?)
            },
            // ... other interface handlers
        }
    }

    #[wasm_bindgen]
    pub async fn logout(&self, session_id: &str) -> Result<(), JsValue> {
        let _lock = self.session_lock.lock().await;
        
        self.verify_session(session_id).await?;
        
        // End session
        *self.active_session.write().await = None;
        self.metrics.record_admin_logout().await;
        
        Ok(())
    }

    async fn verify_session(&self, session_id: &str) -> Result<AdminSession, JsValue> {
        let session = self.active_session.read().await
            .as_ref()
            .ok_or_else(|| JsValue::from_str("No active session"))?
            .clone();

        if session.session_id != session_id {
            return Err(JsValue::from_str("Invalid session ID"));
        }

        // Check session timeout
        let last_access = *session.last_access.read().await;
        if (chrono::Utc::now() - last_access) > chrono::Duration::minutes(30) {
            *self.active_session.write().await = None;
            self.metrics.record_session_timeout().await;
            return Err(JsValue::from_str("Session timed out"));
        }

        Ok(session)
    }
}

// Safe cleanup
impl Drop for SystemControl {
    fn drop(&mut self) {
        if self.active_session.read().blocking_lock().is_some() {
            *self.active_session.write().blocking_lock() = None;
            self.metrics.record_admin_session_cleanup().blocking_lock();
        }
    }
} 