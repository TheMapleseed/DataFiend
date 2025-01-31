use std::sync::Arc;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::HashMap;
use tokio::sync::RwLock;
use std::time::Duration;
use zeroize::ZeroizeOnDrop;

// Security defaults
const DEFAULT_PASSWORD_MIN_LENGTH: usize = 12;
const DEFAULT_PASSWORD_MAX_LENGTH: usize = 128;
const DEFAULT_SESSION_TIMEOUT: Duration = Duration::from_secs(3600); // 1 hour
const DEFAULT_MAX_LOGIN_ATTEMPTS: u32 = 5;
const DEFAULT_LOCKOUT_DURATION: Duration = Duration::from_secs(900); // 15 minutes
const DEFAULT_TLS_MIN_VERSION: &str = "1.3";
const DEFAULT_HASH_ITERATIONS: u32 = 600_000;
const DEFAULT_MEMORY_COST: u32 = 65536; // 64MB
const DEFAULT_PARALLELISM: u32 = 4;

#[derive(Debug, Error)]
pub enum SecureDefaultsError {
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    
    #[error("Value out of range: {0}")]
    OutOfRange(String),
    
    #[error("Invalid override: {0}")]
    InvalidOverride(String),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Serialize, Deserialize, Clone, ZeroizeOnDrop)]
pub struct SecurityDefaults {
    // Authentication
    password_min_length: usize,
    password_max_length: usize,
    password_require_numbers: bool,
    password_require_symbols: bool,
    password_require_mixed_case: bool,
    
    // Session Management
    session_timeout: Duration,
    max_login_attempts: u32,
    lockout_duration: Duration,
    require_mfa: bool,
    
    // Encryption
    tls_min_version: String,
    minimum_key_length: usize,
    hash_iterations: u32,
    memory_cost: u32,
    parallelism: u32,
    
    // Headers
    security_headers: HashMap<String, String>,
    
    // CORS
    allowed_origins: Vec<String>,
    allowed_methods: Vec<String>,
    
    // Rate Limiting
    rate_limit_window: Duration,
    rate_limit_max_requests: u32,
}

pub struct SecureDefaultsManager {
    defaults: Arc<RwLock<SecurityDefaults>>,
    overrides: Arc<RwLock<HashMap<String, SecurityOverride>>>,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
}

#[derive(Clone, Serialize, Deserialize)]
struct SecurityOverride {
    value: String,
    reason: String,
    approved_by: String,
    expires_at: Option<chrono::DateTime<chrono::Utc>>,
}

impl SecureDefaultsManager {
    pub fn new(
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Self {
        let defaults = SecurityDefaults::new_secure_defaults();
        
        Self {
            defaults: Arc::new(RwLock::new(defaults)),
            overrides: Arc::new(RwLock::new(HashMap::new())),
            metrics,
            error_handler,
        }
    }

    pub async fn get_password_policy(&self) -> PasswordPolicy {
        let defaults = self.defaults.read().await;
        
        PasswordPolicy {
            min_length: defaults.password_min_length,
            max_length: defaults.password_max_length,
            require_numbers: defaults.password_require_numbers,
            require_symbols: defaults.password_require_symbols,
            require_mixed_case: defaults.password_require_mixed_case,
        }
    }

    pub async fn get_session_config(&self) -> SessionConfig {
        let defaults = self.defaults.read().await;
        
        SessionConfig {
            timeout: defaults.session_timeout,
            max_login_attempts: defaults.max_login_attempts,
            lockout_duration: defaults.lockout_duration,
            require_mfa: defaults.require_mfa,
        }
    }

    pub async fn get_encryption_config(&self) -> EncryptionConfig {
        let defaults = self.defaults.read().await;
        
        EncryptionConfig {
            tls_min_version: defaults.tls_min_version.clone(),
            minimum_key_length: defaults.minimum_key_length,
            hash_iterations: defaults.hash_iterations,
            memory_cost: defaults.memory_cost,
            parallelism: defaults.parallelism,
        }
    }

    pub async fn override_setting(
        &self,
        key: &str,
        value: &str,
        reason: &str,
        approved_by: &str,
        duration: Option<Duration>,
    ) -> Result<(), SecureDefaultsError> {
        // Validate override
        self.validate_override(key, value).await?;
        
        let expires_at = duration.map(|d| {
            chrono::Utc::now() + chrono::Duration::from_std(d).unwrap()
        });
        
        let override_value = SecurityOverride {
            value: value.to_string(),
            reason: reason.to_string(),
            approved_by: approved_by.to_string(),
            expires_at,
        };
        
        // Apply override
        self.apply_override(key, &override_value).await?;
        
        // Store override
        self.overrides.write().await.insert(key.to_string(), override_value);
        
        self.metrics.record_security_override(key).await;
        Ok(())
    }

    async fn validate_override(
        &self,
        key: &str,
        value: &str,
    ) -> Result<(), SecureDefaultsError> {
        match key {
            "password_min_length" => {
                let length = value.parse::<usize>().map_err(|_| {
                    SecureDefaultsError::InvalidOverride("Invalid password length".to_string())
                })?;
                
                if length < 8 {
                    return Err(SecureDefaultsError::OutOfRange(
                        "Password minimum length too short".to_string()
                    ));
                }
            },
            "tls_min_version" => {
                if !["1.2", "1.3"].contains(&value) {
                    return Err(SecureDefaultsError::InvalidOverride(
                        "Invalid TLS version".to_string()
                    ));
                }
            },
            "hash_iterations" => {
                let iterations = value.parse::<u32>().map_err(|_| {
                    SecureDefaultsError::InvalidOverride("Invalid iteration count".to_string())
                })?;
                
                if iterations < 100_000 {
                    return Err(SecureDefaultsError::OutOfRange(
                        "Hash iterations too low".to_string()
                    ));
                }
            },
            // Add other validations...
            _ => return Err(SecureDefaultsError::InvalidOverride(
                format!("Unknown setting: {}", key)
            )),
        }
        
        Ok(())
    }

    async fn apply_override(
        &self,
        key: &str,
        override_value: &SecurityOverride,
    ) -> Result<(), SecureDefaultsError> {
        let mut defaults = self.defaults.write().await;
        
        match key {
            "password_min_length" => {
                defaults.password_min_length = override_value.value.parse().unwrap();
            },
            "tls_min_version" => {
                defaults.tls_min_version = override_value.value.clone();
            },
            "hash_iterations" => {
                defaults.hash_iterations = override_value.value.parse().unwrap();
            },
            // Add other settings...
            _ => return Err(SecureDefaultsError::InvalidOverride(
                format!("Unknown setting: {}", key)
            )),
        }
        
        Ok(())
    }

    pub async fn cleanup_expired_overrides(&self) {
        let mut overrides = self.overrides.write().await;
        let now = chrono::Utc::now();
        
        overrides.retain(|_, override_value| {
            match override_value.expires_at {
                Some(expiry) => expiry > now,
                None => true,
            }
        });
    }
}

impl SecurityDefaults {
    fn new_secure_defaults() -> Self {
        Self {
            // Authentication
            password_min_length: DEFAULT_PASSWORD_MIN_LENGTH,
            password_max_length: DEFAULT_PASSWORD_MAX_LENGTH,
            password_require_numbers: true,
            password_require_symbols: true,
            password_require_mixed_case: true,
            
            // Session Management
            session_timeout: DEFAULT_SESSION_TIMEOUT,
            max_login_attempts: DEFAULT_MAX_LOGIN_ATTEMPTS,
            lockout_duration: DEFAULT_LOCKOUT_DURATION,
            require_mfa: true,
            
            // Encryption
            tls_min_version: DEFAULT_TLS_MIN_VERSION.to_string(),
            minimum_key_length: 256,
            hash_iterations: DEFAULT_HASH_ITERATIONS,
            memory_cost: DEFAULT_MEMORY_COST,
            parallelism: DEFAULT_PARALLELISM,
            
            // Headers
            security_headers: HashMap::from([
                ("Strict-Transport-Security".to_string(), "max-age=31536000; includeSubDomains".to_string()),
                ("X-Frame-Options".to_string(), "DENY".to_string()),
                ("X-Content-Type-Options".to_string(), "nosniff".to_string()),
                ("Content-Security-Policy".to_string(), "default-src 'self'".to_string()),
                ("X-XSS-Protection".to_string(), "1; mode=block".to_string()),
            ]),
            
            // CORS
            allowed_origins: vec!["https://api.chainrag.com".to_string()],
            allowed_methods: vec!["GET".to_string(), "POST".to_string()],
            
            // Rate Limiting
            rate_limit_window: Duration::from_secs(60),
            rate_limit_max_requests: 100,
        }
    }
}

#[derive(Clone, Debug)]
pub struct PasswordPolicy {
    pub min_length: usize,
    pub max_length: usize,
    pub require_numbers: bool,
    pub require_symbols: bool,
    pub require_mixed_case: bool,
}

#[derive(Clone, Debug)]
pub struct SessionConfig {
    pub timeout: Duration,
    pub max_login_attempts: u32,
    pub lockout_duration: Duration,
    pub require_mfa: bool,
}

#[derive(Clone, Debug)]
pub struct EncryptionConfig {
    pub tls_min_version: String,
    pub minimum_key_length: usize,
    pub hash_iterations: u32,
    pub memory_cost: u32,
    pub parallelism: u32,
} 