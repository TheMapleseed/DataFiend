use rand::{thread_rng, Rng, distributions::{Distribution, WeibullDuration}};
use std::sync::atomic::{AtomicU64, Ordering};
use tokio::time::Duration;
use blake3::Hasher;
use ring::rand::{SecureRandom, SystemRandom};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::sync::Arc;
use tokio::sync::{RwLock, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};
use serde::{Serialize, Deserialize};
use chrono::{DateTime, Utc};
use blake3::Hash;
use uuid;
use bincode;
use thiserror;

pub struct IrregularKeyRotator {
    current_key: Arc<RwLock<RotatingKey>>,
    last_rotation: AtomicU64,
    entropy_pool: Arc<EntropyPool>,
    drift_manager: Arc<DriftManager>,
    rotation_lock: Arc<Mutex<()>>,
    key_consumers: Arc<RwLock<Vec<Box<dyn KeyConsumer + Send + Sync>>>>,
    audit_log: Arc<KeyAuditLog>,
}

#[derive(ZeroizeOnDrop)]
struct RotatingKey {
    key: Key<Aes256Gcm>,
    generation: u64,
    entropy: [u8; 32],
    version: KeyVersion,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct KeyVersion {
    major: u16,
    minor: u16,
    patch: u16,
    created_at: DateTime<Utc>,
    hash: Hash,
    previous_hash: Option<Hash>,
}

#[derive(Clone)]
pub struct VersionedKey {
    key_material: [u8; 32],
    version: KeyVersion,
    metadata: KeyMetadata,
}

#[derive(Clone, Serialize, Deserialize)]
struct KeyMetadata {
    created_at: DateTime<Utc>,
    expires_at: Option<DateTime<Utc>>,
    rotation_id: uuid::Uuid,
    emergency_backup: bool,
}

struct EntropyPool {
    pool: RwLock<Vec<u8>>,
    hasher: Hasher,
    rng: SystemRandom,
}

pub struct KeyRotationManager {
    current_key: Arc<RwLock<VersionedKey>>,
    key_history: Arc<RwLock<KeyHistory>>,
    rotation_lock: Arc<Mutex<()>>,
    metrics: Arc<MetricsStore>,
    audit_log: Arc<KeyAuditLog>,
}

struct KeyHistory {
    versions: Vec<VersionedKey>,
    max_history: usize,
}

impl IrregularKeyRotator {
    pub fn new(drift_manager: Arc<DriftManager>) -> Result<Self> {
        let initial_key = Self::generate_initial_key()?;
        let entropy_pool = Arc::new(EntropyPool::new());
        
        let rotator = Self {
            current_key: Arc::new(RwLock::new(initial_key)),
            last_rotation: AtomicU64::new(SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs()),
            entropy_pool,
            drift_manager,
            rotation_lock: Arc::new(Mutex::new(())),
            key_consumers: Arc::new(RwLock::new(Vec::new())),
            audit_log: Arc::new(KeyAuditLog::new()?),
        };
        
        rotator.start_irregular_rotation();
        Ok(rotator)
    }

    fn generate_initial_key() -> Result<RotatingKey> {
        let rng = SystemRandom::new();
        
        // Secure key generation
        let mut key_bytes = [0u8; 32];
        let mut entropy = [0u8; 32];
        
        rng.fill(&mut key_bytes)
            .map_err(|_| Error::KeyGenerationFailed)?;
        rng.fill(&mut entropy)
            .map_err(|_| Error::KeyGenerationFailed)?;
            
        let version = KeyVersion {
            major: 1,
            minor: 0,
            patch: 0,
            created_at: Utc::now(),
            hash: Hash::default(),
            previous_hash: None,
        };
        
        let key = RotatingKey {
            key: Key::from_slice(&key_bytes),
            generation: 0,
            entropy,
            version,
        };
        
        // Secure cleanup of sensitive data
        key_bytes.zeroize();
        
        Ok(key)
    }

    fn start_irregular_rotation(&self) {
        let self_clone = self.clone();
        tokio::spawn(async move {
            loop {
                // Get irregular interval from drift manager
                let interval = self_clone.drift_manager.get_next_interval().await;
                tokio::time::sleep(interval).await;
                
                if let Err(e) = self_clone.rotate_key().await {
                    error!("Key rotation failed: {}", e);
                    // Alert security team
                    self_clone.alert_security_team(e).await;
                }
            }
        });
    }

    pub async fn get_current_key(&self) -> Result<RotatingKey> {
        let key = self.current_key.read().await;
        Ok(key.clone())
    }

    pub async fn register_consumer(&self, consumer: Box<dyn KeyConsumer + Send + Sync>) {
        let mut consumers = self.key_consumers.write().await;
        consumers.push(consumer);
    }

    async fn alert_security_team(&self, error: Error) {
        // Implement secure alerting
        let alert = SecurityAlert {
            timestamp: chrono::Utc::now(),
            error_type: "key_rotation_failure",
            details: error.to_string(),
            severity: AlertSeverity::Critical,
        };
        
        if let Err(e) = self.audit_log.record_alert(alert).await {
            error!("Failed to record security alert: {}", e);
        }
    }
}

#[async_trait]
pub trait KeyConsumer: Send + Sync {
    async fn notify_key_rotation(&self) -> Result<()>;
    async fn handle_key_failure(&self, error: &Error) -> Result<()>;
}

impl EntropyPool {
    fn new() -> Self {
        Self {
            pool: RwLock::new(Vec::with_capacity(1024)),
            hasher: Hasher::new(),
            rng: SystemRandom::new(),
        }
    }

    async fn add_entropy(&self) -> Result<()> {
        let mut pool = self.pool.write().await;
        let mut random_bytes = [0u8; 32];
        
        self.rng.fill(&mut random_bytes)
            .map_err(|_| Error::EntropyGenerationFailed)?;
            
        pool.extend_from_slice(&random_bytes);
        
        // Keep pool size bounded
        if pool.len() > 1024 {
            pool.drain(0..512);
        }
        
        // Update hasher state
        self.hasher.update(&pool);
        
        Ok(())
    }

    async fn get_entropy(&self) -> Vec<u8> {
        let pool = self.pool.read().await;
        let mut hasher = self.hasher.clone();
        hasher.update(&pool);
        hasher.finalize().as_bytes().to_vec()
    }
}

// Update ObfuscationLayer to use irregular rotation
impl ObfuscationLayer {
    pub fn new(drift_manager: Arc<DriftManager>) -> Self {
        Self {
            keys: Arc::new(IrregularKeyRotator::new(drift_manager)),
            hasher: Hasher::new(),
            nonce_generator: NonceGenerator::new(),
        }
    }
}

// Secure audit logging
struct KeyAuditLog {
    store: Arc<SecureStore>,
}

impl KeyAuditLog {
    async fn record_rotation(
        &self,
        old_version: KeyVersion,
        new_version: KeyVersion
    ) -> Result<()> {
        let entry = AuditEntry {
            timestamp: chrono::Utc::now(),
            event_type: "key_rotation",
            old_version,
            new_version,
            // Add additional audit metadata
        };
        
        self.store.append_encrypted(entry).await
    }

    async fn record_alert(&self, alert: SecurityAlert) -> Result<()> {
        let entry = AuditEntry {
            timestamp: alert.timestamp,
            event_type: alert.error_type,
            old_version: KeyVersion {
                major: 0,
                minor: 0,
                patch: 0,
                created_at: Utc::now(),
                hash: Hash::default(),
                previous_hash: None,
            },
            new_version: KeyVersion {
                major: 0,
                minor: 0,
                patch: 0,
                created_at: Utc::now(),
                hash: Hash::default(),
                previous_hash: None,
            },
            // Add additional audit metadata
        };
        
        self.store.append_encrypted(entry).await
    }
}

pub struct KeyGenerator {
    rng: SystemRandom,
    entropy_pool: Arc<EntropyPool>,
    metrics: Arc<MetricsStore>,
}

impl KeyGenerator {
    pub fn new(metrics: Arc<MetricsStore>) -> Self {
        Self {
            rng: SystemRandom::new(),
            entropy_pool: Arc::new(EntropyPool::new()),
            metrics,
        }
    }

    pub fn generate_key(&self) -> Result<[u8; 32]> {
        let mut key = [0u8; 32];
        self.rng.fill(&mut key)
            .map_err(|_| Error::KeyGenerationFailed)?;
            
        // Mix in additional entropy
        let entropy = self.entropy_pool.get_mixed_entropy()?;
        for (i, byte) in entropy.iter().enumerate() {
            key[i % 32] ^= byte;
        }
        
        // Record metrics
        self.metrics.record_key_generation().await?;
        
        Ok(key)
    }

    pub fn generate_nonce(&self) -> Result<[u8; 12]> {
        let mut nonce = [0u8; 12];
        self.rng.fill(&mut nonce)
            .map_err(|_| Error::NonceGenerationFailed)?;
        Ok(nonce)
    }
}

impl EntropyPool {
    fn get_mixed_entropy(&self) -> Result<Vec<u8>> {
        let mut additional = [0u8; 32];
        self.rng.fill(&mut additional)
            .map_err(|_| Error::EntropyGenerationFailed)?;
            
        let mut pool = self.pool.write().await;
        pool.extend_from_slice(&additional);
        
        // Keep pool size bounded
        if pool.len() > 1024 {
            pool.drain(0..512);
        }
        
        // Mix entropy sources
        let mut hasher = blake3::Hasher::new();
        hasher.update(&pool);
        hasher.update(&additional);
        
        Ok(hasher.finalize().as_bytes().to_vec())
    }
}

impl IrregularKeyRotator {
    async fn generate_rotation_delay(&self) -> Duration {
        let mut delay_bytes = [0u8; 8];
        self.entropy_pool.rng.fill(&mut delay_bytes)
            .expect("Failed to generate secure random delay");
            
        let base_delay = u64::from_le_bytes(delay_bytes) % 1000;
        Duration::from_millis(500 + base_delay) // 500-1500ms range
    }
}

impl TokenGenerator {
    fn generate_token(&self) -> Result<Token> {
        let mut token_bytes = [0u8; 32];
        self.rng.fill(&mut token_bytes)
            .map_err(|_| Error::TokenGenerationFailed)?;
            
        Ok(Token {
            value: token_bytes,
            expires_at: SystemTime::now() + Duration::from_secs(3600),
            namespace: self.namespace,
        })
    }
}

impl KeyRotationManager {
    pub async fn rotate_key(&self) -> Result<(), KeyRotationError> {
        // Acquire rotation lock
        let _lock = self.rotation_lock.lock().await;
        
        // Generate new key material
        let new_key_material = self.generate_secure_key()?;
        
        // Get current key for version increment
        let current = self.current_key.read().await.clone();
        
        // Create new version
        let new_version = self.create_new_version(&current.version)?;
        
        // Calculate hash of new key
        let new_hash = self.calculate_key_hash(&new_key_material, &new_version);
        
        // Create new versioned key
        let new_key = VersionedKey {
            key_material: new_key_material,
            version: new_version.clone(),
            metadata: KeyMetadata {
                created_at: Utc::now(),
                expires_at: None,
                rotation_id: uuid::Uuid::new_v4(),
                emergency_backup: false,
            },
        };

        // Update history before changing current key
        {
            let mut history = self.key_history.write().await;
            history.add_version(current.clone())?;
        }

        // Atomic key update
        {
            let mut current = self.current_key.write().await;
            *current = new_key.clone();
        }

        // Log rotation event
        self.audit_log.record_rotation(
            RotationEvent {
                timestamp: Utc::now(),
                new_version: new_version.clone(),
                previous_version: current.version,
                rotation_id: new_key.metadata.rotation_id,
            }
        ).await?;

        Ok(())
    }

    pub async fn rollback_to_version(&self, target_version: &KeyVersion) -> Result<(), KeyRotationError> {
        let _lock = self.rotation_lock.lock().await;
        
        // Verify rollback is allowed
        self.verify_rollback_allowed(target_version).await?;
        
        // Find target key in history
        let history = self.key_history.read().await;
        let target_key = history.find_version(target_version)?;
        
        // Create emergency backup of current key
        let current = self.current_key.read().await.clone();
        let backup = VersionedKey {
            key_material: current.key_material,
            version: current.version,
            metadata: KeyMetadata {
                created_at: current.metadata.created_at,
                expires_at: Some(Utc::now()),
                rotation_id: current.metadata.rotation_id,
                emergency_backup: true,
            },
        };

        // Update history with emergency backup
        {
            let mut history = self.key_history.write().await;
            history.add_version(backup)?;
        }

        // Perform rollback
        {
            let mut current = self.current_key.write().await;
            *current = target_key.clone();
        }

        // Log rollback event
        self.audit_log.record_rollback(
            RollbackEvent {
                timestamp: Utc::now(),
                target_version: target_version.clone(),
                previous_version: current.version,
                reason: "Emergency rollback".to_string(),
            }
        ).await?;

        Ok(())
    }

    fn create_new_version(&self, current: &KeyVersion) -> Result<KeyVersion, KeyRotationError> {
        let new_version = KeyVersion {
            major: current.major,
            minor: current.minor + 1,
            patch: 0,
            created_at: Utc::now(),
            hash: Hash::default(), // Will be set later
            previous_hash: Some(current.hash),
        };
        
        Ok(new_version)
    }

    fn calculate_key_hash(&self, key_material: &[u8], version: &KeyVersion) -> Hash {
        let mut hasher = blake3::Hasher::new();
        hasher.update(key_material);
        hasher.update(&bincode::serialize(version).unwrap());
        hasher.finalize()
    }
}

impl KeyHistory {
    fn add_version(&mut self, key: VersionedKey) -> Result<(), KeyRotationError> {
        self.versions.push(key);
        
        // Maintain bounded history
        while self.versions.len() > self.max_history {
            self.versions.remove(0);
        }
        
        Ok(())
    }

    fn find_version(&self, target: &KeyVersion) -> Result<VersionedKey, KeyRotationError> {
        self.versions.iter()
            .find(|k| k.version.hash == target.hash)
            .cloned()
            .ok_or(KeyRotationError::VersionNotFound)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum KeyRotationError {
    #[error("Key version not found in history")]
    VersionNotFound,
    
    #[error("Rollback not allowed: {0}")]
    RollbackNotAllowed(String),
    
    #[error("Invalid version transition")]
    InvalidVersionTransition,
} 