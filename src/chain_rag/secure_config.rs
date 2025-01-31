use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use ring::aead::{self, BoundKey, UnboundKey, LessSafeKey};
use ring::rand::SystemRandom;
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use zeroize::{Zeroize, ZeroizeOnDrop};
use std::path::PathBuf;

// Security constants
const KEY_ROTATION_INTERVAL: Duration = Duration::from_secs(86400 * 30); // 30 days
const MIN_ENCRYPTION_KEY_LENGTH: usize = 32;
const MAX_CONFIG_SIZE: usize = 10 * 1024 * 1024; // 10MB
const NONCE_SIZE: usize = 12;

#[derive(Debug, Error)]
pub enum SecureConfigError {
    #[error("Encryption error: {0}")]
    Encryption(String),
    
    #[error("Decryption error: {0}")]
    Decryption(String),
    
    #[error("Invalid key: {0}")]
    InvalidKey(String),
    
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
    
    #[error("Configuration error: {0}")]
    Config(String),
}

#[derive(Serialize, Deserialize)]
struct EncryptedConfig {
    encrypted_data: String,
    key_id: String,
    nonce: String,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize, Deserialize, Clone, ZeroizeOnDrop)]
pub struct SensitiveData {
    #[zeroize(skip)]
    pub key: String,
    #[zeroize(skip)]
    pub value: String,
}

pub struct SecureConfigManager {
    key_store: Arc<KeyStore>,
    config_store: Arc<RwLock<HashMap<String, EncryptedConfig>>>,
    file_path: PathBuf,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
    rotation_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

struct KeyStore {
    current_key: RwLock<EncryptionKey>,
    key_history: RwLock<HashMap<String, EncryptionKey>>,
    rng: SystemRandom,
}

#[derive(Clone, ZeroizeOnDrop)]
struct EncryptionKey {
    id: String,
    key: Vec<u8>,
    created_at: chrono::DateTime<chrono::Utc>,
}

impl SecureConfigManager {
    pub async fn new(
        file_path: PathBuf,
        master_key: &[u8],
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Result<Self, SecureConfigError> {
        let key_store = Arc::new(KeyStore::new(master_key)?);
        let config_store = Arc::new(RwLock::new(HashMap::new()));
        
        let manager = Self {
            key_store,
            config_store,
            file_path,
            metrics,
            error_handler,
            rotation_task: Arc::new(tokio::sync::Mutex::new(None)),
        };
        
        manager.load_config().await?;
        manager.start_key_rotation();
        
        Ok(manager)
    }

    pub async fn set_sensitive_data(
        &self,
        key: &str,
        value: &str,
    ) -> Result<(), SecureConfigError> {
        let sensitive_data = SensitiveData {
            key: key.to_string(),
            value: value.to_string(),
        };
        
        // Serialize and encrypt
        let data = serde_json::to_vec(&sensitive_data)?;
        if data.len() > MAX_CONFIG_SIZE {
            return Err(SecureConfigError::Config(
                format!("Config size exceeds limit: {} > {}", data.len(), MAX_CONFIG_SIZE)
            ));
        }
        
        let encryption_key = self.key_store.current_key.read().await;
        let (encrypted_data, nonce) = self.encrypt(&data, &encryption_key).await?;
        
        let encrypted_config = EncryptedConfig {
            encrypted_data: BASE64.encode(encrypted_data),
            key_id: encryption_key.id.clone(),
            nonce: BASE64.encode(nonce),
            created_at: chrono::Utc::now(),
        };
        
        // Store encrypted config
        self.config_store.write().await.insert(key.to_string(), encrypted_config);
        
        // Save to file
        self.save_config().await?;
        
        self.metrics.record_config_update().await;
        Ok(())
    }

    pub async fn get_sensitive_data(
        &self,
        key: &str,
    ) -> Result<SensitiveData, SecureConfigError> {
        let config_store = self.config_store.read().await;
        let encrypted_config = config_store.get(key)
            .ok_or_else(|| SecureConfigError::Config(format!("Key not found: {}", key)))?;
            
        let key_store = self.key_store.key_history.read().await;
        let encryption_key = key_store.get(&encrypted_config.key_id)
            .ok_or_else(|| SecureConfigError::Config(format!("Key not found: {}", encrypted_config.key_id)))?;
            
        let encrypted_data = BASE64.decode(&encrypted_config.encrypted_data)
            .map_err(|e| SecureConfigError::Decryption(e.to_string()))?;
            
        let nonce = BASE64.decode(&encrypted_config.nonce)
            .map_err(|e| SecureConfigError::Decryption(e.to_string()))?;
            
        let decrypted_data = self.decrypt(&encrypted_data, &nonce, encryption_key).await?;
        
        let sensitive_data: SensitiveData = serde_json::from_slice(&decrypted_data)?;
        
        self.metrics.record_config_access().await;
        Ok(sensitive_data)
    }

    async fn encrypt(
        &self,
        data: &[u8],
        key: &EncryptionKey,
    ) -> Result<(Vec<u8>, Vec<u8>), SecureConfigError> {
        let unbound_key = UnboundKey::new(&aead::CHACHA20_POLY1305, &key.key)
            .map_err(|e| SecureConfigError::Encryption(e.to_string()))?;
            
        let mut nonce = vec![0u8; NONCE_SIZE];
        self.key_store.rng.fill(&mut nonce)
            .map_err(|e| SecureConfigError::Encryption(e.to_string()))?;
            
        let nonce_sequence = OneNonce::new(nonce.clone());
        let mut sealing_key = BoundKey::new(unbound_key, nonce_sequence);
        
        let mut in_out = data.to_vec();
        sealing_key.seal_in_place_append_tag(aead::Aad::empty(), &mut in_out)
            .map_err(|e| SecureConfigError::Encryption(e.to_string()))?;
            
        Ok((in_out, nonce))
    }

    async fn decrypt(
        &self,
        encrypted_data: &[u8],
        nonce: &[u8],
        key: &EncryptionKey,
    ) -> Result<Vec<u8>, SecureConfigError> {
        let unbound_key = UnboundKey::new(&aead::CHACHA20_POLY1305, &key.key)
            .map_err(|e| SecureConfigError::Decryption(e.to_string()))?;
            
        let nonce_sequence = OneNonce::new(nonce.to_vec());
        let mut opening_key = BoundKey::new(unbound_key, nonce_sequence);
        
        let mut in_out = encrypted_data.to_vec();
        let decrypted_len = opening_key.open_in_place(aead::Aad::empty(), &mut in_out)
            .map_err(|e| SecureConfigError::Decryption(e.to_string()))?
            .len();
            
        in_out.truncate(decrypted_len);
        Ok(in_out)
    }

    async fn load_config(&self) -> Result<(), SecureConfigError> {
        if !self.file_path.exists() {
            return Ok(());
        }
        
        let data = tokio::fs::read(&self.file_path).await?;
        let config: HashMap<String, EncryptedConfig> = serde_json::from_slice(&data)?;
        
        *self.config_store.write().await = config;
        Ok(())
    }

    async fn save_config(&self) -> Result<(), SecureConfigError> {
        let config = self.config_store.read().await;
        let data = serde_json::to_vec(&*config)?;
        
        // Atomic write using temporary file
        let temp_path = self.file_path.with_extension("tmp");
        tokio::fs::write(&temp_path, &data).await?;
        tokio::fs::rename(&temp_path, &self.file_path).await?;
        
        Ok(())
    }

    fn start_key_rotation(&self) {
        let key_store = self.key_store.clone();
        let metrics = self.metrics.clone();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(KEY_ROTATION_INTERVAL);
            
            loop {
                interval.tick().await;
                
                if let Err(e) = key_store.rotate_key().await {
                    log::error!("Key rotation failed: {}", e);
                } else {
                    metrics.record_key_rotation().await;
                }
            }
        });

        *self.rotation_task.lock().unwrap() = Some(handle);
    }
}

impl KeyStore {
    fn new(master_key: &[u8]) -> Result<Self, SecureConfigError> {
        if master_key.len() < MIN_ENCRYPTION_KEY_LENGTH {
            return Err(SecureConfigError::InvalidKey(
                format!("Master key too short: {} < {}", master_key.len(), MIN_ENCRYPTION_KEY_LENGTH)
            ));
        }

        let initial_key = EncryptionKey {
            id: Uuid::new_v4().to_string(),
            key: master_key.to_vec(),
            created_at: chrono::Utc::now(),
        };

        Ok(Self {
            current_key: RwLock::new(initial_key.clone()),
            key_history: RwLock::new(HashMap::from([(initial_key.id.clone(), initial_key)])),
            rng: SystemRandom::new(),
        })
    }

    async fn rotate_key(&self) -> Result<(), SecureConfigError> {
        let mut new_key = vec![0u8; MIN_ENCRYPTION_KEY_LENGTH];
        self.rng.fill(&mut new_key)
            .map_err(|e| SecureConfigError::InvalidKey(e.to_string()))?;
            
        let key = EncryptionKey {
            id: Uuid::new_v4().to_string(),
            key: new_key,
            created_at: chrono::Utc::now(),
        };
        
        // Update current key and history
        {
            let mut current_key = self.current_key.write().await;
            let mut key_history = self.key_history.write().await;
            
            key_history.insert(key.id.clone(), key.clone());
            *current_key = key;
        }
        
        Ok(())
    }
}

struct OneNonce {
    nonce: Vec<u8>,
    used: bool,
}

impl OneNonce {
    fn new(nonce: Vec<u8>) -> Self {
        Self {
            nonce,
            used: false,
        }
    }
}

impl ring::aead::NonceSequence for OneNonce {
    fn advance(&mut self) -> Result<ring::aead::Nonce, ring::error::Unspecified> {
        if self.used {
            return Err(ring::error::Unspecified);
        }
        self.used = true;
        ring::aead::Nonce::try_assume_unique_for_key(&self.nonce)
    }
}

// Safe cleanup
impl Drop for SecureConfigManager {
    fn drop(&mut self) {
        if let Some(handle) = self.rotation_task.lock().unwrap().take() {
            handle.abort();
        }
    }
} 