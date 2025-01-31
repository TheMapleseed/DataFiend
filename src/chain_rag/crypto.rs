use ring::{aead, digest, pbkdf2, rand};
use ring::rand::SecureRandom;
use std::sync::Arc;
use std::num::NonZeroU32;
use thiserror::Error;
use zeroize::{Zeroize, ZeroizeOnDrop};

// Crypto constants
const PBKDF2_ITERATIONS: u32 = 600_000; // Recommended minimum for PBKDF2-HMAC-SHA256
const KEY_SIZE: usize = 32; // 256 bits
const NONCE_SIZE: usize = 12; // 96 bits for AES-GCM
const TAG_SIZE: usize = 16; // 128 bits
const SALT_SIZE: usize = 32; // 256 bits

#[derive(Debug, Error)]
pub enum CryptoError {
    #[error("Encryption failed: {0}")]
    EncryptionFailed(String),
    
    #[error("Decryption failed: {0}")]
    DecryptionFailed(String),
    
    #[error("Key derivation failed: {0}")]
    KeyDerivationFailed(String),
    
    #[error("Random generation failed: {0}")]
    RandomGenerationFailed(String),
    
    #[error("Invalid key material")]
    InvalidKeyMaterial,
}

#[derive(ZeroizeOnDrop)]
pub struct CryptoManager {
    rng: rand::SystemRandom,
    key_manager: Arc<KeyManager>,
    metrics: Arc<MetricsStore>,
}

#[derive(ZeroizeOnDrop)]
struct KeyManager {
    master_key: aead::LessSafeKey,
    key_encryption_key: [u8; KEY_SIZE],
}

impl CryptoManager {
    pub fn new(metrics: Arc<MetricsStore>) -> Result<Self, CryptoError> {
        let rng = rand::SystemRandom::new();
        
        // Initialize key manager with secure random keys
        let key_manager = KeyManager::new(&rng)?;
        
        Ok(Self {
            rng,
            key_manager: Arc::new(key_manager),
            metrics,
        })
    }

    pub async fn encrypt(&self, data: &[u8], aad: &[u8]) -> Result<EncryptedData, CryptoError> {
        let start = std::time::Instant::now();
        
        // Generate random nonce
        let mut nonce = [0u8; NONCE_SIZE];
        self.rng.fill(&mut nonce)
            .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
            
        // Encrypt data using AES-GCM
        let encrypted = self.key_manager.master_key
            .seal_in_place_append_tag(
                aead::Nonce::assume_unique_for_key(nonce),
                aead::Aad::from(aad),
                data,
            )
            .map_err(|e| CryptoError::EncryptionFailed(e.to_string()))?;
            
        // Record metrics
        self.metrics.record_encryption(start.elapsed()).await;
        
        Ok(EncryptedData {
            ciphertext: encrypted,
            nonce,
        })
    }

    pub async fn decrypt(
        &self,
        encrypted: &EncryptedData,
        aad: &[u8]
    ) -> Result<Vec<u8>, CryptoError> {
        let start = std::time::Instant::now();
        
        // Decrypt data using AES-GCM
        let plaintext = self.key_manager.master_key
            .open_in_place(
                aead::Nonce::assume_unique_for_key(encrypted.nonce),
                aead::Aad::from(aad),
                &mut encrypted.ciphertext.clone(),
            )
            .map_err(|e| CryptoError::DecryptionFailed(e.to_string()))?;
            
        // Record metrics
        self.metrics.record_decryption(start.elapsed()).await;
        
        Ok(plaintext.to_vec())
    }

    pub fn derive_key(&self, password: &[u8], salt: &[u8]) -> Result<[u8; KEY_SIZE], CryptoError> {
        let mut key = [0u8; KEY_SIZE];
        
        pbkdf2::derive(
            pbkdf2::PBKDF2_HMAC_SHA256,
            NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            salt,
            password,
            &mut key,
        );
        
        Ok(key)
    }

    pub fn generate_salt(&self) -> Result<[u8; SALT_SIZE], CryptoError> {
        let mut salt = [0u8; SALT_SIZE];
        self.rng.fill(&mut salt)
            .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
        Ok(salt)
    }

    pub fn hash_data(&self, data: &[u8]) -> digest::Digest {
        digest::digest(&digest::SHA256, data)
    }
}

impl KeyManager {
    fn new(rng: &rand::SystemRandom) -> Result<Self, CryptoError> {
        // Generate master key
        let mut master_key_bytes = [0u8; KEY_SIZE];
        rng.fill(&mut master_key_bytes)
            .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
            
        let master_key = aead::UnboundKey::new(&aead::AES_256_GCM, &master_key_bytes)
            .map_err(|_| CryptoError::InvalidKeyMaterial)?;
            
        // Generate key encryption key
        let mut key_encryption_key = [0u8; KEY_SIZE];
        rng.fill(&mut key_encryption_key)
            .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
            
        Ok(Self {
            master_key: aead::LessSafeKey::new(master_key),
            key_encryption_key,
        })
    }
}

#[derive(Clone)]
pub struct EncryptedData {
    ciphertext: Vec<u8>,
    nonce: [u8; NONCE_SIZE],
}

// Implement secure cleanup
impl Drop for EncryptedData {
    fn drop(&mut self) {
        self.ciphertext.zeroize();
        self.nonce.zeroize();
    }
}

// Helper functions for constant-time operations
pub fn constant_time_compare(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    
    let result = ring::constant_time::verify_slices_are_equal(a, b);
    result.is_ok()
}

// Helper for secure random number generation
pub fn generate_random_bytes(len: usize) -> Result<Vec<u8>, CryptoError> {
    let mut bytes = vec![0u8; len];
    rand::SystemRandom::new()
        .fill(&mut bytes)
        .map_err(|e| CryptoError::RandomGenerationFailed(e.to_string()))?;
    Ok(bytes)
} 