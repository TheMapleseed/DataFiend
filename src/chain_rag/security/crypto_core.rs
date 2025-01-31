use wasm_bindgen::prelude::*;
use std::sync::Arc;
use ring::{
    aead::{self, BoundKey, Aead, NonceSequence, NONCE_LEN, AES_256_GCM, UnboundKey},
    digest::{Context, SHA512},
    pbkdf2::{self, PBKDF2_HMAC_SHA512},
    rand::{SecureRandom, SystemRandom},
};
use chacha20poly1305::{
    aead::{Aead as ChaChaAead, NewAead, Payload},
    ChaCha20Poly1305, Key, Nonce,
};
use argon2::{self, Config, ThreadMode, Variant, Version};
use zeroize::{Zeroize, ZeroizeOnDrop};
use crate::resource::resource_limits::ResourceLimiter;

const PBKDF2_ITERATIONS: u32 = 600_000; // Updated to modern standards
const ARGON2_MEMORY_SIZE: u32 = 4096; // 4GB in KB
const ARGON2_ITERATIONS: u32 = 3;
const ARGON2_PARALLELISM: u32 = 4;

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct CryptoCore {
    rng: SystemRandom,
    master_key: Vec<u8>,
    aead_key: Arc<RwLock<UnboundKey>>,
    chacha_key: Arc<RwLock<ChaCha20Poly1305>>,
    resource_limiter: Arc<ResourceLimiter>,
}

impl CryptoCore {
    pub fn new(resource_limiter: Arc<ResourceLimiter>) -> Result<Self, JsValue> {
        let rng = SystemRandom::new();
        
        // Check and register key allocations
        resource_limiter.check_memory_allocation(32)?; // master key
        resource_limiter.check_memory_allocation(32)?; // aead key
        
        let mut master_key = vec![0u8; 32];
        rng.fill(&mut master_key)
            .map_err(|_| JsValue::from_str("Failed to generate master key"))?;

        let mut aead_key_bytes = vec![0u8; 32];
        rng.fill(&mut aead_key_bytes)
            .map_err(|_| JsValue::from_str("Failed to generate AEAD key"))?;

        // Register key memory usage
        resource_limiter.register_memory_usage("crypto_core", 64)?;

        let aead_key = UnboundKey::new(&AES_256_GCM, &aead_key_bytes)
            .map_err(|_| JsValue::from_str("Failed to create AEAD key"))?;

        let chacha_key = ChaCha20Poly1305::new(Key::from_slice(&master_key));

        Ok(Self {
            rng,
            master_key,
            aead_key: Arc::new(RwLock::new(aead_key)),
            chacha_key: Arc::new(RwLock::new(chacha_key)),
            resource_limiter,
        })
    }

    pub fn hash_password(&self, password: &[u8]) -> Result<Vec<u8>, JsValue> {
        let mut salt = vec![0u8; 16];
        self.rng.fill(&mut salt)
            .map_err(|_| JsValue::from_str("Failed to generate salt"))?;

        let config = Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: ARGON2_MEMORY_SIZE,
            time_cost: ARGON2_ITERATIONS,
            lanes: ARGON2_PARALLELISM,
            thread_mode: ThreadMode::Parallel,
            secret: &self.master_key,
            ad: &[],
            hash_length: 32
        };

        argon2::hash_raw(password, &salt, &config)
            .map_err(|e| JsValue::from_str(&format!("Failed to hash password: {}", e)))
    }

    pub fn verify_password(&self, password: &[u8], hash: &[u8]) -> Result<bool, JsValue> {
        let config = Config {
            variant: Variant::Argon2id,
            version: Version::Version13,
            mem_cost: ARGON2_MEMORY_SIZE,
            time_cost: ARGON2_ITERATIONS,
            lanes: ARGON2_PARALLELISM,
            thread_mode: ThreadMode::Parallel,
            secret: &self.master_key,
            ad: &[],
            hash_length: 32
        };

        argon2::verify_raw(password, &hash[16..], &hash[..16], &config)
            .map_err(|e| JsValue::from_str(&format!("Failed to verify password: {}", e)))
    }

    pub fn encrypt_data(&self, data: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, JsValue> {
        // Check resource limits for encryption output (data + nonce + tag)
        let estimated_size = data.len() + 12 + 16;
        self.resource_limiter.check_memory_allocation(estimated_size)?;
        
        let mut nonce = vec![0u8; 12];
        self.rng.fill(&mut nonce)
            .map_err(|_| JsValue::from_str("Failed to generate nonce"))?;

        let chacha = self.chacha_key.read().unwrap();
        let payload = Payload {
            msg: data,
            aad: associated_data,
        };

        let ciphertext = chacha.encrypt(Nonce::from_slice(&nonce), payload)
            .map_err(|_| JsValue::from_str("Encryption failed"))?;

        // Register actual memory usage
        let total_size = nonce.len() + ciphertext.len();
        self.resource_limiter.register_memory_usage("crypto_core", total_size)?;

        let mut result = Vec::with_capacity(total_size);
        result.extend_from_slice(&nonce);
        result.extend_from_slice(&ciphertext);
        Ok(result)
    }

    pub fn decrypt_data(&self, encrypted_data: &[u8], associated_data: &[u8]) -> Result<Vec<u8>, JsValue> {
        if encrypted_data.len() < 12 {
            return Err(JsValue::from_str("Invalid encrypted data"));
        }

        let (nonce, ciphertext) = encrypted_data.split_at(12);
        let chacha = self.chacha_key.read().unwrap();
        let payload = Payload {
            msg: ciphertext,
            aad: associated_data,
        };

        chacha.decrypt(Nonce::from_slice(nonce), payload)
            .map_err(|_| JsValue::from_str("Decryption failed"))
    }

    pub fn generate_key(&self, len: usize) -> Result<Vec<u8>, JsValue> {
        let mut key = vec![0u8; len];
        self.rng.fill(&mut key)
            .map_err(|_| JsValue::from_str("Failed to generate key"))?;
        Ok(key)
    }

    pub fn secure_hash(&self, data: &[u8]) -> Vec<u8> {
        let mut context = Context::new(&SHA512);
        context.update(data);
        context.finish().as_ref().to_vec()
    }

    pub fn derive_key(&self, password: &[u8], salt: &[u8], len: usize) -> Result<Vec<u8>, JsValue> {
        let mut key = vec![0u8; len];
        pbkdf2::derive(
            PBKDF2_HMAC_SHA512,
            NonZeroU32::new(PBKDF2_ITERATIONS).unwrap(),
            salt,
            password,
            &mut key
        );
        Ok(key)
    }
}

impl Drop for CryptoCore {
    fn drop(&mut self) {
        // Zero out sensitive cryptographic material
        self.master_key.zeroize();
        
        // Clear AEAD key
        if let Ok(mut key) = self.aead_key.write() {
            // Use as_mut_slice() to get mutable access to the underlying bytes
            if let Ok(key_bytes) = key.as_mut_slice() {
                key_bytes.zeroize();
            }
        }
        
        // Clear ChaCha key
        if let Ok(mut chacha) = self.chacha_key.write() {
            // Access and clear the key material
            chacha.cloned_key_bytes().zeroize();
        }
    }
} 