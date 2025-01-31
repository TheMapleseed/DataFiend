use wasm_bindgen::prelude::*;
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};
use secrecy::{Secret, ExposeSecret};
use crate::security::crypto_core::CryptoCore;
use crate::resource::resource_limits::ResourceLimiter;

#[derive(Zeroize, ZeroizeOnDrop)]
struct SecretEntry {
    value: Vec<u8>,
    metadata: SecretMetadata,
}

#[derive(Zeroize)]
struct SecretMetadata {
    created_at: u64,
    accessed_at: u64,
    rotation_due: u64,
}

#[wasm_bindgen]
pub struct SecretStore {
    secrets: DashMap<String, Arc<RwLock<SecretEntry>>>,
    crypto: Arc<CryptoCore>,
    resource_limiter: Arc<ResourceLimiter>,
}

impl SecretStore {
    pub fn new(resource_limiter: Arc<ResourceLimiter>) -> Self {
        let crypto = Arc::new(CryptoCore::new().expect("Failed to initialize crypto"));
        Self {
            secrets: DashMap::new(),
            crypto,
            resource_limiter,
        }
    }

    pub fn store_secret(&self, id: &str, value: &[u8]) -> Result<(), JsValue> {
        // Check resource limits before encryption
        self.resource_limiter.check_memory_allocation(value.len())?;
        
        let encrypted = self.crypto.encrypt_data(value, id.as_bytes())?;
        
        // Register with resource limiter
        self.resource_limiter.register_memory_usage("secret_store", encrypted.len())?;
        
        let entry = SecretEntry {
            value: encrypted,
            metadata: SecretMetadata {
                created_at: self.current_timestamp()?,
                accessed_at: self.current_timestamp()?,
                rotation_due: self.current_timestamp()? + self.rotation_interval(),
            },
        };
        
        self.secrets.insert(id.to_string(), Arc::new(RwLock::new(entry)));
        Ok(())
    }

    pub fn retrieve_secret(&self, id: &str) -> Result<Vec<u8>, JsValue> {
        let entry = self.secrets.get(id)
            .ok_or_else(|| JsValue::from_str("Secret not found"))?;
        let encrypted = entry.value().value.clone();
        self.crypto.decrypt_data(&encrypted, id.as_bytes())
    }

    pub fn clear_secret(&self, id: &str) -> Result<(), JsValue> {
        if let Some((_, entry)) = self.secrets.remove(id) {
            let size = entry.read().unwrap().value.len();
            self.resource_limiter.deregister_memory_usage("secret_store", size);
        }
        Ok(())
    }
}

impl Drop for SecretStore {
    fn drop(&mut self) {
        // Clear all secrets
        for mut entry in self.secrets.iter_mut() {
            if let Ok(mut secret) = entry.value().write() {
                // Zero out the encrypted value
                secret.value.zeroize();
                // Zero out metadata
                secret.metadata.zeroize();
            }
        }
        
        // Clear the collection
        self.secrets.clear();
        
        // Force memory deallocation
        self.secrets.shrink_to_fit();
    }
} 