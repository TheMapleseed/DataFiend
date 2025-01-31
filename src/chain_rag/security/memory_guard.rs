use wasm_bindgen::prelude::*;
use std::sync::Arc;
use zeroize::{Zeroize, ZeroizeOnDrop};
use secrecy::{Secret, ExposeSecret};
use crate::security::crypto_core::CryptoCore;
use crate::resource::resource_limits::ResourceLimiter;

#[derive(Zeroize, ZeroizeOnDrop)]
struct SensitiveData {
    key_material: Vec<u8>,
    tokens: Vec<u8>,
    credentials: Vec<u8>,
}

#[wasm_bindgen]
pub struct MemoryGuard {
    sensitive_data: Arc<RwLock<SensitiveData>>,
    active_buffers: DashMap<String, Vec<u8>>,
    crypto: Arc<CryptoCore>,
    resource_limiter: Arc<ResourceLimiter>,
}

impl MemoryGuard {
    pub fn new(resource_limiter: Arc<ResourceLimiter>) -> Self {
        let crypto = Arc::new(CryptoCore::new().expect("Failed to initialize crypto"));
        Self {
            sensitive_data: Arc::new(RwLock::new(SensitiveData {
                key_material: Vec::new(),
                tokens: Vec::new(),
                credentials: Vec::new(),
            })),
            active_buffers: DashMap::new(),
            crypto,
            resource_limiter,
        }
    }

    pub fn secure_allocate(&self, size: usize) -> Result<Vec<u8>, JsValue> {
        // Check resource limits before allocation
        self.resource_limiter.check_memory_allocation(size)?;
        
        let buffer_id = self.generate_buffer_id();
        let mut buffer = vec![0u8; size];
        buffer.zeroize();
        
        // Register with resource limiter
        self.resource_limiter.register_memory_usage("memory_guard", size)?;
        self.active_buffers.insert(buffer_id, buffer.clone());
        
        Ok(buffer)
    }

    pub fn secure_free(&self, id: &str, mut buffer: Vec<u8>) {
        let size = buffer.len();
        buffer.zeroize();
        self.resource_limiter.deregister_memory_usage("memory_guard", size);
        self.active_buffers.remove(id);
    }

    pub fn store_sensitive(&self, data: &[u8]) -> Result<String, JsValue> {
        let id = self.generate_buffer_id();
        let mut secure_buffer = self.secure_allocate(data.len())?;
        secure_buffer.copy_from_slice(data);
        self.active_buffers.insert(id.clone(), secure_buffer);
        Ok(id)
    }

    pub fn clear_sensitive(&self, id: &str) -> Result<(), JsValue> {
        if let Some((_, mut buffer)) = self.active_buffers.remove(id) {
            buffer.zeroize();
        }
        Ok(())
    }

    pub fn encrypt_sensitive(&self, data: &[u8]) -> Result<Vec<u8>, JsValue> {
        let associated_data = b"memory_protected";
        self.crypto.encrypt_data(data, associated_data)
    }

    pub fn decrypt_sensitive(&self, encrypted: &[u8]) -> Result<Vec<u8>, JsValue> {
        let associated_data = b"memory_protected";
        self.crypto.decrypt_data(encrypted, associated_data)
    }
}

impl Drop for MemoryGuard {
    fn drop(&mut self) {
        // Clear sensitive data first
        if let Ok(mut data) = self.sensitive_data.write() {
            data.key_material.zeroize();
            data.tokens.zeroize();
            data.credentials.zeroize();
        }

        // Clear all active buffers
        for mut entry in self.active_buffers.iter_mut() {
            entry.value_mut().zeroize();
        }
        self.active_buffers.clear();

        // Ensure buffers are flushed
        self.active_buffers.shrink_to_fit();
    }
} 