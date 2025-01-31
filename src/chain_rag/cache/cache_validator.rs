use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use rand::Rng;
use chrono::{DateTime, Utc};

type HmacSha256 = Hmac<Sha256>;

const POISON_CHECK_INTERVAL_MS: u64 = 1000;
const MAX_VALIDATION_ATTEMPTS: u32 = 3;
const CACHE_ROTATION_HOURS: i64 = 24;

#[derive(Clone, Serialize, Deserialize)]
pub struct CacheEntry {
    data: Vec<u8>,
    hmac: Vec<u8>,
    nonce: Vec<u8>,
    created_at: DateTime<Utc>,
    last_validated: DateTime<Utc>,
    validation_count: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ValidationMetrics {
    total_validations: u64,
    poison_attempts: u64,
    failed_validations: u64,
    last_rotation: DateTime<Utc>,
    compromised_entries: Vec<String>,
}

#[wasm_bindgen]
pub struct CacheValidator {
    cache: Arc<DashMap<String, DashMap<String, CacheEntry>>>,
    metrics: Arc<DashMap<String, ValidationMetrics>>,
    hmac_keys: Arc<RwLock<Vec<Vec<u8>>>>,
    current_key_index: Arc<RwLock<usize>>,
}

#[wasm_bindgen]
impl CacheValidator {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<CacheValidator, JsValue> {
        let validator = CacheValidator {
            cache: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            hmac_keys: Arc::new(RwLock::new(vec![generate_key()?])),
            current_key_index: Arc::new(RwLock::new(0)),
        };

        validator.start_validation_tasks();
        Ok(validator)
    }

    #[wasm_bindgen]
    pub async fn store_entry(
        &self,
        namespace: String,
        key: String,
        data: Vec<u8>,
    ) -> Result<(), JsValue> {
        let nonce = generate_nonce()?;
        let hmac = self.generate_hmac(&data, &nonce).await?;

        let entry = CacheEntry {
            data,
            hmac,
            nonce,
            created_at: Utc::now(),
            last_validated: Utc::now(),
            validation_count: 0,
        };

        self.cache
            .entry(namespace.clone())
            .or_default()
            .insert(key, entry);

        Ok(())
    }

    #[wasm_bindgen]
    pub async fn validate_entry(
        &self,
        namespace: String,
        key: String,
    ) -> Result<bool, JsValue> {
        let namespace_cache = self.cache.get(&namespace)
            .ok_or_else(|| JsValue::from_str("Namespace not found"))?;

        let mut entry = namespace_cache.get_mut(&key)
            .ok_or_else(|| JsValue::from_str("Entry not found"))?;

        if entry.validation_count >= MAX_VALIDATION_ATTEMPTS {
            self.mark_entry_compromised(&namespace, &key).await?;
            return Ok(false);
        }

        let valid = self.verify_hmac(&entry.data, &entry.nonce, &entry.hmac).await?;
        entry.validation_count += 1;
        entry.last_validated = Utc::now();

        if !valid {
            self.update_metrics(&namespace, false).await;
            if entry.validation_count >= MAX_VALIDATION_ATTEMPTS {
                self.mark_entry_compromised(&namespace, &key).await?;
            }
        } else {
            self.update_metrics(&namespace, true).await;
            entry.validation_count = 0; // Reset counter on successful validation
        }

        Ok(valid)
    }

    async fn generate_hmac(&self, data: &[u8], nonce: &[u8]) -> Result<Vec<u8>, JsValue> {
        let keys = self.hmac_keys.read().await;
        let current_index = *self.current_key_index.read().await;
        let key = &keys[current_index];

        let mut mac = HmacSha256::new_from_slice(key)
            .map_err(|e| JsValue::from_str(&format!("HMAC error: {}", e)))?;

        mac.update(nonce);
        mac.update(data);

        Ok(mac.finalize().into_bytes().to_vec())
    }

    async fn verify_hmac(
        &self,
        data: &[u8],
        nonce: &[u8],
        stored_hmac: &[u8],
    ) -> Result<bool, JsValue> {
        let keys = self.hmac_keys.read().await;
        
        // Try all keys in case of recent rotation
        for key in keys.iter() {
            let mut mac = HmacSha256::new_from_slice(key)
                .map_err(|e| JsValue::from_str(&format!("HMAC error: {}", e)))?;

            mac.update(nonce);
            mac.update(data);

            if mac.verify_slice(stored_hmac).is_ok() {
                return Ok(true);
            }
        }

        Ok(false)
    }

    async fn mark_entry_compromised(
        &self,
        namespace: &str,
        key: &str,
    ) -> Result<(), JsValue> {
        self.metrics
            .entry(namespace.to_string())
            .and_modify(|m| {
                m.poison_attempts += 1;
                m.compromised_entries.push(key.to_string());
            });

        // Remove compromised entry
        if let Some(namespace_cache) = self.cache.get_mut(namespace) {
            namespace_cache.remove(key);
        }

        Ok(())
    }

    async fn update_metrics(&self, namespace: &str, valid: bool) {
        self.metrics
            .entry(namespace.to_string())
            .and_modify(|m| {
                m.total_validations += 1;
                if !valid {
                    m.failed_validations += 1;
                }
            })
            .or_insert_with(|| ValidationMetrics {
                total_validations: 1,
                poison_attempts: 0,
                failed_validations: if valid { 0 } else { 1 },
                last_rotation: Utc::now(),
                compromised_entries: Vec::new(),
            });
    }

    async fn rotate_keys(&self) -> Result<(), JsValue> {
        let mut keys = self.hmac_keys.write().await;
        let mut current_index = self.current_key_index.write().await;

        // Generate new key
        keys.push(generate_key()?);
        
        // Update current key index
        *current_index = keys.len() - 1;

        // Keep only last 2 keys for validation overlap
        if keys.len() > 2 {
            keys.remove(0);
            *current_index -= 1;
        }

        // Update rotation timestamp
        for metrics in self.metrics.iter_mut() {
            metrics.last_rotation = Utc::now();
        }

        Ok(())
    }

    fn start_validation_tasks(&self) {
        let validator = Arc::new(self.clone());

        // Periodic validation task
        tokio::spawn({
            let validator = validator.clone();
            async move {
                let mut interval = tokio::time::interval(
                    std::time::Duration::from_millis(POISON_CHECK_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    validator.validate_all_entries().await;
                }
            }
        });

        // Key rotation task
        tokio::spawn({
            let validator = validator.clone();
            async move {
                let mut interval = tokio::time::interval(
                    std::time::Duration::from_secs(CACHE_ROTATION_HOURS as u64 * 3600)
                );
                loop {
                    interval.tick().await;
                    if let Err(e) = validator.rotate_keys().await {
                        web_sys::console::error_1(&e);
                    }
                }
            }
        });

        // Cleanup task
        tokio::spawn({
            let validator = validator.clone();
            async move {
                let mut interval = tokio::time::interval(
                    std::time::Duration::from_secs(3600)
                );
                loop {
                    interval.tick().await;
                    validator.cleanup_old_entries().await;
                }
            }
        });
    }

    async fn validate_all_entries(&self) {
        for namespace_cache in self.cache.iter() {
            let namespace = namespace_cache.key().clone();
            for entry in namespace_cache.value().iter() {
                let key = entry.key().clone();
                if let Err(e) = self.validate_entry(namespace.clone(), key).await {
                    web_sys::console::error_1(&e);
                }
            }
        }
    }

    async fn cleanup_old_entries(&self) {
        let cutoff = Utc::now() - chrono::Duration::hours(CACHE_ROTATION_HOURS);
        
        for namespace_cache in self.cache.iter_mut() {
            namespace_cache.retain(|_, entry| entry.created_at > cutoff);
        }
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self, namespace: String) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get(&namespace) {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&ValidationMetrics {
                total_validations: 0,
                poison_attempts: 0,
                failed_validations: 0,
                last_rotation: Utc::now(),
                compromised_entries: Vec::new(),
            })?)
        }
    }
}

fn generate_key() -> Result<Vec<u8>, JsValue> {
    let mut key = vec![0u8; 32];
    rand::thread_rng()
        .try_fill(&mut key[..])
        .map_err(|e| JsValue::from_str(&format!("Key generation error: {}", e)))?;
    Ok(key)
}

fn generate_nonce() -> Result<Vec<u8>, JsValue> {
    let mut nonce = vec![0u8; 16];
    rand::thread_rng()
        .try_fill(&mut nonce[..])
        .map_err(|e| JsValue::from_str(&format!("Nonce generation error: {}", e)))?;
    Ok(nonce)
}

impl Drop for CacheValidator {
    fn drop(&mut self) {
        self.cache.clear();
        self.metrics.clear();
    }
} 