use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use rand::{RngCore, SeedableRng, rngs::StdRng};
use rand_chacha::ChaCha20Rng;
use getrandom::getrandom;
use sha2::{Sha512, Digest};
use std::time::{SystemTime, UNIX_EPOCH};
use std::collections::VecDeque;

const ENTROPY_POOL_SIZE: usize = 1024;
const MIN_ENTROPY_THRESHOLD: f64 = 0.75;
const RESEED_INTERVAL_MS: u64 = 1000;
const MAX_POOL_AGE_MS: u64 = 5000;

#[derive(Clone, Serialize, Deserialize)]
pub struct EntropyMetrics {
    hardware_failures: u64,
    software_fallbacks: u64,
    total_bytes_generated: u64,
    current_entropy_estimate: f64,
    last_reseed: u64,
    pool_health: PoolHealth,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum PoolHealth {
    Healthy,
    Degraded,
    Critical,
}

#[derive(Clone)]
struct EntropySource {
    priority: u8,
    source_type: SourceType,
    last_failure: Option<u64>,
    success_rate: f64,
}

#[derive(Clone)]
enum SourceType {
    Hardware,
    SystemRng,
    TimeBased,
    ChaCha20,
    Hybrid,
}

#[wasm_bindgen]
pub struct EntropyManager {
    primary_pool: Arc<RwLock<Vec<u8>>>,
    secondary_pool: Arc<RwLock<Vec<u8>>>,
    sources: Arc<DashMap<String, EntropySource>>,
    metrics: Arc<DashMap<String, EntropyMetrics>>,
    chacha_rng: Arc<RwLock<ChaCha20Rng>>,
    mixing_queue: Arc<RwLock<VecDeque<Vec<u8>>>>,
}

#[wasm_bindgen]
impl EntropyManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<EntropyManager, JsValue> {
        let mut initial_seed = [0u8; 32];
        if let Err(_) = getrandom(&mut initial_seed) {
            // Fallback to system time + process specific data
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))?;
            
            let mut hasher = Sha512::new();
            hasher.update(now.as_nanos().to_le_bytes());
            hasher.update(std::process::id().to_le_bytes());
            let hash = hasher.finalize();
            initial_seed.copy_from_slice(&hash[..32]);
        }

        let manager = EntropyManager {
            primary_pool: Arc::new(RwLock::new(Vec::with_capacity(ENTROPY_POOL_SIZE))),
            secondary_pool: Arc::new(RwLock::new(Vec::with_capacity(ENTROPY_POOL_SIZE))),
            sources: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            chacha_rng: Arc::new(RwLock::new(ChaCha20Rng::from_seed(initial_seed))),
            mixing_queue: Arc::new(RwLock::new(VecDeque::new())),
        };

        manager.initialize_sources();
        manager.start_entropy_tasks();
        Ok(manager)
    }

    fn initialize_sources(&self) {
        // Hardware RNG
        self.sources.insert("hardware".to_string(), EntropySource {
            priority: 1,
            source_type: SourceType::Hardware,
            last_failure: None,
            success_rate: 1.0,
        });

        // System RNG
        self.sources.insert("system".to_string(), EntropySource {
            priority: 2,
            source_type: SourceType::SystemRng,
            last_failure: None,
            success_rate: 1.0,
        });

        // ChaCha20 CSPRNG
        self.sources.insert("chacha20".to_string(), EntropySource {
            priority: 3,
            source_type: SourceType::ChaCha20,
            last_failure: None,
            success_rate: 1.0,
        });

        // Time-based entropy
        self.sources.insert("time".to_string(), EntropySource {
            priority: 4,
            source_type: SourceType::TimeBased,
            last_failure: None,
            success_rate: 1.0,
        });

        // Hybrid source
        self.sources.insert("hybrid".to_string(), EntropySource {
            priority: 5,
            source_type: SourceType::Hybrid,
            last_failure: None,
            success_rate: 1.0,
        });
    }

    #[wasm_bindgen]
    pub async fn generate_random_bytes(
        &self,
        length: usize,
    ) -> Result<Vec<u8>, JsValue> {
        let mut result = vec![0u8; length];
        let mut bytes_generated = 0;

        // Try sources in priority order
        for source in self.get_available_sources() {
            if bytes_generated >= length {
                break;
            }

            match self.generate_from_source(&source, length - bytes_generated).await {
                Ok(bytes) => {
                    result[bytes_generated..bytes_generated + bytes.len()]
                        .copy_from_slice(&bytes);
                    bytes_generated += bytes.len();
                    self.update_source_metrics(&source, true);
                }
                Err(_) => {
                    self.update_source_metrics(&source, false);
                    continue;
                }
            }
        }

        if bytes_generated < length {
            return Err(JsValue::from_str("Failed to generate enough random bytes"));
        }

        self.mix_entropy(&result).await?;
        Ok(result)
    }

    async fn generate_from_source(
        &self,
        source: &EntropySource,
        length: usize,
    ) -> Result<Vec<u8>, JsValue> {
        let mut bytes = vec![0u8; length];

        match source.source_type {
            SourceType::Hardware => {
                getrandom(&mut bytes)
                    .map_err(|e| JsValue::from_str(&format!("Hardware RNG error: {}", e)))?;
            }
            SourceType::SystemRng => {
                StdRng::from_entropy().try_fill_bytes(&mut bytes)
                    .map_err(|e| JsValue::from_str(&format!("System RNG error: {}", e)))?;
            }
            SourceType::ChaCha20 => {
                self.chacha_rng.write().await.fill_bytes(&mut bytes);
            }
            SourceType::TimeBased => {
                let now = SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))?;
                
                let mut hasher = Sha512::new();
                hasher.update(now.as_nanos().to_le_bytes());
                hasher.update(&bytes);
                let hash = hasher.finalize();
                bytes.copy_from_slice(&hash[..length]);
            }
            SourceType::Hybrid => {
                // Mix multiple sources
                let mut hybrid_bytes = Vec::new();
                hybrid_bytes.extend_from_slice(&self.primary_pool.read().await);
                hybrid_bytes.extend_from_slice(&self.secondary_pool.read().await);
                
                let mut hasher = Sha512::new();
                hasher.update(&hybrid_bytes);
                let hash = hasher.finalize();
                bytes.copy_from_slice(&hash[..length]);
            }
        }

        Ok(bytes)
    }

    async fn mix_entropy(&self, new_bytes: &[u8]) -> Result<(), JsValue> {
        let mut mixing_queue = self.mixing_queue.write().await;
        mixing_queue.push_back(new_bytes.to_vec());

        while mixing_queue.len() > 16 {
            mixing_queue.pop_front();
        }

        let mut mixed = Vec::new();
        for bytes in mixing_queue.iter() {
            mixed.extend_from_slice(bytes);
        }

        let mut hasher = Sha512::new();
        hasher.update(&mixed);
        let hash = hasher.finalize();

        let mut primary_pool = self.primary_pool.write().await;
        let mut secondary_pool = self.secondary_pool.write().await;

        primary_pool.extend_from_slice(&hash[..32]);
        secondary_pool.extend_from_slice(&hash[32..]);

        while primary_pool.len() > ENTROPY_POOL_SIZE {
            primary_pool.remove(0);
        }
        while secondary_pool.len() > ENTROPY_POOL_SIZE {
            secondary_pool.remove(0);
        }

        Ok(())
    }

    fn get_available_sources(&self) -> Vec<EntropySource> {
        let mut sources: Vec<_> = self.sources
            .iter()
            .map(|entry| entry.value().clone())
            .collect();
        
        sources.sort_by_key(|s| s.priority);
        sources
    }

    fn update_source_metrics(&self, source: &EntropySource, success: bool) {
        if let Some(mut src) = self.sources.get_mut(match source.source_type {
            SourceType::Hardware => "hardware",
            SourceType::SystemRng => "system",
            SourceType::ChaCha20 => "chacha20",
            SourceType::TimeBased => "time",
            SourceType::Hybrid => "hybrid",
        }) {
            if success {
                src.success_rate = src.success_rate * 0.9 + 0.1;
                src.last_failure = None;
            } else {
                src.success_rate = src.success_rate * 0.9;
                src.last_failure = Some(
                    SystemTime::now()
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_millis() as u64
                );
            }
        }
    }

    fn start_entropy_tasks(&self) {
        let manager = Arc::new(self.clone());

        // Reseed task
        tokio::spawn({
            let manager = manager.clone();
            async move {
                let mut interval = tokio::time::interval(
                    std::time::Duration::from_millis(RESEED_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    if let Err(e) = manager.reseed().await {
                        web_sys::console::error_1(&e);
                    }
                }
            }
        });

        // Health check task
        tokio::spawn({
            let manager = manager.clone();
            async move {
                let mut interval = tokio::time::interval(
                    std::time::Duration::from_millis(1000)
                );
                loop {
                    interval.tick().await;
                    manager.update_health_metrics().await;
                }
            }
        });
    }

    async fn reseed(&self) -> Result<(), JsValue> {
        let mut seed = [0u8; 32];
        getrandom(&mut seed)
            .map_err(|e| JsValue::from_str(&format!("Reseed error: {}", e)))?;

        let mut rng = self.chacha_rng.write().await;
        *rng = ChaCha20Rng::from_seed(seed);

        Ok(())
    }

    async fn update_health_metrics(&self) {
        let pool_health = if self.get_entropy_estimate() < MIN_ENTROPY_THRESHOLD {
            PoolHealth::Critical
        } else if self.sources.iter().any(|s| s.value().last_failure.is_some()) {
            PoolHealth::Degraded
        } else {
            PoolHealth::Healthy
        };

        let metrics = EntropyMetrics {
            hardware_failures: self.sources
                .get("hardware")
                .map(|s| s.last_failure.is_some() as u64)
                .unwrap_or(0),
            software_fallbacks: self.sources
                .iter()
                .filter(|s| matches!(s.value().source_type, SourceType::SystemRng | SourceType::ChaCha20))
                .filter(|s| s.value().last_failure.is_none())
                .count() as u64,
            total_bytes_generated: self.primary_pool.read().await.len() as u64
                + self.secondary_pool.read().await.len() as u64,
            current_entropy_estimate: self.get_entropy_estimate(),
            last_reseed: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64,
            pool_health,
        };

        self.metrics.insert("global".to_string(), metrics);
    }

    fn get_entropy_estimate(&self) -> f64 {
        self.sources
            .iter()
            .map(|s| s.value().success_rate)
            .sum::<f64>() / self.sources.len() as f64
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&EntropyMetrics {
                hardware_failures: 0,
                software_fallbacks: 0,
                total_bytes_generated: 0,
                current_entropy_estimate: 1.0,
                last_reseed: 0,
                pool_health: PoolHealth::Healthy,
            })?)
        }
    }
}

impl Drop for EntropyManager {
    fn drop(&mut self) {
        self.sources.clear();
        self.metrics.clear();
    }
}
