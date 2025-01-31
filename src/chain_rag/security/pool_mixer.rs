use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use sha3::{Sha3_512, Digest};
use chacha20poly1305::{ChaCha20Poly1305, Key, Nonce};
use chacha20poly1305::aead::{Aead, NewAead};
use blake3::Hasher as Blake3Hasher;
use std::collections::VecDeque;

const POOL_SIZE: usize = 4096;
const MIN_MIXING_ROUNDS: usize = 3;
const MAX_MIXING_ROUNDS: usize = 10;
const POOL_COUNT: usize = 4;
const MIXING_INTERVAL_MS: u64 = 100;

#[derive(Clone, Serialize, Deserialize)]
pub struct MixingMetrics {
    total_mixes: u64,
    bytes_processed: u64,
    average_entropy: f64,
    pool_health: Vec<f64>,
    last_mix: u64,
    mixing_rounds: usize,
}

#[derive(Clone)]
struct Pool {
    data: Vec<u8>,
    entropy_estimate: f64,
    last_update: u64,
}

#[wasm_bindgen]
pub struct PoolMixer {
    pools: Arc<RwLock<Vec<Pool>>>,
    metrics: Arc<DashMap<String, MixingMetrics>>,
    mixing_history: Arc<RwLock<VecDeque<Vec<u8>>>>,
    chacha: Arc<RwLock<ChaCha20Poly1305>>,
    blake3: Arc<RwLock<Blake3Hasher>>,
}

#[wasm_bindgen]
impl PoolMixer {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<PoolMixer, JsValue> {
        let key = Key::from_slice(&generate_key()?);
        let chacha = ChaCha20Poly1305::new(key);

        let mixer = PoolMixer {
            pools: Arc::new(RwLock::new(vec![
                Pool::new(POOL_SIZE),
                Pool::new(POOL_SIZE),
                Pool::new(POOL_SIZE),
                Pool::new(POOL_SIZE),
            ])),
            metrics: Arc::new(DashMap::new()),
            mixing_history: Arc::new(RwLock::new(VecDeque::new())),
            chacha: Arc::new(RwLock::new(chacha)),
            blake3: Arc::new(RwLock::new(Blake3Hasher::new())),
        };

        mixer.start_mixing_tasks();
        Ok(mixer)
    }

    #[wasm_bindgen]
    pub async fn add_entropy(
        &self,
        data: Vec<u8>,
        source_entropy: f64,
    ) -> Result<(), JsValue> {
        let timestamp = get_timestamp()?;
        let mut pools = self.pools.write().await;

        // Distribute entropy across pools using different mixing strategies
        for (i, pool) in pools.iter_mut().enumerate() {
            let mut mixed = self.mix_input(
                &data,
                &pool.data,
                i as u8,
                timestamp,
            ).await?;

            // Additional mixing based on pool position
            match i {
                0 => self.fast_mix(&mut mixed).await?,
                1 => self.slow_mix(&mut mixed).await?,
                2 => self.cryptographic_mix(&mut mixed).await?,
                3 => self.hybrid_mix(&mut mixed).await?,
                _ => unreachable!(),
            }

            pool.update(mixed, source_entropy);
        }

        self.update_metrics(data.len(), source_entropy).await;
        Ok(())
    }

    async fn mix_input(
        &self,
        input: &[u8],
        pool: &[u8],
        pool_id: u8,
        timestamp: u64,
    ) -> Result<Vec<u8>, JsValue> {
        let mut hasher = Sha3_512::new();
        
        // Mix with multiple rounds
        let rounds = self.calculate_mixing_rounds(input.len());
        let mut mixed = pool.to_vec();

        for round in 0..rounds {
            // Add round-specific data
            hasher.update(&[round as u8]);
            hasher.update(&[pool_id]);
            hasher.update(&timestamp.to_le_bytes());
            
            // Mix input with pool
            hasher.update(input);
            hasher.update(&mixed);
            
            // Additional mixing with ChaCha20Poly1305
            let nonce = Nonce::from_slice(&generate_nonce()?);
            let chacha = self.chacha.read().await;
            mixed = chacha.encrypt(nonce, mixed.as_ref())
                .map_err(|e| JsValue::from_str(&format!("Encryption error: {}", e)))?;
            
            // Final mixing with BLAKE3
            let mut blake3 = self.blake3.write().await;
            blake3.update(&mixed);
            mixed = blake3.finalize().as_bytes().to_vec();
        }

        Ok(mixed)
    }

    async fn fast_mix(&self, data: &mut Vec<u8>) -> Result<(), JsValue> {
        // XOR-based fast mixing
        let mut temp = vec![0u8; data.len()];
        for i in 0..data.len() {
            temp[i] = data[i] ^ data[(i + 1) % data.len()];
        }
        data.copy_from_slice(&temp);
        Ok(())
    }

    async fn slow_mix(&self, data: &mut Vec<u8>) -> Result<(), JsValue> {
        // Diffusion-based slow mixing
        let mut temp = vec![0u8; data.len()];
        for _ in 0..3 {
            for i in 0..data.len() {
                let left = data[(i + data.len() - 1) % data.len()];
                let right = data[(i + 1) % data.len()];
                temp[i] = data[i].wrapping_add(left).wrapping_mul(right);
            }
            data.copy_from_slice(&temp);
        }
        Ok(())
    }

    async fn cryptographic_mix(&self, data: &mut Vec<u8>) -> Result<(), JsValue> {
        // ChaCha20Poly1305 + BLAKE3 mixing
        let nonce = Nonce::from_slice(&generate_nonce()?);
        let chacha = self.chacha.read().await;
        
        *data = chacha.encrypt(nonce, data.as_ref())
            .map_err(|e| JsValue::from_str(&format!("Encryption error: {}", e)))?;

        let mut blake3 = self.blake3.write().await;
        blake3.update(data);
        *data = blake3.finalize().as_bytes().to_vec();
        
        Ok(())
    }

    async fn hybrid_mix(&self, data: &mut Vec<u8>) -> Result<(), JsValue> {
        // Combine multiple mixing strategies
        self.fast_mix(data).await?;
        self.cryptographic_mix(data).await?;
        self.slow_mix(data).await?;
        Ok(())
    }

    fn calculate_mixing_rounds(&self, input_size: usize) -> usize {
        let base_rounds = MIN_MIXING_ROUNDS;
        let additional_rounds = (input_size / 1024).min(MAX_MIXING_ROUNDS - MIN_MIXING_ROUNDS);
        base_rounds + additional_rounds
    }

    async fn update_metrics(&self, bytes: usize, source_entropy: f64) {
        let pools = self.pools.read().await;
        let pool_health: Vec<f64> = pools.iter()
            .map(|p| p.entropy_estimate)
            .collect();

        let average_entropy = pool_health.iter().sum::<f64>() / pool_health.len() as f64;

        self.metrics
            .entry("global".to_string())
            .and_modify(|m| {
                m.total_mixes += 1;
                m.bytes_processed += bytes as u64;
                m.average_entropy = (m.average_entropy * 0.9) + (average_entropy * 0.1);
                m.pool_health = pool_health.clone();
                m.last_mix = get_timestamp().unwrap_or(0);
                m.mixing_rounds = self.calculate_mixing_rounds(bytes);
            })
            .or_insert_with(|| MixingMetrics {
                total_mixes: 1,
                bytes_processed: bytes as u64,
                average_entropy: source_entropy,
                pool_health,
                last_mix: get_timestamp().unwrap_or(0),
                mixing_rounds: self.calculate_mixing_rounds(bytes),
            });
    }

    fn start_mixing_tasks(&self) {
        let mixer = Arc::new(self.clone());

        // Continuous mixing task
        tokio::spawn({
            let mixer = mixer.clone();
            async move {
                let mut interval = tokio::time::interval(
                    std::time::Duration::from_millis(MIXING_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    if let Err(e) = mixer.mix_pools().await {
                        web_sys::console::error_1(&e);
                    }
                }
            }
        });

        // Health monitoring task
        tokio::spawn({
            let mixer = mixer.clone();
            async move {
                let mut interval = tokio::time::interval(
                    std::time::Duration::from_secs(60)
                );
                loop {
                    interval.tick().await;
                    mixer.monitor_pool_health().await;
                }
            }
        });
    }

    async fn mix_pools(&self) -> Result<(), JsValue> {
        let mut pools = self.pools.write().await;
        let timestamp = get_timestamp()?;

        // Cross-pool mixing
        for i in 0..pools.len() {
            let mut mixed = Vec::new();
            for j in 0..pools.len() {
                if i != j {
                    mixed.extend_from_slice(&pools[j].data);
                }
            }

            let mixed = self.mix_input(
                &mixed,
                &pools[i].data,
                i as u8,
                timestamp,
            ).await?;

            pools[i].data = mixed;
        }

        Ok(())
    }

    async fn monitor_pool_health(&self) {
        let pools = self.pools.read().await;
        let mut unhealthy_pools = Vec::new();

        for (i, pool) in pools.iter().enumerate() {
            if pool.entropy_estimate < 0.5 {
                unhealthy_pools.push(i);
            }
        }

        if !unhealthy_pools.is_empty() {
            web_sys::console::warn_1(
                &JsValue::from_str(&format!(
                    "Low entropy detected in pools: {:?}",
                    unhealthy_pools
                ))
            );
        }
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&MixingMetrics {
                total_mixes: 0,
                bytes_processed: 0,
                average_entropy: 0.0,
                pool_health: vec![0.0; POOL_COUNT],
                last_mix: 0,
                mixing_rounds: MIN_MIXING_ROUNDS,
            })?)
        }
    }
}

impl Pool {
    fn new(size: usize) -> Self {
        Self {
            data: vec![0u8; size],
            entropy_estimate: 0.0,
            last_update: get_timestamp().unwrap_or(0),
        }
    }

    fn update(&mut self, new_data: Vec<u8>, source_entropy: f64) {
        self.data = new_data;
        self.entropy_estimate = (self.entropy_estimate * 0.9) + (source_entropy * 0.1);
        self.last_update = get_timestamp().unwrap_or(0);
    }
}

fn generate_key() -> Result<[u8; 32], JsValue> {
    let mut key = [0u8; 32];
    getrandom::getrandom(&mut key)
        .map_err(|e| JsValue::from_str(&format!("Key generation error: {}", e)))?;
    Ok(key)
}

fn generate_nonce() -> Result<[u8; 12], JsValue> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce)
        .map_err(|e| JsValue::from_str(&format!("Nonce generation error: {}", e)))?;
    Ok(nonce)
}

fn get_timestamp() -> Result<u64, JsValue> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for PoolMixer {
    fn drop(&mut self) {
        self.metrics.clear();
    }
} 