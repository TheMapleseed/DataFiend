use std::sync::Arc;
use tokio::sync::RwLock;
use thiserror::Error;
use reed_solomon_erasure::ReedSolomon;
use blake3::Hasher;
use serde::{Serialize, Deserialize};

const ECC_DATA_SHARDS: usize = 10;
const ECC_PARITY_SHARDS: usize = 4;
const MAX_SHARD_SIZE: usize = 1024 * 1024; // 1MB
const HASH_SIZE: usize = 32;

#[derive(Debug, Error)]
pub enum ECCError {
    #[error("Encoding failed: {0}")]
    EncodingFailed(String),
    
    #[error("Decoding failed: {0}")]
    DecodingFailed(String),
    
    #[error("Data corruption detected: {0}")]
    DataCorruption(String),
    
    #[error("Invalid shard size: {0}")]
    InvalidShardSize(usize),
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ECCBlock {
    data_shards: Vec<Vec<u8>>,
    parity_shards: Vec<Vec<u8>>,
    original_len: usize,
    hash: [u8; HASH_SIZE],
}

pub struct ECCSystem {
    reed_solomon: Arc<ReedSolomon>,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
}

impl ECCSystem {
    pub fn new(
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Result<Self, ECCError> {
        let reed_solomon = ReedSolomon::new(ECC_DATA_SHARDS, ECC_PARITY_SHARDS)
            .map_err(|e| ECCError::EncodingFailed(e.to_string()))?;

        Ok(Self {
            reed_solomon: Arc::new(reed_solomon),
            metrics,
            error_handler,
        })
    }

    pub async fn encode_data(&self, data: &[u8]) -> Result<ECCBlock, ECCError> {
        if data.len() > MAX_SHARD_SIZE * ECC_DATA_SHARDS {
            return Err(ECCError::InvalidShardSize(data.len()));
        }

        // Calculate data hash
        let mut hasher = Hasher::new();
        hasher.update(data);
        let hash = hasher.finalize();

        // Split data into shards
        let shard_size = (data.len() + ECC_DATA_SHARDS - 1) / ECC_DATA_SHARDS;
        let mut data_shards: Vec<Vec<u8>> = Vec::with_capacity(ECC_DATA_SHARDS);
        
        for i in 0..ECC_DATA_SHARDS {
            let start = i * shard_size;
            let end = (start + shard_size).min(data.len());
            let mut shard = vec![0u8; shard_size];
            
            if start < data.len() {
                shard[..end-start].copy_from_slice(&data[start..end]);
            }
            
            data_shards.push(shard);
        }

        // Generate parity shards
        let mut parity_shards: Vec<Vec<u8>> = vec![vec![0u8; shard_size]; ECC_PARITY_SHARDS];
        let mut shards: Vec<&mut [u8]> = data_shards
            .iter_mut()
            .chain(parity_shards.iter_mut())
            .map(|shard| shard.as_mut_slice())
            .collect();

        self.reed_solomon
            .encode(&mut shards)
            .map_err(|e| ECCError::EncodingFailed(e.to_string()))?;

        self.metrics.record_ecc_encode().await;

        Ok(ECCBlock {
            data_shards,
            parity_shards,
            original_len: data.len(),
            hash: hash.into(),
        })
    }

    pub async fn decode_data(&self, block: &ECCBlock) -> Result<Vec<u8>, ECCError> {
        // Prepare shards
        let mut all_shards: Vec<Option<Vec<u8>>> = Vec::with_capacity(
            ECC_DATA_SHARDS + ECC_PARITY_SHARDS
        );
        
        all_shards.extend(block.data_shards.iter().cloned().map(Some));
        all_shards.extend(block.parity_shards.iter().cloned().map(Some));

        let mut shards: Vec<&mut [u8]> = all_shards
            .iter_mut()
            .flatten()
            .map(|shard| shard.as_mut_slice())
            .collect();

        // Reconstruct if necessary
        if self.reed_solomon.reconstruct(&mut shards)
            .map_err(|e| ECCError::DecodingFailed(e.to_string()))? 
        {
            self.metrics.record_ecc_reconstruction().await;
        }

        // Combine data shards
        let mut result = Vec::with_capacity(block.original_len);
        for shard in &block.data_shards {
            result.extend_from_slice(shard);
        }
        result.truncate(block.original_len);

        // Verify hash
        let mut hasher = Hasher::new();
        hasher.update(&result);
        let hash = hasher.finalize();

        if hash.as_bytes() != &block.hash {
            self.error_handler.handle_error(
                ECCError::DataCorruption("Hash mismatch after reconstruction".into()),
                "ecc_decode".into()
            ).await;
            return Err(ECCError::DataCorruption("Data integrity check failed".into()));
        }

        self.metrics.record_ecc_decode().await;
        Ok(result)
    }
} 