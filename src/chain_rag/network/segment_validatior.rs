use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, mpsc};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use sha3::{Sha3_512, Digest};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, Instant};

const MAX_SEGMENT_SIZE: usize = 16384; // 16KB
const MIN_SEGMENT_SIZE: usize = 64;    // 64B
const VALIDATION_TIMEOUT_MS: u64 = 1000;
const MAX_VALIDATION_QUEUE: usize = 1000;
const BATCH_SIZE: usize = 100;

#[derive(Clone, Serialize, Deserialize)]
pub struct ValidationMetrics {
    segments_validated: u64,
    segments_rejected: u64,
    validation_errors: u64,
    average_latency_ms: f64,
    current_queue_size: usize,
    validation_rate: f64,
    error_segments: Vec<ErrorSegment>,
    last_validation: u64,
}

#[derive(Clone, Serialize, Deserialize)]
struct ErrorSegment {
    segment_id: String,
    error_type: ValidationErrorType,
    timestamp: u64,
    details: String,
}

#[derive(Clone, Serialize, Deserialize)]
enum ValidationErrorType {
    Size,
    Checksum,
    Format,
    Sequence,
    Timeout,
    Protocol,
}

#[derive(Clone)]
struct SegmentValidation {
    segment_id: String,
    data: Vec<u8>,
    checksum: Vec<u8>,
    sequence: u64,
    protocol_version: u32,
    timestamp: u64,
}

#[wasm_bindgen]
pub struct SegmentValidator {
    metrics: Arc<DashMap<String, ValidationMetrics>>,
    validation_queue: Arc<RwLock<VecDeque<SegmentValidation>>>,
    validated_segments: Arc<DashMap<String, bool>>,
    validation_tx: mpsc::Sender<SegmentValidation>,
    checksums: Arc<DashMap<String, Vec<u8>>>,
}

#[wasm_bindgen]
impl SegmentValidator {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<SegmentValidator, JsValue> {
        let (validation_tx, validation_rx) = mpsc::channel(MAX_VALIDATION_QUEUE);
        
        let validator = SegmentValidator {
            metrics: Arc::new(DashMap::new()),
            validation_queue: Arc::new(RwLock::new(VecDeque::new())),
            validated_segments: Arc::new(DashMap::new()),
            validation_tx,
            checksums: Arc::new(DashMap::new()),
        };

        validator.start_validation_worker(validation_rx)?;
        Ok(validator)
    }

    #[wasm_bindgen]
    pub async fn validate_segment(
        &self,
        segment_id: String,
        data: Vec<u8>,
        checksum: Vec<u8>,
        sequence: u64,
        protocol_version: u32,
    ) -> Result<bool, JsValue> {
        let timestamp = get_timestamp()?;

        // Basic validation checks
        if data.len() > MAX_SEGMENT_SIZE || data.len() < MIN_SEGMENT_SIZE {
            self.record_validation_error(
                &segment_id,
                ValidationErrorType::Size,
                "Invalid segment size",
                timestamp,
            ).await;
            return Ok(false);
        }

        let validation = SegmentValidation {
            segment_id: segment_id.clone(),
            data,
            checksum,
            sequence,
            protocol_version,
            timestamp,
        };

        // Send for async validation
        if let Err(e) = self.validation_tx.send(validation).await {
            self.record_validation_error(
                &segment_id,
                ValidationErrorType::Protocol,
                &format!("Validation queue error: {}", e),
                timestamp,
            ).await;
            return Ok(false);
        }

        // Wait for validation result with timeout
        let timeout = Duration::from_millis(VALIDATION_TIMEOUT_MS);
        match tokio::time::timeout(timeout, self.wait_for_validation(&segment_id)).await {
            Ok(result) => Ok(result),
            Err(_) => {
                self.record_validation_error(
                    &segment_id,
                    ValidationErrorType::Timeout,
                    "Validation timeout",
                    timestamp,
                ).await;
                Ok(false)
            }
        }
    }

    async fn wait_for_validation(&self, segment_id: &str) -> bool {
        let start = Instant::now();
        while start.elapsed() < Duration::from_millis(VALIDATION_TIMEOUT_MS) {
            if let Some(result) = self.validated_segments.get(segment_id) {
                return *result;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        false
    }

    fn start_validation_worker(
        &self,
        mut validation_rx: mpsc::Receiver<SegmentValidation>,
    ) -> Result<(), JsValue> {
        let validator = Arc::new(self.clone());

        tokio::spawn(async move {
            let mut batch = Vec::with_capacity(BATCH_SIZE);
            
            while let Some(validation) = validation_rx.recv().await {
                batch.push(validation);

                if batch.len() >= BATCH_SIZE {
                    if let Err(e) = validator.process_validation_batch(&batch).await {
                        web_sys::console::error_1(&e);
                    }
                    batch.clear();
                }
            }
        });

        Ok(())
    }

    async fn process_validation_batch(
        &self,
        batch: &[SegmentValidation],
    ) -> Result<(), JsValue> {
        let mut validated = 0;
        let mut rejected = 0;
        let start = Instant::now();

        for validation in batch {
            let is_valid = self.perform_validation(validation).await?;
            
            self.validated_segments.insert(
                validation.segment_id.clone(),
                is_valid,
            );

            if is_valid {
                validated += 1;
            } else {
                rejected += 1;
            }
        }

        self.update_metrics(
            validated,
            rejected,
            start.elapsed(),
        ).await;

        Ok(())
    }

    async fn perform_validation(
        &self,
        validation: &SegmentValidation,
    ) -> Result<bool, JsValue> {
        // Verify checksum
        let mut hasher = Sha3_512::new();
        hasher.update(&validation.data);
        let calculated_checksum = hasher.finalize();

        if calculated_checksum.as_slice() != validation.checksum.as_slice() {
            self.record_validation_error(
                &validation.segment_id,
                ValidationErrorType::Checksum,
                "Checksum mismatch",
                validation.timestamp,
            ).await;
            return Ok(false);
        }

        // Verify sequence
        if let Some(prev_checksum) = self.checksums.get(&validation.segment_id) {
            hasher = Sha3_512::new();
            hasher.update(&prev_checksum);
            hasher.update(&validation.data);
            let expected_checksum = hasher.finalize();

            if expected_checksum.as_slice() != validation.checksum.as_slice() {
                self.record_validation_error(
                    &validation.segment_id,
                    ValidationErrorType::Sequence,
                    "Invalid sequence",
                    validation.timestamp,
                ).await;
                return Ok(false);
            }
        }

        // Store checksum for sequence validation
        self.checksums.insert(
            validation.segment_id.clone(),
            validation.checksum.clone(),
        );

        Ok(true)
    }

    async fn record_validation_error(
        &self,
        segment_id: &str,
        error_type: ValidationErrorType,
        details: &str,
        timestamp: u64,
    ) {
        let error = ErrorSegment {
            segment_id: segment_id.to_string(),
            error_type,
            timestamp,
            details: details.to_string(),
        };

        self.metrics
            .entry("global".to_string())
            .and_modify(|m| {
                m.validation_errors += 1;
                m.error_segments.push(error.clone());
                while m.error_segments.len() > 100 {
                    m.error_segments.remove(0);
                }
            });
    }

    async fn update_metrics(
        &self,
        validated: u64,
        rejected: u64,
        duration: Duration,
    ) {
        let queue_size = self.validation_queue.read().await.len();

        self.metrics
            .entry("global".to_string())
            .and_modify(|m| {
                m.segments_validated += validated;
                m.segments_rejected += rejected;
                m.average_latency_ms = (m.average_latency_ms * 0.9)
                    + (duration.as_millis() as f64 * 0.1);
                m.current_queue_size = queue_size;
                m.validation_rate = validated as f64
                    / duration.as_secs_f64();
                m.last_validation = get_timestamp().unwrap_or(0);
            })
            .or_insert_with(|| ValidationMetrics {
                segments_validated: validated,
                segments_rejected: rejected,
                validation_errors: 0,
                average_latency_ms: duration.as_millis() as f64,
                current_queue_size: queue_size,
                validation_rate: validated as f64 / duration.as_secs_f64(),
                error_segments: Vec::new(),
                last_validation: get_timestamp().unwrap_or(0),
            });
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&ValidationMetrics {
                segments_validated: 0,
                segments_rejected: 0,
                validation_errors: 0,
                average_latency_ms: 0.0,
                current_queue_size: 0,
                validation_rate: 0.0,
                error_segments: Vec::new(),
                last_validation: 0,
            })?)
        }
    }
}

fn get_timestamp() -> Result<u64, JsValue> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for SegmentValidator {
    fn drop(&mut self) {
        self.metrics.clear();
        self.validated_segments.clear();
        self.checksums.clear();
    }
}
