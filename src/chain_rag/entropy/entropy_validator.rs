use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::collections::VecDeque;
use statrs::distribution::{ChiSquared, ContinuousCDF};
use bitvec::prelude::*;

const MIN_SAMPLE_SIZE: usize = 2048;
const MAX_HISTORY_SIZE: usize = 100;
const SIGNIFICANCE_LEVEL: f64 = 0.01;
const MIN_ENTROPY_BITS: f64 = 7.5;
const BLOCK_SIZE: usize = 8;

#[derive(Clone, Serialize, Deserialize)]
pub struct ValidationMetrics {
    chi_square_score: f64,
    entropy_bits: f64,
    monobit_score: f64,
    runs_test_score: f64,
    longest_run_score: f64,
    serial_correlation: f64,
    sample_size: usize,
    failed_tests: Vec<String>,
    timestamp: u64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct QualityMetrics {
    current_quality: EntropyQuality,
    historical_scores: VecDeque<ValidationMetrics>,
    total_validations: u64,
    total_failures: u64,
    degradation_detected: bool,
}

#[derive(Clone, Serialize, Deserialize, PartialEq)]
pub enum EntropyQuality {
    Excellent,
    Good,
    Fair,
    Poor,
    Critical,
}

#[wasm_bindgen]
pub struct EntropyValidator {
    metrics: Arc<DashMap<String, QualityMetrics>>,
    validation_history: Arc<RwLock<VecDeque<ValidationMetrics>>>,
    current_sample: Arc<RwLock<Vec<u8>>>,
}

#[wasm_bindgen]
impl EntropyValidator {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let validator = Self {
            metrics: Arc::new(DashMap::new()),
            validation_history: Arc::new(RwLock::new(VecDeque::with_capacity(MAX_HISTORY_SIZE))),
            current_sample: Arc::new(RwLock::new(Vec::with_capacity(MIN_SAMPLE_SIZE))),
        };

        validator.start_validation_tasks();
        validator
    }

    #[wasm_bindgen]
    pub async fn validate_sample(&self, sample: Vec<u8>) -> Result<bool, JsValue> {
        if sample.len() < MIN_SAMPLE_SIZE {
            return Err(JsValue::from_str("Sample size too small"));
        }

        let mut failed_tests = Vec::new();
        let mut metrics = ValidationMetrics {
            chi_square_score: 0.0,
            entropy_bits: 0.0,
            monobit_score: 0.0,
            runs_test_score: 0.0,
            longest_run_score: 0.0,
            serial_correlation: 0.0,
            sample_size: sample.len(),
            failed_tests: Vec::new(),
            timestamp: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs(),
        };

        // Chi-square test
        metrics.chi_square_score = self.perform_chi_square_test(&sample)?;
        if !self.validate_chi_square(metrics.chi_square_score) {
            failed_tests.push("chi_square".to_string());
        }

        // Entropy calculation
        metrics.entropy_bits = self.calculate_entropy(&sample)?;
        if metrics.entropy_bits < MIN_ENTROPY_BITS {
            failed_tests.push("entropy".to_string());
        }

        // Monobit test
        metrics.monobit_score = self.perform_monobit_test(&sample)?;
        if !self.validate_monobit(metrics.monobit_score) {
            failed_tests.push("monobit".to_string());
        }

        // Runs test
        metrics.runs_test_score = self.perform_runs_test(&sample)?;
        if !self.validate_runs(metrics.runs_test_score) {
            failed_tests.push("runs".to_string());
        }

        // Longest run test
        metrics.longest_run_score = self.perform_longest_run_test(&sample)?;
        if !self.validate_longest_run(metrics.longest_run_score) {
            failed_tests.push("longest_run".to_string());
        }

        // Serial correlation test
        metrics.serial_correlation = self.calculate_serial_correlation(&sample)?;
        if !self.validate_serial_correlation(metrics.serial_correlation) {
            failed_tests.push("serial_correlation".to_string());
        }

        metrics.failed_tests = failed_tests.clone();

        // Update history and metrics
        self.update_validation_history(metrics.clone()).await;
        self.update_quality_metrics(failed_tests.is_empty(), metrics.clone());

        Ok(failed_tests.is_empty())
    }

    fn perform_chi_square_test(&self, sample: &[u8]) -> Result<f64, JsValue> {
        let mut counts = vec![0; 256];
        for &byte in sample {
            counts[byte as usize] += 1;
        }

        let expected = sample.len() as f64 / 256.0;
        let chi_square: f64 = counts.iter()
            .map(|&count| {
                let diff = count as f64 - expected;
                diff * diff / expected
            })
            .sum();

        Ok(chi_square)
    }

    fn calculate_entropy(&self, sample: &[u8]) -> Result<f64, JsValue> {
        let mut counts = vec![0; 256];
        for &byte in sample {
            counts[byte as usize] += 1;
        }

        let sample_size = sample.len() as f64;
        let entropy: f64 = counts.iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / sample_size;
                -p * p.log2()
            })
            .sum();

        Ok(entropy)
    }

    fn perform_monobit_test(&self, sample: &[u8]) -> Result<f64, JsValue> {
        let bits = BitVec::<u8, Msb0>::from_slice(sample);
        let ones = bits.count_ones();
        let zeros = bits.len() - ones;
        
        let diff = (ones as f64 - zeros as f64).abs();
        let score = diff / (sample.len() as f64 * 8.0).sqrt();
        
        Ok(score)
    }

    fn perform_runs_test(&self, sample: &[u8]) -> Result<f64, JsValue> {
        let bits = BitVec::<u8, Msb0>::from_slice(sample);
        let mut runs = 0;
        let mut prev = false;

        for bit in bits.iter() {
            if *bit != prev {
                runs += 1;
                prev = *bit;
            }
        }

        let expected_runs = (2.0 * bits.len() as f64 - 1.0) / 3.0;
        let score = (runs as f64 - expected_runs).abs() / expected_runs.sqrt();
        
        Ok(score)
    }

    fn perform_longest_run_test(&self, sample: &[u8]) -> Result<f64, JsValue> {
        let bits = BitVec::<u8, Msb0>::from_slice(sample);
        let mut max_run = 0;
        let mut current_run = 0;
        let mut prev = false;

        for bit in bits.iter() {
            if *bit == prev {
                current_run += 1;
                max_run = max_run.max(current_run);
            } else {
                current_run = 1;
                prev = *bit;
            }
        }

        let expected_max = (bits.len() as f64).log2().floor();
        let score = (max_run as f64 - expected_max).abs() / expected_max.sqrt();
        
        Ok(score)
    }

    fn calculate_serial_correlation(&self, sample: &[u8]) -> Result<f64, JsValue> {
        if sample.len() < 2 {
            return Ok(0.0);
        }

        let n = sample.len() - 1;
        let mut sum_xy = 0.0;
        let mut sum_x = 0.0;
        let mut sum_y = 0.0;
        let mut sum_x2 = 0.0;
        let mut sum_y2 = 0.0;

        for i in 0..n {
            let x = sample[i] as f64;
            let y = sample[i + 1] as f64;
            sum_xy += x * y;
            sum_x += x;
            sum_y += y;
            sum_x2 += x * x;
            sum_y2 += y * y;
        }

        let correlation = (n as f64 * sum_xy - sum_x * sum_y) /
            ((n as f64 * sum_x2 - sum_x * sum_x) *
             (n as f64 * sum_y2 - sum_y * sum_y)).sqrt();

        Ok(correlation)
    }

    fn validate_chi_square(&self, score: f64) -> bool {
        let df = 255.0; // 256 categories - 1
        let chi_dist = ChiSquared::new(df).unwrap();
        let p_value = 1.0 - chi_dist.cdf(score);
        p_value > SIGNIFICANCE_LEVEL
    }

    fn validate_monobit(&self, score: f64) -> bool {
        score < 1.96 // 95% confidence interval
    }

    fn validate_runs(&self, score: f64) -> bool {
        score < 1.96 // 95% confidence interval
    }

    fn validate_longest_run(&self, score: f64) -> bool {
        score < 1.96 // 95% confidence interval
    }

    fn validate_serial_correlation(&self, correlation: f64) -> bool {
        correlation.abs() < 0.1 // Arbitrary threshold for independence
    }

    async fn update_validation_history(&self, metrics: ValidationMetrics) {
        let mut history = self.validation_history.write().await;
        history.push_back(metrics);
        while history.len() > MAX_HISTORY_SIZE {
            history.pop_front();
        }
    }

    fn update_quality_metrics(&self, passed: bool, metrics: ValidationMetrics) {
        self.metrics
            .entry("global".to_string())
            .and_modify(|m| {
                m.total_validations += 1;
                if !passed {
                    m.total_failures += 1;
                }
                m.historical_scores.push_back(metrics.clone());
                while m.historical_scores.len() > MAX_HISTORY_SIZE {
                    m.historical_scores.pop_front();
                }
                m.current_quality = self.determine_quality(&m.historical_scores);
                m.degradation_detected = self.detect_degradation(&m.historical_scores);
            })
            .or_insert_with(|| {
                let mut scores = VecDeque::new();
                scores.push_back(metrics);
                QualityMetrics {
                    current_quality: EntropyQuality::Good,
                    historical_scores: scores,
                    total_validations: 1,
                    total_failures: if passed { 0 } else { 1 },
                    degradation_detected: false,
                }
            });
    }

    fn determine_quality(&self, history: &VecDeque<ValidationMetrics>) -> EntropyQuality {
        let recent: Vec<_> = history.iter().rev().take(10).collect();
        let avg_entropy = recent.iter()
            .map(|m| m.entropy_bits)
            .sum::<f64>() / recent.len() as f64;

        match avg_entropy {
            e if e >= 7.9 => EntropyQuality::Excellent,
            e if e >= 7.5 => EntropyQuality::Good,
            e if e >= 7.0 => EntropyQuality::Fair,
            e if e >= 6.5 => EntropyQuality::Poor,
            _ => EntropyQuality::Critical,
        }
    }

    fn detect_degradation(&self, history: &VecDeque<ValidationMetrics>) -> bool {
        if history.len() < 10 {
            return false;
        }

        let recent: Vec<_> = history.iter().rev().take(10).collect();
        let old: Vec<_> = history.iter().rev().skip(10).take(10).collect();

        if recent.is_empty() || old.is_empty() {
            return false;
        }

        let recent_avg = recent.iter().map(|m| m.entropy_bits).sum::<f64>() / recent.len() as f64;
        let old_avg = old.iter().map(|m| m.entropy_bits).sum::<f64>() / old.len() as f64;

        (old_avg - recent_avg) > 0.5 // Significant degradation threshold
    }

    fn start_validation_tasks(&self) {
        let validator = Arc::new(self.clone());

        tokio::spawn({
            let validator = validator.clone();
            async move {
                let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
                loop {
                    interval.tick().await;
                    validator.perform_periodic_validation().await;
                }
            }
        });
    }

    async fn perform_periodic_validation(&self) {
        let sample = self.current_sample.read().await.clone();
        if sample.len() >= MIN_SAMPLE_SIZE {
            if let Err(e) = self.validate_sample(sample).await {
                web_sys::console::error_1(&e);
            }
        }
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&QualityMetrics {
                current_quality: EntropyQuality::Good,
                historical_scores: VecDeque::new(),
                total_validations: 0,
                total_failures: 0,
                degradation_detected: false,
            })?)
        }
    }
}

impl Drop for EntropyValidator {
    fn drop(&mut self) {
        self.metrics.clear();
    }
} 