use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use sha3::{Sha3_512, Digest};
use std::collections::VecDeque;
use statrs::distribution::{ChiSquared, ContinuousCDF};
use bitvec::prelude::*;

const MIN_SAMPLE_SIZE: usize = 1024;
const VERIFICATION_ROUNDS: usize = 3;
const HISTORY_SIZE: usize = 100;
const MIN_ENTROPY_SCORE: f64 = 0.75;
const SIGNIFICANCE_LEVEL: f64 = 0.01;

#[derive(Clone, Serialize, Deserialize)]
pub struct SourceMetrics {
    source_id: String,
    entropy_score: f64,
    reliability_score: f64,
    verification_count: u64,
    failure_count: u64,
    last_verified: u64,
    statistical_scores: StatisticalScores,
    verification_history: VecDeque<VerificationResult>,
}

#[derive(Clone, Serialize, Deserialize)]
struct StatisticalScores {
    chi_square: f64,
    entropy_bits: f64,
    monte_carlo_pi: f64,
    serial_correlation: f64,
    longest_run: f64,
    monobit_frequency: f64,
}

#[derive(Clone, Serialize, Deserialize)]
struct VerificationResult {
    timestamp: u64,
    passed: bool,
    entropy_score: f64,
    failure_reasons: Vec<String>,
}

#[wasm_bindgen]
pub struct EntropyVerifier {
    sources: Arc<DashMap<String, SourceMetrics>>,
    verification_history: Arc<RwLock<VecDeque<VerificationResult>>>,
    current_verifications: Arc<DashMap<String, u64>>,
}

#[wasm_bindgen]
impl EntropyVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let verifier = Self {
            sources: Arc::new(DashMap::new()),
            verification_history: Arc::new(RwLock::new(VecDeque::with_capacity(HISTORY_SIZE))),
            current_verifications: Arc::new(DashMap::new()),
        };

        verifier.start_verification_tasks();
        verifier
    }

    #[wasm_bindgen]
    pub async fn verify_source(
        &self,
        source_id: String,
        sample: Vec<u8>,
    ) -> Result<bool, JsValue> {
        if sample.len() < MIN_SAMPLE_SIZE {
            return Err(JsValue::from_str("Sample size too small"));
        }

        let mut failure_reasons = Vec::new();
        let timestamp = get_timestamp()?;

        // Perform multiple verification rounds
        let mut total_entropy_score = 0.0;
        for round in 0..VERIFICATION_ROUNDS {
            let round_sample = self.prepare_round_sample(&sample, round)?;
            
            // Statistical tests
            let stats = self.perform_statistical_tests(&round_sample)?;
            
            // Verify individual metrics
            if !self.verify_chi_square(stats.chi_square) {
                failure_reasons.push(format!("Chi-square test failed in round {}", round));
            }
            
            if stats.entropy_bits < 7.0 {
                failure_reasons.push(format!("Low entropy bits in round {}", round));
            }
            
            if !self.verify_monte_carlo_pi(stats.monte_carlo_pi) {
                failure_reasons.push(format!("Monte Carlo PI test failed in round {}", round));
            }
            
            if !self.verify_serial_correlation(stats.serial_correlation) {
                failure_reasons.push(format!("High serial correlation in round {}", round));
            }
            
            total_entropy_score += self.calculate_entropy_score(&stats);
        }

        let avg_entropy_score = total_entropy_score / VERIFICATION_ROUNDS as f64;
        let passed = failure_reasons.is_empty() && avg_entropy_score >= MIN_ENTROPY_SCORE;

        // Update source metrics
        self.update_source_metrics(
            &source_id,
            passed,
            avg_entropy_score,
            failure_reasons.clone(),
            timestamp,
        ).await;

        Ok(passed)
    }

    fn prepare_round_sample(&self, sample: &[u8], round: usize) -> Result<Vec<u8>, JsValue> {
        let mut hasher = Sha3_512::new();
        hasher.update(&[round as u8]);
        hasher.update(sample);
        Ok(hasher.finalize().to_vec())
    }

    fn perform_statistical_tests(&self, sample: &[u8]) -> Result<StatisticalScores, JsValue> {
        let chi_square = self.calculate_chi_square(sample)?;
        let entropy_bits = self.calculate_entropy_bits(sample)?;
        let monte_carlo_pi = self.estimate_pi(sample)?;
        let serial_correlation = self.calculate_serial_correlation(sample)?;
        let longest_run = self.find_longest_run(sample)?;
        let monobit_frequency = self.calculate_monobit_frequency(sample)?;

        Ok(StatisticalScores {
            chi_square,
            entropy_bits,
            monte_carlo_pi,
            serial_correlation,
            longest_run,
            monobit_frequency,
        })
    }

    fn calculate_chi_square(&self, sample: &[u8]) -> Result<f64, JsValue> {
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

    fn calculate_entropy_bits(&self, sample: &[u8]) -> Result<f64, JsValue> {
        let mut counts = vec![0; 256];
        for &byte in sample {
            counts[byte as usize] += 1;
        }

        let len = sample.len() as f64;
        let entropy: f64 = counts.iter()
            .filter(|&&count| count > 0)
            .map(|&count| {
                let p = count as f64 / len;
                -p * p.log2()
            })
            .sum();

        Ok(entropy)
    }

    fn estimate_pi(&self, sample: &[u8]) -> Result<f64, JsValue> {
        let mut inside = 0u32;
        let mut total = 0u32;

        for chunk in sample.chunks(8) {
            if chunk.len() < 8 {
                continue;
            }

            let x = (chunk[0] as f64 * 256.0 + chunk[1] as f64) / 65535.0;
            let y = (chunk[2] as f64 * 256.0 + chunk[3] as f64) / 65535.0;

            if x * x + y * y <= 1.0 {
                inside += 1;
            }
            total += 1;
        }

        Ok(4.0 * inside as f64 / total as f64)
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

    fn find_longest_run(&self, sample: &[u8]) -> Result<f64, JsValue> {
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

        Ok(max_run as f64)
    }

    fn calculate_monobit_frequency(&self, sample: &[u8]) -> Result<f64, JsValue> {
        let bits = BitVec::<u8, Msb0>::from_slice(sample);
        let ones = bits.count_ones();
        let zeros = bits.len() - ones;
        
        let diff = (ones as f64 - zeros as f64).abs();
        Ok(diff / (sample.len() as f64 * 8.0).sqrt())
    }

    fn verify_chi_square(&self, score: f64) -> bool {
        let df = 255.0; // 256 categories - 1
        let chi_dist = ChiSquared::new(df).unwrap();
        let p_value = 1.0 - chi_dist.cdf(score);
        p_value > SIGNIFICANCE_LEVEL
    }

    fn verify_monte_carlo_pi(&self, pi_estimate: f64) -> bool {
        (pi_estimate - std::f64::consts::PI).abs() < 0.1
    }

    fn verify_serial_correlation(&self, correlation: f64) -> bool {
        correlation.abs() < 0.1
    }

    fn calculate_entropy_score(&self, stats: &StatisticalScores) -> f64 {
        let mut score = 0.0;
        
        // Weight different statistical measures
        score += if self.verify_chi_square(stats.chi_square) { 0.3 } else { 0.0 };
        score += (stats.entropy_bits / 8.0).min(1.0) * 0.3;
        score += if self.verify_monte_carlo_pi(stats.monte_carlo_pi) { 0.2 } else { 0.0 };
        score += if self.verify_serial_correlation(stats.serial_correlation) { 0.2 } else { 0.0 };

        score
    }

    async fn update_source_metrics(
        &self,
        source_id: &str,
        passed: bool,
        entropy_score: f64,
        failure_reasons: Vec<String>,
        timestamp: u64,
    ) {
        let result = VerificationResult {
            timestamp,
            passed,
            entropy_score,
            failure_reasons,
        };

        self.sources
            .entry(source_id.to_string())
            .and_modify(|m| {
                m.verification_count += 1;
                if !passed {
                    m.failure_count += 1;
                }
                m.entropy_score = (m.entropy_score * 0.9) + (entropy_score * 0.1);
                m.reliability_score = 1.0 - (m.failure_count as f64 / m.verification_count as f64);
                m.last_verified = timestamp;
                m.verification_history.push_back(result.clone());
                while m.verification_history.len() > HISTORY_SIZE {
                    m.verification_history.pop_front();
                }
            })
            .or_insert_with(|| {
                let mut history = VecDeque::new();
                history.push_back(result.clone());
                SourceMetrics {
                    source_id: source_id.to_string(),
                    entropy_score,
                    reliability_score: if passed { 1.0 } else { 0.0 },
                    verification_count: 1,
                    failure_count: if passed { 0 } else { 1 },
                    last_verified: timestamp,
                    statistical_scores: StatisticalScores {
                        chi_square: 0.0,
                        entropy_bits: 0.0,
                        monte_carlo_pi: 0.0,
                        serial_correlation: 0.0,
                        longest_run: 0.0,
                        monobit_frequency: 0.0,
                    },
                    verification_history: history,
                }
            });

        let mut history = self.verification_history.write().await;
        history.push_back(result);
        while history.len() > HISTORY_SIZE {
            history.pop_front();
        }
    }

    fn start_verification_tasks(&self) {
        let verifier = Arc::new(self.clone());

        // Periodic cleanup task
        tokio::spawn({
            let verifier = verifier.clone();
            async move {
                let mut interval = tokio::time::interval(
                    std::time::Duration::from_secs(3600)
                );
                loop {
                    interval.tick().await;
                    verifier.cleanup_old_verifications();
                }
            }
        });
    }

    fn cleanup_old_verifications(&self) {
        let cutoff = get_timestamp().unwrap_or(0) - 86400; // 24 hours
        self.sources.retain(|_, m| m.last_verified > cutoff);
        self.current_verifications.retain(|_, &mut t| t > cutoff);
    }

    #[wasm_bindgen]
    pub fn get_source_metrics(&self, source_id: String) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.sources.get(&source_id) {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Err(JsValue::from_str("Source not found"))
        }
    }
}

fn get_timestamp() -> Result<u64, JsValue> {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for EntropyVerifier {
    fn drop(&mut self) {
        self.sources.clear();
        self.current_verifications.clear();
    }
} 