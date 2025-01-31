use rand::{Rng, thread_rng};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};

pub struct TimeDrift {
    base_drift: AtomicU64,
    jitter_range: RwLock<(u64, u64)>,
    last_update: AtomicU64,
    update_frequency: AtomicU64,
}

impl TimeDrift {
    pub fn new() -> Self {
        let mut rng = thread_rng();
        let initial_drift = rng.gen_range(100..1000);
        let initial_jitter = (rng.gen_range(50..200), rng.gen_range(200..500));
        
        let drift = Self {
            base_drift: AtomicU64::new(initial_drift),
            jitter_range: RwLock::new(initial_jitter),
            last_update: AtomicU64::new(Self::current_time_ms()),
            update_frequency: AtomicU64::new(rng.gen_range(1000..5000)),
        };

        drift.start_drift_updates();
        drift
    }

    fn current_time_ms() -> u64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap_or(Duration::from_secs(0))
            .as_millis() as u64
    }

    pub fn get_time(&self) -> u64 {
        let current = Self::current_time_ms();
        let base = self.base_drift.load(Ordering::Relaxed);
        let jitter = self.calculate_jitter();
        
        current.wrapping_add(base).wrapping_add(jitter)
    }

    fn calculate_jitter(&self) -> u64 {
        let range = self.jitter_range.read();
        let mut rng = thread_rng();
        rng.gen_range(range.0..range.1)
    }

    fn start_drift_updates(&self) {
        let drift_clone = std::sync::Arc::new(self.clone());
        
        std::thread::spawn(move || {
            let mut rng = thread_rng();
            loop {
                let sleep_time = rng.gen_range(100..1000);
                std::thread::sleep(Duration::from_millis(sleep_time));
                
                drift_clone.update_drift();
            }
        });
    }

    fn update_drift(&self) {
        let current = Self::current_time_ms();
        let last = self.last_update.load(Ordering::Relaxed);
        let freq = self.update_frequency.load(Ordering::Relaxed);

        if current - last > freq {
            let mut rng = thread_rng();
            
            // Update base drift
            let new_drift = rng.gen_range(100..1000);
            self.base_drift.store(new_drift, Ordering::Relaxed);

            // Update jitter range
            let mut range = self.jitter_range.write();
            *range = (rng.gen_range(50..200), rng.gen_range(200..500));

            // Update frequency
            let new_freq = rng.gen_range(1000..5000);
            self.update_frequency.store(new_freq, Ordering::Relaxed);

            // Update timestamp
            self.last_update.store(current, Ordering::Relaxed);
        }
    }
}

#[derive(Clone)]
pub struct DriftAwareToken {
    value: [u8; 32],
    drift_window: (u64, u64),
    created_at: u64,
}

impl DriftAwareToken {
    pub fn new(value: [u8; 32], drift: &TimeDrift) -> Self {
        let current = drift.get_time();
        let mut rng = thread_rng();
        let window_size = rng.gen_range(5000..15000);
        
        Self {
            value,
            drift_window: (current, current + window_size),
            created_at: current,
        }
    }

    pub fn is_valid(&self, drift: &TimeDrift) -> bool {
        let current = drift.get_time();
        let age = current.wrapping_sub(self.created_at);
        
        // Check if token is within its drift window
        current >= self.drift_window.0 && 
        current <= self.drift_window.1 && 
        age < self.drift_window.1.wrapping_sub(self.drift_window.0)
    }
}

pub struct DriftManager {
    drift: TimeDrift,
    token_buffer: RwLock<Vec<DriftAwareToken>>,
    max_tokens: usize,
}

impl DriftManager {
    pub fn new(max_tokens: usize) -> Self {
        Self {
            drift: TimeDrift::new(),
            token_buffer: RwLock::new(Vec::with_capacity(max_tokens)),
            max_tokens,
        }
    }

    pub fn create_token(&self, value: [u8; 32]) -> DriftAwareToken {
        let token = DriftAwareToken::new(value, &self.drift);
        
        let mut buffer = self.token_buffer.write();
        if buffer.len() >= self.max_tokens {
            buffer.remove(0); // Remove oldest token
        }
        buffer.push(token.clone());
        
        token
    }

    pub fn validate_token(&self, token: &DriftAwareToken) -> bool {
        let buffer = self.token_buffer.read();
        
        // Check if token exists and is valid
        buffer.iter().any(|t| {
            t.value == token.value && 
            t.is_valid(&self.drift)
        })
    }

    pub fn get_current_time(&self) -> u64 {
        self.drift.get_time()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_drift_variation() {
        let drift = TimeDrift::new();
        let initial = drift.get_time();
        
        // Test multiple readings
        let mut times = Vec::new();
        for _ in 0..100 {
            std::thread::sleep(Duration::from_millis(10));
            times.push(drift.get_time());
        }

        // Verify time progression isn't linear
        let differences: Vec<i64> = times.windows(2)
            .map(|w| w[1] as i64 - w[0] as i64)
            .collect();
            
        let unique_diffs: std::collections::HashSet<_> = 
            differences.iter().copied().collect();
            
        // Should have multiple different time steps
        assert!(unique_diffs.len() > 1);
    }
} 