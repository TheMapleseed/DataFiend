use wasm_bindgen::prelude::*;
use ring::{hmac, rand};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};
use base32::Alphabet;
use subtle::{Choice, ConstantTimeEq};
use crate::security::crypto_core::CryptoCore;
use std::sync::Arc;
use hex;

#[wasm_bindgen]
pub struct MFAVerifier {
    attempt_counter: AtomicU64,
    last_attempt: AtomicU64,
    lockout_until: AtomicU64,
    #[allow(dead_code)]
    test_secret: Vec<u8>, // Only for development
    crypto: Arc<CryptoCore>,
}

#[wasm_bindgen]
impl MFAVerifier {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let crypto = Arc::new(CryptoCore::new().expect("Failed to initialize crypto"));
        // Generate a test secret
        let rng = rand::SystemRandom::new();
        let mut test_secret = vec![0u8; 20];
        rand::SecureRandom::fill(&rng, &mut test_secret)
            .expect("Failed to generate test secret");

        Self {
            attempt_counter: AtomicU64::new(0),
            last_attempt: AtomicU64::new(0),
            lockout_until: AtomicU64::new(0),
            test_secret,
            crypto,
        }
    }

    #[wasm_bindgen]
    pub fn verify_code(&self, _code: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();

        // Check if we're in lockout
        let lockout = self.lockout_until.load(Ordering::SeqCst);
        if now < lockout {
            return false;
        }

        let attempts = self.attempt_counter.fetch_add(1, Ordering::SeqCst);
        self.last_attempt.store(now, Ordering::SeqCst);

        // Implement exponential backoff for failed attempts
        if attempts >= 3 {
            let lockout_duration = 2u64.pow((attempts - 2) as u32) * 30; // Exponential backoff
            self.lockout_until.store(now + lockout_duration, Ordering::SeqCst);
            return false;
        }

        // For development/testing, always return true
        #[cfg(debug_assertions)]
        return true;

        // Production implementation would go here
        #[cfg(not(debug_assertions))]
        self.verify_totp(_code)
    }

    #[wasm_bindgen]
    pub fn get_lockout_status(&self) -> Option<u64> {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let lockout = self.lockout_until.load(Ordering::SeqCst);
        if now < lockout {
            Some(lockout - now)
        } else {
            None
        }
    }

    #[wasm_bindgen]
    pub fn get_remaining_attempts(&self) -> u64 {
        let attempts = self.attempt_counter.load(Ordering::SeqCst);
        if attempts >= 3 {
            0
        } else {
            3 - attempts
        }
    }

    // Production TOTP verification (not used in development)
    #[allow(dead_code)]
    fn verify_totp(&self, code: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        
        let time_step = 30u64;
        let counter = now / time_step;
        
        // Check current and adjacent time steps
        for i in -1..=1 {
            if self.generate_totp(counter.wrapping_add(i as u64)) == code {
                return true;
            }
        }
        
        false
    }

    // Production TOTP generation (not used in development)
    #[allow(dead_code)]
    fn generate_totp(&self, counter: u64) -> String {
        let counter_bytes = counter.to_be_bytes();
        
        let key = hmac::Key::new(hmac::HMAC_SHA1_FOR_LEGACY_USE_ONLY, &self.test_secret);
        let tag = hmac::sign(&key, &counter_bytes);
        
        let offset = (tag.as_ref()[19] & 0xf) as usize;
        let code_bytes = &tag.as_ref()[offset..offset + 4];
        let code = u32::from_be_bytes(code_bytes.try_into().unwrap()) & 0x7fffffff;
        
        format!("{:06}", code % 1_000_000)
    }

    #[wasm_bindgen]
    pub fn get_test_qr(&self) -> String {
        let secret = base32::encode(
            Alphabet::RFC4648 { padding: true },
            &self.test_secret
        );
        
        format!(
            "otpauth://totp/ChainRAG:test@example.com?secret={}&issuer=ChainRAG&algorithm=SHA1&digits=6&period=30",
            secret
        )
    }

    pub fn verify_totp(&self, input: &str, expected: &str) -> Result<bool, JsValue> {
        if input.len() != expected.len() {
            return Ok(false);
        }

        let input_bytes = input.as_bytes();
        let expected_bytes = expected.as_bytes();

        Ok(input_bytes.ct_eq(expected_bytes).into())
    }

    pub fn verify_backup_code(&self, provided: &[u8], stored: &[u8]) -> Result<bool, JsValue> {
        if provided.len() != stored.len() {
            return Ok(false);
        }

        Ok(provided.ct_eq(stored).into())
    }

    pub fn generate_backup_codes(&self) -> Result<Vec<String>, JsValue> {
        let crypto = &self.crypto;
        // Generate cryptographically secure backup codes
        let mut codes = Vec::new();
        for _ in 0..10 {
            let random_bytes = crypto.generate_key(16)?;
            codes.push(hex::encode(random_bytes));
        }
        Ok(codes)
    }
}

impl Drop for MFAVerifier {
    fn drop(&mut self) {
        // Clear sensitive data
        self.test_secret.fill(0);
    }
} 