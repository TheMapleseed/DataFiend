use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::HashMap;
use chrono::{DateTime, Utc, Duration};
use ring::{rand, hmac};
use serde::{Serialize, Deserialize};
use dashmap::DashMap;

#[derive(Clone, Serialize, Deserialize)]
struct SessionData {
    user_id: String,
    created_at: DateTime<Utc>,
    expires_at: DateTime<Utc>,
    last_activity: DateTime<Utc>,
    mfa_verified: bool,
    ip_address: String,
    user_agent: String,
    permissions: Vec<String>,
}

#[wasm_bindgen]
pub struct SessionManager {
    sessions: Arc<DashMap<String, SessionData>>,
    invalidated: Arc<DashMap<String, DateTime<Utc>>>,
    key: hmac::Key,
    cleanup_interval: Duration,
}

#[wasm_bindgen]
impl SessionManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let rng = rand::SystemRandom::new();
        let mut key_bytes = vec![0u8; 32];
        rand::SecureRandom::fill(&rng, &mut key_bytes)
            .expect("Failed to generate session key");

        let manager = Self {
            sessions: Arc::new(DashMap::new()),
            invalidated: Arc::new(DashMap::new()),
            key: hmac::Key::new(hmac::HMAC_SHA256, &key_bytes),
            cleanup_interval: Duration::minutes(5),
        };

        // Start cleanup task
        manager.start_cleanup();
        manager
    }

    #[wasm_bindgen]
    pub fn create_session(
        &self,
        user_id: &str,
        ip_address: &str,
        user_agent: &str,
        permissions: Vec<String>,
    ) -> Result<String, JsValue> {
        let session_id = self.generate_session_id();
        let now = Utc::now();

        let session = SessionData {
            user_id: user_id.to_string(),
            created_at: now,
            expires_at: now + Duration::hours(24),
            last_activity: now,
            mfa_verified: false,
            ip_address: ip_address.to_string(),
            user_agent: user_agent.to_string(),
            permissions,
        };

        self.sessions.insert(session_id.clone(), session);
        Ok(session_id)
    }

    #[wasm_bindgen]
    pub fn invalidate_session(&self, session_id: &str) -> bool {
        if let Some((_, session)) = self.sessions.remove(session_id) {
            self.invalidated.insert(
                session_id.to_string(),
                Utc::now() + Duration::hours(24)
            );
            true
        } else {
            false
        }
    }

    #[wasm_bindgen]
    pub fn invalidate_all_user_sessions(&self, user_id: &str) {
        let sessions_to_invalidate: Vec<String> = self.sessions
            .iter()
            .filter(|r| r.value().user_id == user_id)
            .map(|r| r.key().clone())
            .collect();

        for session_id in sessions_to_invalidate {
            self.invalidate_session(&session_id);
        }
    }

    #[wasm_bindgen]
    pub fn verify_session(&self, session_id: &str) -> bool {
        // Check if session is in invalidated list
        if self.invalidated.contains_key(session_id) {
            return false;
        }

        if let Some(mut session) = self.sessions.get_mut(session_id) {
            let now = Utc::now();
            
            // Check expiration
            if session.expires_at < now {
                self.invalidate_session(session_id);
                return false;
            }

            // Update last activity
            session.last_activity = now;
            true
        } else {
            false
        }
    }

    #[wasm_bindgen]
    pub fn extend_session(&self, session_id: &str) -> bool {
        if let Some(mut session) = self.sessions.get_mut(session_id) {
            let now = Utc::now();
            session.expires_at = now + Duration::hours(24);
            session.last_activity = now;
            true
        } else {
            false
        }
    }

    fn generate_session_id(&self) -> String {
        let rng = rand::SystemRandom::new();
        let mut bytes = vec![0u8; 32];
        rand::SecureRandom::fill(&rng, &mut bytes)
            .expect("Failed to generate session ID");

        let tag = hmac::sign(&self.key, &bytes);
        base64::encode(tag.as_ref())
    }

    fn start_cleanup(&self) {
        let sessions = Arc::clone(&self.sessions);
        let invalidated = Arc::clone(&self.invalidated);
        let interval = self.cleanup_interval;

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(
                std::time::Duration::from_secs(interval.num_seconds() as u64)
            );

            loop {
                interval.tick().await;
                let now = Utc::now();

                // Clean up expired sessions
                sessions.retain(|_, session| session.expires_at > now);

                // Clean up old invalidated sessions
                invalidated.retain(|_, invalid_time| *invalid_time > now);
            }
        });
    }

    #[wasm_bindgen]
    pub fn get_session_info(&self, session_id: &str) -> Result<JsValue, JsValue> {
        if let Some(session) = self.sessions.get(session_id) {
            Ok(serde_wasm_bindgen::to_value(&*session)?)
        } else {
            Err(JsValue::from_str("Session not found"))
        }
    }
}

impl Drop for SessionManager {
    fn drop(&mut self) {
        // Clear all sensitive data
        self.sessions.clear();
        self.invalidated.clear();
    }
} 