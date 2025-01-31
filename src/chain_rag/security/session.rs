use wasm_bindgen::prelude::*;
use crate::security::crypto_core::CryptoCore;

impl SessionManager {
    pub fn new() -> Self {
        let crypto = Arc::new(CryptoCore::new().expect("Failed to initialize crypto"));
        // ... rest of initialization
    }

    pub fn create_session_token(&self) -> Result<String, JsValue> {
        let token_bytes = self.crypto.generate_key(32)?;
        let encrypted = self.crypto.encrypt_data(&token_bytes, &[])?;
        Ok(hex::encode(encrypted))
    }

    pub fn validate_session(&self, token: &str) -> Result<bool, JsValue> {
        let token_bytes = hex::decode(token).map_err(|_| JsValue::from_str("Invalid token format"))?;
        self.crypto.decrypt_data(&token_bytes, &[]).map(|_| true)
    }
}

impl Drop for SessionManager {
    fn drop(&mut self) {
        // Clear active sessions
        for mut session in self.active_sessions.iter_mut() {
            if let Ok(mut session_data) = session.value().write() {
                // Zero out session tokens
                session_data.token.zeroize();
                // Zero out any session-specific keys
                session_data.keys.zeroize();
                // Clear session metadata
                session_data.metadata.zeroize();
            }
        }
        
        // Clear the sessions collection
        self.active_sessions.clear();
        
        // Force memory deallocation
        self.active_sessions.shrink_to_fit();
    }
} 