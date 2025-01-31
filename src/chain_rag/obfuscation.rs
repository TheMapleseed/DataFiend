use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, NewAead};
use blake3::Hasher;
use std::sync::Arc;
use rand::{thread_rng, Rng};

pub struct ObfuscationLayer {
    keys: Arc<KeyRotator>,
    hasher: Hasher,
    nonce_generator: NonceGenerator,
}

impl ObfuscationLayer {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(KeyRotator::new()),
            hasher: Hasher::new(),
            nonce_generator: NonceGenerator::new(),
        }
    }

    pub fn obfuscate_system(&self) -> ObfuscatedSystem {
        ObfuscatedSystem {
            layer: self.clone(),
            patterns: PatternObfuscator::new(),
        }
    }

    pub fn obfuscate_data(&self, data: &[u8]) -> Vec<u8> {
        let key = self.keys.current_key();
        let nonce = self.nonce_generator.generate();
        let cipher = Aes256Gcm::new(key);
        
        cipher.encrypt(&nonce, data)
            .expect("encryption failure!")
    }

    pub fn deobfuscate_data(&self, data: &[u8]) -> Vec<u8> {
        let key = self.keys.current_key();
        let nonce = self.nonce_generator.current();
        let cipher = Aes256Gcm::new(key);
        
        cipher.decrypt(&nonce, data)
            .expect("decryption failure!")
    }
}

struct KeyRotator {
    current: RwLock<Key<Aes256Gcm>>,
    rotation_interval: Duration,
}

impl KeyRotator {
    fn new() -> Self {
        let mut rng = thread_rng();
        let mut key_bytes = [0u8; 32];
        rng.fill(&mut key_bytes);
        
        let initial_key = Key::from_slice(&key_bytes);
        
        Self {
            current: RwLock::new(*initial_key),
            rotation_interval: Duration::from_secs(300), // 5 minutes
        }
    }

    fn start_rotation(&self) {
        let self_clone = self.clone();
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(self_clone.rotation_interval).await;
                self_clone.rotate_key().await;
            }
        });
    }

    async fn rotate_key(&self) {
        let mut rng = thread_rng();
        let mut new_key_bytes = [0u8; 32];
        rng.fill(&mut new_key_bytes);
        
        let new_key = Key::from_slice(&new_key_bytes);
        *self.current.write().await = *new_key;
    }
}

struct NonceGenerator {
    current: AtomicU64,
}

impl NonceGenerator {
    fn new() -> Self {
        Self {
            current: AtomicU64::new(thread_rng().gen()),
        }
    }

    fn generate(&self) -> Nonce<Aes256Gcm> {
        let nonce_value = self.current.fetch_add(1, Ordering::SeqCst);
        let mut nonce_bytes = [0u8; 12];
        nonce_bytes[..8].copy_from_slice(&nonce_value.to_le_bytes());
        Nonce::from(nonce_bytes)
    }
}

pub struct ObfuscatedSystem {
    layer: ObfuscationLayer,
    patterns: PatternObfuscator,
}

impl ObfuscatedSystem {
    pub fn wrap_component<T: Component>(&self, component: T) -> ObfuscatedComponent<T> {
        ObfuscatedComponent {
            inner: component,
            layer: self.layer.clone(),
            patterns: self.patterns.clone(),
        }
    }
}

pub struct ObfuscatedComponent<T> {
    inner: T,
    layer: ObfuscationLayer,
    patterns: PatternObfuscator,
}

impl<T: Component> ObfuscatedComponent<T> {
    pub async fn process(&self, input: &[u8]) -> Result<Vec<u8>> {
        // Deobfuscate input
        let deobfuscated = self.layer.deobfuscate_data(input);
        
        // Process with component
        let result = self.inner.process(&deobfuscated).await?;
        
        // Re-obfuscate output
        Ok(self.layer.obfuscate_data(&result))
    }
}

// Apply to the integrated system
impl IntegratedSystem {
    pub fn with_obfuscation(self) -> ObfuscatedSystem {
        let obfuscation = ObfuscationLayer::new();
        let system = obfuscation.obfuscate_system();
        
        // Wrap all components
        system.wrap_component(self)
    }
}

// WASM interface obfuscation
impl WASMInterface {
    fn obfuscate_request(&self, request: &JsValue) -> Result<Vec<u8>> {
        let bytes = serde_wasm_bindgen::to_value(request)?;
        Ok(self.obfuscation.obfuscate_data(&bytes))
    }

    fn deobfuscate_response(&self, response: &[u8]) -> Result<JsValue> {
        let bytes = self.obfuscation.deobfuscate_data(response);
        Ok(serde_wasm_bindgen::from_value(&bytes)?)
    }
}

// Pattern obfuscation for learning system
struct PatternObfuscator {
    pattern_map: Arc<RwLock<HashMap<String, String>>>,
}

impl PatternObfuscator {
    fn new() -> Self {
        Self {
            pattern_map: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn obfuscate_pattern(&self, pattern: &str) -> String {
        let mut hasher = blake3::Hasher::new();
        hasher.update(pattern.as_bytes());
        hex::encode(hasher.finalize().as_bytes())
    }
} 