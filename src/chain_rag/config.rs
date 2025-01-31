use serde::{Serialize, Deserialize};
use std::path::PathBuf;

#[derive(Debug, Serialize, Deserialize)]
pub struct SystemConfig {
    pub vm: VMConfig,
    pub security: SecurityConfig,
    pub network: NetworkConfig,
    pub model: ModelConfig,
    pub metrics: MetricsConfig,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct VMConfig {
    pub vcpu_count: u8,
    pub memory_mib: u32,
    pub rootfs_path: PathBuf,
    pub kernel_path: PathBuf,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct SecurityConfig {
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub drift_enabled: bool,
    pub token_rotation_seconds: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct NetworkConfig {
    pub vsock_cid: u32,
    pub vsock_port: u32,
    pub allowed_clients: Vec<String>,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct ModelConfig {
    pub batch_size: usize,
    pub learning_rate: f32,
    pub optimization_interval: u64,
}

#[derive(Debug, Serialize, Deserialize)]
pub struct MetricsConfig {
    pub collection_interval: u64,
    pub retention_days: u32,
    pub log_path: PathBuf,
}

impl SystemConfig {
    pub fn load() -> Result<Self> {
        let config_path = std::env::var("SYSTEM_CONFIG")
            .unwrap_or_else(|_| "config/system.yaml".to_string());
            
        let config_str = std::fs::read_to_string(config_path)?;
        Ok(serde_yaml::from_str(&config_str)?)
    }

    pub fn validate(&self) -> Result<()> {
        // Validate paths exist
        self.validate_paths()?;
        
        // Validate resource constraints
        self.validate_resources()?;
        
        // Validate security settings
        self.validate_security()?;
        
        Ok(())
    }
} 