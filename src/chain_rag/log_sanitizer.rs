use std::sync::Arc;
use regex::Regex;
use lazy_static::lazy_static;
use serde::{Serialize, Deserialize};
use thiserror::Error;
use std::collections::{HashMap, HashSet};
use dashmap::DashMap;

// Sanitization constants
const MAX_PATTERN_LENGTH: usize = 1024;
const MAX_PATTERNS: usize = 1000;
const MAX_REPLACEMENTS: usize = 1000;
const MAX_LOG_SIZE: usize = 10 * 1024 * 1024; // 10MB
const CACHE_TTL: Duration = Duration::from_secs(3600);

#[derive(Debug, Error)]
pub enum SanitizerError {
    #[error("Invalid pattern: {0}")]
    InvalidPattern(String),
    
    #[error("Pattern limit exceeded")]
    PatternLimitExceeded,
    
    #[error("Log size exceeded")]
    LogSizeExceeded,
    
    #[error("Regex error: {0}")]
    Regex(#[from] regex::Error),
    
    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SanitizationPattern {
    pattern: String,
    replacement: String,
    description: String,
    priority: u32,
}

pub struct LogSanitizer {
    patterns: Arc<DashMap<String, SanitizationPattern>>,
    compiled_patterns: Arc<DashMap<String, (Regex, String)>>,
    pattern_cache: Arc<DashMap<String, (String, Instant)>>,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
}

lazy_static! {
    static ref DEFAULT_PATTERNS: Vec<SanitizationPattern> = vec![
        // Credit Card Numbers
        SanitizationPattern {
            pattern: r"\b\d{4}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b".to_string(),
            replacement: "[REDACTED_CC]".to_string(),
            description: "Credit card numbers".to_string(),
            priority: 100,
        },
        // Social Security Numbers
        SanitizationPattern {
            pattern: r"\b\d{3}[-.]?\d{2}[-.]?\d{4}\b".to_string(),
            replacement: "[REDACTED_SSN]".to_string(),
            description: "Social security numbers".to_string(),
            priority: 100,
        },
        // Email Addresses
        SanitizationPattern {
            pattern: r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b".to_string(),
            replacement: "[REDACTED_EMAIL]".to_string(),
            description: "Email addresses".to_string(),
            priority: 90,
        },
        // API Keys
        SanitizationPattern {
            pattern: r"\b(?i)(api[_-]?key|access[_-]?token|secret)[^\s]*\s*[:=]\s*['"]?\w+['"]?".to_string(),
            replacement: "[REDACTED_API_KEY]".to_string(),
            description: "API keys and tokens".to_string(),
            priority: 100,
        },
        // Passwords
        SanitizationPattern {
            pattern: r"\b(?i)(password|passwd|pwd)[^\s]*\s*[:=]\s*['"]?\S+['"]?".to_string(),
            replacement: "[REDACTED_PASSWORD]".to_string(),
            description: "Passwords".to_string(),
            priority: 100,
        },
        // Private Keys
        SanitizationPattern {
            pattern: r"-----BEGIN [A-Z ]+ PRIVATE KEY-----[^-]+-----END [A-Z ]+ PRIVATE KEY-----".to_string(),
            replacement: "[REDACTED_PRIVATE_KEY]".to_string(),
            description: "Private keys".to_string(),
            priority: 100,
        },
        // JWT Tokens
        SanitizationPattern {
            pattern: r"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*".to_string(),
            replacement: "[REDACTED_JWT]".to_string(),
            description: "JWT tokens".to_string(),
            priority: 90,
        },
    ];
}

impl LogSanitizer {
    pub fn new(
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Result<Self, SanitizerError> {
        let sanitizer = Self {
            patterns: Arc::new(DashMap::new()),
            compiled_patterns: Arc::new(DashMap::new()),
            pattern_cache: Arc::new(DashMap::new()),
            metrics,
            error_handler,
        };
        
        // Load default patterns
        for pattern in DEFAULT_PATTERNS.iter() {
            sanitizer.add_pattern(pattern.clone())?;
        }
        
        Ok(sanitizer)
    }

    pub fn add_pattern(
        &self,
        pattern: SanitizationPattern,
    ) -> Result<(), SanitizerError> {
        // Validate pattern
        if pattern.pattern.len() > MAX_PATTERN_LENGTH {
            return Err(SanitizerError::InvalidPattern(
                "Pattern too long".to_string()
            ));
        }

        if self.patterns.len() >= MAX_PATTERNS {
            return Err(SanitizerError::PatternLimitExceeded);
        }

        // Compile and validate regex
        let regex = Regex::new(&pattern.pattern)?;
        
        self.patterns.insert(pattern.pattern.clone(), pattern.clone());
        self.compiled_patterns.insert(
            pattern.pattern,
            (regex, pattern.replacement),
        );
        
        self.metrics.record_pattern_added().await;
        Ok(())
    }

    pub fn sanitize_log(
        &self,
        log_entry: &str,
    ) -> Result<String, SanitizerError> {
        if log_entry.len() > MAX_LOG_SIZE {
            return Err(SanitizerError::LogSizeExceeded);
        }

        // Check cache first
        if let Some((sanitized, timestamp)) = self.pattern_cache.get(log_entry) {
            if timestamp.elapsed() < CACHE_TTL {
                self.metrics.record_cache_hit().await;
                return Ok(sanitized.clone());
            }
        }

        let mut sanitized = log_entry.to_string();
        
        // Sort patterns by priority
        let mut patterns: Vec<_> = self.compiled_patterns.iter().collect();
        patterns.sort_by_key(|p| self.patterns.get(&p.key()).unwrap().priority);
        
        // Apply patterns in priority order
        for pattern_entry in patterns {
            let (regex, replacement) = pattern_entry.value();
            sanitized = regex.replace_all(&sanitized, replacement.as_str()).to_string();
        }

        // Update cache
        self.pattern_cache.insert(
            log_entry.to_string(),
            (sanitized.clone(), Instant::now()),
        );
        
        self.metrics.record_log_sanitized().await;
        Ok(sanitized)
    }

    pub fn sanitize_structured_log(
        &self,
        log: &mut HashMap<String, serde_json::Value>,
    ) -> Result<(), SanitizerError> {
        let sensitive_fields = HashSet::from([
            "password",
            "token",
            "key",
            "secret",
            "credential",
            "auth",
            "cookie",
        ]);

        for (key, value) in log.iter_mut() {
            if let serde_json::Value::String(s) = value {
                // Check if field name indicates sensitive data
                if sensitive_fields.iter().any(|f| key.to_lowercase().contains(f)) {
                    *value = serde_json::Value::String("[REDACTED]".to_string());
                    continue;
                }
                
                // Apply regex patterns
                let sanitized = self.sanitize_log(s)?;
                if sanitized != *s {
                    *value = serde_json::Value::String(sanitized);
                }
            }
        }

        Ok(())
    }

    pub fn cleanup_cache(&self) {
        let now = Instant::now();
        self.pattern_cache.retain(|_, (_, timestamp)| {
            timestamp.elapsed() < CACHE_TTL
        });
    }
}

// Helper function for common data types
impl LogSanitizer {
    fn is_sensitive_data(&self, value: &str) -> bool {
        // Credit card validation
        if value.chars().filter(|c| c.is_digit(10)).count() == 16 {
            return true;
        }
        
        // SSN validation
        if value.chars().filter(|c| c.is_digit(10)).count() == 9 {
            return true;
        }
        
        // API key patterns
        if value.len() >= 32 && value.chars().all(|c| c.is_alphanumeric()) {
            return true;
        }
        
        false
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_sensitive_data_sanitization() {
        let sanitizer = LogSanitizer::new(
            Arc::new(MetricsStore::new()),
            Arc::new(ErrorHandler::new()),
        ).unwrap();

        let test_cases = vec![
            (
                "Credit card: 4111-1111-1111-1111",
                "Credit card: [REDACTED_CC]",
            ),
            (
                "SSN: 123-45-6789",
                "SSN: [REDACTED_SSN]",
            ),
            (
                "API key: sk_test_1234567890abcdef",
                "API key: [REDACTED_API_KEY]",
            ),
            (
                "Password: super_secret123",
                "Password: [REDACTED_PASSWORD]",
            ),
        ];

        for (input, expected) in test_cases {
            let result = sanitizer.sanitize_log(input).unwrap();
            assert_eq!(result, expected);
        }
    }
} 