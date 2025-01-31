use super::{ChainRAG, ChainRAGError, RetrievalStep, VerificationStep, GenerationStep};
use std::sync::Arc;
use tokio::sync::RwLock;
use serde::{Serialize, Deserialize};
use metrics::{counter, gauge};
use validator::{Validate, ValidationError};
use regex::Regex;
use thiserror::Error;
use std::collections::HashSet;

// Validation constants
const MAX_QUERY_LENGTH: usize = 4096;
const MIN_QUERY_LENGTH: usize = 3;
const MAX_CONTEXT_LENGTH: usize = 8192;
const MAX_RESULTS: usize = 100;
const MIN_CONFIDENCE: f32 = 0.1;
const MAX_CONFIDENCE: f32 = 1.0;

#[derive(Debug, Error)]
pub enum QueryValidationError {
    #[error("Query length invalid: {length} chars (min: {min}, max: {max})")]
    InvalidLength { length: usize, min: usize, max: usize },
    
    #[error("Invalid characters in query")]
    InvalidCharacters,
    
    #[error("Context too large: {size} > {max}")]
    ContextTooLarge { size: usize, max: usize },
    
    #[error("Too many results requested: {count} > {max}")]
    TooManyResults { count: usize, max: usize },
    
    #[error("Invalid confidence threshold: {value} (min: {min}, max: {max})")]
    InvalidConfidence { value: f32, min: f32, max: f32 },
    
    #[error("Required parameter missing: {0}")]
    MissingParameter(String),
}

#[derive(Debug, Validate, Serialize, Deserialize)]
pub struct QueryRequest {
    #[validate(length(min = "MIN_QUERY_LENGTH", max = "MAX_QUERY_LENGTH"))]
    #[validate(regex = "QUERY_PATTERN")]
    query: String,
    
    #[validate(range(max = "MAX_RESULTS"))]
    max_results: usize,
    
    #[validate(range(min = "MIN_CONFIDENCE", max = "MAX_CONFIDENCE"))]
    confidence_threshold: f32,
    
    #[validate(custom = "validate_context")]
    context: Option<Vec<String>>,
    
    #[validate]
    parameters: QueryParameters,
}

#[derive(Debug, Validate, Serialize, Deserialize)]
pub struct QueryParameters {
    #[validate(range(min = 1, max = 100))]
    depth: usize,
    
    #[validate(range(min = 1, max = 10))]
    retries: usize,
    
    #[validate]
    filters: Option<QueryFilters>,
}

#[derive(Debug, Validate, Serialize, Deserialize)]
pub struct QueryFilters {
    #[validate(length(max = 50))]
    categories: Option<Vec<String>>,
    
    #[validate(range(min = "0", max = "31536000"))] // 1 year in seconds
    time_range: Option<u32>,
    
    #[validate(custom = "validate_source_types")]
    source_types: Option<Vec<String>>,
}

pub struct ChainRAGService {
    chain_rag: Arc<ChainRAG>,
    cache: Arc<RwLock<LruCache<String, QueryResponse>>>,
    metrics_reporter: Arc<MetricsReporter>,
    validator: QueryValidator,
    metrics: Arc<MetricsStore>,
}

struct QueryValidator {
    query_pattern: Regex,
    source_types: HashSet<String>,
}

impl QueryValidator {
    fn new() -> Self {
        let allowed_source_types: HashSet<String> = vec![
            "document", "database", "api", "knowledge_base"
        ].into_iter().map(String::from).collect();

        Self {
            query_pattern: Regex::new(r"^[\w\s\-\.,:;?!()\[\]{}\"']+$").unwrap(),
            source_types: allowed_source_types,
        }
    }

    async fn validate_request(&self, request: &QueryRequest) -> Result<(), QueryValidationError> {
        // Validate using derive(Validate)
        request.validate()
            .map_err(|e| QueryValidationError::InvalidCharacters)?;
            
        // Additional custom validations
        self.validate_query(&request.query)?;
        self.validate_context(&request.context)?;
        self.validate_parameters(&request.parameters)?;
        
        Ok(())
    }

    fn validate_query(&self, query: &str) -> Result<(), QueryValidationError> {
        // Check length
        let length = query.len();
        if length < MIN_QUERY_LENGTH || length > MAX_QUERY_LENGTH {
            return Err(QueryValidationError::InvalidLength {
                length,
                min: MIN_QUERY_LENGTH,
                max: MAX_QUERY_LENGTH,
            });
        }

        // Check pattern
        if !self.query_pattern.is_match(query) {
            return Err(QueryValidationError::InvalidCharacters);
        }

        Ok(())
    }

    fn validate_context(&self, context: &Option<Vec<String>>) -> Result<(), QueryValidationError> {
        if let Some(context) = context {
            let total_size: usize = context.iter()
                .map(|s| s.len())
                .sum();
                
            if total_size > MAX_CONTEXT_LENGTH {
                return Err(QueryValidationError::ContextTooLarge {
                    size: total_size,
                    max: MAX_CONTEXT_LENGTH,
                });
            }
            
            // Validate each context string
            for ctx in context {
                if !self.query_pattern.is_match(ctx) {
                    return Err(QueryValidationError::InvalidCharacters);
                }
            }
        }
        
        Ok(())
    }

    fn validate_parameters(&self, params: &QueryParameters) -> Result<(), QueryValidationError> {
        if let Some(filters) = &params.filters {
            // Validate source types
            if let Some(sources) = &filters.source_types {
                for source in sources {
                    if !self.source_types.contains(source) {
                        return Err(QueryValidationError::InvalidSourceType {
                            source: source.clone(),
                        });
                    }
                }
            }
        }
        
        Ok(())
    }
}

impl ChainRAGService {
    pub fn new(
        retrieval_steps: Vec<Arc<dyn RetrievalStep + Send + Sync>>,
        verification_steps: Vec<Arc<dyn VerificationStep + Send + Sync>>,
        generation_step: Arc<dyn GenerationStep + Send + Sync>,
        max_concurrent: usize,
        cache_size: usize,
    ) -> Self {
        let chain_rag = Arc::new(ChainRAG::new(
            retrieval_steps,
            verification_steps,
            generation_step,
            max_concurrent,
        ));

        Self {
            chain_rag,
            cache: Arc::new(RwLock::new(LruCache::new(cache_size))),
            metrics_reporter: Arc::new(MetricsReporter::new()),
            validator: QueryValidator::new(),
            metrics: Arc::new(MetricsStore::new()),
        }
    }

    pub async fn process_query(&self, request: QueryRequest) -> Result<QueryResponse, ChainRAGError> {
        // Validate request
        self.validator.validate_request(&request).await
            .map_err(ChainRAGError::ValidationError)?;
            
        // Record metrics
        self.metrics.record_query_request(&request).await;
        
        // Process query
        let start_time = Instant::now();
        
        let response = self.chain_rag.process(
            &request.query,
            request.parameters,
            request.context.as_deref(),
        ).await?;
        
        // Record timing
        self.metrics.record_query_timing(start_time.elapsed()).await;
        
        Ok(response)
    }

    pub async fn health_check(&self) -> Result<HealthStatus, ChainRAGError> {
        let chain_verified = self.chain_rag.verify_chain().await?;
        let cache_size = self.cache.read().await.len();
        
        Ok(HealthStatus {
            chain_verified,
            cache_size,
            uptime: self.metrics_reporter.get_uptime(),
            total_queries: self.metrics_reporter.get_total_queries(),
        })
    }

    async fn check_cache(&self, query: &str) -> Option<QueryResponse> {
        self.cache.read().await.get(query).cloned()
    }

    async fn update_cache(&self, query: &str, response: QueryResponse) {
        self.cache.write().await.put(query.to_string(), response);
    }

    pub async fn validate_query(&self, query: &str) -> Result<(), QueryValidationError> {
        self.validator.validate_query(query)
    }
}

#[derive(Debug, Serialize)]
pub struct HealthStatus {
    chain_verified: bool,
    cache_size: usize,
    uptime: Duration,
    total_queries: u64,
}

// Custom validation functions
fn validate_context(context: &Option<Vec<String>>) -> Result<(), ValidationError> {
    if let Some(context) = context {
        let total_size: usize = context.iter()
            .map(|s| s.len())
            .sum();
            
        if total_size > MAX_CONTEXT_LENGTH {
            return Err(ValidationError::new("context_too_large"));
        }
    }
    Ok(())
}

fn validate_source_types(sources: &Option<Vec<String>>) -> Result<(), ValidationError> {
    if let Some(sources) = sources {
        let allowed: HashSet<String> = vec![
            "document", "database", "api", "knowledge_base"
        ].into_iter().map(String::from).collect();
        
        for source in sources {
            if !allowed.contains(source) {
                return Err(ValidationError::new("invalid_source_type"));
            }
        }
    }
    Ok(())
} 