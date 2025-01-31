use super::service::{ChainRAGService, QueryRequest, QueryResponse};
use axum::{
    routing::{post, get},
    Router, Json, Extension,
};
use std::sync::Arc;
use actix_web::{web, HttpResponse, Error};
use serde::{Serialize, Deserialize};
use validator::{Validate, ValidationError};
use thiserror::Error;

// API input limits
const MAX_REQUEST_SIZE: usize = 10 * 1024 * 1024; // 10MB
const MAX_PAYLOAD_SIZE: usize = 5 * 1024 * 1024;  // 5MB
const MAX_FIELD_LENGTH: usize = 1024;             // 1KB
const MAX_ARRAY_LENGTH: usize = 1000;
const MAX_FILE_SIZE: usize = 50 * 1024 * 1024;    // 50MB
const MAX_BATCH_SIZE: usize = 100;

#[derive(Debug, Error)]
pub enum ApiValidationError {
    #[error("Request too large: {size} bytes (max: {max})")]
    RequestTooLarge { size: usize, max: usize },
    
    #[error("Field too long: {field} is {size} chars (max: {max})")]
    FieldTooLong { field: String, size: usize, max: usize },
    
    #[error("Array too large: {field} has {size} items (max: {max})")]
    ArrayTooLarge { field: String, size: usize, max: usize },
    
    #[error("File too large: {size} bytes (max: {max})")]
    FileTooLarge { size: usize, max: usize },
    
    #[error("Batch too large: {size} items (max: {max})")]
    BatchTooLarge { size: usize, max: usize },
}

pub struct ApiEndpoints {
    validator: RequestValidator,
    metrics: Arc<MetricsStore>,
    rate_limiter: Arc<RateLimiter>,
}

#[derive(Debug, Validate)]
struct RequestValidator {
    #[validate(custom = "validate_request_size")]
    max_request_size: usize,
    
    #[validate(custom = "validate_payload_size")]
    max_payload_size: usize,
}

impl ApiEndpoints {
    pub fn new(metrics: Arc<MetricsStore>, rate_limiter: Arc<RateLimiter>) -> Self {
        Self {
            validator: RequestValidator {
                max_request_size: MAX_REQUEST_SIZE,
                max_payload_size: MAX_PAYLOAD_SIZE,
            },
            metrics,
            rate_limiter,
        }
    }

    pub async fn validate_request<T: Validate>(
        &self,
        request: &T,
        content_length: usize
    ) -> Result<(), ApiValidationError> {
        // Check overall request size
        if content_length > MAX_REQUEST_SIZE {
            return Err(ApiValidationError::RequestTooLarge {
                size: content_length,
                max: MAX_REQUEST_SIZE,
            });
        }

        // Validate request using derive(Validate)
        request.validate()
            .map_err(|e| ApiValidationError::ValidationFailed(e.to_string()))?;

        Ok(())
    }

    // Example API endpoint with input validation
    pub async fn create_document(
        &self,
        req: HttpRequest,
        doc: web::Json<CreateDocumentRequest>,
    ) -> Result<HttpResponse, Error> {
        // Validate request size
        let content_length = req.headers()
            .get("content-length")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<usize>().ok())
            .unwrap_or(0);
            
        self.validate_request(&doc, content_length).await?;

        // Rate limiting
        self.rate_limiter.check_rate_limit(
            &doc.user_id,
            req.peer_addr().map(|a| a.ip()).unwrap_or_default()
        ).await?;

        // Process request
        let response = self.process_document_creation(doc.into_inner()).await?;
        
        // Record metrics
        self.metrics.record_api_request("create_document", content_length).await;
        
        Ok(HttpResponse::Ok().json(response))
    }

    // Example batch API endpoint
    pub async fn batch_process(
        &self,
        req: HttpRequest,
        batch: web::Json<BatchRequest>,
    ) -> Result<HttpResponse, Error> {
        // Validate batch size
        if batch.items.len() > MAX_BATCH_SIZE {
            return Err(ApiValidationError::BatchTooLarge {
                size: batch.items.len(),
                max: MAX_BATCH_SIZE,
            }.into());
        }

        // Validate each item in batch
        for item in &batch.items {
            self.validate_request(item, std::mem::size_of_val(item)).await?;
        }

        // Process batch
        let response = self.process_batch(batch.into_inner()).await?;
        
        Ok(HttpResponse::Ok().json(response))
    }

    // File upload endpoint
    pub async fn upload_file(
        &self,
        req: HttpRequest,
        payload: actix_multipart::Multipart,
    ) -> Result<HttpResponse, Error> {
        let mut size: usize = 0;
        
        // Stream and validate file size
        let mut payload = payload;
        while let Some(item) = payload.next().await {
            let field = item?;
            size += field.size();
            
            if size > MAX_FILE_SIZE {
                return Err(ApiValidationError::FileTooLarge {
                    size,
                    max: MAX_FILE_SIZE,
                }.into());
            }
        }

        // Process file
        let response = self.process_file_upload(payload, size).await?;
        
        Ok(HttpResponse::Ok().json(response))
    }
}

// Request validation structs
#[derive(Debug, Validate, Serialize, Deserialize)]
pub struct CreateDocumentRequest {
    #[validate(length(max = "MAX_FIELD_LENGTH"))]
    title: String,
    
    #[validate(length(max = "MAX_PAYLOAD_SIZE"))]
    content: String,
    
    #[validate(length(max = "MAX_ARRAY_LENGTH"))]
    tags: Vec<String>,
    
    #[validate]
    metadata: DocumentMetadata,
}

#[derive(Debug, Validate, Serialize, Deserialize)]
pub struct DocumentMetadata {
    #[validate(length(max = "MAX_FIELD_LENGTH"))]
    author: String,
    
    #[validate(length(max = "MAX_FIELD_LENGTH"))]
    category: String,
    
    #[validate(range(max = "100"))]
    version: u32,
}

#[derive(Debug, Validate, Serialize, Deserialize)]
pub struct BatchRequest {
    #[validate]
    items: Vec<CreateDocumentRequest>,
    
    #[validate(range(min = "1", max = "MAX_BATCH_SIZE"))]
    batch_size: usize,
}

// Custom validation functions
fn validate_request_size(size: &usize) -> Result<(), ValidationError> {
    if *size > MAX_REQUEST_SIZE {
        return Err(ValidationError::new("request_too_large"));
    }
    Ok(())
}

fn validate_payload_size(size: &usize) -> Result<(), ValidationError> {
    if *size > MAX_PAYLOAD_SIZE {
        return Err(ValidationError::new("payload_too_large"));
    }
    Ok(())
}

pub fn create_router(service: Arc<ChainRAGService>) -> Router {
    Router::new()
        .route("/query", post(handle_query))
        .route("/health", get(health_check))
        .layer(Extension(service))
}

async fn handle_query(
    Extension(service): Extension<Arc<ChainRAGService>>,
    Json(request): Json<QueryRequest>,
) -> Result<Json<QueryResponse>, StatusCode> {
    match service.process_query(request).await {
        Ok(response) => Ok(Json(response)),
        Err(e) => {
            error!("Query processing error: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

async fn health_check(
    Extension(service): Extension<Arc<ChainRAGService>>,
) -> Result<Json<HealthStatus>, StatusCode> {
    match service.health_check().await {
        Ok(status) => Ok(Json(status)),
        Err(_) => Err(StatusCode::INTERNAL_SERVER_ERROR),
    }
} 