// REMOVING unbounded cache implementation
// REPLACING with size-limited LRU cache
use lru::LruCache;
use super::errors::{ChainRAGError, DatabaseError, ErrorContext, ErrorHandler};
use std::sync::Arc;
use tokio::sync::Mutex;
use uuid::Uuid;
use sqlx::{Pool, Postgres};
use async_trait::async_trait;

pub struct DatabaseManager {
    pool: Pool<Postgres>,
    error_handler: Arc<ErrorHandler>,
    metrics: Arc<MetricsStore>,
}

impl DatabaseManager {
    pub fn new(
        pool: Pool<Postgres>,
        error_handler: Arc<ErrorHandler>,
        metrics: Arc<MetricsStore>,
    ) -> Self {
        Self {
            pool,
            error_handler,
            metrics,
        }
    }

    pub async fn execute_query<T>(
        &self,
        query: &str,
        params: &[&(dyn sqlx::Encode + Sync)],
    ) -> Result<T, ChainRAGError>
    where
        T: for<'r> sqlx::FromRow<'r, sqlx::postgres::PgRow> + Send + Unpin,
    {
        let context = ErrorContext {
            error_id: Uuid::new_v4(),
            component: "database".to_string(),
            operation: "execute_query".to_string(),
            timestamp: chrono::Utc::now(),
            trace_id: opentelemetry::trace::current_span_context().trace_id().to_string().into(),
            user_id: None,
        };

        let result = sqlx::query_as::<_, T>(query)
            .bind_all(params)
            .fetch_one(&self.pool)
            .await;

        match result {
            Ok(data) => {
                self.metrics.record_query_success().await;
                Ok(data)
            }
            Err(err) => {
                let db_error = match err {
                    sqlx::Error::Database(ref db_err) => {
                        if db_err.code().as_deref() == Some("40P01") {
                            DatabaseError::DeadlockDetected
                        } else {
                            DatabaseError::QueryFailed(db_err.message().to_string())
                        }
                    }
                    sqlx::Error::PoolTimedOut => {
                        DatabaseError::ConnectionFailed("Connection pool timeout".to_string())
                    }
                    _ => DatabaseError::QueryFailed(err.to_string()),
                };

                let chain_error = ChainRAGError::Database(db_error);
                self.error_handler.handle_error(chain_error, context).await;
                Err(chain_error)
            }
        }
    }

    pub async fn execute_transaction<F, T, E>(&self, operations: F) -> Result<T, ChainRAGError>
    where
        F: FnOnce(&mut sqlx::Transaction<'_, Postgres>) -> Result<T, E>,
        E: Into<ChainRAGError>,
    {
        let context = ErrorContext {
            error_id: Uuid::new_v4(),
            component: "database".to_string(),
            operation: "execute_transaction".to_string(),
            timestamp: chrono::Utc::now(),
            trace_id: opentelemetry::trace::current_span_context().trace_id().to_string().into(),
            user_id: None,
        };

        let mut tx = self.pool.begin().await.map_err(|e| {
            let db_error = DatabaseError::TransactionFailed(e.to_string());
            ChainRAGError::Database(db_error)
        })?;

        match operations(&mut tx).map_err(Into::into) {
            Ok(result) => {
                tx.commit().await.map_err(|e| {
                    let db_error = DatabaseError::TransactionFailed(e.to_string());
                    ChainRAGError::Database(db_error)
                })?;
                self.metrics.record_transaction_success().await;
                Ok(result)
            }
            Err(err) => {
                let _ = tx.rollback().await;
                self.error_handler.handle_error(err, context).await;
                Err(err)
            }
        }
    }

    pub async fn health_check(&self) -> Result<(), ChainRAGError> {
        let context = ErrorContext {
            error_id: Uuid::new_v4(),
            component: "database".to_string(),
            operation: "health_check".to_string(),
            timestamp: chrono::Utc::now(),
            trace_id: opentelemetry::trace::current_span_context().trace_id().to_string().into(),
            user_id: None,
        };

        match sqlx::query("SELECT 1").execute(&self.pool).await {
            Ok(_) => {
                self.metrics.record_health_check_success().await;
                Ok(())
            }
            Err(err) => {
                let db_error = DatabaseError::ConnectionFailed(err.to_string());
                let chain_error = ChainRAGError::Database(db_error);
                self.error_handler.handle_error(chain_error, context).await;
                Err(chain_error)
            }
        }
    }
}

// Safe cleanup
impl Drop for DatabaseManager {
    fn drop(&mut self) {
        // Ensure all connections are properly closed
        self.pool.close();
    }
}

impl DatabaseInterface {
    async fn cache_query_result(&self, query: &str, result: QueryResult) {
        let mut cache = self.query_cache.write().await;
        
        // Enforce cache size limits
        if cache.len() >= self.config.max_cache_size {
            // Remove least recently used entries
            while cache.len() >= self.config.max_cache_size {
                if let Some((k, _)) = cache.pop_lru() {
                    debug!("Evicting query cache entry: {}", k);
                }
            }
        }
        
        cache.put(query.to_string(), result);
    }
} 