use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::RwLock;
use chrono::{DateTime, Utc, Duration};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct CleanupPolicy {
    resource_type: String,
    retention_period: Duration,
    cleanup_batch_size: usize,
    priority: i32,
    secure_delete: bool,
    verification_required: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CleanupMetrics {
    last_run: DateTime<Utc>,
    items_cleaned: u64,
    errors_encountered: u64,
    space_reclaimed: u64,
}

#[wasm_bindgen]
pub struct CleanupManager {
    policies: Arc<DashMap<String, CleanupPolicy>>,
    metrics: Arc<DashMap<String, CleanupMetrics>>,
    active_cleanups: Arc<DashMap<String, DateTime<Utc>>>,
    verification_queue: Arc<RwLock<Vec<(String, String)>>>,
    session_manager: Arc<SessionManager>,
    acl: Arc<AccessControlList>,
}

#[wasm_bindgen]
impl CleanupManager {
    #[wasm_bindgen(constructor)]
    pub fn new(
        session_manager: Arc<SessionManager>,
        acl: Arc<AccessControlList>
    ) -> Self {
        let manager = Self {
            policies: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            active_cleanups: Arc::new(DashMap::new()),
            verification_queue: Arc::new(RwLock::new(Vec::new())),
            session_manager,
            acl,
        };

        manager.start_cleanup_scheduler();
        manager
    }

    #[wasm_bindgen]
    pub fn add_cleanup_policy(&self, policy: JsValue) -> Result<(), JsValue> {
        let cleanup_policy: CleanupPolicy = serde_wasm_bindgen::from_value(policy)?;
        self.policies.insert(cleanup_policy.resource_type.clone(), cleanup_policy);
        Ok(())
    }

    async fn perform_cleanup(&self, resource_type: &str) -> Result<(), JsValue> {
        if let Some(policy) = self.policies.get(resource_type) {
            // Record cleanup start
            self.active_cleanups.insert(
                resource_type.to_string(),
                Utc::now()
            );

            let mut metrics = CleanupMetrics {
                last_run: Utc::now(),
                items_cleaned: 0,
                errors_encountered: 0,
                space_reclaimed: 0,
            };

            // Sessions cleanup
            if resource_type == "sessions" {
                self.cleanup_sessions(&policy, &mut metrics).await?;
            }

            // ACL rules cleanup
            if resource_type == "acl_rules" {
                self.cleanup_acl_rules(&policy, &mut metrics).await?;
            }

            // Route cleanup
            if resource_type == "routes" {
                self.cleanup_routes(&policy, &mut metrics).await?;
            }

            // Verification queue cleanup
            if resource_type == "verification_queue" {
                self.cleanup_verification_queue(&policy, &mut metrics).await?;
            }

            // Update metrics
            self.metrics.insert(resource_type.to_string(), metrics);

            // Remove from active cleanups
            self.active_cleanups.remove(resource_type);

            Ok(())
        } else {
            Err(JsValue::from_str("No cleanup policy found"))
        }
    }

    async fn cleanup_sessions(
        &self,
        policy: &CleanupPolicy,
        metrics: &mut CleanupMetrics
    ) -> Result<(), JsValue> {
        let cutoff = Utc::now() - policy.retention_period;
        let mut batch_count = 0;

        let sessions_to_remove: Vec<String> = self.session_manager
            .get_expired_sessions(cutoff)
            .await?
            .into_iter()
            .take(policy.cleanup_batch_size)
            .collect();

        for session_id in sessions_to_remove {
            if policy.secure_delete {
                // Secure deletion of session data
                self.session_manager.secure_delete_session(&session_id).await?;
            } else {
                self.session_manager.remove_session(&session_id).await?;
            }
            batch_count += 1;
            metrics.items_cleaned += 1;
        }

        if policy.verification_required && batch_count > 0 {
            self.verification_queue.write().await.push((
                "sessions".to_string(),
                format!("Cleaned {} sessions", batch_count)
            ));
        }

        Ok(())
    }

    async fn cleanup_acl_rules(
        &self,
        policy: &CleanupPolicy,
        metrics: &mut CleanupMetrics
    ) -> Result<(), JsValue> {
        let cutoff = Utc::now() - policy.retention_period;
        let mut batch_count = 0;

        let rules_to_remove: Vec<(String, i32)> = self.acl
            .get_expired_rules(cutoff)
            .await?
            .into_iter()
            .take(policy.cleanup_batch_size)
            .collect();

        for (resource_pattern, priority) in rules_to_remove {
            if self.acl.remove_rule(resource_pattern.clone(), priority) {
                batch_count += 1;
                metrics.items_cleaned += 1;
            } else {
                metrics.errors_encountered += 1;
            }
        }

        if policy.verification_required && batch_count > 0 {
            self.verification_queue.write().await.push((
                "acl_rules".to_string(),
                format!("Cleaned {} ACL rules", batch_count)
            ));
        }

        Ok(())
    }

    async fn cleanup_routes(
        &self,
        policy: &CleanupPolicy,
        metrics: &mut CleanupMetrics
    ) -> Result<(), JsValue> {
        // Implementation for route cleanup
        Ok(())
    }

    async fn cleanup_verification_queue(
        &self,
        policy: &CleanupPolicy,
        metrics: &mut CleanupMetrics
    ) -> Result<(), JsValue> {
        let mut queue = self.verification_queue.write().await;
        let cutoff = Utc::now() - policy.retention_period;
        let initial_len = queue.len();

        queue.retain(|_| {
            // In a real implementation, we would check timestamps
            true
        });

        metrics.items_cleaned += (initial_len - queue.len()) as u64;
        Ok(())
    }

    fn start_cleanup_scheduler(&self) {
        let policies = Arc::clone(&self.policies);
        let manager = Arc::new(self.clone());

        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(3600));
            loop {
                interval.tick().await;
                
                // Sort policies by priority
                let mut policy_types: Vec<String> = policies.iter()
                    .map(|ref_multi| ref_multi.key().clone())
                    .collect();
                
                policy_types.sort_by_key(|t| {
                    policies.get(t)
                        .map(|p| -p.priority)
                        .unwrap_or(0)
                });

                // Execute cleanups in priority order
                for resource_type in policy_types {
                    if let Err(e) = manager.perform_cleanup(&resource_type).await {
                        web_sys::console::error_1(&e);
                    }
                }
            }
        });
    }

    #[wasm_bindgen]
    pub fn get_cleanup_metrics(&self, resource_type: String) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get(&resource_type) {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Err(JsValue::from_str("No metrics found"))
        }
    }

    #[wasm_bindgen]
    pub fn is_cleanup_active(&self, resource_type: String) -> bool {
        self.active_cleanups.contains_key(&resource_type)
    }
}

impl Drop for CleanupManager {
    fn drop(&mut self) {
        // Ensure all cleanups are completed
        self.active_cleanups.clear();
        self.verification_queue.blocking_write().clear();
        self.metrics.clear();
        self.policies.clear();
    }
} 