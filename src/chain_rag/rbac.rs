use std::sync::Arc;
use tokio::sync::RwLock;
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant};
use uuid::Uuid;

// RBAC constants
const MAX_ROLES: usize = 1000;
const MAX_PERMISSIONS: usize = 1000;
const MAX_USERS_PER_ROLE: usize = 10000;
const CACHE_TTL: Duration = Duration::from_secs(300);
const AUDIT_RETENTION_DAYS: i64 = 365;

#[derive(Debug, Error)]
pub enum RbacError {
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Invalid role: {0}")]
    InvalidRole(String),
    
    #[error("Invalid permission: {0}")]
    InvalidPermission(String),
    
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),
    
    #[error("Validation error: {0}")]
    Validation(String),
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Role {
    id: Uuid,
    name: String,
    description: String,
    permissions: HashSet<String>,
    metadata: HashMap<String, String>,
    requires_mfa: bool,
    max_session_duration: Duration,
    created_at: chrono::DateTime<chrono::Utc>,
    updated_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permission {
    id: Uuid,
    name: String,
    description: String,
    resource_type: String,
    actions: HashSet<String>,
    conditions: Option<serde_json::Value>,
    metadata: HashMap<String, String>,
    created_at: chrono::DateTime<chrono::Utc>,
}

pub struct RbacManager {
    roles: Arc<DashMap<String, Role>>,
    permissions: Arc<DashMap<String, Permission>>,
    user_roles: Arc<DashMap<String, HashSet<String>>>,
    role_assignments: Arc<DashMap<String, HashSet<String>>>,
    permission_cache: Arc<DashMap<(String, String), (bool, Instant)>>,
    db_pool: Arc<sqlx::PgPool>,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
}

impl RbacManager {
    pub async fn new(
        db_pool: Arc<sqlx::PgPool>,
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Result<Self, RbacError> {
        let manager = Self {
            roles: Arc::new(DashMap::new()),
            permissions: Arc::new(DashMap::new()),
            user_roles: Arc::new(DashMap::new()),
            role_assignments: Arc::new(DashMap::new()),
            permission_cache: Arc::new(DashMap::new()),
            db_pool,
            metrics,
            error_handler,
        };
        
        manager.load_initial_state().await?;
        Ok(manager)
    }

    async fn load_initial_state(&self) -> Result<(), RbacError> {
        // Load roles
        let roles = sqlx::query!(
            "SELECT * FROM roles WHERE deleted_at IS NULL"
        )
        .fetch_all(&*self.db_pool)
        .await?;

        for role in roles {
            let role_obj = Role {
                id: role.id,
                name: role.name,
                description: role.description,
                permissions: serde_json::from_value(role.permissions)?,
                metadata: serde_json::from_value(role.metadata)?,
                requires_mfa: role.requires_mfa,
                max_session_duration: Duration::from_secs(role.max_session_duration as u64),
                created_at: role.created_at,
                updated_at: role.updated_at,
            };
            self.roles.insert(role_obj.name.clone(), role_obj);
        }

        // Load permissions
        let permissions = sqlx::query!(
            "SELECT * FROM permissions WHERE deleted_at IS NULL"
        )
        .fetch_all(&*self.db_pool)
        .await?;

        for perm in permissions {
            let perm_obj = Permission {
                id: perm.id,
                name: perm.name,
                description: perm.description,
                resource_type: perm.resource_type,
                actions: serde_json::from_value(perm.actions)?,
                conditions: perm.conditions,
                metadata: serde_json::from_value(perm.metadata)?,
                created_at: perm.created_at,
            };
            self.permissions.insert(perm_obj.name.clone(), perm_obj);
        }

        // Load role assignments
        let assignments = sqlx::query!(
            "SELECT user_id, role_name FROM user_roles WHERE deleted_at IS NULL"
        )
        .fetch_all(&*self.db_pool)
        .await?;

        for assignment in assignments {
            self.user_roles
                .entry(assignment.user_id)
                .or_default()
                .insert(assignment.role_name);
        }

        self.metrics.record_rbac_loaded().await;
        Ok(())
    }

    pub async fn check_permission(
        &self,
        user_id: &str,
        permission: &str,
        resource: &str,
        action: &str,
        context: Option<&serde_json::Value>,
    ) -> Result<bool, RbacError> {
        // Check cache first
        let cache_key = (user_id.to_string(), permission.to_string());
        if let Some((allowed, timestamp)) = self.permission_cache.get(&cache_key) {
            if timestamp.elapsed() < CACHE_TTL {
                return Ok(*allowed);
            }
        }

        // Get user roles
        let user_roles = self.user_roles.get(user_id)
            .ok_or_else(|| RbacError::PermissionDenied(
                "User has no roles assigned".to_string()
            ))?;

        // Check each role's permissions
        let mut allowed = false;
        for role_name in user_roles.iter() {
            let role = self.roles.get(role_name)
                .ok_or_else(|| RbacError::InvalidRole(
                    format!("Role not found: {}", role_name)
                ))?;

            if role.permissions.contains(permission) {
                // Validate permission
                if let Some(perm) = self.permissions.get(permission) {
                    if perm.resource_type == resource && perm.actions.contains(action) {
                        // Check conditions if they exist
                        if let Some(conditions) = &perm.conditions {
                            if let Some(ctx) = context {
                                if self.evaluate_conditions(conditions, ctx)? {
                                    allowed = true;
                                    break;
                                }
                            }
                        } else {
                            allowed = true;
                            break;
                        }
                    }
                }
            }
        }

        // Update cache
        self.permission_cache.insert(
            cache_key,
            (allowed, Instant::now()),
        );

        self.metrics.record_permission_check().await;
        Ok(allowed)
    }

    fn evaluate_conditions(
        &self,
        conditions: &serde_json::Value,
        context: &serde_json::Value,
    ) -> Result<bool, RbacError> {
        // Implement condition evaluation logic
        // This could include time-based conditions, IP-based conditions, etc.
        Ok(true)
    }

    pub async fn assign_role(
        &self,
        user_id: &str,
        role_name: &str,
    ) -> Result<(), RbacError> {
        // Validate role exists
        if !self.roles.contains_key(role_name) {
            return Err(RbacError::InvalidRole(
                format!("Role does not exist: {}", role_name)
            ));
        }

        // Check user role limit
        let user_roles = self.user_roles.entry(user_id.to_string()).or_default();
        if user_roles.len() >= MAX_USERS_PER_ROLE {
            return Err(RbacError::Validation(
                "Maximum roles per user exceeded".to_string()
            ));
        }

        // Add role assignment
        user_roles.insert(role_name.to_string());

        // Persist to database
        sqlx::query!(
            "INSERT INTO user_roles (user_id, role_name) VALUES ($1, $2)",
            user_id,
            role_name,
        )
        .execute(&*self.db_pool)
        .await?;

        self.metrics.record_role_assigned().await;
        Ok(())
    }

    pub async fn create_role(
        &self,
        role: Role,
    ) -> Result<(), RbacError> {
        // Validate role
        if self.roles.len() >= MAX_ROLES {
            return Err(RbacError::Validation(
                "Maximum number of roles exceeded".to_string()
            ));
        }

        // Validate permissions exist
        for perm in &role.permissions {
            if !self.permissions.contains_key(perm) {
                return Err(RbacError::InvalidPermission(
                    format!("Permission does not exist: {}", perm)
                ));
            }
        }

        // Insert into database
        sqlx::query!(
            "INSERT INTO roles (id, name, description, permissions, metadata, requires_mfa, max_session_duration)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            role.id,
            role.name,
            role.description,
            serde_json::to_value(&role.permissions)?,
            serde_json::to_value(&role.metadata)?,
            role.requires_mfa,
            role.max_session_duration.as_secs() as i64,
        )
        .execute(&*self.db_pool)
        .await?;

        // Update cache
        self.roles.insert(role.name.clone(), role);

        self.metrics.record_role_created().await;
        Ok(())
    }

    pub async fn create_permission(
        &self,
        permission: Permission,
    ) -> Result<(), RbacError> {
        // Validate permission
        if self.permissions.len() >= MAX_PERMISSIONS {
            return Err(RbacError::Validation(
                "Maximum number of permissions exceeded".to_string()
            ));
        }

        // Insert into database
        sqlx::query!(
            "INSERT INTO permissions (id, name, description, resource_type, actions, conditions, metadata)
             VALUES ($1, $2, $3, $4, $5, $6, $7)",
            permission.id,
            permission.name,
            permission.description,
            permission.resource_type,
            serde_json::to_value(&permission.actions)?,
            permission.conditions,
            serde_json::to_value(&permission.metadata)?,
        )
        .execute(&*self.db_pool)
        .await?;

        // Update cache
        self.permissions.insert(permission.name.clone(), permission);

        self.metrics.record_permission_created().await;
        Ok(())
    }

    pub async fn cleanup_cache(&self) {
        let now = Instant::now();
        self.permission_cache.retain(|_, (_, timestamp)| {
            timestamp.elapsed() < CACHE_TTL
        });
    }
}

// Safe cleanup
impl Drop for RbacManager {
    fn drop(&mut self) {
        self.cleanup_cache();
    }
} 