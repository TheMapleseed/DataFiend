use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, Semaphore};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque, HashSet, BTreeMap};
use sha3::{Sha3_512, Digest};
use jsonwebtoken::{encode, decode, Header, Algorithm, Validation, EncodingKey, DecodingKey};
use subtle::{Choice, ConstantTimeEq};
use crate::security::crypto_core::CryptoCore;

const MAX_PERMISSIONS: usize = 1000;
const MAX_ROLES: usize = 100;
const ACCESS_CHECK_INTERVAL_MS: u64 = 100;
const MAX_CONCURRENT_CHECKS: usize = 50;

#[derive(Clone, Serialize, Deserialize)]
pub struct AccessControl {
    policy_id: String,
    permissions: HashMap<String, Permission>,
    roles: HashMap<String, Role>,
    rules: Vec<AccessRule>,
    metrics: AccessMetrics,
    audit_trail: VecDeque<AuditEntry>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Permission {
    permission_id: String,
    resource_type: ResourceType,
    actions: HashSet<Action>,
    conditions: Vec<AccessCondition>,
    metadata: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Role {
    role_id: String,
    permissions: HashSet<String>,
    inheritance: Vec<String>,
    restrictions: Vec<Restriction>,
    metadata: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AccessRule {
    rule_id: String,
    priority: u32,
    conditions: Vec<AccessCondition>,
    effect: Effect,
    metadata: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AccessMetrics {
    total_checks: u64,
    allowed_access: u64,
    denied_access: u64,
    average_check_time_ms: f64,
    violation_attempts: u64,
    suspicious_patterns: Vec<SuspiciousPattern>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    entry_id: String,
    timestamp: u64,
    subject: String,
    action: Action,
    resource: String,
    decision: Effect,
    context: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AccessToken {
    token_id: String,
    subject: String,
    roles: HashSet<String>,
    permissions: HashSet<String>,
    issued_at: u64,
    expires_at: u64,
    metadata: HashMap<String, String>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    Data,
    Function,
    Service,
    Network,
    System,
    Custom(String),
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum Action {
    Read,
    Write,
    Execute,
    Delete,
    Admin,
    Custom(String),
}

#[derive(Clone, Serialize, Deserialize)]
pub enum AccessCondition {
    Time(TimeRange),
    Location(LocationConstraint),
    Authentication(AuthLevel),
    Resource(ResourceConstraint),
    Custom(String),
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum Effect {
    Allow,
    Deny,
    RequireApproval,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct Restriction {
    restriction_type: RestrictionType,
    value: String,
    expiration: Option<u64>,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum RestrictionType {
    IPRange,
    TimeWindow,
    RateLimit,
    Location,
    Custom,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SuspiciousPattern {
    pattern_type: String,
    frequency: u32,
    severity: SecurityLevel,
    details: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
struct AccessPolicy {
    required_permissions: HashSet<String>,
    required_roles: HashSet<String>,
    ip_whitelist: Option<HashSet<String>>,
    mfa_required: bool,
    max_attempts: u32,
    lockout_duration: u64,
    risk_level: RiskLevel,
}

#[derive(Clone, Copy, Serialize, Deserialize, PartialEq)]
enum RiskLevel {
    Low,
    Medium,
    High,
    Critical,
}

#[wasm_bindgen]
pub struct AccessController {
    policies: DashMap<String, AccessPolicy>,
    role_hierarchy: Arc<RwLock<HashMap<String, HashSet<String>>>>,
    failed_attempts: DashMap<String, (u32, u64)>,
    memory_guard: Arc<MemoryGuard>,
    crypto: Arc<CryptoCore>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AccessEvent {
    event_id: String,
    subject_id: String,
    event_type: AccessEventType,
    timestamp: u64,
    details: HashMap<String, String>,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum AccessEventType {
    Granted,
    Denied,
    Violation,
    Expired,
    Suspicious,
}

#[wasm_bindgen]
impl AccessController {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let crypto = Arc::new(CryptoCore::new().expect("Failed to initialize crypto"));
        let (notification_tx, _) = broadcast::channel(1000);
        
        let controller = Self {
            policies: DashMap::new(),
            role_hierarchy: Arc::new(RwLock::new(HashMap::new())),
            failed_attempts: DashMap::new(),
            memory_guard: Arc::new(MemoryGuard),
            crypto,
        };

        controller.start_access_tasks();
        controller
    }

    #[wasm_bindgen]
    pub async fn check_access(
        &self,
        request: JsValue,
    ) -> Result<JsValue, JsValue> {
        let access_request: AccessRequest = serde_wasm_bindgen::from_value(request)?;
        
        let _permit = self.check_semaphore.acquire().await
            .map_err(|e| JsValue::from_str(&format!("Failed to acquire permit: {}", e)))?;

        // Validate token
        let token = self.validate_token(&access_request.token).await?;

        // Check permissions
        let decision = self.evaluate_access(&token, &access_request).await?;

        // Record audit
        self.record_audit_entry(&token, &access_request, &decision).await?;

        // Update metrics
        self.update_access_metrics(&decision).await?;

        Ok(serde_wasm_bindgen::to_value(&decision)?)
    }

    async fn validate_token(&self, token: &str) -> Result<AccessToken, JsValue> {
        let validation = Validation::new(Algorithm::HS256);
        
        let token_data = decode::<AccessToken>(
            token,
            &DecodingKey::from_secret("your-secret-key".as_ref()),
            &validation,
        ).map_err(|e| JsValue::from_str(&format!("Invalid token: {}", e)))?;

        if token_data.claims.expires_at < get_timestamp()? {
            return Err(JsValue::from_str("Token expired"));
        }

        Ok(token_data.claims)
    }

    async fn evaluate_access(
        &self,
        token: &AccessToken,
        request: &AccessRequest,
    ) -> Result<AccessDecision, JsValue> {
        // Check role-based permissions
        for role_id in &token.roles {
            if let Some(role) = self.get_role(role_id) {
                if self.check_role_permissions(&role, request).await? {
                    return Ok(AccessDecision::Allow);
                }
            }
        }

        // Check direct permissions
        for permission_id in &token.permissions {
            if let Some(permission) = self.get_permission(permission_id) {
                if self.check_permission(&permission, request).await? {
                    return Ok(AccessDecision::Allow);
                }
            }
        }

        // Check access rules
        if let Some(policy) = self.get_policy(&request.policy_id) {
            for rule in &policy.rules {
                if self.evaluate_rule(rule, token, request).await? {
                    return Ok(rule.effect.into());
                }
            }
        }

        Ok(AccessDecision::Deny)
    }

    async fn check_role_permissions(
        &self,
        role: &Role,
        request: &AccessRequest,
    ) -> Result<bool, JsValue> {
        // Check role restrictions
        for restriction in &role.restrictions {
            if !self.check_restriction(restriction, request).await? {
                return Ok(false);
            }
        }

        // Check inherited roles
        for inherited_role_id in &role.inheritance {
            if let Some(inherited_role) = self.get_role(inherited_role_id) {
                if self.check_role_permissions(&inherited_role, request).await? {
                    return Ok(true);
                }
            }
        }

        // Check permissions
        for permission_id in &role.permissions {
            if let Some(permission) = self.get_permission(permission_id) {
                if self.check_permission(&permission, request).await? {
                    return Ok(true);
                }
            }
        }

        Ok(false)
    }

    async fn check_permission(
        &self,
        permission: &Permission,
        request: &AccessRequest,
    ) -> Result<bool, JsValue> {
        // Check resource type
        if permission.resource_type != request.resource_type {
            return Ok(false);
        }

        // Check actions
        if !permission.actions.contains(&request.action) {
            return Ok(false);
        }

        // Check conditions
        for condition in &permission.conditions {
            if !self.evaluate_condition(condition, request).await? {
                return Ok(false);
            }
        }

        Ok(true)
    }

    async fn evaluate_condition(
        &self,
        condition: &AccessCondition,
        request: &AccessRequest,
    ) -> Result<bool, JsValue> {
        match condition {
            AccessCondition::Time(range) => {
                let now = get_timestamp()?;
                Ok(now >= range.start && now <= range.end)
            }
            AccessCondition::Location(constraint) => {
                self.check_location_constraint(constraint, request).await
            }
            AccessCondition::Authentication(level) => {
                self.check_auth_level(level, request).await
            }
            AccessCondition::Resource(constraint) => {
                self.check_resource_constraint(constraint, request).await
            }
            AccessCondition::Custom(rule) => {
                self.evaluate_custom_condition(rule, request).await
            }
        }
    }

    async fn record_audit_entry(
        &self,
        token: &AccessToken,
        request: &AccessRequest,
        decision: &AccessDecision,
    ) -> Result<(), JsValue> {
        let entry = AuditEntry {
            entry_id: generate_entry_id(),
            timestamp: get_timestamp()?,
            subject: token.subject.clone(),
            action: request.action,
            resource: request.resource.clone(),
            decision: (*decision).into(),
            context: request.context.clone(),
        };

        if let Some(mut policy) = self.policies.get_mut(&request.policy_id) {
            policy.audit_trail.push_back(entry);
            while policy.audit_trail.len() > 1000 {
                policy.audit_trail.pop_front();
            }
        }

        Ok(())
    }

    fn start_access_tasks(&self) {
        let controller = Arc::new(self.clone());

        // Metrics update task
        tokio::spawn({
            let controller = controller.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(ACCESS_CHECK_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    controller.update_access_metrics().await;
                }
            }
        });

        // Session cleanup task
        tokio::spawn({
            let controller = controller.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    controller.cleanup_expired_sessions().await;
                }
            }
        });
    }

    async fn update_access_metrics(&self) {
        // Update access metrics
    }

    async fn cleanup_expired_sessions(&self) {
        let mut sessions = self.active_sessions.write().await;
        let now = get_timestamp().unwrap_or(0);
        
        sessions.retain(|_, session| session.expires_at > now);
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&AccessMetrics {
                total_checks: 0,
                allowed_access: 0,
                denied_access: 0,
                average_check_time_ms: 0.0,
                violation_attempts: 0,
                suspicious_patterns: Vec::new(),
            })?)
        }
    }

    pub fn verify_session_token(&self, token: &[u8], stored: &[u8]) -> Result<bool, JsValue> {
        if token.len() != stored.len() {
            return Ok(false);
        }

        Ok(token.ct_eq(stored).into())
    }

    pub fn verify_access_signature(&self, sig1: &[u8], sig2: &[u8]) -> Result<bool, JsValue> {
        if sig1.len() != sig2.len() {
            return Ok(false);
        }

        Ok(sig1.ct_eq(sig2).into())
    }

    pub async fn validate_access(&self, 
        user_id: &str,
        resource_id: &str,
        user_permissions: &HashSet<String>,
        user_roles: &HashSet<String>,
        client_ip: &str,
        mfa_verified: bool,
    ) -> Result<bool, JsValue> {
        // Check if user is locked out
        if self.is_locked_out(user_id).await? {
            return Ok(false);
        }

        let policy = match self.policies.get(resource_id) {
            Some(p) => p.clone(),
            None => return Ok(false),
        };

        // Validate IP whitelist if present
        if let Some(ref whitelist) = policy.ip_whitelist {
            if !whitelist.contains(client_ip) {
                self.record_failed_attempt(user_id).await?;
                return Ok(false);
            }
        }

        // Validate MFA requirement
        if policy.mfa_required && !mfa_verified {
            self.record_failed_attempt(user_id).await?;
            return Ok(false);
        }

        // Validate permissions and roles
        let effective_permissions = self.get_effective_permissions(user_permissions, user_roles).await?;
        let effective_roles = self.get_effective_roles(user_roles).await?;

        if !policy.required_permissions.is_subset(&effective_permissions) ||
           !policy.required_roles.is_subset(&effective_roles) {
            self.record_failed_attempt(user_id).await?;
            return Ok(false);
        }

        Ok(true)
    }

    async fn get_effective_permissions(
        &self,
        user_permissions: &HashSet<String>,
        user_roles: &HashSet<String>,
    ) -> Result<HashSet<String>, JsValue> {
        let mut effective = user_permissions.clone();
        let role_hierarchy = self.role_hierarchy.read().await;

        for role in user_roles {
            if let Some(inherited_roles) = role_hierarchy.get(role) {
                for inherited_role in inherited_roles {
                    if let Some(role_permissions) = self.get_role_permissions(inherited_role) {
                        effective.extend(role_permissions);
                    }
                }
            }
        }

        Ok(effective)
    }

    async fn get_effective_roles(&self, user_roles: &HashSet<String>) -> Result<HashSet<String>, JsValue> {
        let mut effective = user_roles.clone();
        let role_hierarchy = self.role_hierarchy.read().await;

        let mut to_process = user_roles.clone();
        while let Some(role) = to_process.iter().next().cloned() {
            to_process.remove(&role);

            if let Some(inherited_roles) = role_hierarchy.get(&role) {
                for inherited_role in inherited_roles {
                    if effective.insert(inherited_role.clone()) {
                        to_process.insert(inherited_role.clone());
                    }
                }
            }
        }

        Ok(effective)
    }

    async fn is_locked_out(&self, user_id: &str) -> Result<bool, JsValue> {
        if let Some(entry) = self.failed_attempts.get(user_id) {
            let (attempts, last_attempt) = *entry;
            let policy = self.get_lockout_policy()?;
            
            if attempts >= policy.max_attempts {
                let current_time = self.current_timestamp()?;
                if current_time - last_attempt < policy.lockout_duration {
                    return Ok(true);
                } else {
                    self.failed_attempts.remove(user_id);
                }
            }
        }
        Ok(false)
    }

    async fn record_failed_attempt(&self, user_id: &str) -> Result<(), JsValue> {
        let entry = self.failed_attempts
            .entry(user_id.to_string())
            .or_insert_with(|| (0, self.current_timestamp()?));
        
        entry.0 += 1;
        entry.1 = self.current_timestamp()?;
        Ok(())
    }

    pub fn hash_credentials(&self, credentials: &[u8]) -> Result<Vec<u8>, JsValue> {
        self.crypto.hash_password(credentials)
    }

    pub fn verify_credentials(&self, input: &[u8], stored_hash: &[u8]) -> Result<bool, JsValue> {
        self.crypto.verify_password(input, stored_hash)
    }
}

fn generate_entry_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("ENTRY-{:016x}", rng.gen::<u64>())
}

fn get_timestamp() -> Result<u64, JsValue> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for AccessController {
    fn drop(&mut self) {
        // Clear permission cache
        for mut entry in self.permission_cache.iter_mut() {
            entry.value_mut().zeroize();
        }
        self.permission_cache.clear();
        
        // Clear role mappings
        if let Ok(mut roles) = self.role_hierarchy.write() {
            for (_, permissions) in roles.iter_mut() {
                permissions.clear();
            }
            roles.clear();
        }
        
        // Clear token blacklist
        for mut token in self.token_blacklist.iter_mut() {
            token.value_mut().zeroize();
        }
        self.token_blacklist.clear();
        
        // Force memory deallocation
        self.permission_cache.shrink_to_fit();
        self.token_blacklist.shrink_to_fit();
    }
}
