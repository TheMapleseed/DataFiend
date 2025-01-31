use wasm_bindgen::prelude::*;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use dashmap::DashMap;
use regex::Regex;

#[derive(Clone, Serialize, Deserialize)]
pub struct RoutePermission {
    path_pattern: String,
    methods: Vec<String>,
    required_permissions: Vec<String>,
    mfa_required: bool,
    rate_limit: Option<RateLimit>,
    validation_rules: Vec<ValidationRule>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RateLimit {
    requests: u32,
    window_seconds: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum ValidationRule {
    RequireParams(Vec<String>),
    MaxBodySize(usize),
    ContentType(String),
    CustomValidator(String),
}

#[wasm_bindgen]
pub struct RouteValidator {
    route_permissions: Arc<DashMap<String, RoutePermission>>,
    path_patterns: Arc<DashMap<String, Regex>>,
    session_manager: Arc<SessionManager>,
}

#[wasm_bindgen]
impl RouteValidator {
    #[wasm_bindgen(constructor)]
    pub fn new(session_manager: Arc<SessionManager>) -> Self {
        Self {
            route_permissions: Arc::new(DashMap::new()),
            path_patterns: Arc::new(DashMap::new()),
            session_manager,
        }
    }

    #[wasm_bindgen]
    pub fn validate_route(
        &self,
        path: &str,
        method: &str,
        session_id: &str,
        request_data: JsValue,
    ) -> Result<bool, JsValue> {
        // Verify session first
        if !self.session_manager.verify_session(session_id) {
            return Ok(false);
        }

        // Get session info
        let session_info = self.session_manager.get_session_info(session_id)?;
        let session: SessionData = serde_wasm_bindgen::from_value(session_info)?;

        // Find matching route permission
        let permission = self.find_matching_route(path)?;
        
        if let Some(permission) = permission {
            // Validate HTTP method
            if !permission.methods.iter().any(|m| m == method) {
                return Ok(false);
            }

            // Check MFA requirement
            if permission.mfa_required && !session.mfa_verified {
                return Ok(false);
            }

            // Validate permissions
            if !self.validate_permissions(&permission.required_permissions, &session.permissions) {
                return Ok(false);
            }

            // Apply rate limiting if configured
            if let Some(rate_limit) = &permission.rate_limit {
                if !self.check_rate_limit(session_id, &permission, rate_limit)? {
                    return Ok(false);
                }
            }

            // Apply validation rules
            if !self.apply_validation_rules(&permission.validation_rules, &request_data)? {
                return Ok(false);
            }

            Ok(true)
        } else {
            // No matching route found - default to denied
            Ok(false)
        }
    }

    fn find_matching_route(&self, path: &str) -> Result<Option<RoutePermission>, JsValue> {
        for entry in self.route_permissions.iter() {
            let pattern = self.path_patterns
                .entry(entry.key().clone())
                .or_insert_with(|| {
                    Regex::new(entry.value().path_pattern.as_str())
                        .expect("Invalid route pattern")
                });

            if pattern.is_match(path) {
                return Ok(Some(entry.value().clone()));
            }
        }
        Ok(None)
    }

    fn validate_permissions(
        &self,
        required: &[String],
        user_permissions: &[String],
    ) -> bool {
        required.iter().all(|req| user_permissions.contains(req))
    }

    fn check_rate_limit(
        &self,
        session_id: &str,
        permission: &RoutePermission,
        rate_limit: &RateLimit,
    ) -> Result<bool, JsValue> {
        // Implementation would track request counts per session/route
        // and enforce rate limits based on the configuration
        Ok(true) // Placeholder
    }

    fn apply_validation_rules(
        &self,
        rules: &[ValidationRule],
        request_data: &JsValue,
    ) -> Result<bool, JsValue> {
        for rule in rules {
            match rule {
                ValidationRule::RequireParams(params) => {
                    let data: serde_json::Value = serde_wasm_bindgen::from_value(request_data.clone())?;
                    if !params.iter().all(|param| data.get(param).is_some()) {
                        return Ok(false);
                    }
                },
                ValidationRule::MaxBodySize(max_size) => {
                    let data: String = serde_wasm_bindgen::from_value(request_data.clone())?;
                    if data.len() > *max_size {
                        return Ok(false);
                    }
                },
                ValidationRule::ContentType(content_type) => {
                    let headers: js_sys::Object = serde_wasm_bindgen::from_value(request_data.clone())?;
                    let content_type_header = js_sys::Reflect::get(&headers, &"content-type".into())?;
                    if content_type_header != content_type {
                        return Ok(false);
                    }
                },
                ValidationRule::CustomValidator(validator_name) => {
                    // Custom validation logic would go here
                    if !self.execute_custom_validator(validator_name, request_data)? {
                        return Ok(false);
                    }
                }
            }
        }
        Ok(true)
    }

    fn execute_custom_validator(
        &self,
        validator_name: &str,
        request_data: &JsValue,
    ) -> Result<bool, JsValue> {
        // Custom validator implementation would go here
        Ok(true) // Placeholder
    }

    #[wasm_bindgen]
    pub fn add_route_permission(&self, route_config: JsValue) -> Result<(), JsValue> {
        let permission: RoutePermission = serde_wasm_bindgen::from_value(route_config)?;
        let pattern = permission.path_pattern.clone();
        
        // Validate the regex pattern
        Regex::new(&pattern)
            .map_err(|e| JsValue::from_str(&format!("Invalid route pattern: {}", e)))?;
            
        self.route_permissions.insert(pattern.clone(), permission);
        Ok(())
    }
} 