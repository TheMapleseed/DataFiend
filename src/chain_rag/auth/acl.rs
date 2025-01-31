use wasm_bindgen::prelude::*;
use std::sync::Arc;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::collections::{HashMap, HashSet};
use chrono::{DateTime, Utc};

#[derive(Clone, Serialize, Deserialize)]
pub struct AccessRule {
    resource_pattern: String,
    permissions: HashSet<String>,
    conditions: Vec<AccessCondition>,
    priority: i32,
    expiration: Option<DateTime<Utc>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub enum AccessCondition {
    TimeWindow {
        start_hour: u8,
        end_hour: u8,
        days: HashSet<String>,
    },
    IPRange {
        allowed_ranges: Vec<String>,
    },
    RateLimit {
        max_requests: u32,
        window_seconds: u32,
    },
    RequireAttributes {
        attributes: HashMap<String, String>,
    },
    CustomCondition {
        validator: String,
        params: HashMap<String, String>,
    },
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AccessRequest {
    resource: String,
    action: String,
    user_id: String,
    ip_address: String,
    attributes: HashMap<String, String>,
    timestamp: DateTime<Utc>,
}

#[wasm_bindgen]
pub struct AccessControlList {
    rules: Arc<DashMap<String, Vec<AccessRule>>>,
    rate_limits: Arc<DashMap<String, DashMap<String, Vec<DateTime<Utc>>>>>,
    user_attributes: Arc<DashMap<String, HashMap<String, String>>>,
}

#[wasm_bindgen]
impl AccessControlList {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            rules: Arc::new(DashMap::new()),
            rate_limits: Arc::new(DashMap::new()),
            user_attributes: Arc::new(DashMap::new()),
        }
    }

    #[wasm_bindgen]
    pub fn check_access(&self, request: JsValue) -> Result<bool, JsValue> {
        let access_req: AccessRequest = serde_wasm_bindgen::from_value(request)?;
        
        // Get applicable rules
        let mut applicable_rules: Vec<AccessRule> = Vec::new();
        for entry in self.rules.iter() {
            for rule in entry.value() {
                if self.matches_resource_pattern(&rule.resource_pattern, &access_req.resource) {
                    applicable_rules.push(rule.clone());
                }
            }
        }

        // Sort by priority
        applicable_rules.sort_by_key(|rule| -rule.priority);

        // Check each rule
        for rule in applicable_rules {
            // Check if rule is expired
            if let Some(expiration) = rule.expiration {
                if expiration < access_req.timestamp {
                    continue;
                }
            }

            // Check permissions
            if !rule.permissions.contains(&access_req.action) {
                continue;
            }

            // Check conditions
            let mut conditions_met = true;
            for condition in &rule.conditions {
                if !self.evaluate_condition(condition, &access_req)? {
                    conditions_met = false;
                    break;
                }
            }

            if conditions_met {
                return Ok(true);
            }
        }

        Ok(false)
    }

    fn evaluate_condition(&self, condition: &AccessCondition, request: &AccessRequest) -> Result<bool, JsValue> {
        match condition {
            AccessCondition::TimeWindow { start_hour, end_hour, days } => {
                let hour = request.timestamp.hour();
                let day = request.timestamp.format("%A").to_string();
                
                Ok(*start_hour <= hour && hour <= *end_hour && days.contains(&day))
            },
            
            AccessCondition::IPRange { allowed_ranges } => {
                // Implement IP range checking
                for range in allowed_ranges {
                    if self.ip_in_range(&request.ip_address, range) {
                        return Ok(true);
                    }
                }
                Ok(false)
            },
            
            AccessCondition::RateLimit { max_requests, window_seconds } => {
                let key = format!("{}:{}", request.user_id, request.resource);
                let now = Utc::now();
                let window_start = now - chrono::Duration::seconds(*window_seconds as i64);
                
                if let Some(mut requests) = self.rate_limits.get_mut(&key) {
                    // Clean old requests
                    requests.retain(|_, times| {
                        times.retain(|&time| time >= window_start);
                        !times.is_empty()
                    });
                    
                    // Check current count
                    let count = requests.values().map(|times| times.len()).sum::<usize>();
                    Ok(count < *max_requests as usize)
                } else {
                    Ok(true)
                }
            },
            
            AccessCondition::RequireAttributes { attributes } => {
                if let Some(user_attrs) = self.user_attributes.get(&request.user_id) {
                    Ok(attributes.iter().all(|(k, v)| {
                        user_attrs.get(k).map_or(false, |user_v| user_v == v)
                    }))
                } else {
                    Ok(false)
                }
            },
            
            AccessCondition::CustomCondition { validator, params } => {
                self.evaluate_custom_condition(validator, params, request)
            }
        }
    }

    #[wasm_bindgen]
    pub fn add_rule(&self, rule: JsValue) -> Result<(), JsValue> {
        let access_rule: AccessRule = serde_wasm_bindgen::from_value(rule)?;
        
        self.rules
            .entry(access_rule.resource_pattern.clone())
            .or_insert_with(Vec::new)
            .push(access_rule);

        Ok(())
    }

    #[wasm_bindgen]
    pub fn remove_rule(&self, resource_pattern: String, priority: i32) -> bool {
        if let Some(mut rules) = self.rules.get_mut(&resource_pattern) {
            let initial_len = rules.len();
            rules.retain(|rule| rule.priority != priority);
            initial_len != rules.len()
        } else {
            false
        }
    }

    #[wasm_bindgen]
    pub fn set_user_attributes(&self, user_id: String, attributes: JsValue) -> Result<(), JsValue> {
        let attrs: HashMap<String, String> = serde_wasm_bindgen::from_value(attributes)?;
        self.user_attributes.insert(user_id, attrs);
        Ok(())
    }

    // Helper methods
    fn matches_resource_pattern(&self, pattern: &str, resource: &str) -> bool {
        // Implement pattern matching (could use regex or glob patterns)
        pattern == "*" || pattern == resource || 
        (pattern.ends_with('*') && resource.starts_with(&pattern[..pattern.len()-1]))
    }

    fn ip_in_range(&self, ip: &str, range: &str) -> bool {
        // Implement IP range checking
        // This is a placeholder - real implementation would parse CIDR notation
        ip.starts_with(range)
    }

    fn evaluate_custom_condition(
        &self,
        validator: &str,
        params: &HashMap<String, String>,
        request: &AccessRequest
    ) -> Result<bool, JsValue> {
        // Implement custom condition evaluation
        // This would integrate with a plugin system or predefined validators
        Ok(true) // Placeholder
    }
}

impl Drop for AccessControlList {
    fn drop(&mut self) {
        // Clear sensitive data
        self.rules.clear();
        self.rate_limits.clear();
        self.user_attributes.clear();
    }
} 
