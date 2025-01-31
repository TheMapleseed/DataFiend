use wasm_bindgen::prelude::*;
use std::sync::Arc;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

// Default limits in bytes
const DEFAULT_MAX_STRING_SIZE: usize = 1024 * 1024;  // 1MB
const DEFAULT_MAX_ARRAY_SIZE: usize = 10 * 1024 * 1024;  // 10MB
const DEFAULT_MAX_OBJECT_SIZE: usize = 50 * 1024 * 1024;  // 50MB
const DEFAULT_MAX_TOTAL_SIZE: usize = 100 * 1024 * 1024;  // 100MB
const DEFAULT_MAX_DEPTH: usize = 20;
const DEFAULT_MAX_KEYS: usize = 1000;

#[derive(Clone, Serialize, Deserialize)]
pub struct EntryLimits {
    max_string_size: usize,
    max_array_size: usize,
    max_object_size: usize,
    max_total_size: usize,
    max_depth: usize,
    max_keys: usize,
    type_specific_limits: HashMap<String, TypeLimit>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct TypeLimit {
    max_size: usize,
    max_count: usize,
    allowed_types: Vec<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SizeMetrics {
    current_total_size: usize,
    largest_entry: usize,
    rejected_entries: u64,
    oversized_types: HashMap<String, u64>,
}

#[wasm_bindgen]
pub struct EntryLimiter {
    limits: Arc<DashMap<String, EntryLimits>>,
    metrics: Arc<DashMap<String, SizeMetrics>>,
}

#[wasm_bindgen]
impl EntryLimiter {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            limits: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
        }
    }

    #[wasm_bindgen]
    pub fn set_limits(&self, namespace: String, limits: JsValue) -> Result<(), JsValue> {
        let mut entry_limits: EntryLimits = serde_wasm_bindgen::from_value(limits)?;
        
        // Validate and set defaults if needed
        entry_limits.max_string_size = entry_limits.max_string_size
            .max(0)
            .min(DEFAULT_MAX_STRING_SIZE);
            
        entry_limits.max_array_size = entry_limits.max_array_size
            .max(0)
            .min(DEFAULT_MAX_ARRAY_SIZE);
            
        entry_limits.max_object_size = entry_limits.max_object_size
            .max(0)
            .min(DEFAULT_MAX_OBJECT_SIZE);
            
        entry_limits.max_total_size = entry_limits.max_total_size
            .max(0)
            .min(DEFAULT_MAX_TOTAL_SIZE);
            
        entry_limits.max_depth = entry_limits.max_depth
            .max(1)
            .min(DEFAULT_MAX_DEPTH);
            
        entry_limits.max_keys = entry_limits.max_keys
            .max(1)
            .min(DEFAULT_MAX_KEYS);

        self.limits.insert(namespace, entry_limits);
        Ok(())
    }

    #[wasm_bindgen]
    pub fn validate_entry(&self, namespace: String, entry: JsValue) -> Result<bool, JsValue> {
        let limits = self.limits
            .get(&namespace)
            .ok_or_else(|| JsValue::from_str("No limits defined for namespace"))?;

        let mut context = ValidationContext {
            current_depth: 0,
            total_size: 0,
            current_path: Vec::new(),
        };

        match self.validate_value(&entry, &limits, &mut context) {
            Ok(size) => {
                // Update metrics
                self.update_metrics(&namespace, size, true, None);
                Ok(true)
            },
            Err(e) => {
                // Update failure metrics
                if let Some(type_name) = self.get_type_name(&entry) {
                    self.update_metrics(&namespace, 0, false, Some(type_name));
                }
                Err(e)
            }
        }
    }

    fn validate_value(
        &self,
        value: &JsValue,
        limits: &EntryLimits,
        context: &mut ValidationContext,
    ) -> Result<usize, JsValue> {
        // Check depth
        if context.current_depth >= limits.max_depth {
            return Err(JsValue::from_str("Maximum depth exceeded"));
        }
        context.current_depth += 1;

        let size = match self.get_type_name(value) {
            Some("string") => self.validate_string(value, limits)?,
            Some("array") => self.validate_array(value, limits, context)?,
            Some("object") => self.validate_object(value, limits, context)?,
            Some("number") => std::mem::size_of::<f64>(),
            Some("boolean") => std::mem::size_of::<bool>(),
            Some("null") => 0,
            _ => return Err(JsValue::from_str("Unsupported type")),
        };

        // Check total size
        context.total_size += size;
        if context.total_size > limits.max_total_size {
            return Err(JsValue::from_str("Maximum total size exceeded"));
        }

        context.current_depth -= 1;
        Ok(size)
    }

    fn validate_string(&self, value: &JsValue, limits: &EntryLimits) -> Result<usize, JsValue> {
        if let Some(s) = value.as_string() {
            let size = s.len();
            if size > limits.max_string_size {
                return Err(JsValue::from_str("String size exceeds limit"));
            }
            Ok(size)
        } else {
            Err(JsValue::from_str("Invalid string value"))
        }
    }

    fn validate_array(
        &self,
        value: &JsValue,
        limits: &EntryLimits,
        context: &mut ValidationContext,
    ) -> Result<usize, JsValue> {
        if let Ok(arr) = js_sys::Array::from(value).dyn_into::<js_sys::Array>() {
            let length = arr.length() as usize;
            let mut total_size = std::mem::size_of::<usize>(); // Array header

            for i in 0..length {
                context.current_path.push(i.to_string());
                let item = arr.get(i);
                total_size += self.validate_value(&item, limits, context)?;
                context.current_path.pop();
            }

            if total_size > limits.max_array_size {
                return Err(JsValue::from_str("Array size exceeds limit"));
            }
            Ok(total_size)
        } else {
            Err(JsValue::from_str("Invalid array value"))
        }
    }

    fn validate_object(
        &self,
        value: &JsValue,
        limits: &EntryLimits,
        context: &mut ValidationContext,
    ) -> Result<usize, JsValue> {
        if let Ok(obj) = js_sys::Object::from(value).dyn_into::<js_sys::Object>() {
            let keys = js_sys::Object::keys(&obj);
            let key_count = keys.length() as usize;

            if key_count > limits.max_keys {
                return Err(JsValue::from_str("Too many object keys"));
            }

            let mut total_size = std::mem::size_of::<usize>(); // Object header

            for i in 0..key_count {
                let key = keys.get(i).as_string()
                    .ok_or_else(|| JsValue::from_str("Invalid object key"))?;
                
                context.current_path.push(key.clone());
                let value = js_sys::Reflect::get(&obj, &JsValue::from_str(&key))?;
                total_size += key.len() + self.validate_value(&value, limits, context)?;
                context.current_path.pop();
            }

            if total_size > limits.max_object_size {
                return Err(JsValue::from_str("Object size exceeds limit"));
            }
            Ok(total_size)
        } else {
            Err(JsValue::from_str("Invalid object value"))
        }
    }

    fn get_type_name(&self, value: &JsValue) -> Option<&'static str> {
        if value.is_string() { Some("string") }
        else if value.is_array() { Some("array") }
        else if value.is_object() { Some("object") }
        else if value.is_number() { Some("number") }
        else if value.is_boolean() { Some("boolean") }
        else if value.is_null() { Some("null") }
        else { None }
    }

    fn update_metrics(
        &self,
        namespace: &str,
        size: usize,
        success: bool,
        type_name: Option<String>,
    ) {
        self.metrics
            .entry(namespace.to_string())
            .or_insert_with(|| SizeMetrics {
                current_total_size: 0,
                largest_entry: 0,
                rejected_entries: 0,
                oversized_types: HashMap::new(),
            })
            .and_modify(|m| {
                if success {
                    m.current_total_size += size;
                    m.largest_entry = m.largest_entry.max(size);
                } else {
                    m.rejected_entries += 1;
                    if let Some(t) = type_name {
                        *m.oversized_types.entry(t).or_insert(0) += 1;
                    }
                }
            });
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self, namespace: String) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get(&namespace) {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Err(JsValue::from_str("No metrics found for namespace"))
        }
    }
}

struct ValidationContext {
    current_depth: usize,
    total_size: usize,
    current_path: Vec<String>,
}

impl Drop for EntryLimiter {
    fn drop(&mut self) {
        self.limits.clear();
        self.metrics.clear();
    }
} 