use wasm_bindgen::prelude::*;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;
use num_traits::{NumCast, Bounded};

#[derive(Clone, Serialize, Deserialize)]
pub enum ValidationType {
    Integer {
        min: i64,
        max: i64,
        allow_unsigned: bool,
    },
    Float {
        min: f64,
        max: f64,
        precision: u8,
    },
    String {
        min_length: usize,
        max_length: usize,
        pattern: Option<String>,
    },
    Array {
        min_items: usize,
        max_items: usize,
        item_type: Box<ValidationType>,
    },
    Object {
        properties: HashMap<String, ValidationType>,
        required: Vec<String>,
    },
}

#[wasm_bindgen]
pub struct TypeValidator {
    type_registry: Arc<HashMap<String, ValidationType>>,
}

#[wasm_bindgen]
impl TypeValidator {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let mut registry = HashMap::new();
        
        // Register common types
        registry.insert("i32".to_string(), ValidationType::Integer {
            min: i32::MIN as i64,
            max: i32::MAX as i64,
            allow_unsigned: false,
        });
        
        registry.insert("u32".to_string(), ValidationType::Integer {
            min: 0,
            max: u32::MAX as i64,
            allow_unsigned: true,
        });
        
        registry.insert("i64".to_string(), ValidationType::Integer {
            min: i64::MIN,
            max: i64::MAX,
            allow_unsigned: false,
        });
        
        registry.insert("f64".to_string(), ValidationType::Float {
            min: f64::MIN,
            max: f64::MAX,
            precision: 15,
        });

        Self {
            type_registry: Arc::new(registry),
        }
    }

    #[wasm_bindgen]
    pub fn validate_cast(&self, value: JsValue, target_type: String) -> Result<JsValue, JsValue> {
        let validation_type = self.type_registry
            .get(&target_type)
            .ok_or_else(|| JsValue::from_str("Unknown target type"))?;

        self.validate_value(&value, validation_type)
    }

    fn validate_value(&self, value: &JsValue, validation_type: &ValidationType) -> Result<JsValue, JsValue> {
        match validation_type {
            ValidationType::Integer { min, max, allow_unsigned } => {
                self.validate_integer(value, *min, *max, *allow_unsigned)
            },
            ValidationType::Float { min, max, precision } => {
                self.validate_float(value, *min, *max, *precision)
            },
            ValidationType::String { min_length, max_length, pattern } => {
                self.validate_string(value, *min_length, *max_length, pattern)
            },
            ValidationType::Array { min_items, max_items, item_type } => {
                self.validate_array(value, *min_items, *max_items, item_type)
            },
            ValidationType::Object { properties, required } => {
                self.validate_object(value, properties, required)
            },
        }
    }

    fn validate_integer(
        &self,
        value: &JsValue,
        min: i64,
        max: i64,
        allow_unsigned: bool,
    ) -> Result<JsValue, JsValue> {
        if let Some(num) = value.as_f64() {
            // Check if it's a whole number
            if num.fract() != 0.0 {
                return Err(JsValue::from_str("Value must be a whole number"));
            }

            // Check unsigned constraint
            if !allow_unsigned && num < 0.0 {
                return Err(JsValue::from_str("Negative values not allowed"));
            }

            // Check bounds
            let num_i64: i64 = num as i64;
            if num_i64 < min || num_i64 > max {
                return Err(JsValue::from_str(&format!(
                    "Value must be between {} and {}",
                    min, max
                )));
            }

            Ok(JsValue::from_f64(num))
        } else {
            Err(JsValue::from_str("Value must be a number"))
        }
    }

    fn validate_float(
        &self,
        value: &JsValue,
        min: f64,
        max: f64,
        precision: u8,
    ) -> Result<JsValue, JsValue> {
        if let Some(num) = value.as_f64() {
            // Check bounds
            if num < min || num > max || num.is_nan() {
                return Err(JsValue::from_str(&format!(
                    "Value must be between {} and {}",
                    min, max
                )));
            }

            // Round to specified precision
            let factor = 10f64.powi(precision as i32);
            let rounded = (num * factor).round() / factor;

            Ok(JsValue::from_f64(rounded))
        } else {
            Err(JsValue::from_str("Value must be a number"))
        }
    }

    fn validate_string(
        &self,
        value: &JsValue,
        min_length: usize,
        max_length: usize,
        pattern: &Option<String>,
    ) -> Result<JsValue, JsValue> {
        if let Some(s) = value.as_string() {
            // Check length constraints
            if s.len() < min_length || s.len() > max_length {
                return Err(JsValue::from_str(&format!(
                    "String length must be between {} and {}",
                    min_length, max_length
                )));
            }

            // Check pattern if specified
            if let Some(pattern) = pattern {
                let regex = regex::Regex::new(pattern)
                    .map_err(|_| JsValue::from_str("Invalid pattern"))?;
                
                if !regex.is_match(&s) {
                    return Err(JsValue::from_str("String does not match pattern"));
                }
            }

            Ok(JsValue::from_str(&s))
        } else {
            Err(JsValue::from_str("Value must be a string"))
        }
    }

    fn validate_array(
        &self,
        value: &JsValue,
        min_items: usize,
        max_items: usize,
        item_type: &ValidationType,
    ) -> Result<JsValue, JsValue> {
        if let Ok(arr) = js_sys::Array::from(value).dyn_into::<js_sys::Array>() {
            // Check length constraints
            let length = arr.length() as usize;
            if length < min_items || length > max_items {
                return Err(JsValue::from_str(&format!(
                    "Array length must be between {} and {}",
                    min_items, max_items
                )));
            }

            // Validate each item
            let mut validated = js_sys::Array::new();
            for i in 0..length {
                let item = arr.get(i);
                let validated_item = self.validate_value(&item, item_type)?;
                validated.push(&validated_item);
            }

            Ok(validated.into())
        } else {
            Err(JsValue::from_str("Value must be an array"))
        }
    }

    fn validate_object(
        &self,
        value: &JsValue,
        properties: &HashMap<String, ValidationType>,
        required: &[String],
    ) -> Result<JsValue, JsValue> {
        if let Ok(obj) = js_sys::Object::from(value).dyn_into::<js_sys::Object>() {
            // Check required properties
            for prop in required {
                if js_sys::Reflect::get(&obj, &JsValue::from_str(prop))?.is_undefined() {
                    return Err(JsValue::from_str(&format!(
                        "Missing required property: {}",
                        prop
                    )));
                }
            }

            // Validate each property
            let result = js_sys::Object::new();
            for (prop, prop_type) in properties {
                if let Ok(value) = js_sys::Reflect::get(&obj, &JsValue::from_str(prop)) {
                    if !value.is_undefined() {
                        let validated = self.validate_value(&value, prop_type)?;
                        js_sys::Reflect::set(
                            &result,
                            &JsValue::from_str(prop),
                            &validated,
                        )?;
                    }
                }
            }

            Ok(result.into())
        } else {
            Err(JsValue::from_str("Value must be an object"))
        }
    }

    #[wasm_bindgen]
    pub fn safe_cast<T: NumCast + Bounded>(
        &self,
        value: f64,
        type_name: &str,
    ) -> Result<f64, JsValue> {
        let min = T::min_value().to_f64()
            .ok_or_else(|| JsValue::from_str("Could not convert minimum value"))?;
        
        let max = T::max_value().to_f64()
            .ok_or_else(|| JsValue::from_str("Could not convert maximum value"))?;

        if value < min || value > max {
            return Err(JsValue::from_str(&format!(
                "Value {} out of range for type {}: [{}, {}]",
                value, type_name, min, max
            )));
        }

        Ok(value)
    }
} 