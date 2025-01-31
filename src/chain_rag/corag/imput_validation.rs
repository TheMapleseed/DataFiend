use wasm_bindgen::prelude::*;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use serde_json::Value;
use crate::error::error_system::{SystemError, ValidationError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InputConstraints {
    max_size: usize,
    allowed_types: Vec<String>,
    pattern: Option<String>,
    range: Option<(f64, f64)>,
    required_fields: Vec<String>,
    custom_validators: Vec<String>,
}

impl CoRAG {
    pub async fn validate_input(&self, input: &Value, context: &str) -> Result<(), SystemError> {
        // Get learned constraints for this context
        let constraints = self.chain
            .get_input_constraints(context)
            .await?;

        // Size validation
        self.validate_input_size(input, &constraints).await?;

        // Type validation
        self.validate_input_types(input, &constraints).await?;

        // Pattern validation
        self.validate_input_patterns(input, &constraints).await?;

        // Structure validation
        self.validate_input_structure(input, &constraints).await?;

        // Custom validation rules from learning
        self.validate_learned_rules(input, context).await?;

        Ok(())
    }

    async fn validate_input_size(&self, input: &Value, constraints: &InputConstraints) -> Result<(), SystemError> {
        let input_size = serde_json::to_string(input)
            .map_err(|_| SystemError::ValidationError(ValidationError::FormatError {
                expected: "serializable JSON".to_string(),
                received: "invalid JSON".to_string(),
            }))?
            .len();

        if input_size > constraints.max_size {
            return Err(SystemError::ValidationError(ValidationError::SizeError {
                max: constraints.max_size,
                received: input_size,
            }));
        }

        Ok(())
    }

    async fn validate_input_types(&self, input: &Value, constraints: &InputConstraints) -> Result<(), SystemError> {
        match input {
            Value::Object(map) => {
                for (key, value) in map {
                    let value_type = match value {
                        Value::Null => "null",
                        Value::Bool(_) => "boolean",
                        Value::Number(_) => "number",
                        Value::String(_) => "string",
                        Value::Array(_) => "array",
                        Value::Object(_) => "object",
                    };

                    if !constraints.allowed_types.contains(&value_type.to_string()) {
                        return Err(SystemError::ValidationError(ValidationError::TypeError {
                            field: key.clone(),
                            expected: constraints.allowed_types.join(", "),
                            received: value_type.to_string(),
                        }));
                    }
                }
            },
            _ => return Err(SystemError::ValidationError(ValidationError::TypeError {
                field: "root".to_string(),
                expected: "object".to_string(),
                received: "non-object".to_string(),
            })),
        }

        Ok(())
    }

    async fn validate_input_patterns(&self, input: &Value, constraints: &InputConstraints) -> Result<(), SystemError> {
        if let Some(pattern) = &constraints.pattern {
            let regex = regex::Regex::new(pattern)
                .map_err(|_| SystemError::ValidationError(ValidationError::PatternError {
                    pattern: pattern.clone(),
                    details: "Invalid regex pattern".to_string(),
                }))?;

            match input {
                Value::String(s) => {
                    if !regex.is_match(s) {
                        return Err(SystemError::ValidationError(ValidationError::PatternError {
                            pattern: pattern.clone(),
                            details: format!("String '{}' does not match pattern", s),
                        }));
                    }
                },
                Value::Object(map) => {
                    for (key, value) in map {
                        if let Value::String(s) = value {
                            if !regex.is_match(s) {
                                return Err(SystemError::ValidationError(ValidationError::PatternError {
                                    pattern: pattern.clone(),
                                    details: format!("Field '{}' with value '{}' does not match pattern", key, s),
                                }));
                            }
                        }
                    }
                },
                _ => {}
            }
        }

        Ok(())
    }

    async fn validate_input_structure(&self, input: &Value, constraints: &InputConstraints) -> Result<(), SystemError> {
        if let Value::Object(map) = input {
            // Check required fields
            for field in &constraints.required_fields {
                if !map.contains_key(field) {
                    return Err(SystemError::ValidationError(ValidationError::MissingField {
                        field: field.clone(),
                    }));
                }
            }

            // Validate numeric ranges
            if let Some((min, max)) = constraints.range {
                for (key, value) in map {
                    if let Value::Number(n) = value {
                        let n = n.as_f64().unwrap();
                        if n < min || n > max {
                            return Err(SystemError::ValidationError(ValidationError::RangeError {
                                field: key.clone(),
                                min,
                                max,
                                value: n,
                            }));
                        }
                    }
                }
            }
        }

        Ok(())
    }

    async fn validate_learned_rules(&self, input: &Value, context: &str) -> Result<(), SystemError> {
        // Get learned validation rules from the chain
        let rules = self.chain
            .get_validation_rules(context)
            .await?;

        for rule in rules {
            if !self.evaluate_rule(input, &rule).await? {
                return Err(SystemError::ValidationError(ValidationError::RuleViolation {
                    rule: rule.name,
                    details: rule.description,
                }));
            }
        }

        Ok(())
    }

    async fn evaluate_rule(&self, input: &Value, rule: &ValidationRule) -> Result<bool, SystemError> {
        // Apply learned validation rules
        match rule.rule_type {
            RuleType::Dependency => self.validate_field_dependency(input, rule).await?,
            RuleType::Correlation => self.validate_field_correlation(input, rule).await?,
            RuleType::Format => self.validate_format_rule(input, rule).await?,
            RuleType::Custom => self.validate_custom_rule(input, rule).await?,
        }
    }
} 
