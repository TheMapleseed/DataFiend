use std::collections::HashMap;
use serde::{Serialize, Deserialize};
use crate::error::error_system::SystemError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlTable {
    spaces: HashMap<String, ControlSpace>,
    priorities: HashMap<String, Priority>,
    limits: ControlLimits,
    metadata: TableMetadata,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlSpace {
    name: String,
    signals: Vec<SignalDefinition>,
    constraints: Vec<Constraint>,
    handlers: Vec<HandlerDefinition>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SignalDefinition {
    name: String,
    signal_type: SignalType,
    parameters: Vec<Parameter>,
    validation: ValidationRule,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ControlTableBuilder {
    table: ControlTable,
    current_space: Option<String>,
}

impl ControlTableBuilder {
    pub fn new() -> Self {
        Self {
            table: ControlTable {
                spaces: HashMap::new(),
                priorities: HashMap::new(),
                limits: ControlLimits::default(),
                metadata: TableMetadata::default(),
            },
            current_space: None,
        }
    }

    pub fn add_space(&mut self, name: &str) -> &mut Self {
        self.table.spaces.insert(name.to_string(), ControlSpace {
            name: name.to_string(),
            signals: Vec::new(),
            constraints: Vec::new(),
            handlers: Vec::new(),
        });
        self.current_space = Some(name.to_string());
        self
    }

    pub fn add_signal(&mut self, signal: SignalDefinition) -> Result<&mut Self, SystemError> {
        if let Some(space_name) = &self.current_space {
            if let Some(space) = self.table.spaces.get_mut(space_name) {
                // Validate signal before adding
                self.validate_signal(&signal)?;
                space.signals.push(signal);
                Ok(self)
            } else {
                Err(SystemError::ControlError("Invalid control space".into()))
            }
        } else {
            Err(SystemError::ControlError("No control space selected".into()))
        }
    }

    pub fn add_constraint(&mut self, constraint: Constraint) -> Result<&mut Self, SystemError> {
        if let Some(space_name) = &self.current_space {
            if let Some(space) = self.table.spaces.get_mut(space_name) {
                space.constraints.push(constraint);
                Ok(self)
            } else {
                Err(SystemError::ControlError("Invalid control space".into()))
            }
        } else {
            Err(SystemError::ControlError("No control space selected".into()))
        }
    }

    pub fn add_handler(&mut self, handler: HandlerDefinition) -> Result<&mut Self, SystemError> {
        if let Some(space_name) = &self.current_space {
            if let Some(space) = self.table.spaces.get_mut(space_name) {
                space.handlers.push(handler);
                Ok(self)
            } else {
                Err(SystemError::ControlError("Invalid control space".into()))
            }
        } else {
            Err(SystemError::ControlError("No control space selected".into()))
        }
    }

    pub fn set_priority(&mut self, space_name: &str, priority: Priority) -> &mut Self {
        self.table.priorities.insert(space_name.to_string(), priority);
        self
    }

    pub fn set_limits(&mut self, limits: ControlLimits) -> &mut Self {
        self.table.limits = limits;
        self
    }

    pub fn validate_signal(&self, signal: &SignalDefinition) -> Result<(), SystemError> {
        // Validate signal parameters
        for param in &signal.parameters {
            if !self.is_valid_parameter(param) {
                return Err(SystemError::ControlError(
                    format!("Invalid parameter: {}", param.name)
                ));
            }
        }

        // Validate against limits
        if signal.parameters.len() > self.table.limits.max_parameters {
            return Err(SystemError::ControlError("Too many parameters".into()));
        }

        Ok(())
    }

    pub fn build(self) -> Result<ControlTable, SystemError> {
        // Validate entire table
        self.validate_table()?;
        Ok(self.table)
    }

    fn validate_table(&self) -> Result<(), SystemError> {
        // Check for empty spaces
        if self.table.spaces.is_empty() {
            return Err(SystemError::ControlError("No control spaces defined".into()));
        }

        // Validate each space
        for (name, space) in &self.table.spaces {
            // Check for empty signals
            if space.signals.is_empty() {
                return Err(SystemError::ControlError(
                    format!("No signals defined in space: {}", name)
                ));
            }

            // Check for handler coverage
            let handled_signals: Vec<_> = space.handlers.iter()
                .flat_map(|h| &h.handled_signals)
                .collect();
            
            for signal in &space.signals {
                if !handled_signals.contains(&signal.name) {
                    return Err(SystemError::ControlError(
                        format!("No handler for signal: {}", signal.name)
                    ));
                }
            }
        }

        Ok(())
    }

    fn is_valid_parameter(&self, param: &Parameter) -> bool {
        match param.param_type {
            ParameterType::Numeric => {
                if let Some(range) = &param.range {
                    range.min < range.max
                } else {
                    false
                }
            },
            ParameterType::String => {
                if let Some(max_length) = param.max_length {
                    max_length > 0 && max_length <= self.table.limits.max_string_length
                } else {
                    false
                }
            },
            ParameterType::Boolean => true,
            ParameterType::Enum => {
                if let Some(values) = &param.enum_values {
                    !values.is_empty() && values.len() <= self.table.limits.max_enum_values
                } else {
                    false
                }
            },
        }
    }
}

// Example usage:
impl ControlTable {
    pub fn builder() -> ControlTableBuilder {
        ControlTableBuilder::new()
    }

    pub fn get_signal(&self, space: &str, signal: &str) -> Option<&SignalDefinition> {
        self.spaces.get(space)
            .and_then(|space| space.signals.iter().find(|s| s.name == signal))
    }

    pub fn validate_signal_value(&self, space: &str, signal: &str, value: &SignalValue) 
        -> Result<(), SystemError> 
    {
        if let Some(signal_def) = self.get_signal(space, signal) {
            signal_def.validation.validate(value)
        } else {
            Err(SystemError::ControlError("Signal not found".into()))
        }
    }
} 