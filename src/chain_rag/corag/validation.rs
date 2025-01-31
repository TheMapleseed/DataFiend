use wasm_bindgen::prelude::*;
use std::sync::Arc;
use serde::{Serialize, Deserialize};
use crate::error::error_system::{SystemError, ValidationError};
use crate::resource::resource_limits::ResourceLimiter;

#[derive(Debug, Clone, Eq, PartialEq, Hash, Serialize, Deserialize)]
pub enum CoRAGState {
    Learning,
    Validating,
    Reasoning,
    Applying,
    Error,
}

impl CoRAG {
    pub async fn validate_state_transition(&self, from: CoRAGState, to: CoRAGState) -> Result<(), SystemError> {
        // Check if transition is valid based on learned patterns
        let transition_valid = self.chain
            .query_transition_validity(&from, &to)
            .await?;
            
        if !transition_valid {
            return Err(SystemError::ValidationError(ValidationError::StateValidation {
                check: "state_transition".to_string(),
                details: format!("Invalid transition from {:?} to {:?}", from, to)
            }));
        }

        // Validate resource requirements for new state
        self.validate_state_resources(&to).await?;

        // Check reasoning chain consistency
        self.validate_chain_consistency().await?;

        Ok(())
    }

    async fn validate_state_resources(&self, state: &CoRAGState) -> Result<(), SystemError> {
        match state {
            CoRAGState::Learning => {
                // Ensure enough memory for learning patterns
                self.resource_limiter.check_memory_allocation(
                    self.get_learning_memory_requirement().await?
                )?;
            },
            CoRAGState::Reasoning => {
                // Verify processing capacity for reasoning
                self.resource_limiter.check_processing_capacity().await?;
            },
            CoRAGState::Applying => {
                // Validate resources for applying changes
                self.resource_limiter.check_modification_capacity().await?;
            },
            _ => {}
        }
        Ok(())
    }

    async fn validate_chain_consistency(&self) -> Result<(), SystemError> {
        // Verify chain integrity
        if !self.chain.verify_integrity().await? {
            return Err(SystemError::ValidationError(ValidationError::IntegrityError {
                check: "chain_consistency".to_string(),
                details: "Chain integrity validation failed".to_string()
            }));
        }

        // Validate reasoning patterns
        self.validate_reasoning_patterns().await?;

        Ok(())
    }

    async fn validate_reasoning_patterns(&self) -> Result<(), SystemError> {
        let patterns = self.chain.get_recent_patterns().await?;
        
        // Check for pattern consistency
        for pattern in patterns {
            if !self.validate_pattern(&pattern).await? {
                return Err(SystemError::ValidationError(ValidationError::PatternError {
                    check: "reasoning_pattern".to_string(),
                    details: format!("Invalid pattern detected: {:?}", pattern)
                }));
            }
        }

        Ok(())
    }

    pub async fn validate_operation(&self, operation: &CoRAGOperation) -> Result<(), SystemError> {
        // Validate operation against current state
        let current_state = self.get_current_state().await?;
        
        if !self.is_operation_valid_for_state(operation, &current_state).await? {
            return Err(SystemError::ValidationError(ValidationError::OperationError {
                check: "operation_state".to_string(),
                details: format!("Operation {:?} invalid in state {:?}", operation, current_state)
            }));
        }

        // Check operation resources
        self.validate_operation_resources(operation).await?;

        Ok(())
    }

    async fn validate_operation_resources(&self, operation: &CoRAGOperation) -> Result<(), SystemError> {
        let required_resources = self.calculate_operation_resources(operation).await?;
        
        // Check each resource requirement
        for (resource_type, amount) in required_resources {
            self.resource_limiter.check_resource_availability(&resource_type, amount).await?;
        }

        Ok(())
    }
} 