use std::sync::Arc;
use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use crate::corag::{CoRAG, ControlSignal};
use crate::error::error_system::SystemError;
use crate::networking::protocol::NetworkProtocol;

#[wasm_bindgen]
#[derive(Debug)]
pub struct NetworkSignalHandler {
    corag: Arc<CoRAG>,
    signal_buffer: Arc<RwLock<SignalBuffer>>,
    network_protocol: Arc<NetworkProtocol>,
}

// ... [Previous SignalBuffer and ProcessedSignal structs remain the same] ...

#[wasm_bindgen]
impl NetworkSignalHandler {
    #[wasm_bindgen(constructor)]
    pub fn new(corag: Arc<CoRAG>, protocol: Arc<NetworkProtocol>) -> Self {
        Self {
            corag,
            signal_buffer: Arc::new(RwLock::new(SignalBuffer::default())),
            network_protocol,
        }
    }

    #[wasm_bindgen]
    pub async fn handle_network_signal(&self, signal_data: JsValue) -> Result<JsValue, JsValue> {
        // Validate network signal
        self.network_protocol.validate_signal(&signal_data)
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        
        // Convert JS signal to Rust
        let signal: ControlSignal = serde_wasm_bindgen::from_value(signal_data)?;
        
        // Buffer the signal
        self.buffer_signal(signal.clone()).await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        
        // Process through network protocol
        let result = self.process_network_signal(signal).await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;
        
        Ok(serde_wasm_bindgen::to_value(&result)?)
    }

    async fn process_network_signal(&self, signal: ControlSignal) -> Result<SignalResult, SystemError> {
        // Apply network protocol
        self.network_protocol.prepare_signal(&signal).await?;
        
        // Process through CoRAG
        let result = self.corag.emit_signal(signal.clone()).await;
        
        // Update network status
        self.network_protocol.update_signal_status(&signal, &result).await?;
        
        // Update buffer with result
        let mut buffer = self.signal_buffer.write().await;
        let processed = ProcessedSignal {
            signal,
            timestamp: chrono::Utc::now(),
            result: match result {
                Ok(()) => SignalResult::Success,
                Err(e) => SignalResult::Failure(e.to_string()),
            },
        };
        
        buffer.processed_signals.push(processed.clone());
        buffer.last_processed = processed.timestamp;
        
        Ok(processed.result)
    }

    // ... [Previous buffer methods remain the same] ...
}

#[wasm_bindgen]
pub struct NetworkInterface {
    signal_handler: Arc<NetworkSignalHandler>,
    network_protocol: Arc<NetworkProtocol>,
}

#[wasm_bindgen]
impl NetworkInterface {
    #[wasm_bindgen(constructor)]
    pub fn new(corag: Arc<CoRAG>, protocol: Arc<NetworkProtocol>) -> Self {
        Self {
            signal_handler: Arc::new(NetworkSignalHandler::new(corag, protocol.clone())),
            network_protocol,
        }
    }

    #[wasm_bindgen]
    pub async fn emit_network_signal(&self, signal_type: &str, data: JsValue) -> Result<JsValue, JsValue> {
        // Validate network state
        self.network_protocol.validate_network_state().await
            .map_err(|e| JsValue::from_str(&e.to_string()))?;

        // Convert API signal to CoRAG signal with network protocol
        let control_signal = self.network_protocol.convert_signal(signal_type, data).await?;

        // Handle through network
        self.signal_handler.handle_network_signal(
            serde_wasm_bindgen::to_value(&control_signal)?
        ).await
    }

    #[wasm_bindgen]
    pub async fn get_network_signal_status(&self) -> Result<JsValue, JsValue> {
        let status = self.network_protocol.get_status().await?;
        let pending = self.signal_handler.get_pending_signals().await?;
        let processed = self.signal_handler.get_processed_signals().await?;
        
        Ok(serde_wasm_bindgen::to_value(&NetworkSignalStatus {
            network_status: status,
            pending,
            processed,
        })?)
    }
}
