use wasm_bindgen::prelude::*;
use std::sync::Arc;
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::collections::HashSet;

#[derive(Clone, Serialize, Deserialize)]
pub struct SegmentRoute {
    source_segment: String,
    destination_segment: String,
    allowed_operations: HashSet<String>,
    max_payload_size: usize,
    require_encryption: bool,
    allowed_protocols: HashSet<String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RoutingRequest {
    source: String,
    destination: String,
    operation: String,
    payload_size: usize,
    protocol: String,
    encryption_level: String,
}

#[wasm_bindgen]
pub struct SegmentValidator {
    route_map: Arc<DashMap<(String, String), SegmentRoute>>,
    segment_permissions: Arc<DashMap<String, HashSet<String>>>,
    active_routes: Arc<DashMap<String, HashSet<String>>>,
}

#[wasm_bindgen]
impl SegmentValidator {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        Self {
            route_map: Arc::new(DashMap::new()),
            segment_permissions: Arc::new(DashMap::new()),
            active_routes: Arc::new(DashMap::new()),
        }
    }

    #[wasm_bindgen]
    pub fn validate_route(&self, request: JsValue) -> Result<bool, JsValue> {
        let route_req: RoutingRequest = serde_wasm_bindgen::from_value(request)?;
        
        // Check if route exists
        let route_key = (route_req.source.clone(), route_req.destination.clone());
        if let Some(route) = self.route_map.get(&route_key) {
            // Validate operation permissions
            if !route.allowed_operations.contains(&route_req.operation) {
                return Ok(false);
            }

            // Validate payload size
            if route_req.payload_size > route.max_payload_size {
                return Ok(false);
            }

            // Validate protocol
            if !route.allowed_protocols.contains(&route_req.protocol) {
                return Ok(false);
            }

            // Check encryption requirements
            if route.require_encryption && route_req.encryption_level == "none" {
                return Ok(false);
            }

            // Check segment permissions
            if let Some(permissions) = self.segment_permissions.get(&route_req.source) {
                if !permissions.contains(&route_req.destination) {
                    return Ok(false);
                }
            } else {
                return Ok(false);
            }

            // Track active route
            if let Some(mut active) = self.active_routes.get_mut(&route_req.source) {
                active.insert(route_req.destination);
            } else {
                let mut set = HashSet::new();
                set.insert(route_req.destination);
                self.active_routes.insert(route_req.source, set);
            }

            Ok(true)
        } else {
            Ok(false)
        }
    }

    #[wasm_bindgen]
    pub fn add_route(&self, route: JsValue) -> Result<(), JsValue> {
        let segment_route: SegmentRoute = serde_wasm_bindgen::from_value(route)?;
        let route_key = (
            segment_route.source_segment.clone(),
            segment_route.destination_segment.clone()
        );
        
        // Add route to map
        self.route_map.insert(route_key, segment_route.clone());

        // Update segment permissions
        self.segment_permissions
            .entry(segment_route.source_segment.clone())
            .or_insert_with(HashSet::new)
            .insert(segment_route.destination_segment.clone());

        Ok(())
    }

    #[wasm_bindgen]
    pub fn remove_route(&self, source: String, destination: String) -> bool {
        let route_key = (source.clone(), destination.clone());
        
        // Remove from route map
        let removed = self.route_map.remove(&route_key).is_some();

        // Remove from permissions
        if let Some(mut perms) = self.segment_permissions.get_mut(&source) {
            perms.remove(&destination);
        }

        // Remove from active routes
        if let Some(mut active) = self.active_routes.get_mut(&source) {
            active.remove(&destination);
        }

        removed
    }

    #[wasm_bindgen]
    pub fn get_active_routes(&self, segment: String) -> Result<JsValue, JsValue> {
        if let Some(routes) = self.active_routes.get(&segment) {
            Ok(serde_wasm_bindgen::to_value(&*routes)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&HashSet::<String>::new())?)
        }
    }

    #[wasm_bindgen]
    pub fn validate_segment_access(&self, source: String, destination: String) -> bool {
        if let Some(permissions) = self.segment_permissions.get(&source) {
            permissions.contains(&destination)
        } else {
            false
        }
    }
}

impl Drop for SegmentValidator {
    fn drop(&mut self) {
        // Clear sensitive routing data
        self.route_map.clear();
        self.segment_permissions.clear();
        self.active_routes.clear();
    }
} 