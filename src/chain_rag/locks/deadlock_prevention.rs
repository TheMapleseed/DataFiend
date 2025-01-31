use wasm_bindgen::prelude::*;
use std::sync::Arc;
use dashmap::DashMap;
use tokio::sync::Mutex;
use std::collections::{HashMap, HashSet, BTreeMap};
use chrono::{DateTime, Utc};
use serde::{Serialize, Deserialize};

#[derive(Clone, Serialize, Deserialize)]
pub struct ResourceNode {
    resource_id: String,
    priority: i32,
    holders: HashSet<String>,
    waiters: Vec<String>,
    timestamp: DateTime<Utc>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct WaitForGraph {
    edges: HashMap<String, HashSet<String>>,
    timestamps: HashMap<(String, String), DateTime<Utc>>,
}

#[wasm_bindgen]
pub struct DeadlockPrevention {
    resource_graph: Arc<DashMap<String, ResourceNode>>,
    wait_for_graph: Arc<Mutex<WaitForGraph>>,
    resource_ordering: Arc<BTreeMap<String, i32>>,
    timeout_ms: u64,
    metrics: Arc<DashMap<String, DeadlockMetrics>>,
}

#[derive(Clone, Serialize, Deserialize, Default)]
pub struct DeadlockMetrics {
    prevented_deadlocks: u64,
    resource_conflicts: u64,
    wait_chain_length: u64,
    timeout_aborts: u64,
}

#[wasm_bindgen]
impl DeadlockPrevention {
    #[wasm_bindgen(constructor)]
    pub fn new(timeout_ms: u64) -> Self {
        Self {
            resource_graph: Arc::new(DashMap::new()),
            wait_for_graph: Arc::new(Mutex::new(WaitForGraph {
                edges: HashMap::new(),
                timestamps: HashMap::new(),
            })),
            resource_ordering: Arc::new(BTreeMap::new()),
            timeout_ms,
            metrics: Arc::new(DashMap::new()),
        }
    }

    #[wasm_bindgen]
    pub async fn request_resource(
        &self,
        resource_id: String,
        requester_id: String,
    ) -> Result<bool, JsValue> {
        // Check resource ordering
        if let Some(current_resources) = self.get_holder_resources(&requester_id).await {
            for held_resource in current_resources {
                if self.would_violate_ordering(&held_resource, &resource_id) {
                    self.update_metrics(&resource_id, "prevented_deadlocks");
                    return Ok(false);
                }
            }
        }

        // Try to acquire the resource
        if let Some(mut node) = self.resource_graph.get_mut(&resource_id) {
            if node.holders.is_empty() {
                // Resource is free
                node.holders.insert(requester_id.clone());
                node.timestamp = Utc::now();
                return Ok(true);
            }

            // Check for timeout on current holders
            let now = Utc::now();
            if (now - node.timestamp).num_milliseconds() > self.timeout_ms as i64 {
                // Force release timed-out holders
                self.force_release_resource(&resource_id).await?;
                self.update_metrics(&resource_id, "timeout_aborts");
                return self.request_resource(resource_id, requester_id).await;
            }

            // Add to waiters if not already waiting
            if !node.waiters.contains(&requester_id) {
                node.waiters.push(requester_id.clone());
                self.update_wait_for_graph(&resource_id, &requester_id).await?;
            }

            self.update_metrics(&resource_id, "resource_conflicts");
            Ok(false)
        } else {
            // Create new resource node
            let node = ResourceNode {
                resource_id: resource_id.clone(),
                priority: self.get_resource_priority(&resource_id),
                holders: HashSet::from([requester_id.clone()]),
                waiters: Vec::new(),
                timestamp: Utc::now(),
            };
            self.resource_graph.insert(resource_id, node);
            Ok(true)
        }
    }

    async fn update_wait_for_graph(
        &self,
        resource_id: &str,
        waiter_id: &str,
    ) -> Result<(), JsValue> {
        let mut graph = self.wait_for_graph.lock().await;
        
        if let Some(node) = self.resource_graph.get(resource_id) {
            for holder in &node.holders {
                graph.edges
                    .entry(waiter_id.to_string())
                    .or_default()
                    .insert(holder.to_string());
                
                graph.timestamps.insert(
                    (waiter_id.to_string(), holder.to_string()),
                    Utc::now(),
                );
            }
        }

        // Update wait chain length metric
        if let Some(max_chain) = self.find_longest_wait_chain(&graph.edges, waiter_id) {
            if let Some(mut metrics) = self.metrics.get_mut(resource_id) {
                metrics.wait_chain_length = max_chain;
            }
        }

        Ok(())
    }

    fn find_longest_wait_chain(
        &self,
        edges: &HashMap<String, HashSet<String>>,
        start: &str,
    ) -> Option<u64> {
        let mut visited = HashSet::new();
        let mut max_length = 0u64;
        let mut stack = vec![(start.to_string(), 0u64)];

        while let Some((node, length)) = stack.pop() {
            if length > max_length {
                max_length = length;
            }

            if let Some(neighbors) = edges.get(&node) {
                for neighbor in neighbors {
                    if visited.insert(neighbor.clone()) {
                        stack.push((neighbor.clone(), length + 1));
                    }
                }
            }
        }

        Some(max_length)
    }

    async fn force_release_resource(&self, resource_id: &str) -> Result<(), JsValue> {
        if let Some(mut node) = self.resource_graph.get_mut(resource_id) {
            // Clear holders and update timestamp
            node.holders.clear();
            node.timestamp = Utc::now();

            // Update wait-for graph
            let mut graph = self.wait_for_graph.lock().await;
            for waiter in &node.waiters {
                graph.edges.remove(waiter);
            }
        }
        Ok(())
    }

    fn would_violate_ordering(&self, held_resource: &str, requested_resource: &str) -> bool {
        let held_priority = self.get_resource_priority(held_resource);
        let requested_priority = self.get_resource_priority(requested_resource);
        held_priority > requested_priority
    }

    fn get_resource_priority(&self, resource_id: &str) -> i32 {
        self.resource_ordering
            .get(resource_id)
            .copied()
            .unwrap_or_default()
    }

    async fn get_holder_resources(&self, holder_id: &str) -> Option<HashSet<String>> {
        let mut resources = HashSet::new();
        for entry in self.resource_graph.iter() {
            if entry.holders.contains(holder_id) {
                resources.insert(entry.key().clone());
            }
        }
        Some(resources)
    }

    fn update_metrics(&self, resource_id: &str, metric_type: &str) {
        self.metrics
            .entry(resource_id.to_string())
            .or_default()
            .and_modify(|m| {
                match metric_type {
                    "prevented_deadlocks" => m.prevented_deadlocks += 1,
                    "resource_conflicts" => m.resource_conflicts += 1,
                    "timeout_aborts" => m.timeout_aborts += 1,
                    _ => {}
                }
            });
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self, resource_id: String) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get(&resource_id) {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&DeadlockMetrics::default())?)
        }
    }
}

impl Drop for DeadlockPrevention {
    fn drop(&mut self) {
        // Clear all graphs and metrics
        self.resource_graph.clear();
        self.metrics.clear();
    }
}
