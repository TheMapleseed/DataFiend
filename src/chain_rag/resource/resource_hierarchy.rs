use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, Semaphore};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque, HashSet, BTreeMap};
use petgraph::{Graph, Directed};
use petgraph::graph::{NodeIndex, EdgeIndex};
use petgraph::algo::{has_path_connecting, toposort};

const MAX_HIERARCHY_DEPTH: usize = 100;
const MAX_CHILDREN: usize = 1000;
const HIERARCHY_CHECK_INTERVAL_MS: u64 = 1000;
const MAX_CONCURRENT_OPERATIONS: usize = 50;

#[derive(Clone, Serialize, Deserialize)]
pub struct ResourceHierarchy {
    hierarchy_id: String,
    root_node: String,
    nodes: HashMap<String, ResourceNode>,
    edges: Vec<ResourceEdge>,
    policies: Vec<HierarchyPolicy>,
    metrics: HierarchyMetrics,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ResourceNode {
    node_id: String,
    node_type: NodeType,
    attributes: HashMap<String, String>,
    state: NodeState,
    constraints: Vec<NodeConstraint>,
    metadata: HashMap<String, String>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ResourceEdge {
    edge_id: String,
    source: String,
    target: String,
    edge_type: EdgeType,
    weight: f64,
    constraints: Vec<EdgeConstraint>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HierarchyPolicy {
    policy_id: String,
    rules: Vec<HierarchyRule>,
    priority: u32,
    scope: PolicyScope,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HierarchyMetrics {
    total_nodes: u64,
    total_edges: u64,
    max_depth: u32,
    branching_factor: f64,
    resource_distribution: HashMap<NodeType, u64>,
    access_patterns: HashMap<String, u64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct NodeConstraint {
    constraint_type: ConstraintType,
    parameters: HashMap<String, String>,
    validation: ValidationRule,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EdgeConstraint {
    constraint_type: ConstraintType,
    parameters: HashMap<String, String>,
    validation: ValidationRule,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HierarchyRule {
    rule_id: String,
    conditions: Vec<RuleCondition>,
    actions: Vec<RuleAction>,
    priority: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ValidationRule {
    rule_type: ValidationType,
    parameters: HashMap<String, String>,
    error_message: String,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NodeType {
    Service,
    Component,
    Resource,
    Container,
    Function,
    Data,
    Custom(String),
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum NodeState {
    Active,
    Inactive,
    Pending,
    Failed,
    Custom(String),
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum EdgeType {
    Dependency,
    Composition,
    Association,
    Inheritance,
    Custom(String),
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum PolicyScope {
    Global,
    Subtree,
    Node,
    Edge,
    Custom(String),
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ConstraintType {
    Capacity,
    Access,
    Flow,
    State,
    Custom(String),
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ValidationType {
    Required,
    Unique,
    Range,
    Pattern,
    Custom(String),
}

#[wasm_bindgen]
pub struct HierarchyController {
    hierarchies: Arc<DashMap<String, ResourceHierarchy>>,
    graphs: Arc<DashMap<String, Graph<String, f64, Directed>>>,
    metrics: Arc<DashMap<String, HierarchyMetrics>>,
    operation_semaphore: Arc<Semaphore>,
    notification_tx: Arc<broadcast::Sender<HierarchyEvent>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct HierarchyEvent {
    event_id: String,
    hierarchy_id: String,
    event_type: HierarchyEventType,
    timestamp: u64,
    details: HashMap<String, String>,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum HierarchyEventType {
    NodeAdded,
    NodeRemoved,
    EdgeAdded,
    EdgeRemoved,
    PolicyViolation,
    Custom(String),
}

#[wasm_bindgen]
impl HierarchyController {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let (notification_tx, _) = broadcast::channel(1000);
        
        let controller = Self {
            hierarchies: Arc::new(DashMap::new()),
            graphs: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            operation_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_OPERATIONS)),
            notification_tx: Arc::new(notification_tx),
        };

        controller.start_hierarchy_tasks();
        controller
    }

    async fn add_node(
        &self,
        hierarchy_id: &str,
        node: ResourceNode,
    ) -> Result<(), JsValue> {
        let _permit = self.operation_semaphore.acquire().await;
        
        if let Some(mut hierarchy) = self.hierarchies.get_mut(hierarchy_id) {
            // Validate node constraints
            self.validate_node_constraints(&node, &hierarchy).await?;
            
            // Add node to hierarchy
            hierarchy.nodes.insert(node.node_id.clone(), node.clone());
            
            // Update graph
            if let Some(mut graph) = self.graphs.get_mut(hierarchy_id) {
                graph.add_node(node.node_id.clone());
            }
            
            // Update metrics
            self.update_hierarchy_metrics(&hierarchy).await?;
            
            // Notify listeners
            self.notify_hierarchy_event(
                hierarchy_id,
                HierarchyEventType::NodeAdded,
                &node.node_id,
            ).await?;
        }
        
        Ok(())
    }

    async fn add_edge(
        &self,
        hierarchy_id: &str,
        edge: ResourceEdge,
    ) -> Result<(), JsValue> {
        let _permit = self.operation_semaphore.acquire().await;
        
        if let Some(mut hierarchy) = self.hierarchies.get_mut(hierarchy_id) {
            // Validate edge constraints
            self.validate_edge_constraints(&edge, &hierarchy).await?;
            
            // Check for cycles
            if self.would_create_cycle(hierarchy_id, &edge).await? {
                return Err(JsValue::from_str("Edge would create cycle"));
            }
            
            // Add edge to hierarchy
            hierarchy.edges.push(edge.clone());
            
            // Update graph
            if let Some(mut graph) = self.graphs.get_mut(hierarchy_id) {
                graph.add_edge(
                    self.get_node_index(&edge.source)?,
                    self.get_node_index(&edge.target)?,
                    edge.weight,
                );
            }
            
            // Update metrics
            self.update_hierarchy_metrics(&hierarchy).await?;
            
            // Notify listeners
            self.notify_hierarchy_event(
                hierarchy_id,
                HierarchyEventType::EdgeAdded,
                &edge.edge_id,
            ).await?;
        }
        
        Ok(())
    }

    async fn validate_node_constraints(
        &self,
        node: &ResourceNode,
        hierarchy: &ResourceHierarchy,
    ) -> Result<(), JsValue> {
        for constraint in &node.constraints {
            match constraint.constraint_type {
                ConstraintType::Capacity => {
                    self.validate_capacity_constraint(node, constraint).await?;
                }
                ConstraintType::Access => {
                    self.validate_access_constraint(node, constraint).await?;
                }
                ConstraintType::State => {
                    self.validate_state_constraint(node, constraint).await?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn validate_edge_constraints(
        &self,
        edge: &ResourceEdge,
        hierarchy: &ResourceHierarchy,
    ) -> Result<(), JsValue> {
        for constraint in &edge.constraints {
            match constraint.constraint_type {
                ConstraintType::Flow => {
                    self.validate_flow_constraint(edge, constraint).await?;
                }
                ConstraintType::State => {
                    self.validate_edge_state_constraint(edge, constraint).await?;
                }
                _ => {}
            }
        }
        Ok(())
    }

    async fn would_create_cycle(
        &self,
        hierarchy_id: &str,
        edge: &ResourceEdge,
    ) -> Result<bool, JsValue> {
        if let Some(graph) = self.graphs.get(hierarchy_id) {
            let source = self.get_node_index(&edge.source)?;
            let target = self.get_node_index(&edge.target)?;
            
            Ok(has_path_connecting(&graph, target, source, None))
        } else {
            Ok(false)
        }
    }

    async fn update_hierarchy_metrics(
        &self,
        hierarchy: &ResourceHierarchy,
    ) -> Result<(), JsValue> {
        if let Some(mut metrics) = self.metrics.get_mut(&hierarchy.hierarchy_id) {
            metrics.total_nodes = hierarchy.nodes.len() as u64;
            metrics.total_edges = hierarchy.edges.len() as u64;
            
            // Calculate max depth
            if let Some(graph) = self.graphs.get(&hierarchy.hierarchy_id) {
                metrics.max_depth = self.calculate_max_depth(&graph)?;
            }
            
            // Calculate branching factor
            metrics.branching_factor = if metrics.total_nodes > 1 {
                metrics.total_edges as f64 / (metrics.total_nodes - 1) as f64
            } else {
                0.0
            };
            
            // Update resource distribution
            metrics.resource_distribution.clear();
            for node in hierarchy.nodes.values() {
                *metrics.resource_distribution.entry(node.node_type).or_insert(0) += 1;
            }
        }
        Ok(())
    }

    fn start_hierarchy_tasks(&self) {
        let controller = Arc::new(self.clone());

        // Metrics update task
        tokio::spawn({
            let controller = controller.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(HIERARCHY_CHECK_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    controller.update_metrics().await;
                }
            }
        });
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&HierarchyMetrics {
                total_nodes: 0,
                total_edges: 0,
                max_depth: 0,
                branching_factor: 0.0,
                resource_distribution: HashMap::new(),
                access_patterns: HashMap::new(),
            })?)
        }
    }
}

fn generate_hierarchy_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("HIERARCHY-{:016x}", rng.gen::<u64>())
}

fn get_timestamp() -> Result<u64, JsValue> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for HierarchyController {
    fn drop(&mut self) {
        self.hierarchies.clear();
        self.graphs.clear();
        self.metrics.clear();
    }
} 