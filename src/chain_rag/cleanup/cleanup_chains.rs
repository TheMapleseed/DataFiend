use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, Semaphore};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque, HashSet};
use futures::future::join_all;

const MAX_CHAIN_DEPTH: usize = 100;
const MAX_CONCURRENT_CLEANUPS: usize = 20;
const CLEANUP_TIMEOUT_MS: u64 = 10000;
const MAX_RETRY_ATTEMPTS: u32 = 3;

#[derive(Clone, Serialize, Deserialize)]
pub struct CleanupChain {
    chain_id: String,
    nodes: Vec<CleanupNode>,
    dependencies: HashMap<String, Vec<String>>,
    execution_order: Vec<String>,
    status: ChainStatus,
    created_at: u64,
    completed_at: Option<u64>,
    retry_count: u32,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct CleanupNode {
    node_id: String,
    resource_type: ResourceType,
    cleanup_action: CleanupAction,
    state: NodeState,
    dependencies: Vec<String>,
    retries: u32,
    error: Option<String>,
    start_time: Option<u64>,
    end_time: Option<u64>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ChainMetrics {
    total_chains: u64,
    successful_chains: u64,
    failed_chains: u64,
    average_completion_time_ms: f64,
    chain_success_rate: f64,
    node_success_rates: HashMap<ResourceType, f64>,
    dependency_patterns: Vec<DependencyPattern>,
    cleanup_patterns: Vec<CleanupPattern>,
}

#[derive(Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ResourceType {
    Memory,
    File,
    Network,
    Database,
    Cache,
    Lock,
    Thread,
    Process,
    Connection,
    Transaction,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum CleanupAction {
    Release,
    Delete,
    Disconnect,
    Rollback,
    Reset,
    Kill,
    Flush,
    Archive,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum ChainStatus {
    Pending,
    InProgress,
    Completed,
    Failed,
    PartiallyCompleted,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum NodeState {
    Pending,
    Running,
    Completed,
    Failed,
    Skipped,
}

#[derive(Clone, Serialize, Deserialize)]
struct DependencyPattern {
    pattern_id: String,
    resources: Vec<ResourceType>,
    frequency: u32,
    success_rate: f64,
    average_duration_ms: f64,
}

#[derive(Clone, Serialize, Deserialize)]
struct CleanupPattern {
    pattern_id: String,
    action_sequence: Vec<CleanupAction>,
    success_rate: f64,
    average_duration_ms: f64,
    failure_points: Vec<String>,
}

#[wasm_bindgen]
pub struct CleanupChainManager {
    chains: Arc<DashMap<String, CleanupChain>>,
    metrics: Arc<DashMap<String, ChainMetrics>>,
    cleanup_semaphore: Arc<Semaphore>,
    notification_tx: Arc<broadcast::Sender<CleanupChain>>,
    active_chains: Arc<RwLock<VecDeque<String>>>,
}

#[wasm_bindgen]
impl CleanupChainManager {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Self {
        let (notification_tx, _) = broadcast::channel(1000);
        
        let manager = Self {
            chains: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            cleanup_semaphore: Arc::new(Semaphore::new(MAX_CONCURRENT_CLEANUPS)),
            notification_tx: Arc::new(notification_tx),
            active_chains: Arc::new(RwLock::new(VecDeque::new())),
        };

        manager.start_maintenance_tasks();
        manager
    }

    #[wasm_bindgen]
    pub async fn create_chain(
        &self,
        resources: JsValue,
        dependencies: JsValue,
    ) -> Result<String, JsValue> {
        let resources: Vec<(ResourceType, CleanupAction)> = serde_wasm_bindgen::from_value(resources)?;
        let dependencies: HashMap<String, Vec<String>> = serde_wasm_bindgen::from_value(dependencies)?;
        
        if resources.len() > MAX_CHAIN_DEPTH {
            return Err(JsValue::from_str("Chain depth exceeds maximum"));
        }

        let chain_id = generate_chain_id();
        let timestamp = get_timestamp()?;

        let nodes: Vec<CleanupNode> = resources
            .into_iter()
            .map(|(resource_type, cleanup_action)| {
                CleanupNode {
                    node_id: generate_node_id(),
                    resource_type,
                    cleanup_action,
                    state: NodeState::Pending,
                    dependencies: Vec::new(),
                    retries: 0,
                    error: None,
                    start_time: None,
                    end_time: None,
                }
            })
            .collect();

        let execution_order = self.calculate_execution_order(&nodes, &dependencies)?;

        let chain = CleanupChain {
            chain_id: chain_id.clone(),
            nodes,
            dependencies,
            execution_order,
            status: ChainStatus::Pending,
            created_at: timestamp,
            completed_at: None,
            retry_count: 0,
        };

        self.chains.insert(chain_id.clone(), chain.clone());
        self.notify_chain_created(chain).await?;

        Ok(chain_id)
    }

    fn calculate_execution_order(
        &self,
        nodes: &[CleanupNode],
        dependencies: &HashMap<String, Vec<String>>,
    ) -> Result<Vec<String>, JsValue> {
        let mut order = Vec::new();
        let mut visited = HashSet::new();
        let mut temp_visited = HashSet::new();

        fn visit(
            node_id: &str,
            deps: &HashMap<String, Vec<String>>,
            visited: &mut HashSet<String>,
            temp_visited: &mut HashSet<String>,
            order: &mut Vec<String>,
        ) -> Result<(), JsValue> {
            if temp_visited.contains(node_id) {
                return Err(JsValue::from_str("Circular dependency detected"));
            }
            if visited.contains(node_id) {
                return Ok(());
            }

            temp_visited.insert(node_id.to_string());

            if let Some(node_deps) = deps.get(node_id) {
                for dep in node_deps {
                    visit(dep, deps, visited, temp_visited, order)?;
                }
            }

            temp_visited.remove(node_id);
            visited.insert(node_id.to_string());
            order.push(node_id.to_string());

            Ok(())
        }

        for node in nodes {
            visit(
                &node.node_id,
                dependencies,
                &mut visited,
                &mut temp_visited,
                &mut order,
            )?;
        }

        Ok(order)
    }

    #[wasm_bindgen]
    pub async fn execute_chain(&self, chain_id: String) -> Result<bool, JsValue> {
        let _permit = tokio::time::timeout(
            Duration::from_millis(CLEANUP_TIMEOUT_MS),
            self.cleanup_semaphore.acquire(),
        ).await
            .map_err(|_| JsValue::from_str("Cleanup timeout"))?
            .map_err(|e| JsValue::from_str(&format!("Semaphore error: {}", e)))?;

        let start_time = Instant::now();
        let result = self.perform_cleanup(&chain_id).await;
        let duration = start_time.elapsed();

        self.update_metrics(&chain_id, result.is_ok(), duration).await;
        
        result
    }

    async fn perform_cleanup(&self, chain_id: &str) -> Result<bool, JsValue> {
        let mut chain = self.chains.get_mut(chain_id)
            .ok_or_else(|| JsValue::from_str("Chain not found"))?;

        chain.status = ChainStatus::InProgress;

        for node_id in chain.execution_order.clone() {
            if let Some(node) = chain.nodes.iter_mut()
                .find(|n| n.node_id == node_id) {
                
                node.state = NodeState::Running;
                node.start_time = Some(get_timestamp()?);

                match self.execute_cleanup_node(node).await {
                    Ok(()) => {
                        node.state = NodeState::Completed;
                        node.end_time = Some(get_timestamp()?);
                    }
                    Err(e) => {
                        node.error = Some(e.as_string().unwrap_or_else(|| "Unknown error".to_string()));
                        node.state = NodeState::Failed;
                        node.end_time = Some(get_timestamp()?);

                        if node.retries < MAX_RETRY_ATTEMPTS {
                            node.retries += 1;
                            chain.retry_count += 1;
                            return self.perform_cleanup(chain_id).await;
                        } else {
                            chain.status = ChainStatus::Failed;
                            return Ok(false);
                        }
                    }
                }
            }
        }

        chain.status = ChainStatus::Completed;
        chain.completed_at = Some(get_timestamp()?);
        
        Ok(true)
    }

    async fn execute_cleanup_node(&self, node: &CleanupNode) -> Result<(), JsValue> {
        match (node.resource_type, node.cleanup_action) {
            (ResourceType::Memory, CleanupAction::Release) => {
                // Implement memory release
            }
            (ResourceType::File, CleanupAction::Delete) => {
                // Implement file deletion
            }
            (ResourceType::Network, CleanupAction::Disconnect) => {
                // Implement network disconnect
            }
            (ResourceType::Database, CleanupAction::Rollback) => {
                // Implement database rollback
            }
            (ResourceType::Cache, CleanupAction::Flush) => {
                // Implement cache flush
            }
            (ResourceType::Lock, CleanupAction::Release) => {
                // Implement lock release
            }
            (ResourceType::Thread, CleanupAction::Kill) => {
                // Implement thread termination
            }
            (ResourceType::Process, CleanupAction::Kill) => {
                // Implement process termination
            }
            (ResourceType::Connection, CleanupAction::Disconnect) => {
                // Implement connection cleanup
            }
            (ResourceType::Transaction, CleanupAction::Rollback) => {
                // Implement transaction rollback
            }
            _ => return Err(JsValue::from_str("Unsupported cleanup action")),
        }

        Ok(())
    }

    async fn notify_chain_created(&self, chain: CleanupChain) -> Result<(), JsValue> {
        if let Err(e) = self.notification_tx.send(chain) {
            return Err(JsValue::from_str(&format!("Notification error: {}", e)));
        }
        Ok(())
    }

    async fn update_metrics(
        &self,
        chain_id: &str,
        success: bool,
        duration: Duration,
    ) {
        if let Some(chain) = self.chains.get(chain_id) {
            self.metrics
                .entry("global".to_string())
                .and_modify(|m| {
                    m.total_chains += 1;
                    if success {
                        m.successful_chains += 1;
                    } else {
                        m.failed_chains += 1;
                    }
                    m.average_completion_time_ms = (m.average_completion_time_ms * 0.9)
                        + (duration.as_millis() as f64 * 0.1);
                    m.chain_success_rate = m.successful_chains as f64 / m.total_chains as f64;

                    // Update node success rates
                    for node in &chain.nodes {
                        let success_rate = m.node_success_rates
                            .entry(node.resource_type)
                            .or_insert(0.0);
                        *success_rate = (*success_rate * 0.9)
                            + (if node.state == NodeState::Completed { 1.0 } else { 0.0 } * 0.1);
                    }
                })
                .or_insert_with(|| ChainMetrics {
                    total_chains: 1,
                    successful_chains: if success { 1 } else { 0 },
                    failed_chains: if success { 0 } else { 1 },
                    average_completion_time_ms: duration.as_millis() as f64,
                    chain_success_rate: if success { 1.0 } else { 0.0 },
                    node_success_rates: HashMap::new(),
                    dependency_patterns: Vec::new(),
                    cleanup_patterns: Vec::new(),
                });
        }
    }

    fn start_maintenance_tasks(&self) {
        let manager = Arc::new(self.clone());

        // Cleanup task
        tokio::spawn({
            let manager = manager.clone();
            async move {
                let mut interval = tokio::time::interval(Duration::from_secs(3600));
                loop {
                    interval.tick().await;
                    manager.cleanup_old_chains().await;
                }
            }
        });
    }

    async fn cleanup_old_chains(&self) {
        let cutoff = get_timestamp().unwrap_or(0) - 86400; // 24 hours
        self.chains.retain(|_, chain| {
            chain.created_at > cutoff || chain.status == ChainStatus::InProgress
        });
        
        let mut active_chains = self.active_chains.write().await;
        active_chains.retain(|chain_id| {
            self.chains.contains_key(chain_id)
        });
    }

    #[wasm_bindgen]
    pub fn get_metrics(&self) -> Result<JsValue, JsValue> {
        if let Some(metrics) = self.metrics.get("global") {
            Ok(serde_wasm_bindgen::to_value(&*metrics)?)
        } else {
            Ok(serde_wasm_bindgen::to_value(&ChainMetrics {
                total_chains: 0,
                successful_chains: 0,
                failed_chains: 0,
                average_completion_time_ms: 0.0,
                chain_success_rate: 0.0,
                node_success_rates: HashMap::new(),
                dependency_patterns: Vec::new(),
                cleanup_patterns: Vec::new(),
            })?)
        }
    }
}

fn generate_chain_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("CHAIN-{:016x}", rng.gen::<u64>())
}

fn generate_node_id() -> String {
    use rand::{thread_rng, Rng};
    let mut rng = thread_rng();
    format!("NODE-{:016x}", rng.gen::<u64>())
}

fn get_timestamp() -> Result<u64, JsValue> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|e| JsValue::from_str(&format!("Time error: {}", e)))
}

impl Drop for CleanupChainManager {
    fn drop(&mut self) {
        self.chains.clear();
        self.metrics.clear();
    }
} 
