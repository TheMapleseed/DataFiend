use std::sync::Arc;
use tokio::sync::RwLock;
use crate::{
    vm::UnifiedVMSystem,
    coordinator::UnifiedCoordinator,
    learning::LearningCoordinator,
    metrics::MetricsStore,
    drift::DriftManager,
};

pub struct IntegratedSystem {
    // Core systems
    vm: Arc<UnifiedVMSystem>,
    coordinator: Arc<UnifiedCoordinator>,
    learning: Arc<LearningCoordinator>,
    
    // Shared components
    metrics: Arc<MetricsStore>,
    drift: Arc<DriftManager>,
    
    // System state
    state: Arc<RwLock<SystemState>>,
}

impl IntegratedSystem {
    pub async fn new() -> Result<Self> {
        // Initialize shared components first
        let metrics = Arc::new(MetricsStore::new()?);
        let drift = Arc::new(DriftManager::new(32));

        // Initialize core systems with shared components
        let vm = UnifiedVMSystem::new(metrics.clone()).await?;
        let coordinator = UnifiedCoordinator::new().await?;
        let learning = LearningCoordinator::new(metrics.clone()).await;

        let system = Self {
            vm: Arc::new(vm),
            coordinator: Arc::new(coordinator),
            learning: Arc::new(learning),
            metrics,
            drift,
            state: Arc::new(RwLock::new(SystemState::new())),
        };

        // Initialize cross-system connections
        system.initialize_connections().await?;
        
        Ok(system)
    }

    async fn initialize_connections(&self) -> Result<()> {
        // Connect VM metrics to coordinator
        self.vm.connect_metrics(self.coordinator.clone()).await?;
        
        // Connect learning system to both VM and coordinator
        self.learning.connect_systems(
            self.vm.clone(),
            self.coordinator.clone()
        ).await?;
        
        // Initialize drift-aware communication
        self.initialize_drift_aware_comms().await?;
        
        Ok(())
    }

    pub async fn start(&self) -> Result<()> {
        // Start all subsystems
        let vm_handle = self.start_vm_system();
        let coord_handle = self.start_coordinator();
        let learning_handle = self.start_learning_system();

        // Monitor system health
        self.monitor_system_health().await?;

        // Wait for all systems to be ready
        tokio::try_join!(vm_handle, coord_handle, learning_handle)?;

        Ok(())
    }

    async fn start_vm_system(&self) -> Result<()> {
        let vm = self.vm.clone();
        let metrics = self.metrics.clone();
        let state = self.state.clone();

        tokio::spawn(async move {
            loop {
                let vm_status = vm.check_status().await?;
                metrics.record_vm_status(&vm_status);
                
                if let Status::Error(e) = vm_status {
                    state.write().await.handle_vm_error(e);
                }

                tokio::time::sleep(Duration::from_secs(1)).await;
            }
        });

        Ok(())
    }

    async fn start_coordinator(&self) -> Result<()> {
        let coordinator = self.coordinator.clone();
        let metrics = self.metrics.clone();
        let learning = self.learning.clone();

        tokio::spawn(async move {
            loop {
                // Process coordination events
                if let Some(event) = coordinator.next_event().await {
                    // Record metrics
                    metrics.record_coordination_event(&event);
                    
                    // Feed event to learning system
                    learning.process_event(event).await?;
                }

                tokio::time::sleep(Duration::from_millis(100)).await;
            }
        });

        Ok(())
    }

    async fn start_learning_system(&self) -> Result<()> {
        let learning = self.learning.clone();
        let metrics = self.metrics.clone();
        let state = self.state.clone();

        tokio::spawn(async move {
            loop {
                // Optimize learning patterns
                learning.optimize_learning().await?;
                
                // Update metrics
                metrics.record_learning_optimization();
                
                // Update system state
                state.write().await.update_learning_state(
                    learning.get_state().await
                );

                tokio::time::sleep(Duration::from_secs(30)).await;
            }
        });

        Ok(())
    }

    pub async fn handle_request(&self, request: SystemRequest) -> Result<SystemResponse> {
        // Record request metrics
        self.metrics.record_request(&request);
        
        // Process through appropriate system
        let response = match request {
            SystemRequest::VM(req) => {
                self.vm.handle_request(req).await?
            }
            SystemRequest::Coordination(req) => {
                self.coordinator.handle_request(req).await?
            }
            SystemRequest::Learning(req) => {
                self.learning.handle_request(req).await?
            }
        };

        // Update learning system
        self.learning.learn_from_interaction(&request, &response).await?;
        
        // Record response metrics
        self.metrics.record_response(&response);
        
        Ok(response)
    }

    pub async fn shutdown(&self) -> Result<()> {
        // Graceful shutdown sequence
        self.learning.stop().await?;
        self.coordinator.stop().await?;
        self.vm.stop().await?;
        
        // Final metrics dump
        self.metrics.dump_final_state().await?;
        
        Ok(())
    }

    async fn initialize(&self) -> Result<()> {
        self.start_components()
            .await
            .context("Failed to start system components")?;
        
        if let Err(e) = self.verify_components().await {
            error!("Component verification failed: {:?}", e);
            return Err(Error::InitializationFailed {
                context: e.to_string(),
                component: e.component(),
                state: self.get_debug_state().await?,
            });
        }
        
        Ok(())
    }
}

#[derive(Debug)]
struct SystemState {
    vm_status: VMStatus,
    coordinator_status: CoordinatorStatus,
    learning_status: LearningStatus,
    health: SystemHealth,
}

impl SystemState {
    fn new() -> Self {
        Self {
            vm_status: VMStatus::default(),
            coordinator_status: CoordinatorStatus::default(),
            learning_status: LearningStatus::default(),
            health: SystemHealth::default(),
        }
    }

    async fn update_learning_state(&mut self, learning_state: LearningState) {
        self.learning_status = LearningStatus::from(learning_state);
        self.health.update_from_learning(&self.learning_status);
    }

    async fn handle_vm_error(&mut self, error: VMError) {
        self.vm_status.record_error(error);
        self.health.update_from_vm(&self.vm_status);
    }
} 