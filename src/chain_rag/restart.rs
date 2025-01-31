use tokio::time::Duration;

impl IntegratedSystem {
    pub async fn restart(&self) -> Result<()> {
        info!("Initiating system restart");
        
        // Save critical state
        let state = self.save_critical_state().await?;
        
        // Graceful shutdown
        self.shutdown().await?;
        
        // Brief pause to ensure clean shutdown
        tokio::time::sleep(Duration::from_secs(1)).await;
        
        // Reinitialize
        self.initialize().await?;
        
        // Restore critical state
        self.restore_critical_state(state).await?;
        
        info!("System restart completed");
        Ok(())
    }

    async fn save_critical_state(&self) -> Result<SystemState> {
        // Save only essential state needed for continuity
        let state = SystemState {
            metrics: self.metrics.get_current().await?,
            learning_state: self.learning.get_state().await?,
            active_sessions: self.get_active_sessions().await?,
        };
        
        Ok(state)
    }

    async fn restore_critical_state(&self, state: SystemState) -> Result<()> {
        // Restore metrics
        self.metrics.restore_state(state.metrics).await?;
        
        // Restore learning state
        self.learning.restore_state(state.learning_state).await?;
        
        // Restore active sessions if possible
        for session in state.active_sessions {
            if let Err(e) = self.restore_session(session).await {
                warn!("Failed to restore session: {}", e);
            }
        }
        
        Ok(())
    }
}

#[derive(Debug)]
struct SystemState {
    metrics: MetricsState,
    learning_state: LearningState,
    active_sessions: Vec<SessionState>,
} 