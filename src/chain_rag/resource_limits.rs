use std::sync::Arc;
use tokio::sync::RwLock;
use dashmap::DashMap;
use std::time::{Duration, Instant};
use parking_lot::Mutex as PLMutex;
use thiserror::Error;
use metrics::{Counter, Gauge};

// Global resource limits
const MAX_MEMORY_MB: usize = 4096; // 4GB total memory limit
const MAX_CPU_PERCENT: u8 = 80; // 80% CPU limit
const MAX_CONCURRENT_TASKS: usize = 1000;
const MAX_QUEUE_SIZE: usize = 10_000;
const RATE_LIMIT_WINDOW: Duration = Duration::from_secs(60);
const CLEANUP_INTERVAL: Duration = Duration::from_secs(30);

#[derive(Debug, Error)]
pub enum ResourceLimitError {
    #[error("Memory limit exceeded: {current}MB/{limit}MB")]
    MemoryLimitExceeded { current: usize, limit: usize },
    
    #[error("CPU limit exceeded: {current}%/{limit}%")]
    CpuLimitExceeded { current: u8, limit: u8 },
    
    #[error("Task limit exceeded: {current}/{limit}")]
    TaskLimitExceeded { current: usize, limit: usize },
    
    #[error("Queue limit exceeded: {current}/{limit}")]
    QueueLimitExceeded { current: usize, limit: usize },
    
    #[error("Rate limit exceeded: {current}/{limit} requests/minute")]
    RateLimitExceeded { current: usize, limit: usize },
    
    #[error("Component limit exceeded: {component} - {message}")]
    ComponentLimitExceeded { component: String, message: String },
}

pub struct ResourceLimiter {
    memory_tracker: Arc<MemoryTracker>,
    cpu_tracker: Arc<CpuTracker>,
    task_tracker: Arc<TaskTracker>,
    rate_limiter: Arc<RateLimiter>,
    component_limits: Arc<ComponentLimits>,
    metrics: Arc<MetricsStore>,
    error_handler: Arc<ErrorHandler>,
    cleanup_task: Arc<PLMutex<Option<tokio::task::JoinHandle<()>>>>,
}

struct MemoryTracker {
    current_bytes: std::sync::atomic::AtomicUsize,
    high_water_mark: std::sync::atomic::AtomicUsize,
    allocations: DashMap<String, usize>,
}

struct CpuTracker {
    usage_samples: Arc<RwLock<VecDeque<(Instant, f64)>>>,
    current_usage: std::sync::atomic::AtomicU8,
}

struct TaskTracker {
    active_tasks: std::sync::atomic::AtomicUsize,
    queued_tasks: std::sync::atomic::AtomicUsize,
    task_history: DashMap<String, VecDeque<Instant>>,
}

struct RateLimiter {
    windows: DashMap<String, VecDeque<Instant>>,
    limits: DashMap<String, usize>,
}

struct ComponentLimits {
    limits: DashMap<String, ComponentLimit>,
}

struct ComponentLimit {
    memory_mb: usize,
    cpu_percent: u8,
    max_tasks: usize,
    rate_limit: usize,
}

impl ResourceLimiter {
    pub fn new(
        metrics: Arc<MetricsStore>,
        error_handler: Arc<ErrorHandler>,
    ) -> Self {
        let limiter = Self {
            memory_tracker: Arc::new(MemoryTracker::new()),
            cpu_tracker: Arc::new(CpuTracker::new()),
            task_tracker: Arc::new(TaskTracker::new()),
            rate_limiter: Arc::new(RateLimiter::new()),
            component_limits: Arc::new(ComponentLimits::new()),
            metrics,
            error_handler,
            cleanup_task: Arc::new(PLMutex::new(None)),
        };
        
        limiter.start_cleanup_task();
        limiter
    }

    pub async fn allocate_memory(
        &self,
        component: &str,
        bytes: usize,
    ) -> Result<(), ResourceLimitError> {
        // Check component-specific limit
        if let Some(limit) = self.component_limits.get_memory_limit(component) {
            let component_usage = self.memory_tracker.get_component_usage(component);
            if component_usage + bytes > limit * 1024 * 1024 {
                return Err(ResourceLimitError::ComponentLimitExceeded {
                    component: component.to_string(),
                    message: format!("Memory limit exceeded: {}MB/{}MB", 
                        component_usage / (1024 * 1024), limit),
                });
            }
        }

        // Check global limit
        let current_mb = self.memory_tracker.get_total_mb();
        let required_mb = (bytes + 1024 * 1024 - 1) / (1024 * 1024); // Round up
        
        if current_mb + required_mb > MAX_MEMORY_MB {
            return Err(ResourceLimitError::MemoryLimitExceeded {
                current: current_mb,
                limit: MAX_MEMORY_MB,
            });
        }

        self.memory_tracker.allocate(component, bytes);
        self.metrics.record_memory_allocation(component, bytes).await;
        
        Ok(())
    }

    pub async fn track_cpu_usage(
        &self,
        component: &str,
        usage: f64,
    ) -> Result<(), ResourceLimitError> {
        // Check component-specific limit
        if let Some(limit) = self.component_limits.get_cpu_limit(component) {
            if usage > f64::from(limit) {
                return Err(ResourceLimitError::ComponentLimitExceeded {
                    component: component.to_string(),
                    message: format!("CPU limit exceeded: {:.1}%/{}%", usage, limit),
                });
            }
        }

        // Check global limit
        let current_usage = self.cpu_tracker.record_usage(usage);
        if current_usage > MAX_CPU_PERCENT {
            return Err(ResourceLimitError::CpuLimitExceeded {
                current: current_usage,
                limit: MAX_CPU_PERCENT,
            });
        }

        self.metrics.record_cpu_usage(component, usage).await;
        Ok(())
    }

    pub async fn start_task(
        &self,
        component: &str,
    ) -> Result<TaskGuard, ResourceLimitError> {
        // Check component-specific limit
        if let Some(limit) = self.component_limits.get_task_limit(component) {
            let component_tasks = self.task_tracker.get_component_tasks(component);
            if component_tasks >= limit {
                return Err(ResourceLimitError::ComponentLimitExceeded {
                    component: component.to_string(),
                    message: format!("Task limit exceeded: {}/{}", component_tasks, limit),
                });
            }
        }

        // Check global limits
        let active_tasks = self.task_tracker.get_active_tasks();
        if active_tasks >= MAX_CONCURRENT_TASKS {
            return Err(ResourceLimitError::TaskLimitExceeded {
                current: active_tasks,
                limit: MAX_CONCURRENT_TASKS,
            });
        }

        let queued_tasks = self.task_tracker.get_queued_tasks();
        if queued_tasks >= MAX_QUEUE_SIZE {
            return Err(ResourceLimitError::QueueLimitExceeded {
                current: queued_tasks,
                limit: MAX_QUEUE_SIZE,
            });
        }

        self.task_tracker.start_task(component);
        self.metrics.record_task_started(component).await;
        
        Ok(TaskGuard::new(self.task_tracker.clone(), component.to_string()))
    }

    pub async fn check_rate_limit(
        &self,
        component: &str,
        count: usize,
    ) -> Result<(), ResourceLimitError> {
        // Check component-specific limit
        if let Some(limit) = self.component_limits.get_rate_limit(component) {
            let current_rate = self.rate_limiter.get_current_rate(component);
            if current_rate + count > limit {
                return Err(ResourceLimitError::ComponentLimitExceeded {
                    component: component.to_string(),
                    message: format!("Rate limit exceeded: {}/{} requests/minute", 
                        current_rate + count, limit),
                });
            }
        }

        self.rate_limiter.record_requests(component, count);
        self.metrics.record_rate_limit_check(component, count).await;
        
        Ok(())
    }

    fn start_cleanup_task(&self) {
        let memory_tracker = self.memory_tracker.clone();
        let cpu_tracker = self.cpu_tracker.clone();
        let task_tracker = self.task_tracker.clone();
        let rate_limiter = self.rate_limiter.clone();
        let metrics = self.metrics.clone();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(CLEANUP_INTERVAL);
            
            loop {
                interval.tick().await;
                
                // Cleanup old CPU samples
                cpu_tracker.cleanup_old_samples();
                
                // Cleanup old task history
                task_tracker.cleanup_old_history();
                
                // Cleanup old rate limit windows
                rate_limiter.cleanup_old_windows();
                
                // Record metrics
                metrics.record_resource_cleanup().await;
            }
        });

        *self.cleanup_task.lock() = Some(handle);
    }
}

// Task guard for automatic cleanup
struct TaskGuard {
    tracker: Arc<TaskTracker>,
    component: String,
}

impl TaskGuard {
    fn new(tracker: Arc<TaskTracker>, component: String) -> Self {
        Self { tracker, component }
    }
}

impl Drop for TaskGuard {
    fn drop(&mut self) {
        self.tracker.end_task(&self.component);
    }
}

// Safe cleanup
impl Drop for ResourceLimiter {
    fn drop(&mut self) {
        if let Some(handle) = self.cleanup_task.lock().take() {
            handle.abort();
        }
    }
} 