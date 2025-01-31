use wasm_bindgen::prelude::*;
use std::sync::Arc;
use tokio::sync::{RwLock, broadcast, Semaphore};
use dashmap::DashMap;
use serde::{Serialize, Deserialize};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use std::collections::{HashMap, VecDeque, HashSet, BTreeMap};
use sha3::{Sha3_512, Digest};
use ring::aead::{self, BoundKey, Aad, UnboundKey, AES_256_GCM};
use constant_time_eq::constant_time_eq;
use std::ffi::{CStr, CString};
use std::os::raw::{c_void, c_char};
use std::num::Wrapping;
use std::ops::{Add, Sub, Mul, Div};
use crate::security::crypto_core::CryptoCore;

const MAX_MODEL_SIZE_MB: usize = 1024 * 10; // 10GB
const VM_SECURITY_CHECK_INTERVAL_MS: u64 = 100;
const MAX_CONCURRENT_EXECUTIONS: usize = 20;
const MEMORY_LIMIT_MB: usize = 1024 * 4; // 4GB
const MEMORY_PAGE_SIZE: usize = 4096;
const GUARD_PAGE_SIZE: usize = 4096;
const MAX_MEMORY_REGIONS: usize = 1000;
const SECURITY_CHECK_INTERVAL_MS: u64 = 25;
const MAX_FFI_BUFFER_SIZE: usize = 1024 * 1024; // 1MB

#[derive(Clone, Serialize, Deserialize)]
pub struct ModelVMSecurity {
    security_id: String,
    model_security: ModelSecurity,
    vm_security: VMSecurity,
    execution_policy: ExecutionPolicy,
    metrics: SecurityMetrics,
    memory_protection: MemoryProtection,
    side_channel_protection: SideChannelProtection,
    execution_context: ExecutionContext,
    ffi_protection: FFIProtection,
    initialization_protection: InitializationProtection,
    race_protection: RaceProtection,
    integer_protection: IntegerProtection,
    crypto: Arc<CryptoCore>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ModelSecurity {
    encryption_config: EncryptionConfig,
    access_control: AccessControl,
    integrity_checks: Vec<IntegrityCheck>,
    sandbox_config: SandboxConfig,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct VMSecurity {
    isolation_level: IsolationLevel,
    memory_protection: MemoryProtection,
    execution_constraints: ExecutionConstraints,
    runtime_validation: RuntimeValidation,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExecutionPolicy {
    allowed_operations: HashSet<Operation>,
    resource_limits: ResourceLimits,
    security_level: SecurityLevel,
    runtime_checks: Vec<RuntimeCheck>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecurityMetrics {
    security_violations: u64,
    blocked_executions: u64,
    memory_violations: u64,
    integrity_failures: u64,
    average_validation_time_ms: f64,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct EncryptionConfig {
    algorithm: EncryptionAlgorithm,
    key_rotation: KeyRotation,
    integrity_protection: IntegrityProtection,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct MemoryProtection {
    regions: HashMap<String, ProtectedRegion>,
    permissions: HashMap<String, Permissions>,
    guard_pages: bool,
    aslr_enabled: bool,
    dep_enabled: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SideChannelProtection {
    constant_time_ops: bool,
    memory_clearing: bool,
    cache_isolation: bool,
    timing_protection: bool,
    spectre_protection: bool,
    meltdown_protection: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ProtectedRegion {
    region_id: String,
    start_address: usize,
    size: usize,
    permissions: Permissions,
    guard_pages: Vec<GuardPage>,
    encryption_key: Option<Vec<u8>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct ExecutionContext {
    context_id: String,
    isolation_level: IsolationLevel,
    memory_access: AccessControl,
    execution_flags: ExecutionFlags,
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum IsolationLevel {
    Full,      // Complete process and memory isolation
    Partial,   // Shared memory with protection
    Container, // Container-based isolation
    Custom(u32),
}

#[derive(Clone, Copy, PartialEq, Serialize, Deserialize)]
pub enum SecurityLevel {
    Maximum,   // Most restrictive
    High,      // Production level
    Standard,  // Default level
    Custom(u32),
}

#[derive(Clone, Serialize, Deserialize)]
pub struct FFIProtection {
    enabled: bool,
    isolation_level: IsolationLevel,
    buffer_checks: BufferChecks,
    call_limits: CallLimits,
    sanitization: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct InitializationProtection {
    zero_on_alloc: bool,
    pattern_fill: bool,
    verification_enabled: bool,
    tracking_enabled: bool,
    initialization_patterns: Vec<u8>,
    secure_free: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RaceProtection {
    access_control: AccessControl,
    sync_primitives: SyncPrimitives,
    deadlock_prevention: DeadlockPrevention,
    contention_management: ContentionManagement,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct AccessControl {
    read_locks: Arc<RwLock<HashMap<usize, AccessRecord>>>,
    write_locks: Arc<RwLock<HashMap<usize, AccessRecord>>>,
    access_queue: Arc<Semaphore>,
    priority_boost: bool,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct IntegerProtection {
    overflow_checks: bool,
    underflow_checks: bool,
    division_checks: bool,
    bounds_validation: bool,
    wrapping_behavior: WrappingBehavior,
    range_limits: RangeLimits,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct RangeLimits {
    i32_range: (i32, i32),
    i64_range: (i64, i64),
    u32_range: (u32, u32),
    u64_range: (u64, u64),
    usize_range: (usize, usize),
}

#[wasm_bindgen]
pub struct SecurityController {
    securities: Arc<DashMap<String, ModelVMSecurity>>,
    metrics: Arc<DashMap<String, SecurityMetrics>>,
    operation_semaphore: Arc<Semaphore>,
    notification_tx: Arc<broadcast::Sender<SecurityEvent>>,
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SecurityEvent {
    event_id: String,
    security_id: String,
    event_type: SecurityEventType,
    severity: SecuritySeverity,
    timestamp: u64,
    details: HashMap<String, String>,
}

impl SecurityController {
    async fn validate_model_security(
        &self,
        model_id: &str,
        security: &ModelVMSecurity,
    ) -> Result<(), JsValue> {
        // Validate model size
        self.check_model_size(model_id, security).await?;
        
        // Verify model integrity
        self.verify_model_integrity(model_id, &security.model_security).await?;
        
        // Check encryption
        self.validate_encryption(&security.model_security.encryption_config).await?;
        
        // Validate access permissions
        self.validate_access_control(model_id, &security.model_security.access_control).await?;
        
        Ok(())
    }

    async fn secure_vm_execution(
        &self,
        vm_id: &str,
        security: &ModelVMSecurity,
    ) -> Result<(), JsValue> {
        // Set up memory protection
        self.configure_memory_protection(vm_id, &security.vm_security.memory_protection).await?;
        
        // Apply execution constraints
        self.apply_execution_constraints(
            vm_id, 
            &security.vm_security.execution_constraints
        ).await?;
        
        // Initialize runtime validation
        self.setup_runtime_validation(
            vm_id,
            &security.vm_security.runtime_validation
        ).await?;
        
        // Configure isolation
        self.configure_isolation(vm_id, security.vm_security.isolation_level).await?;
        
        Ok(())
    }

    async fn verify_model_integrity(
        &self,
        model_id: &str,
        security: &ModelSecurity,
    ) -> Result<(), JsValue> {
        for check in &security.integrity_checks {
            match check.check_type {
                IntegrityCheckType::Hash => {
                    self.verify_hash(model_id, check).await?;
                }
                IntegrityCheckType::Signature => {
                    self.verify_signature(model_id, check).await?;
                }
                IntegrityCheckType::Watermark => {
                    self.verify_watermark(model_id, check).await?;
                }
            }
        }
        Ok(())
    }

    async fn configure_memory_protection(
        &self,
        vm_id: &str,
        protection: &MemoryProtection,
    ) -> Result<(), JsValue> {
        if protection.guard_pages {
            self.setup_guard_pages(vm_id).await?;
        }
        
        if protection.aslr_enabled {
            self.enable_aslr(vm_id).await?;
        }
        
        if protection.dep_enabled {
            self.enable_dep(vm_id).await?;
        }
        
        Ok(())
    }

    async fn apply_execution_constraints(
        &self,
        vm_id: &str,
        constraints: &ExecutionConstraints,
    ) -> Result<(), JsValue> {
        // Set resource limits
        self.set_instruction_limit(vm_id, constraints.max_instructions).await?;
        self.set_memory_limit(vm_id, constraints.max_memory_mb).await?;
        self.set_thread_limit(vm_id, constraints.max_threads).await?;
        
        // Configure syscall filtering
        self.configure_syscall_filter(vm_id, &constraints.allowed_syscalls).await?;
        
        Ok(())
    }

    async fn setup_runtime_validation(
        &self,
        vm_id: &str,
        validation: &RuntimeValidation,
    ) -> Result<(), JsValue> {
        if validation.memory_checks {
            self.enable_memory_validation(vm_id).await?;
        }
        
        if validation.control_flow_integrity {
            self.enable_cfi(vm_id).await?;
        }
        
        if validation.input_validation {
            self.enable_input_validation(vm_id).await?;
        }
        
        if validation.output_sanitization {
            self.enable_output_sanitization(vm_id).await?;
        }
        
        Ok(())
    }

    async fn configure_isolation(
        &self,
        vm_id: &str,
        level: IsolationLevel,
    ) -> Result<(), JsValue> {
        match level {
            IsolationLevel::Full => {
                self.setup_full_isolation(vm_id).await?;
            }
            IsolationLevel::Partial => {
                self.setup_partial_isolation(vm_id).await?;
            }
            IsolationLevel::Container => {
                self.setup_container_isolation(vm_id).await?;
            }
            IsolationLevel::Custom(level) => {
                self.setup_custom_isolation(vm_id, level).await?;
            }
        }
        Ok(())
    }

    fn start_security_tasks(&self) {
        let controller = Arc::new(self.clone());

        // Security monitoring task
        tokio::spawn({
            let controller = controller.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(VM_SECURITY_CHECK_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    controller.monitor_security().await;
                }
            }
        });

        // Memory protection monitoring
        tokio::spawn({
            let controller = controller.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(SECURITY_CHECK_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    controller.verify_memory_protection().await;
                }
            }
        });

        // Side-channel protection monitoring
        tokio::spawn({
            let controller = controller.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(SECURITY_CHECK_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    controller.monitor_side_channels().await;
                }
            }
        });
    }
}

impl ModelVMSecurity {
    pub fn new() -> Self {
        let crypto = Arc::new(CryptoCore::new().expect("Failed to initialize crypto"));
        // ... rest of initialization
    }

    pub fn encrypt_model_data(&self, data: &[u8]) -> Result<Vec<u8>, JsValue> {
        let associated_data = b"model_data";
        self.crypto.encrypt_data(data, associated_data)
    }

    pub fn decrypt_model_data(&self, encrypted: &[u8]) -> Result<Vec<u8>, JsValue> {
        let associated_data = b"model_data";
        self.crypto.decrypt_data(encrypted, associated_data)
    }

    pub async fn protect_memory_access(
        &self,
        address: usize,
        size: usize,
        access_type: AccessType,
    ) -> Result<(), JsValue> {
        // Constant-time boundary check
        let in_bounds = self.constant_time_range_check(address, size)?;
        if !in_bounds {
            return Err(JsValue::from_str("Memory access violation"));
        }
        
        // Verify permissions in constant time
        self.verify_permissions_constant_time(address, access_type).await?;
        
        // Check guard pages
        self.verify_guard_pages(address, size).await?;
        
        // Apply memory encryption if enabled
        if let Some(key) = self.get_encryption_key(address)? {
            self.encrypt_memory_region(address, size, &key).await?;
        }
        
        Ok(())
    }

    async fn constant_time_memory_compare(
        &self,
        region1: &[u8],
        region2: &[u8],
    ) -> Result<bool, JsValue> {
        if region1.len() != region2.len() {
            return Ok(false);
        }
        
        Ok(constant_time_eq(region1, region2))
    }

    async fn protect_against_timing(
        &self,
        operation: impl FnOnce() -> Result<(), JsValue>,
    ) -> Result<(), JsValue> {
        let start_time = Instant::now();
        
        // Execute operation
        let result = operation();
        
        // Add random delay to mask timing
        let random_delay = self.generate_random_delay()?;
        sleep(Duration::from_micros(random_delay)).await;
        
        result
    }

    async fn clear_memory_constant_time(
        &self,
        region: &mut [u8],
    ) -> Result<(), JsValue> {
        // Use volatile writes to prevent optimization
        for byte in region.iter_mut() {
            unsafe {
                std::ptr::write_volatile(byte, 0);
            }
        }
        
        // Memory fence to ensure writes complete
        std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
        
        Ok(())
    }

    async fn isolate_cache_lines(
        &self,
        region: &ProtectedRegion,
    ) -> Result<(), JsValue> {
        // Align memory to cache line boundaries
        let aligned_start = (region.start_address + 63) & !63;
        let aligned_size = (region.size + 63) & !63;
        
        // Create cache isolation
        self.create_cache_partition(aligned_start, aligned_size).await?;
        
        Ok(())
    }

    async fn protect_against_spectre(
        &self,
        region: &ProtectedRegion,
    ) -> Result<(), JsValue> {
        // Add speculation barriers
        self.add_speculation_barrier(region).await?;
        
        // Implement array bounds clipping
        self.implement_bounds_clipping(region).await?;
        
        // Add branch predictor isolation
        self.isolate_branch_predictor(region).await?;
        
        Ok(())
    }

    async fn protect_against_meltdown(
        &self,
        region: &ProtectedRegion,
    ) -> Result<(), JsValue> {
        // Implement KPTI-style isolation
        self.implement_page_table_isolation(region).await?;
        
        // Add memory access validation
        self.validate_memory_access(region).await?;
        
        Ok(())
    }

    async fn verify_guard_pages(
        &self,
        address: usize,
        size: usize,
    ) -> Result<(), JsValue> {
        for guard_page in &self.memory_protection.regions
            .values()
            .flat_map(|r| &r.guard_pages) 
        {
            // Constant-time check for guard page violations
            let violation = self.constant_time_range_check(
                guard_page.start_address,
                GUARD_PAGE_SIZE,
            )?;
            
            if violation {
                return Err(JsValue::from_str("Guard page violation"));
            }
        }
        Ok(())
    }

    pub async fn secure_ffi_call<T, R>(
        &self,
        func: unsafe extern "C" fn(*mut T) -> R,
        data: &mut [T],
    ) -> Result<R, JsValue> {
        if !self.ffi_protection.enabled {
            return Err(JsValue::from_str("FFI protection must be enabled"));
        }

        // Validate buffer size and setup protection
        self.validate_ffi_buffer(data).await?;
        
        // Execute in protected context
        self.execute_in_protected_context(|| unsafe {
            self.validate_ffi_pointer(data.as_ptr())?;
            Ok(func(data.as_mut_ptr()))
        }).await
    }

    async fn validate_ffi_buffer<T>(
        &self,
        data: &[T],
    ) -> Result<(), JsValue> {
        // Size validation
        if data.len() * std::mem::size_of::<T>() > MAX_FFI_BUFFER_SIZE {
            return Err(JsValue::from_str("Buffer size exceeds maximum"));
        }
        
        // Apply buffer protection
        if self.ffi_protection.buffer_checks.enabled {
            self.protect_buffer(data).await?;
        }
        
        Ok(())
    }

    pub async fn protect_memory_allocation<T>(
        &self,
        size: usize,
    ) -> Result<Vec<T>, JsValue> {
        let layout = std::alloc::Layout::array::<T>(size)
            .map_err(|e| JsValue::from_str(&format!("Invalid allocation: {}", e)))?;

        // Secure allocation with initialization
        let mut memory = unsafe {
            let ptr = std::alloc::alloc(layout) as *mut T;
            if ptr.is_null() {
                return Err(JsValue::from_str("Allocation failed"));
            }
            Vec::from_raw_parts(ptr, size, size)
        };

        // Initialize memory
        self.initialize_memory(&mut memory).await?;

        // Verify initialization
        self.verify_initialization(&memory).await?;

        Ok(memory)
    }

    async fn initialize_memory<T>(
        &self,
        memory: &mut [T],
    ) -> Result<(), JsValue> {
        let size = memory.len() * std::mem::size_of::<T>();
        let ptr = memory.as_mut_ptr() as *mut u8;

        // Zero initialization
        if self.initialization_protection.zero_on_alloc {
            unsafe {
                std::ptr::write_bytes(ptr, 0, size);
                std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            }
        }

        // Pattern fill
        if self.initialization_protection.pattern_fill {
            unsafe {
                for (i, &pattern) in self.initialization_protection
                    .initialization_patterns
                    .iter()
                    .cycle()
                    .take(size)
                    .enumerate() 
                {
                    *ptr.add(i) = pattern;
                }
                std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            }
        }

        // Track initialization
        if self.initialization_protection.tracking_enabled {
            self.track_memory_initialization(ptr as *const _, size).await?;
        }

        Ok(())
    }

    async fn verify_initialization<T>(
        &self,
        memory: &[T],
    ) -> Result<(), JsValue> {
        if !self.initialization_protection.verification_enabled {
            return Ok(());
        }

        let size = memory.len() * std::mem::size_of::<T>();
        let ptr = memory.as_ptr() as *const u8;

        // Verify no uninitialized bytes
        unsafe {
            let bytes = std::slice::from_raw_parts(ptr, size);
            for (i, &byte) in bytes.iter().enumerate() {
                if !self.is_initialized_pattern(byte) {
                    return Err(JsValue::from_str(
                        &format!("Uninitialized memory detected at offset {}", i)
                    ));
                }
            }
        }

        Ok(())
    }

    pub async fn secure_memory_free<T>(
        &self,
        memory: Vec<T>,
    ) -> Result<(), JsValue> {
        let ptr = memory.as_ptr();
        let size = memory.len() * std::mem::size_of::<T>();
        let layout = std::alloc::Layout::array::<T>(memory.len())
            .map_err(|e| JsValue::from_str(&format!("Invalid layout: {}", e)))?;

        // Secure cleanup before free
        if self.initialization_protection.secure_free {
            unsafe {
                // Zero all memory before free
                std::ptr::write_bytes(ptr as *mut u8, 0, size);
                std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);

                // Pattern overwrite for security
                for (i, &pattern) in self.initialization_protection
                    .initialization_patterns
                    .iter()
                    .cycle()
                    .take(size)
                    .enumerate() 
                {
                    *((ptr as *mut u8).add(i)) = pattern;
                }
                std::sync::atomic::fence(std::sync::atomic::Ordering::SeqCst);
            }
        }

        // Remove from tracking
        if self.initialization_protection.tracking_enabled {
            self.untrack_memory_initialization(ptr as *const _, size).await?;
        }

        // Free memory
        unsafe {
            std::alloc::dealloc(ptr as *mut u8, layout);
        }

        Ok(())
    }

    async fn track_memory_initialization(
        &self,
        ptr: *const c_void,
        size: usize,
    ) -> Result<(), JsValue> {
        let mut tracking = self.initialization_tracking.write().await;
        tracking.insert(
            ptr as usize,
            InitializationRecord {
                size,
                timestamp: SystemTime::now()
                    .duration_since(UNIX_EPOCH)
                    .unwrap()
                    .as_secs(),
                initialized: true,
            },
        );
        Ok(())
    }

    fn is_initialized_pattern(&self, byte: u8) -> bool {
        self.initialization_protection.initialization_patterns.contains(&byte)
            || byte == 0 // Consider zero as initialized
    }

    pub async fn synchronized_access<T, F, R>(
        &self,
        data: &mut T,
        access_type: AccessType,
        operation: F
    ) -> Result<R, JsValue> 
    where
        F: FnOnce(&mut T) -> Result<R, JsValue>,
    {
        let addr = data as *const T as usize;
        
        // Acquire appropriate lock
        let _guard = match access_type {
            AccessType::Read => {
                self.acquire_read_lock(addr).await?
            }
            AccessType::Write => {
                self.acquire_write_lock(addr).await?
            }
        };

        // Track access patterns
        self.track_access_pattern(addr, access_type).await?;

        // Execute with deadlock prevention
        let result = self.execute_with_deadlock_prevention(|| {
            operation(data)
        }).await?;

        // Release lock (automatically handled by guard)
        self.update_contention_metrics(addr, access_type).await?;

        Ok(result)
    }

    async fn acquire_read_lock(
        &self,
        addr: usize,
    ) -> Result<RwLockReadGuard<()>, JsValue> {
        let timeout = Duration::from_millis(1000);
        let start = Instant::now();

        while start.elapsed() < timeout {
            // Check for existing write lock
            if !self.has_write_lock(addr).await? {
                // Try to acquire read lock
                if let Ok(guard) = self.race_protection
                    .access_control
                    .read_locks
                    .try_write_for(Duration::from_millis(10))
                    .await 
                {
                    // Record access
                    guard.insert(addr, AccessRecord {
                        timestamp: SystemTime::now(),
                        thread_id: std::thread::current().id(),
                        access_type: AccessType::Read,
                    });
                    return Ok(guard);
                }
            }
            sleep(Duration::from_millis(1)).await;
        }

        Err(JsValue::from_str("Read lock acquisition timeout"))
    }

    async fn acquire_write_lock(
        &self,
        addr: usize,
    ) -> Result<RwLockWriteGuard<()>, JsValue> {
        let timeout = Duration::from_millis(1000);
        let start = Instant::now();

        while start.elapsed() < timeout {
            // Check for any existing locks
            if !self.has_any_lock(addr).await? {
                // Try to acquire write lock
                if let Ok(guard) = self.race_protection
                    .access_control
                    .write_locks
                    .try_write_for(Duration::from_millis(10))
                    .await 
                {
                    // Record access
                    guard.insert(addr, AccessRecord {
                        timestamp: SystemTime::now(),
                        thread_id: std::thread::current().id(),
                        access_type: AccessType::Write,
                    });
                    return Ok(guard);
                }
            }
            sleep(Duration::from_millis(1)).await;
        }

        Err(JsValue::from_str("Write lock acquisition timeout"))
    }

    async fn execute_with_deadlock_prevention<F, R>(
        &self,
        operation: F
    ) -> Result<R, JsValue>
    where
        F: FnOnce() -> Result<R, JsValue>,
    {
        let timeout = Duration::from_millis(1000);
        let start = Instant::now();

        while start.elapsed() < timeout {
            // Check for potential deadlock
            if !self.detect_potential_deadlock().await? {
                // Execute operation
                return operation();
            }
            
            // Release locks if deadlock detected
            self.resolve_deadlock().await?;
            sleep(Duration::from_millis(1)).await;
        }

        Err(JsValue::from_str("Operation timeout - potential deadlock"))
    }

    async fn track_access_pattern(
        &self,
        addr: usize,
        access_type: AccessType,
    ) -> Result<(), JsValue> {
        let mut patterns = self.access_patterns.write().await;
        
        patterns.push_back(AccessPattern {
            address: addr,
            access_type,
            timestamp: SystemTime::now(),
            thread_id: std::thread::current().id(),
        });

        // Keep pattern history bounded
        while patterns.len() > 1000 {
            patterns.pop_front();
        }

        // Analyze patterns for potential issues
        self.analyze_access_patterns(&patterns).await?;

        Ok(())
    }

    async fn detect_potential_deadlock(&self) -> Result<bool, JsValue> {
        let read_locks = self.race_protection.access_control.read_locks.read().await;
        let write_locks = self.race_protection.access_control.write_locks.read().await;

        // Check for circular wait conditions
        let mut resource_graph = HashMap::new();
        
        for (addr, record) in read_locks.iter() {
            if write_locks.contains_key(addr) {
                resource_graph.insert(record.thread_id, addr);
            }
        }

        // Detect cycles in resource graph
        self.detect_cycles(&resource_graph)
    }

    async fn resolve_deadlock(&self) -> Result<(), JsValue> {
        // Priority-based resolution
        if self.race_protection.access_control.priority_boost {
            self.boost_priority().await?;
        }

        // Release lower priority locks
        self.release_low_priority_locks().await?;

        Ok(())
    }

    async fn update_contention_metrics(
        &self,
        addr: usize,
        access_type: AccessType,
    ) -> Result<(), JsValue> {
        let mut metrics = self.metrics.write().await;
        
        metrics.contention_points.entry(addr)
            .or_insert_with(ContentionMetrics::default)
            .update(access_type);

        Ok(())
    }

    fn start_security_tasks(&self) {
        let security = Arc::new(self.clone());

        // Memory protection monitoring
        tokio::spawn({
            let security = security.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(SECURITY_CHECK_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    security.verify_memory_protection().await;
                }
            }
        });

        // Side-channel protection monitoring
        tokio::spawn({
            let security = security.clone();
            async move {
                let mut interval = tokio::time::interval(
                    Duration::from_millis(SECURITY_CHECK_INTERVAL_MS)
                );
                loop {
                    interval.tick().await;
                    security.monitor_side_channels().await;
                }
            }
        });
    }

    pub async fn checked_arithmetic<T>(
        &self,
        operation: ArithmeticOp,
        a: T,
        b: T
    ) -> Result<T, JsValue>
    where
        T: Copy + PartialOrd + Add<Output = T> + Sub<Output = T> + 
           Mul<Output = T> + Div<Output = T> + Into<i128> + TryFrom<i128>,
    {
        // Validate input ranges
        self.validate_range(a)?;
        self.validate_range(b)?;

        // Perform checked operation
        let result = match operation {
            ArithmeticOp::Add => self.checked_add(a, b)?,
            ArithmeticOp::Sub => self.checked_sub(a, b)?,
            ArithmeticOp::Mul => self.checked_mul(a, b)?,
            ArithmeticOp::Div => self.checked_div(a, b)?,
        };

        // Validate result range
        self.validate_range(result)?;

        Ok(result)
    }

    fn checked_add<T>(&self, a: T, b: T) -> Result<T, JsValue>
    where
        T: Copy + Into<i128> + TryFrom<i128>,
    {
        let a_wide: i128 = a.into();
        let b_wide: i128 = b.into();

        // Perform addition with overflow check
        let result = a_wide.checked_add(b_wide)
            .ok_or_else(|| JsValue::from_str("Integer overflow in addition"))?;

        // Convert back to target type
        T::try_from(result)
            .map_err(|_| JsValue::from_str("Result out of range"))
    }

    fn checked_sub<T>(&self, a: T, b: T) -> Result<T, JsValue>
    where
        T: Copy + Into<i128> + TryFrom<i128>,
    {
        let a_wide: i128 = a.into();
        let b_wide: i128 = b.into();

        // Perform subtraction with underflow check
        let result = a_wide.checked_sub(b_wide)
            .ok_or_else(|| JsValue::from_str("Integer underflow in subtraction"))?;

        // Convert back to target type
        T::try_from(result)
            .map_err(|_| JsValue::from_str("Result out of range"))
    }

    fn checked_mul<T>(&self, a: T, b: T) -> Result<T, JsValue>
    where
        T: Copy + Into<i128> + TryFrom<i128>,
    {
        let a_wide: i128 = a.into();
        let b_wide: i128 = b.into();

        // Perform multiplication with overflow check
        let result = a_wide.checked_mul(b_wide)
            .ok_or_else(|| JsValue::from_str("Integer overflow in multiplication"))?;

        // Convert back to target type
        T::try_from(result)
            .map_err(|_| JsValue::from_str("Result out of range"))
    }

    fn checked_div<T>(&self, a: T, b: T) -> Result<T, JsValue>
    where
        T: Copy + Into<i128> + TryFrom<i128>,
    {
        let a_wide: i128 = a.into();
        let b_wide: i128 = b.into();

        // Check for division by zero
        if b_wide == 0 {
            return Err(JsValue::from_str("Division by zero"));
        }

        // Perform division with overflow check
        let result = a_wide.checked_div(b_wide)
            .ok_or_else(|| JsValue::from_str("Integer overflow in division"))?;

        // Convert back to target type
        T::try_from(result)
            .map_err(|_| JsValue::from_str("Result out of range"))
    }

    fn validate_range<T>(&self, value: T) -> Result<(), JsValue>
    where
        T: Copy + PartialOrd,
    {
        if !self.integer_protection.bounds_validation {
            return Ok(());
        }

        match std::mem::size_of::<T>() {
            4 if std::any::TypeId::of::<T>() == std::any::TypeId::of::<i32>() => {
                let value = unsafe { std::mem::transmute::<T, i32>(value) };
                if value < self.integer_protection.range_limits.i32_range.0 ||
                   value > self.integer_protection.range_limits.i32_range.1 {
                    return Err(JsValue::from_str("i32 value out of allowed range"));
                }
            }
            8 if std::any::TypeId::of::<T>() == std::any::TypeId::of::<i64>() => {
                let value = unsafe { std::mem::transmute::<T, i64>(value) };
                if value < self.integer_protection.range_limits.i64_range.0 ||
                   value > self.integer_protection.range_limits.i64_range.1 {
                    return Err(JsValue::from_str("i64 value out of allowed range"));
                }
            }
            // Add similar checks for u32, u64, usize
            _ => {}
        }

        Ok(())
    }

    pub async fn safe_array_index<T>(
        &self,
        index: usize,
        array: &[T],
    ) -> Result<&T, JsValue> {
        // Validate index range
        if index >= array.len() {
            return Err(JsValue::from_str("Array index out of bounds"));
        }

        // Perform bounds-checked access
        array.get(index)
            .ok_or_else(|| JsValue::from_str("Array access error"))
    }

    pub async fn safe_arithmetic_sequence<T>(
        &self,
        start: T,
        step: T,
        count: usize,
    ) -> Result<Vec<T>, JsValue>
    where
        T: Copy + Add<Output = T> + Into<i128> + TryFrom<i128>,
    {
        let mut result = Vec::with_capacity(count);
        let mut current = start;

        for _ in 0..count {
            result.push(current);
            current = self.checked_add(current, step)?;
        }

        Ok(result)
    }
} 