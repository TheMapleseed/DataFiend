use memmap2::{MmapMut, MmapOptions};
use std::fs::OpenOptions;
use std::sync::atomic::{AtomicU64, Ordering};
use shared_memory::{ShmemConf, Shmem};
use std::time::Instant;
use std::sync::RwLock;
use std::time::Duration;
use futures::future;
use std::sync::Arc;
use tokio::sync::RwLock as TRwLock;
use dashmap::DashMap;
use metrics::{Counter, Gauge, Histogram};
use std::time::{Duration, Instant};
use thiserror::Error;
use uuid::Uuid;
use parking_lot::RwLock as PLRwLock;

pub struct MetricsStore {
    mmap: MmapMut,
    shm: Shmem,
    start_time: Instant,
    events: RwLock<Vec<MetricEvent>>,
    collectors: Vec<Box<dyn MetricCollector>>,
    counters: DashMap<String, Counter>,
    gauges: DashMap<String, Gauge>,
    histograms: DashMap<String, Histogram>,
    buffer: Arc<MetricsBuffer>,
    exporter: Arc<MetricsExporter>,
    labels: Arc<PLRwLock<HashMap<String, String>>>,
    flush_task: Arc<tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>>,
}

#[repr(C)]
pub struct MetricsData {
    queries_total: AtomicU64,
    queries_failed: AtomicU64,
    processing_time_ns: AtomicU64,
    memory_used_bytes: AtomicU64,
    active_connections: AtomicU64,
}

impl MetricsStore {
    pub fn new() -> std::io::Result<Self> {
        // Memory mapped file for persistence
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open("/dev/shm/chain_rag_metrics")?;
            
        file.set_len(1024)?;
        let mmap = unsafe { MmapOptions::new().map_mut(&file)? };

        // Shared memory for IPC
        let shm = ShmemConf::new()
            .size(4096)
            .os_id("chain_rag_metrics")
            .create()?;

        Ok(Self {
            mmap,
            shm,
            start_time: Instant::now(),
            events: RwLock::new(Vec::new()),
            collectors: Vec::new(),
            counters: DashMap::new(),
            gauges: DashMap::new(),
            histograms: DashMap::new(),
            buffer: Arc::new(MetricsBuffer::new()),
            exporter: Arc::new(MetricsExporter::new()),
            labels: Arc::new(PLRwLock::new(HashMap::new())),
            flush_task: Arc::new(tokio::sync::Mutex::new(None)),
        })
    }

    pub fn increment_queries(&self) {
        let metrics = self.get_metrics_ptr();
        metrics.queries_total.fetch_add(1, Ordering::Release);
    }

    pub fn record_processing_time(&self, ns: u64) {
        let metrics = self.get_metrics_ptr();
        metrics.processing_time_ns.fetch_add(ns, Ordering::Release);
    }

    fn get_metrics_ptr(&self) -> &MetricsData {
        unsafe { &*(self.shm.as_ptr() as *const MetricsData) }
    }

    pub async fn record_event(&self, event: MetricEvent) -> Result<()> {
        let mut events = self.events.write().await;
        if events.len() >= MAX_EVENTS {
            events.drain(0..events.len() - MAX_EVENTS + 1);
        }
        events.push(event);
        Ok(())
    }

    async fn collect_metrics(&self) -> Result<()> {
        let collectors = self.collectors.iter()
            .map(|c| c.collect())
            .collect::<Vec<_>>();
            
        futures::future::join_all(collectors)
            .await
            .into_iter()
            .collect::<Result<Vec<_>>>()?;
        
        Ok(())
    }
}

// Zero-cost error handling
#[repr(u8)]
pub enum ErrorCode {
    Success = 0,
    QueryFailed = 1,
    ChainCorrupted = 2,
    MemoryError = 3,
    NetworkError = 4,
}

pub struct ErrorStore {
    error_mmap: MmapMut,
}

impl ErrorStore {
    pub fn new() -> std::io::Result<Self> {
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .open("/dev/shm/chain_rag_errors")?;
            
        file.set_len(4096)?;
        let error_mmap = unsafe { MmapOptions::new().map_mut(&file)? };

        Ok(Self { error_mmap })
    }

    pub fn record_error(&mut self, code: ErrorCode, details: &str) {
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_secs();

        let error_entry = format!("{},{},{}\n", timestamp, code as u8, details);
        
        // Lock-free append to mmap
        let current_pos = self.find_end();
        if let Some(slice) = self.error_mmap.get_mut(current_pos..current_pos + error_entry.len()) {
            slice.copy_from_slice(error_entry.as_bytes());
        }
    }

    fn find_end(&self) -> usize {
        self.error_mmap.iter()
            .position(|&x| x == 0)
            .unwrap_or(0)
    }
}

// Direct IPC using shared memory
pub struct IPCChannel {
    shm: Shmem,
    write_pos: AtomicU64,
    read_pos: AtomicU64,
}

impl IPCChannel {
    pub fn new(channel_id: &str) -> std::io::Result<Self> {
        let shm = ShmemConf::new()
            .size(1024 * 1024) // 1MB buffer
            .os_id(channel_id)
            .create()?;

        Ok(Self {
            shm,
            write_pos: AtomicU64::new(0),
            read_pos: AtomicU64::new(0),
        })
    }

    pub fn send(&self, data: &[u8]) -> bool {
        let write_pos = self.write_pos.load(Ordering::Acquire);
        let read_pos = self.read_pos.load(Ordering::Acquire);
        
        let available_space = self.shm.len() as u64 - (write_pos - read_pos);
        if available_space < data.len() as u64 {
            return false;
        }

        let write_offset = (write_pos % self.shm.len() as u64) as usize;
        unsafe {
            std::ptr::copy_nonoverlapping(
                data.as_ptr(),
                self.shm.as_ptr().add(write_offset),
                data.len()
            );
        }

        self.write_pos.fetch_add(data.len() as u64, Ordering::Release);
        true
    }

    pub fn receive(&self, buf: &mut [u8]) -> Option<usize> {
        let write_pos = self.write_pos.load(Ordering::Acquire);
        let read_pos = self.read_pos.load(Ordering::Acquire);
        
        if read_pos == write_pos {
            return None;
        }

        let available_data = (write_pos - read_pos) as usize;
        let read_size = available_data.min(buf.len());
        let read_offset = (read_pos % self.shm.len() as u64) as usize;

        unsafe {
            std::ptr::copy_nonoverlapping(
                self.shm.as_ptr().add(read_offset),
                buf.as_mut_ptr(),
                read_size
            );
        }

        self.read_pos.fetch_add(read_size as u64, Ordering::Release);
        Some(read_size)
    }
}

// Metrics constants
const MAX_LABELS: usize = 100;
const FLUSH_INTERVAL: Duration = Duration::from_secs(10);
const MAX_BUFFER_SIZE: usize = 10_000;
const HISTOGRAM_BUCKETS: &[f64] = &[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0];

#[derive(Debug, Error)]
pub enum MetricsError {
    #[error("Metrics collection failed: {0}")]
    CollectionFailed(String),
    
    #[error("Buffer overflow")]
    BufferOverflow,
    
    #[error("Invalid label: {0}")]
    InvalidLabel(String),
    
    #[error("Export failed: {0}")]
    ExportFailed(String),
}

struct MetricsBuffer {
    entries: DashMap<String, Vec<MetricEntry>>,
    size: AtomicUsize,
}

#[derive(Clone)]
struct MetricEntry {
    name: String,
    value: f64,
    labels: HashMap<String, String>,
    timestamp: chrono::DateTime<chrono::Utc>,
    metric_type: MetricType,
}

#[derive(Clone, Copy)]
enum MetricType {
    Counter,
    Gauge,
    Histogram,
}

impl MetricsStore {
    pub fn new(exporter: Arc<MetricsExporter>) -> Self {
        let store = Self {
            mmap: MmapMut::new(),
            shm: Shmem::new(),
            start_time: Instant::now(),
            events: RwLock::new(Vec::new()),
            collectors: Vec::new(),
            counters: DashMap::new(),
            gauges: DashMap::new(),
            histograms: DashMap::new(),
            buffer: Arc::new(MetricsBuffer::new()),
            exporter,
            labels: Arc::new(PLRwLock::new(HashMap::new())),
            flush_task: Arc::new(tokio::sync::Mutex::new(None)),
        };
        
        store.start_flush_task();
        store
    }

    pub async fn increment_counter(
        &self,
        name: &str,
        value: f64,
        labels: HashMap<String, String>,
    ) -> Result<(), MetricsError> {
        self.validate_labels(&labels)?;
        
        let counter = self.counters
            .entry(name.to_string())
            .or_insert_with(|| Counter::new(name));
            
        counter.increment(value);
        
        self.buffer_metric(
            name,
            value,
            labels,
            MetricType::Counter,
        ).await?;
        
        Ok(())
    }

    pub async fn set_gauge(
        &self,
        name: &str,
        value: f64,
        labels: HashMap<String, String>,
    ) -> Result<(), MetricsError> {
        self.validate_labels(&labels)?;
        
        let gauge = self.gauges
            .entry(name.to_string())
            .or_insert_with(|| Gauge::new(name));
            
        gauge.set(value);
        
        self.buffer_metric(
            name,
            value,
            labels,
            MetricType::Gauge,
        ).await?;
        
        Ok(())
    }

    pub async fn record_histogram(
        &self,
        name: &str,
        value: f64,
        labels: HashMap<String, String>,
    ) -> Result<(), MetricsError> {
        self.validate_labels(&labels)?;
        
        let histogram = self.histograms
            .entry(name.to_string())
            .or_insert_with(|| {
                Histogram::new(name)
                    .with_buckets(HISTOGRAM_BUCKETS.to_vec())
            });
            
        histogram.record(value);
        
        self.buffer_metric(
            name,
            value,
            labels,
            MetricType::Histogram,
        ).await?;
        
        Ok(())
    }

    async fn buffer_metric(
        &self,
        name: &str,
        value: f64,
        labels: HashMap<String, String>,
        metric_type: MetricType,
    ) -> Result<(), MetricsError> {
        // Check buffer capacity
        if self.buffer.size.load(Ordering::Relaxed) >= MAX_BUFFER_SIZE {
            return Err(MetricsError::BufferOverflow);
        }

        let entry = MetricEntry {
            name: name.to_string(),
            value,
            labels: self.merge_labels(labels),
            timestamp: chrono::Utc::now(),
            metric_type,
        };

        self.buffer.add_entry(name, entry)?;
        Ok(())
    }

    fn merge_labels(&self, mut labels: HashMap<String, String>) -> HashMap<String, String> {
        let global_labels = self.labels.read();
        labels.extend(global_labels.iter().map(|(k, v)| (k.clone(), v.clone())));
        labels
    }

    fn validate_labels(&self, labels: &HashMap<String, String>) -> Result<(), MetricsError> {
        if labels.len() > MAX_LABELS {
            return Err(MetricsError::InvalidLabel(
                format!("Too many labels: {} > {}", labels.len(), MAX_LABELS)
            ));
        }

        for (key, value) in labels {
            if key.is_empty() || value.is_empty() {
                return Err(MetricsError::InvalidLabel(
                    "Empty label key or value".to_string()
                ));
            }
        }

        Ok(())
    }

    fn start_flush_task(&self) {
        let buffer = self.buffer.clone();
        let exporter = self.exporter.clone();
        
        let handle = tokio::spawn(async move {
            let mut interval = tokio::time::interval(FLUSH_INTERVAL);
            
            loop {
                interval.tick().await;
                
                if let Err(e) = Self::flush_metrics(&buffer, &exporter).await {
                    log::error!("Failed to flush metrics: {}", e);
                }
            }
        });

        *self.flush_task.lock().unwrap() = Some(handle);
    }

    async fn flush_metrics(
        buffer: &MetricsBuffer,
        exporter: &MetricsExporter,
    ) -> Result<(), MetricsError> {
        let mut batch = Vec::new();
        
        // Collect metrics from buffer
        buffer.entries.iter().for_each(|entry| {
            batch.extend(entry.value().clone());
        });
        
        // Clear buffer after collecting
        buffer.clear();
        
        // Export metrics
        exporter.export_metrics(batch).await?;
        
        Ok(())
    }
}

impl MetricsBuffer {
    fn new() -> Self {
        Self {
            entries: DashMap::new(),
            size: AtomicUsize::new(0),
        }
    }

    fn add_entry(&self, name: &str, entry: MetricEntry) -> Result<(), MetricsError> {
        self.entries
            .entry(name.to_string())
            .or_default()
            .push(entry);
            
        self.size.fetch_add(1, Ordering::Relaxed);
        Ok(())
    }

    fn clear(&self) {
        self.entries.clear();
        self.size.store(0, Ordering::Relaxed);
    }
}

// Safe cleanup
impl Drop for MetricsStore {
    fn drop(&mut self) {
        if let Some(handle) = self.flush_task.lock().unwrap().take() {
            handle.abort();
        }
    }
} 