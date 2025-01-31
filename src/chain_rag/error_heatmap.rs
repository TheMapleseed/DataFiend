use wasm_bindgen::prelude::*;
use serde::{Serialize, Deserialize};
use std::sync::atomic::{AtomicU32, Ordering};
use chrono::{DateTime, Utc, Duration};

#[wasm_bindgen]
#[derive(Serialize, Deserialize)]
pub struct ErrorHeatmap {
    width: usize,
    height: usize,
    data: Vec<AtomicU32>,
    error_types: Vec<String>,
    start_time: DateTime<Utc>,
    bucket_duration: Duration,
    max_value: AtomicU32,
}

#[wasm_bindgen]
impl ErrorHeatmap {
    #[wasm_bindgen(constructor)]
    pub fn new(width: usize, height: usize, bucket_minutes: i64) -> Self {
        let data = (0..width * height)
            .map(|_| AtomicU32::new(0))
            .collect();

        Self {
            width,
            height,
            data,
            error_types: Vec::new(),
            start_time: Utc::now(),
            bucket_duration: Duration::minutes(bucket_minutes),
            max_value: AtomicU32::new(0),
        }
    }

    #[wasm_bindgen]
    pub fn add_error_type(&mut self, error_type: String) -> usize {
        if let Some(index) = self.error_types.iter().position(|et| et == &error_type) {
            return index;
        }
        
        if self.error_types.len() < self.height {
            let index = self.error_types.len();
            self.error_types.push(error_type);
            index
        } else {
            self.height - 1 // Use last row as overflow
        }
    }

    #[wasm_bindgen]
    pub fn record_error(&self, error_type: String, timestamp: f64) {
        let error_index = self.get_error_index(&error_type);
        let time_index = self.get_time_index(timestamp);

        if let Some((x, y)) = time_index.zip(error_index) {
            if x < self.width && y < self.height {
                let index = y * self.width + x;
                let new_value = self.data[index].fetch_add(1, Ordering::SeqCst) + 1;
                
                // Update max value if needed
                let mut current_max = self.max_value.load(Ordering::Relaxed);
                while new_value > current_max {
                    match self.max_value.compare_exchange_weak(
                        current_max,
                        new_value,
                        Ordering::SeqCst,
                        Ordering::Relaxed,
                    ) {
                        Ok(_) => break,
                        Err(actual) => current_max = actual,
                    }
                }
            }
        }
    }

    #[wasm_bindgen]
    pub fn get_heatmap_data(&self) -> Result<JsValue, JsValue> {
        let heatmap_data = HeatmapData {
            width: self.width,
            height: self.height,
            data: self.data.iter()
                .map(|atomic| atomic.load(Ordering::Relaxed))
                .collect(),
            error_types: self.error_types.clone(),
            max_value: self.max_value.load(Ordering::Relaxed),
            start_time: self.start_time,
            bucket_duration: self.bucket_duration,
        };

        Ok(serde_wasm_bindgen::to_value(&heatmap_data)?)
    }

    fn get_error_index(&self, error_type: &str) -> Option<usize> {
        self.error_types
            .iter()
            .position(|et| et == error_type)
    }

    fn get_time_index(&self, timestamp: f64) -> Option<usize> {
        let error_time = DateTime::from_timestamp(timestamp as i64, 0)?;
        let duration_since_start = error_time - self.start_time;
        let bucket = (duration_since_start.num_milliseconds() / 
                     self.bucket_duration.num_milliseconds()) as usize;
        
        if bucket < self.width {
            Some(bucket)
        } else {
            None
        }
    }

    #[wasm_bindgen]
    pub fn get_gl_data(&self) -> Result<js_sys::Float32Array, JsValue> {
        let max = self.max_value.load(Ordering::Relaxed) as f32;
        let data: Vec<f32> = self.data.iter()
            .map(|atomic| atomic.load(Ordering::Relaxed) as f32 / max)
            .collect();
            
        Ok(js_sys::Float32Array::from(&data[..]))
    }
}

#[derive(Serialize)]
struct HeatmapData {
    width: usize,
    height: usize,
    data: Vec<u32>,
    error_types: Vec<String>,
    max_value: u32,
    start_time: DateTime<Utc>,
    bucket_duration: Duration,
} 