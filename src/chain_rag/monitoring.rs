use wasm_bindgen::prelude::*;
use web_sys::{WebGl2RenderingContext, WebGlProgram, WebGlShader};
use serde::{Serialize, Deserialize};
use std::sync::atomic::{AtomicU64, Ordering};
use js_sys::{Array, Float32Array, Uint8Array};

#[wasm_bindgen]
pub struct WasmMonitor {
    context: WebGl2RenderingContext,
    metrics_program: WebGlProgram,
    error_program: WebGlProgram,
    scan_count: AtomicU64,
    error_count: AtomicU64,
}

#[wasm_bindgen]
impl WasmMonitor {
    #[wasm_bindgen(constructor)]
    pub fn new() -> Result<WasmMonitor, JsValue> {
        let document = web_sys::window()
            .ok_or("No window found")?
            .document()
            .ok_or("No document found")?;

        let canvas = document
            .get_element_by_id("monitoring-canvas")
            .ok_or("No canvas element found")?
            .dyn_into::<web_sys::HtmlCanvasElement>()?;

        let context = canvas
            .get_context("webgl2")?
            .ok_or("No WebGL2 context found")?
            .dyn_into::<WebGl2RenderingContext>()?;

        let metrics_program = compile_program(
            &context,
            include_str!("shaders/metrics.vert"),
            include_str!("shaders/metrics.frag"),
        )?;

        let error_program = compile_program(
            &context,
            include_str!("shaders/error.vert"),
            include_str!("shaders/error.frag"),
        )?;

        Ok(WasmMonitor {
            context,
            metrics_program,
            error_program,
            scan_count: AtomicU64::new(0),
            error_count: AtomicU64::new(0),
        })
    }

    #[wasm_bindgen]
    pub fn scan_system(&mut self, data: &[u8]) -> Result<JsValue, JsValue> {
        let scan_results = self.perform_scan(data)?;
        self.scan_count.fetch_add(1, Ordering::SeqCst);
        
        if scan_results.errors_found > 0 {
            self.error_count.fetch_add(
                scan_results.errors_found as u64,
                Ordering::SeqCst
            );
        }

        self.render_metrics(&scan_results)?;
        Ok(serde_wasm_bindgen::to_value(&scan_results)?)
    }

    #[wasm_bindgen]
    pub fn render_metrics(&self, scan_results: &ScanResults) -> Result<(), JsValue> {
        self.context.use_program(Some(&self.metrics_program));
        
        // Update metrics visualization
        let metrics_data = Float32Array::new_with_length(4);
        metrics_data.set_index(0, scan_results.scan_coverage);
        metrics_data.set_index(1, scan_results.error_rate);
        metrics_data.set_index(2, scan_results.correction_rate);
        metrics_data.set_index(3, scan_results.health_score);

        // Render using WebGL
        self.context.bind_buffer(
            WebGl2RenderingContext::ARRAY_BUFFER,
            Some(&self.create_buffer(&metrics_data)?),
        );

        self.context.draw_arrays(
            WebGl2RenderingContext::TRIANGLES,
            0,
            3,
        );

        Ok(())
    }

    #[wasm_bindgen]
    pub fn render_errors(&self, error_data: &[u8]) -> Result<(), JsValue> {
        self.context.use_program(Some(&self.error_program));
        
        let error_buffer = Uint8Array::new_with_length(error_data.len() as u32);
        error_buffer.copy_from(error_data);

        self.context.bind_buffer(
            WebGl2RenderingContext::ARRAY_BUFFER,
            Some(&self.create_buffer(&error_buffer)?),
        );

        self.context.draw_arrays(
            WebGl2RenderingContext::POINTS,
            0,
            error_data.len() as i32,
        );

        Ok(())
    }

    fn perform_scan(&self, data: &[u8]) -> Result<ScanResults, JsValue> {
        let mut results = ScanResults {
            blocks_scanned: 0,
            errors_found: 0,
            corrections_made: 0,
            scan_coverage: 0.0,
            error_rate: 0.0,
            correction_rate: 0.0,
            health_score: 1.0,
        };

        // Scan data in WASM memory
        for chunk in data.chunks(1024) {
            results.blocks_scanned += 1;
            
            if let Some(error) = self.check_block_integrity(chunk) {
                results.errors_found += 1;
                if self.attempt_correction(chunk).is_ok() {
                    results.corrections_made += 1;
                }
            }
        }

        // Calculate metrics
        results.scan_coverage = results.blocks_scanned as f32 / data.len() as f32;
        results.error_rate = results.errors_found as f32 / results.blocks_scanned as f32;
        results.correction_rate = if results.errors_found > 0 {
            results.corrections_made as f32 / results.errors_found as f32
        } else {
            1.0
        };
        results.health_score = 1.0 - (results.error_rate * (1.0 - results.correction_rate));

        Ok(results)
    }

    fn create_buffer(&self, data: &js_sys::Object) -> Result<WebGlBuffer, JsValue> {
        let buffer = self.context
            .create_buffer()
            .ok_or("Failed to create buffer")?;
            
        self.context.bind_buffer(
            WebGl2RenderingContext::ARRAY_BUFFER,
            Some(&buffer),
        );

        self.context.buffer_data_with_object(
            WebGl2RenderingContext::ARRAY_BUFFER,
            data,
            WebGl2RenderingContext::STATIC_DRAW,
        );

        Ok(buffer)
    }
}

#[derive(Serialize, Deserialize)]
struct ScanResults {
    blocks_scanned: usize,
    errors_found: usize,
    corrections_made: usize,
    scan_coverage: f32,
    error_rate: f32,
    correction_rate: f32,
    health_score: f32,
} 