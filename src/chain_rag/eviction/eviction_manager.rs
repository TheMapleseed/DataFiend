use crate::logging::error_logger::{ErrorLogger, ErrorLevel};
use wasm_bindgen::prelude::*;
use web_sys::{WebGl2RenderingContext, WebGlBuffer, WebGlProgram, WebGlShader};
use js_sys::{Float32Array, Uint16Array};

#[wasm_bindgen]
pub struct EvictionManager {
    configs: Arc<DashMap<String, EvictionConfig>>,
    items: Arc<DashMap<String, DashMap<String, ItemMetadata>>>,
    metrics: Arc<DashMap<String, EvictionMetrics>>,
    eviction_lock: Arc<Mutex<bool>>,
    memory_controller: Arc<MemoryController>,
    error_logger: Arc<ErrorLogger>,
    gl_context: Arc<WebGl2RenderingContext>,
    vertex_buffer: WebGlBuffer,
    index_buffer: WebGlBuffer,
    shader_program: WebGlProgram,
    visualization_enabled: bool,
}

#[wasm_bindgen]
impl EvictionManager {
    #[wasm_bindgen(constructor)]
    pub fn new(
        memory_controller: Arc<MemoryController>,
        error_logger: Arc<ErrorLogger>,
        gl_context: WebGl2RenderingContext,
    ) -> Result<EvictionManager, JsValue> {
        let vertex_shader = compile_shader(
            &gl_context,
            WebGl2RenderingContext::VERTEX_SHADER,
            r#"
                attribute vec4 position;
                void main() {
                    gl_Position = position;
                }
            "#,
        )?;

        let fragment_shader = compile_shader(
            &gl_context,
            WebGl2RenderingContext::FRAGMENT_SHADER,
            r#"
                void main() {
                    gl_FragColor = vec4(1.0, 0.0, 0.0, 1.0);
                }
            "#,
        )?;

        let program = link_program(&gl_context, &vertex_shader, &fragment_shader)?;
        let vertex_buffer = gl_context.create_buffer().ok_or("Failed to create vertex buffer")?;
        let index_buffer = gl_context.create_buffer().ok_or("Failed to create index buffer")?;

        let manager = Self {
            configs: Arc::new(DashMap::new()),
            items: Arc::new(DashMap::new()),
            metrics: Arc::new(DashMap::new()),
            eviction_lock: Arc::new(Mutex::new(false)),
            memory_controller,
            error_logger,
            gl_context: Arc::new(gl_context),
            vertex_buffer,
            index_buffer,
            shader_program: program,
            visualization_enabled: false,
        };

        manager.start_monitoring();
        Ok(manager)
    }

    #[wasm_bindgen]
    pub fn toggle_visualization(&mut self, enabled: bool) {
        self.visualization_enabled = enabled;
    }

    #[wasm_bindgen]
    pub fn render_eviction_visualization(&self) -> Result<(), JsValue> {
        if !self.visualization_enabled {
            return Ok(());
        }

        let gl = &self.gl_context;

        let vertices = self.create_visualization_vertices(&self.items)?;
        let indices = self.create_visualization_indices(&self.items)?;

        gl.bind_buffer(WebGl2RenderingContext::ARRAY_BUFFER, Some(&self.vertex_buffer));
        gl.buffer_data_with_array_buffer_view(
            WebGl2RenderingContext::ARRAY_BUFFER,
            &vertices,
            WebGl2RenderingContext::STATIC_DRAW,
        );

        gl.bind_buffer(WebGl2RenderingContext::ELEMENT_ARRAY_BUFFER, Some(&self.index_buffer));
        gl.buffer_data_with_array_buffer_view(
            WebGl2RenderingContext::ELEMENT_ARRAY_BUFFER,
            &indices,
            WebGl2RenderingContext::STATIC_DRAW,
        );

        gl.use_program(Some(&self.shader_program));
        gl.draw_elements_with_i32(
            WebGl2RenderingContext::TRIANGLES,
            indices.length() as i32,
            WebGl2RenderingContext::UNSIGNED_SHORT,
            0,
        );

        Ok(())
    }

    async fn evict_items(
        &self,
        namespace: &str,
        target_bytes: u64,
    ) -> Result<(), JsValue> {
        let mut eviction_lock = self.eviction_lock.lock().await;
        if *eviction_lock {
            return Ok(());
        }
        *eviction_lock = true;

        let config = self.configs.get(namespace)
            .ok_or_else(|| JsValue::from_str("No eviction policy configured"))?;

        let mut evicted_bytes = 0;
        let mut evicted_count = 0;
        let mut eviction_errors = Vec::new();

        if let Some(mut namespace_items) = self.items.get_mut(namespace) {
            let items_to_evict = self.select_items_for_eviction(
                &config.policy,
                &namespace_items,
                target_bytes,
                config.max_batch_size,
            )?;

            for item_id in items_to_evict {
                match namespace_items.remove(&item_id) {
                    Some(metadata) => {
                        evicted_bytes += metadata.size_bytes;
                        evicted_count += 1;

                        // Update metrics
                        self.update_metrics(namespace, &metadata, &config.policy);
                    }
                    None => {
                        eviction_errors.push(format!("Failed to evict item: {}", item_id));
                    }
                }

                if evicted_bytes >= target_bytes {
                    break;
                }
            }
        }

        // Log eviction results
        let mut context = HashMap::new();
        context.insert("namespace".to_string(), namespace.to_string());
        context.insert("target_bytes".to_string(), target_bytes.to_string());
        context.insert("evicted_bytes".to_string(), evicted_bytes.to_string());
        context.insert("evicted_count".to_string(), evicted_count.to_string());
        context.insert("policy".to_string(), format!("{:?}", config.policy));

        if !eviction_errors.is_empty() {
            // Log errors as warnings
            self.error_logger.log_error(
                "eviction".to_string(),
                "warning".to_string(),
                format!("Eviction completed with {} errors", eviction_errors.len()),
                serde_wasm_bindgen::to_value(&context)?,
                Some(eviction_errors.join("\n")),
            ).await?;
        }

        // Log successful eviction as info
        if evicted_count > 0 {
            self.error_logger.log_error(
                "eviction".to_string(),
                "info".to_string(),
                format!("Evicted {} items ({} bytes)", evicted_count, evicted_bytes),
                serde_wasm_bindgen::to_value(&context)?,
                None,
            ).await?;
        }

        *eviction_lock = false;
        Ok(())
    }

    async fn check_eviction_needed(&self, namespace: &str) -> Result<(), JsValue> {
        let config = self.configs.get(namespace)
            .ok_or_else(|| JsValue::from_str("No eviction policy configured"))?;

        let total_size = self.get_namespace_size(namespace);
        let threshold_size = self.get_threshold_size(namespace)?;

        if total_size > threshold_size {
            let mut context = HashMap::new();
            context.insert("namespace".to_string(), namespace.to_string());
            context.insert("total_size".to_string(), total_size.to_string());
            context.insert("threshold_size".to_string(), threshold_size.to_string());

            // Log threshold exceeded
            self.error_logger.log_error(
                "eviction".to_string(),
                "warning".to_string(),
                format!("Memory threshold exceeded, initiating eviction"),
                serde_wasm_bindgen::to_value(&context)?,
                None,
            ).await?;

            self.evict_items(namespace, total_size - threshold_size).await?;
        }

        Ok(())
    }

    fn start_monitoring(&self) {
        let manager = Arc::new(self.clone());
        
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            loop {
                interval.tick().await;
                
                // Check all namespaces for eviction
                for namespace in manager.configs.iter().map(|e| e.key().clone()) {
                    if let Err(e) = manager.check_eviction_needed(&namespace).await {
                        // Log monitoring errors
                        let mut context = HashMap::new();
                        context.insert("namespace".to_string(), namespace.clone());
                        
                        if let Err(log_err) = manager.error_logger.log_error(
                            "eviction".to_string(),
                            "error".to_string(),
                            format!("Eviction monitoring error: {}", e.as_string().unwrap_or_default()),
                            serde_wasm_bindgen::to_value(&context).unwrap_or_default(),
                            None,
                        ).await {
                            web_sys::console::error_1(&log_err);
                        }
                    }
                }
            }
        });
    }

    // Helper functions for WebGL
    fn create_visualization_vertices(items: &DashMap<String, DashMap<String, ItemMetadata>>) 
        -> Result<Float32Array, JsValue> {
        let mut vertices = Vec::new();
        for namespace_items in items.iter() {
            for item in namespace_items.value().iter() {
                vertices.extend_from_slice(&[
                    item.value().size_bytes as f32,
                    item.value().access_count as f32,
                    item.value().priority as f32,
                ]);
            }
        }
        Ok(Float32Array::from(&vertices[..]))
    }

    fn create_visualization_indices(items: &DashMap<String, DashMap<String, ItemMetadata>>) 
        -> Result<Uint16Array, JsValue> {
        let mut indices = Vec::new();
        let mut current_index = 0;
        for namespace_items in items.iter() {
            for _ in namespace_items.value().iter() {
                indices.extend_from_slice(&[
                    current_index,
                    current_index + 1,
                    current_index + 2,
                ]);
                current_index += 3;
            }
        }
        Ok(Uint16Array::from(&indices[..]))
    }
}

// WebGL helper functions
fn compile_shader(
    gl: &WebGl2RenderingContext,
    shader_type: u32,
    source: &str,
) -> Result<WebGlShader, String> {
    let shader = gl
        .create_shader(shader_type)
        .ok_or_else(|| String::from("Unable to create shader object"))?;
    gl.shader_source(&shader, source);
    gl.compile_shader(&shader);

    if gl
        .get_shader_parameter(&shader, WebGl2RenderingContext::COMPILE_STATUS)
        .as_bool()
        .unwrap_or(false)
    {
        Ok(shader)
    } else {
        Err(gl
            .get_shader_info_log(&shader)
            .unwrap_or_else(|| String::from("Unknown error creating shader")))
    }
}

fn link_program(
    gl: &WebGl2RenderingContext,
    vert_shader: &WebGlShader,
    frag_shader: &WebGlShader,
) -> Result<WebGlProgram, String> {
    let program = gl
        .create_program()
        .ok_or_else(|| String::from("Unable to create shader object"))?;

    gl.attach_shader(&program, vert_shader);
    gl.attach_shader(&program, frag_shader);
    gl.link_program(&program);

    if gl
        .get_program_parameter(&program, WebGl2RenderingContext::LINK_STATUS)
        .as_bool()
        .unwrap_or(false)
    {
        Ok(program)
    } else {
        Err(gl
            .get_program_info_log(&program)
            .unwrap_or_else(|| String::from("Unknown error creating program")))
    }
}
