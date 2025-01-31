use wasm_bindgen::prelude::*;
use web_sys::{WebGlRenderingContext, WebGlBuffer, WebGlProgram, WebGlShader, WebGlTexture};
use std::sync::Arc;
use dashmap::DashMap;
use crate::resource::resource_limits::ResourceLimiter;

#[wasm_bindgen]
pub struct WebGLManager {
    context: WebGlRenderingContext,
    buffers: DashMap<String, WebGlBuffer>,
    textures: DashMap<String, WebGlTexture>,
    shaders: DashMap<String, WebGlShader>,
    programs: DashMap<String, WebGlProgram>,
    resource_limiter: Arc<ResourceLimiter>,
}

impl WebGLManager {
    pub fn new(context: WebGlRenderingContext, resource_limiter: Arc<ResourceLimiter>) -> Result<Self, JsValue> {
        Ok(Self {
            context,
            buffers: DashMap::new(),
            textures: DashMap::new(),
            shaders: DashMap::new(),
            programs: DashMap::new(),
            resource_limiter,
        })
    }

    pub fn create_buffer(&self, id: &str, data: &[u8]) -> Result<(), JsValue> {
        // Check resource limits
        self.resource_limiter.check_memory_allocation(data.len())?;
        
        let buffer = self.context.create_buffer()
            .ok_or_else(|| JsValue::from_str("Failed to create buffer"))?;
        
        self.context.bind_buffer(WebGlRenderingContext::ARRAY_BUFFER, Some(&buffer));
        self.context.buffer_data_with_u8_array(
            WebGlRenderingContext::ARRAY_BUFFER,
            data,
            WebGlRenderingContext::STATIC_DRAW,
        );

        // Register resource usage
        self.resource_limiter.register_memory_usage("webgl_buffers", data.len())?;
        self.buffers.insert(id.to_string(), buffer);
        
        Ok(())
    }

    pub fn create_texture(&self, id: &str, width: u32, height: u32, data: Option<&[u8]>) -> Result<(), JsValue> {
        let texture_size = (width * height * 4) as usize; // RGBA
        self.resource_limiter.check_memory_allocation(texture_size)?;
        
        let texture = self.context.create_texture()
            .ok_or_else(|| JsValue::from_str("Failed to create texture"))?;
        
        self.context.bind_texture(WebGlRenderingContext::TEXTURE_2D, Some(&texture));
        
        if let Some(pixels) = data {
            self.context.tex_image_2d_with_i32_and_i32_and_i32_and_format_and_type_and_opt_u8_array(
                WebGlRenderingContext::TEXTURE_2D,
                0,
                WebGlRenderingContext::RGBA as i32,
                width as i32,
                height as i32,
                0,
                WebGlRenderingContext::RGBA,
                WebGlRenderingContext::UNSIGNED_BYTE,
                Some(pixels),
            )?;
        }

        self.resource_limiter.register_memory_usage("webgl_textures", texture_size)?;
        self.textures.insert(id.to_string(), texture);
        
        Ok(())
    }

    pub fn create_shader(&self, id: &str, shader_type: u32, source: &str) -> Result<(), JsValue> {
        self.resource_limiter.check_memory_allocation(source.len())?;
        
        let shader = self.context.create_shader(shader_type)
            .ok_or_else(|| JsValue::from_str("Failed to create shader"))?;
        
        self.context.shader_source(&shader, source);
        self.context.compile_shader(&shader);

        if !self.context.get_shader_parameter(&shader, WebGlRenderingContext::COMPILE_STATUS)
            .as_bool()
            .unwrap_or(false)
        {
            let log = self.context.get_shader_info_log(&shader)
                .unwrap_or_else(|| String::from("Unknown error creating shader"));
            return Err(JsValue::from_str(&log));
        }

        self.resource_limiter.register_memory_usage("webgl_shaders", source.len())?;
        self.shaders.insert(id.to_string(), shader);
        
        Ok(())
    }

    pub fn create_program(&self, id: &str, vertex_shader_id: &str, fragment_shader_id: &str) -> Result<(), JsValue> {
        let program = self.context.create_program()
            .ok_or_else(|| JsValue::from_str("Failed to create program"))?;
        
        let vertex_shader = self.shaders.get(vertex_shader_id)
            .ok_or_else(|| JsValue::from_str("Vertex shader not found"))?;
        let fragment_shader = self.shaders.get(fragment_shader_id)
            .ok_or_else(|| JsValue::from_str("Fragment shader not found"))?;
        
        self.context.attach_shader(&program, vertex_shader.value());
        self.context.attach_shader(&program, fragment_shader.value());
        self.context.link_program(&program);

        if !self.context.get_program_parameter(&program, WebGlRenderingContext::LINK_STATUS)
            .as_bool()
            .unwrap_or(false)
        {
            let log = self.context.get_program_info_log(&program)
                .unwrap_or_else(|| String::from("Unknown error creating program"));
            return Err(JsValue::from_str(&log));
        }

        self.resource_limiter.register_memory_usage("webgl_programs", std::mem::size_of::<WebGlProgram>())?;
        self.programs.insert(id.to_string(), program);
        
        Ok(())
    }

    pub fn delete_buffer(&self, id: &str) {
        if let Some((_, buffer)) = self.buffers.remove(id) {
            self.context.delete_buffer(Some(&buffer));
            // Deregister resource usage - approximate size based on last known buffer size
            if let Some(size) = self.get_buffer_size(&buffer) {
                self.resource_limiter.deregister_memory_usage("webgl_buffers", size);
            }
        }
    }

    pub fn delete_texture(&self, id: &str) {
        if let Some((_, texture)) = self.textures.remove(id) {
            self.context.delete_texture(Some(&texture));
            // Deregister resource usage - approximate size based on last known texture dimensions
            if let Some(size) = self.get_texture_size(&texture) {
                self.resource_limiter.deregister_memory_usage("webgl_textures", size);
            }
        }
    }

    pub fn delete_shader(&self, id: &str) {
        if let Some((_, shader)) = self.shaders.remove(id) {
            self.context.delete_shader(Some(&shader));
            // Deregister approximate shader resource usage
            self.resource_limiter.deregister_memory_usage("webgl_shaders", 1024); // Approximate size
        }
    }

    pub fn delete_program(&self, id: &str) {
        if let Some((_, program)) = self.programs.remove(id) {
            self.context.delete_program(Some(&program));
            self.resource_limiter.deregister_memory_usage("webgl_programs", std::mem::size_of::<WebGlProgram>());
        }
    }

    fn get_buffer_size(&self, buffer: &WebGlBuffer) -> Option<usize> {
        // Implementation to get buffer size from WebGL
        // This is approximate as WebGL doesn't provide direct size query
        None
    }

    fn get_texture_size(&self, texture: &WebGlTexture) -> Option<usize> {
        // Implementation to get texture size from WebGL
        // This is approximate as WebGL doesn't provide direct size query
        None
    }
}

impl Drop for WebGLManager {
    fn drop(&mut self) {
        // Clean up all WebGL resources
        for (_, buffer) in self.buffers.iter() {
            self.context.delete_buffer(Some(buffer.value()));
        }
        
        for (_, texture) in self.textures.iter() {
            self.context.delete_texture(Some(texture.value()));
        }
        
        for (_, shader) in self.shaders.iter() {
            self.context.delete_shader(Some(shader.value()));
        }
        
        for (_, program) in self.programs.iter() {
            self.context.delete_program(Some(program.value()));
        }

        // Clear collections
        self.buffers.clear();
        self.textures.clear();
        self.shaders.clear();
        self.programs.clear();
    }
}
