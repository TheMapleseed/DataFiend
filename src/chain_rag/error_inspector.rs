use wasm_bindgen::prelude::*;
use web_sys::{WebGl2RenderingContext, WebGlFramebuffer, WebGlTexture};
use serde::{Serialize, Deserialize};
use std::sync::Arc;

#[wasm_bindgen]
pub struct ErrorInspector {
    gl: WebGl2RenderingContext,
    framebuffer: WebGlFramebuffer,
    texture: WebGlTexture,
    width: i32,
    height: i32,
    error_map: Arc<ErrorHeatmap>,
}

#[derive(Serialize, Deserialize)]
pub struct ErrorDetail {
    intensity: f32,
    timestamp: f64,
    error_type: String,
    location: String,
    count: u32,
    severity: String,
}

#[wasm_bindgen]
impl ErrorInspector {
    #[wasm_bindgen(constructor)]
    pub fn new(
        gl: WebGl2RenderingContext,
        width: i32,
        height: i32,
        error_map: Arc<ErrorHeatmap>
    ) -> Result<ErrorInspector, JsValue> {
        // Create framebuffer for pixel reading
        let framebuffer = gl.create_framebuffer()
            .ok_or("Failed to create framebuffer")?;
        gl.bind_framebuffer(WebGl2RenderingContext::FRAMEBUFFER, Some(&framebuffer));

        // Create texture for reading
        let texture = gl.create_texture()
            .ok_or("Failed to create texture")?;
        gl.bind_texture(WebGl2RenderingContext::TEXTURE_2D, Some(&texture));
        gl.tex_image_2d_with_i32_and_i32_and_i32_and_format_and_type_and_opt_array_buffer_view(
            WebGl2RenderingContext::TEXTURE_2D,
            0,
            WebGl2RenderingContext::R32F as i32,
            width,
            height,
            0,
            WebGl2RenderingContext::RED,
            WebGl2RenderingContext::FLOAT,
            None,
        )?;

        // Attach texture to framebuffer
        gl.framebuffer_texture_2d(
            WebGl2RenderingContext::FRAMEBUFFER,
            WebGl2RenderingContext::COLOR_ATTACHMENT0,
            WebGl2RenderingContext::TEXTURE_2D,
            Some(&texture),
            0,
        );

        Ok(ErrorInspector {
            gl,
            framebuffer,
            texture,
            width,
            height,
            error_map,
        })
    }

    #[wasm_bindgen]
    pub fn inspect_error(&self, x: i32, y: i32) -> Result<JsValue, JsValue> {
        // Bind framebuffer for reading
        self.gl.bind_framebuffer(
            WebGl2RenderingContext::FRAMEBUFFER,
            Some(&self.framebuffer)
        );

        // Read pixel value
        let intensity = self.get_error_at(x, y);

        // Convert coordinates to error map indices
        let error_x = ((x as f32 / self.width as f32) * self.error_map.get_width() as f32) as usize;
        let error_y = ((y as f32 / self.height as f32) * self.error_map.get_height() as f32) as usize;

        // Get error details from the map
        let error_detail = self.error_map.get_error_details(error_x, error_y)?;

        // Create detailed error information
        let detail = ErrorDetail {
            intensity,
            timestamp: error_detail.timestamp,
            error_type: error_detail.error_type,
            location: error_detail.location,
            count: error_detail.count,
            severity: self.get_severity_label(intensity),
        };

        Ok(serde_wasm_bindgen::to_value(&detail)?)
    }

    fn get_error_at(&self, x: i32, y: i32) -> f32 {
        let mut pixel = [0.0f32];
        self.gl.read_pixels_with_opt_f32_array(
            x,
            self.height - y - 1, // Flip y coordinate for GL coordinate system
            1,
            1,
            WebGl2RenderingContext::RED,
            WebGl2RenderingContext::FLOAT,
            Some(&mut pixel),
        ).unwrap_or(());
        pixel[0]
    }

    fn get_severity_label(&self, intensity: f32) -> String {
        match intensity {
            i if i >= 0.8 => "Critical",
            i if i >= 0.5 => "High",
            i if i >= 0.3 => "Medium",
            i if i > 0.0 => "Low",
            _ => "None",
        }.to_string()
    }

    #[wasm_bindgen]
    pub fn update_inspection_texture(&self) -> Result<(), JsValue> {
        self.gl.bind_texture(WebGl2RenderingContext::TEXTURE_2D, Some(&self.texture));
        
        // Get latest error data
        let error_data = self.error_map.get_gl_data()?;
        
        // Update texture with new data
        self.gl.tex_image_2d_with_i32_and_i32_and_i32_and_format_and_type_and_opt_array_buffer_view(
            WebGl2RenderingContext::TEXTURE_2D,
            0,
            WebGl2RenderingContext::R32F as i32,
            self.width,
            self.height,
            0,
            WebGl2RenderingContext::RED,
            WebGl2RenderingContext::FLOAT,
            Some(&error_data),
        )?;

        Ok(())
    }
}

impl Drop for ErrorInspector {
    fn drop(&mut self) {
        self.gl.delete_framebuffer(Some(&self.framebuffer));
        self.gl.delete_texture(Some(&self.texture));
    }
} 