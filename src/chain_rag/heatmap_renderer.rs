use wasm_bindgen::prelude::*;
use web_sys::{WebGl2RenderingContext, WebGlProgram, WebGlShader, WebGlTexture, WebGlBuffer};
use std::sync::Arc;

pub struct HeatmapRenderer {
    gl: WebGl2RenderingContext,
    program: WebGlProgram,
    vertex_buffer: WebGlBuffer,
    texture: WebGlTexture,
    width: u32,
    height: u32,
}

impl HeatmapRenderer {
    pub fn new(gl: WebGl2RenderingContext, width: u32, height: u32) -> Result<Self, JsValue> {
        let program = create_program(&gl)?;
        let vertex_buffer = create_vertex_buffer(&gl)?;
        let texture = create_empty_texture(&gl, width, height)?;

        Ok(Self {
            gl,
            program,
            vertex_buffer,
            texture,
            width,
            height,
        })
    }

    pub fn update_data(&self, data: &[f32]) -> Result<(), JsValue> {
        self.gl.bind_texture(WebGl2RenderingContext::TEXTURE_2D, Some(&self.texture));
        
        unsafe {
            let uarray = js_sys::Float32Array::view(data);
            self.gl.tex_image_2d_with_i32_and_i32_and_i32_and_format_and_type_and_opt_array_buffer_view(
                WebGl2RenderingContext::TEXTURE_2D,
                0,
                WebGl2RenderingContext::R32F as i32,
                self.width as i32,
                self.height as i32,
                0,
                WebGl2RenderingContext::RED,
                WebGl2RenderingContext::FLOAT,
                Some(&uarray)
            )?;
        }

        Ok(())
    }

    pub fn render(&self, color_low: [f32; 3], color_high: [f32; 3]) -> Result<(), JsValue> {
        self.gl.use_program(Some(&self.program));
        
        // Set uniforms
        let color_low_loc = self.gl.get_uniform_location(&self.program, "colorLow")
            .ok_or("Failed to get colorLow uniform location")?;
        let color_high_loc = self.gl.get_uniform_location(&self.program, "colorHigh")
            .ok_or("Failed to get colorHigh uniform location")?;

        self.gl.uniform3fv_with_f32_array(Some(&color_low_loc), &color_low);
        self.gl.uniform3fv_with_f32_array(Some(&color_high_loc), &color_high);

        // Bind texture
        self.gl.active_texture(WebGl2RenderingContext::TEXTURE0);
        self.gl.bind_texture(WebGl2RenderingContext::TEXTURE_2D, Some(&self.texture));
        
        let sampler_loc = self.gl.get_uniform_location(&self.program, "heatmapTexture")
            .ok_or("Failed to get sampler uniform location")?;
        self.gl.uniform1i(Some(&sampler_loc), 0);

        // Draw
        self.gl.bind_buffer(
            WebGl2RenderingContext::ARRAY_BUFFER,
            Some(&self.vertex_buffer)
        );

        let position_loc = self.gl.get_attrib_location(&self.program, "position") as u32;
        self.gl.enable_vertex_attrib_array(position_loc);
        self.gl.vertex_attrib_pointer_with_i32(
            position_loc,
            2,
            WebGl2RenderingContext::FLOAT,
            false,
            0,
            0,
        );

        self.gl.draw_arrays(WebGl2RenderingContext::TRIANGLE_STRIP, 0, 4);

        Ok(())
    }
}

fn create_program(gl: &WebGl2RenderingContext) -> Result<WebGlProgram, JsValue> {
    let vert_shader = compile_shader(
        gl,
        WebGl2RenderingContext::VERTEX_SHADER,
        r#"#version 300 es
        precision highp float;
        
        in vec2 position;
        out vec2 texCoord;
        
        void main() {
            texCoord = position * 0.5 + 0.5;
            gl_Position = vec4(position, 0.0, 1.0);
        }
        "#,
    )?;

    let frag_shader = compile_shader(
        gl,
        WebGl2RenderingContext::FRAGMENT_SHADER,
        r#"#version 300 es
        precision highp float;
        
        uniform sampler2D heatmapTexture;
        uniform vec3 colorLow;
        uniform vec3 colorHigh;
        
        in vec2 texCoord;
        out vec4 fragColor;
        
        void main() {
            float value = texture(heatmapTexture, texCoord).r;
            vec3 color = mix(colorLow, colorHigh, value);
            fragColor = vec4(color, value);
        }
        "#,
    )?;

    let program = gl.create_program().ok_or("Failed to create program")?;
    gl.attach_shader(&program, &vert_shader);
    gl.attach_shader(&program, &frag_shader);
    gl.link_program(&program);

    if !gl.get_program_parameter(&program, WebGl2RenderingContext::LINK_STATUS)
        .as_bool()
        .unwrap_or(false)
    {
        return Err(JsValue::from_str(&gl.get_program_info_log(&program)
            .unwrap_or_else(|| String::from("Unknown error creating program"))));
    }

    Ok(program)
}

fn compile_shader(
    gl: &WebGl2RenderingContext,
    shader_type: u32,
    source: &str,
) -> Result<WebGlShader, JsValue> {
    let shader = gl.create_shader(shader_type)
        .ok_or("Failed to create shader")?;
    
    gl.shader_source(&shader, source);
    gl.compile_shader(&shader);

    if !gl.get_shader_parameter(&shader, WebGl2RenderingContext::COMPILE_STATUS)
        .as_bool()
        .unwrap_or(false)
    {
        return Err(JsValue::from_str(&gl.get_shader_info_log(&shader)
            .unwrap_or_else(|| String::from("Unknown error compiling shader"))));
    }

    Ok(shader)
}

fn create_vertex_buffer(gl: &WebGl2RenderingContext) -> Result<WebGlBuffer, JsValue> {
    let vertices: [f32; 8] = [
        -1.0, -1.0,
        1.0, -1.0,
        -1.0, 1.0,
        1.0, 1.0,
    ];

    let buffer = gl.create_buffer().ok_or("Failed to create buffer")?;
    gl.bind_buffer(WebGl2RenderingContext::ARRAY_BUFFER, Some(&buffer));

    unsafe {
        let vert_array = js_sys::Float32Array::view(&vertices);
        gl.buffer_data_with_array_buffer_view(
            WebGl2RenderingContext::ARRAY_BUFFER,
            &vert_array,
            WebGl2RenderingContext::STATIC_DRAW,
        );
    }

    Ok(buffer)
}

fn create_empty_texture(
    gl: &WebGl2RenderingContext,
    width: u32,
    height: u32,
) -> Result<WebGlTexture, JsValue> {
    let texture = gl.create_texture().ok_or("Failed to create texture")?;
    gl.bind_texture(WebGl2RenderingContext::TEXTURE_2D, Some(&texture));
    
    gl.tex_parameteri(
        WebGl2RenderingContext::TEXTURE_2D,
        WebGl2RenderingContext::TEXTURE_MIN_FILTER,
        WebGl2RenderingContext::LINEAR as i32,
    );
    gl.tex_parameteri(
        WebGl2RenderingContext::TEXTURE_2D,
        WebGl2RenderingContext::TEXTURE_MAG_FILTER,
        WebGl2RenderingContext::LINEAR as i32,
    );

    Ok(texture)
} 