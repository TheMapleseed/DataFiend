pub const VERTEX_SHADER: &str = r#"#version 300 es
precision highp float;

in vec2 position;
out vec2 vTexCoord;

void main() {
    vTexCoord = position * 0.5 + 0.5;  // Convert from clip space to texture coordinates
    gl_Position = vec4(position, 0.0, 1.0);
}
"#;

pub const FRAGMENT_SHADER: &str = r#"#version 300 es
precision highp float;

uniform sampler2D heatmapTexture;  // Error frequency texture
uniform float timeScale;           // For animation
uniform float intensity;           // Global intensity multiplier
uniform vec2 resolution;          // Viewport resolution
in vec2 vTexCoord;
out vec4 fragColor;

// Noise function for smooth transitions
float rand(vec2 co) {
    return fract(sin(dot(co.xy ,vec2(12.9898,78.233))) * 43758.5453);
}

void main() {
    // Sample base intensity
    float baseIntensity = texture(heatmapTexture, vTexCoord).r;
    
    // Add subtle animation
    vec2 animatedCoord = vTexCoord + vec2(
        sin(timeScale * 0.001 + vTexCoord.y * 10.0) * 0.001,
        cos(timeScale * 0.001 + vTexCoord.x * 10.0) * 0.001
    );
    
    // Add noise for more organic look
    float noise = rand(animatedCoord + timeScale * 0.0001) * 0.05;
    float finalIntensity = clamp(baseIntensity * intensity + noise, 0.0, 1.0);

    // Enhanced color gradient (black → deep blue → red → yellow → white)
    vec3 color;
    if (finalIntensity < 0.2) {
        color = mix(vec3(0.0, 0.0, 0.0), 
                   vec3(0.0, 0.0, 0.5), 
                   finalIntensity * 5.0);
    } else if (finalIntensity < 0.5) {
        color = mix(vec3(0.0, 0.0, 0.5), 
                   vec3(1.0, 0.0, 0.0), 
                   (finalIntensity - 0.2) * 3.33);
    } else if (finalIntensity < 0.8) {
        color = mix(vec3(1.0, 0.0, 0.0), 
                   vec3(1.0, 1.0, 0.0), 
                   (finalIntensity - 0.5) * 3.33);
    } else {
        color = mix(vec3(1.0, 1.0, 0.0), 
                   vec3(1.0, 1.0, 1.0), 
                   (finalIntensity - 0.8) * 5.0);
    }

    // Add glow effect
    float glow = 0.0;
    if (finalIntensity > 0.5) {
        float glowRadius = (finalIntensity - 0.5) * 20.0;
        vec2 pixelSize = 1.0 / resolution;
        for (float x = -glowRadius; x <= glowRadius; x += 1.0) {
            for (float y = -glowRadius; y <= glowRadius; y += 1.0) {
                vec2 offset = vec2(x, y) * pixelSize;
                float dist = length(offset);
                if (dist <= glowRadius) {
                    float sample = texture(heatmapTexture, vTexCoord + offset).r;
                    glow += sample * (1.0 - dist / glowRadius);
                }
            }
        }
        glow = glow / (glowRadius * glowRadius * 4.0);
    }

    // Blend glow with base color
    color = mix(color, vec3(1.0), glow * 0.2);

    // Add subtle edge highlight
    float edge = length(vec2(
        dFdx(finalIntensity),
        dFdy(finalIntensity)
    )) * 2.0;
    color += vec3(edge) * 0.5;

    fragColor = vec4(color, 1.0);
}
"#;

pub struct HeatmapShaderUniforms {
    pub time_scale: f32,
    pub intensity: f32,
    pub resolution: [f32; 2],
}

impl Default for HeatmapShaderUniforms {
    fn default() -> Self {
        Self {
            time_scale: 0.0,
            intensity: 1.0,
            resolution: [800.0, 600.0],
        }
    }
} 