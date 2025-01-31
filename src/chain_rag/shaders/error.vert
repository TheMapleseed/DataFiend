#version 300 es
precision highp float;

layout(location = 0) in vec2 position;
layout(location = 1) in float error_severity;

uniform mat4 transform;
uniform vec2 viewport;

out float v_severity;

void main() {
    v_severity = error_severity;
    gl_Position = transform * vec4(position, 0.0, 1.0);
    gl_PointSize = 4.0 + (error_severity * 4.0);
} 