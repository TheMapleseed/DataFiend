#version 300 es
precision highp float;

layout(location = 0) in vec2 position;
layout(location = 1) in float metric_value;

uniform mat4 transform;
uniform vec2 viewport;

out float v_value;

void main() {
    v_value = metric_value;
    gl_Position = transform * vec4(position, 0.0, 1.0);
    gl_PointSize = 2.0;
} 