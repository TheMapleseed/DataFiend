#version 300 es
precision highp float;

in float v_value;
out vec4 fragColor;

uniform vec3 colorLow;
uniform vec3 colorHigh;

void main() {
    vec3 color = mix(colorLow, colorHigh, v_value);
    fragColor = vec4(color, 1.0);
} 