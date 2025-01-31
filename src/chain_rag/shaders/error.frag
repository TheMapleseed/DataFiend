#version 300 es
precision highp float;

in float v_severity;
out vec4 fragColor;

uniform vec3 errorLow;
uniform vec3 errorHigh;

void main() {
    vec3 color = mix(errorLow, errorHigh, v_severity);
    float alpha = 0.7 + (v_severity * 0.3);
    fragColor = vec4(color, alpha);
}
