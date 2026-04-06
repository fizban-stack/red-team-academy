---
layout: training-page
title: "Edge LLM Setup — Red Team Academy"
module: "AI Red Team Agents"
tags:
  - llm
  - ollama
  - llama-cpp
  - gguf
  - rpi5
  - edge-ai
  - quantization
page_key: "ai-edge-llm-setup"
render_with_liquid: false
---

# Edge LLM Setup

Running large language models locally on constrained hardware — single-board computers, embedded GPUs, or air-gapped rigs — enables AI-assisted red teaming without cloud API dependencies. This page covers hardware selection, quantization formats, Ollama and llama.cpp deployment, and model recommendations for sub-8B inference on common red team hardware.

## Hardware Comparison

### Raspberry Pi 5 (8GB)

```
# RPi5 Specifications
CPU:       BCM2712 — 4× Cortex-A76 @ 2.4 GHz (64-bit)
RAM:       8GB LPDDR4X — ~17 GB/s bandwidth
Storage:   NVMe SSD via PCIe 2.0 x1 HAT (strongly recommended)
Power:     ~7W active inference load, 5A USB-C PSU required
Thermal:   Active cooling MANDATORY — CPU throttles at 85°C

# Inference throughput (Q4_K_M, 4-bit quantization):
Gemma-3-1B:      18-22 tokens/s  (best for RPi5, fits in RAM)
Llama-3.2-3B:     4-5 tokens/s  (recommended balance)
Phi-4-mini-3.8B:  3-4 tokens/s  (strong reasoning, ~2.5GB)
Qwen2.5-7B:       NOT viable    (8GB RAM insufficient for 7B Q4)

# Key constraints:
- No GPU — pure CPU inference via ARM NEON/SVE SIMD
- 8GB shared between OS + model + context window
- Keep OS + swap to <2GB; leave ~6GB for model + context
- Enable swap: sudo dphys-swapfile swapoff && sudo nano /etc/dphys-swapfile
  CONF_SWAPSIZE=4096  # 4GB swap on NVMe for overflow
```

### Orange Pi 4 Pro (RK3588)

```
# Orange Pi 4 Pro Specifications
CPU:       RK3588 — 4× A76 @ 2.4 GHz + 4× A55 @ 1.8 GHz
RAM:       8GB or 16GB LPDDR4X
NPU:       6 TOPS — INT8/INT4 quantization ONLY (W8A8)
GPU:       Mali-G610 MP4 — limited OpenCL inference
Storage:   eMMC + M.2 NVMe slot

# NPU via RKLLM toolkit (NOT compatible with GGUF/Ollama):
pip install rkllm-toolkit
# Convert GGUF → RKNN format first (lossy, proprietary)
# RKLLM supports: Llama, Qwen, Gemma (select models only)

# CPU inference (GGUF via llama.cpp — same as RPi5):
Llama-3.2-3B Q4_K_M: ~5-8 tokens/s (A76 cores)

# 16GB variant:
Qwen2.5-7B Q4_K_M: ~4-6 tokens/s — feasible with 16GB RAM

# RKLLM workflow (NPU path):
git clone https://github.com/airockchip/rknn-llm
pip install rkllm-toolkit
python rkllm_convert.py --model Qwen2.5-3B --output qwen2.5-3b.rkllm
# Run inference via rkllm_run binary (provided in SDK)
```

### Consumer GPU (RTX 3060 / RTX 4070 12GB)

```
# RTX 3060 12GB
VRAM:      12GB GDDR6
Bandwidth: 360 GB/s
Power:     ~170W TDP

# RTX 4070 12GB
VRAM:      12GB GDDR6X
Bandwidth: 504 GB/s
Power:     ~200W TDP

# Inference throughput (GPU fully offloaded, -ngl 99):
Qwen2.5-7B Q4_K_M (4.5GB):   40-50 t/s (3060) / 60-80 t/s (4070)
Llama-3.2-3B Q4_K_M (2.0GB): 80-120 t/s — fast enough for agentic loops
Phi-4-mini Q4_K_M (2.5GB):   70-100 t/s

# 7B fits in 12GB VRAM at Q4 — full GPU offload
# 13B Q4 (~8GB): fits in 12GB — still fast at 25-40 t/s

# CUDA setup:
nvidia-smi  # verify driver
nvcc --version  # verify CUDA toolkit
ollama pull qwen2.5:7b  # auto-uses GPU if detected
```

### NVIDIA Jetson (Orin Series)

```
# Jetson Orin Nano Super 8GB
AI Perf:   67 TOPS INT8
RAM:       8GB LPDDR5 unified (CPU + GPU share)
Power:     7-15W configurable
Best for:  3B-7B models, long-running drop-box ops

# Jetson Orin NX 16GB
AI Perf:   157 TOPS INT8
RAM:       16GB LPDDR5 unified
Best for:  7B-13B models, heavier analysis tasks

# Use llama.cpp with CUDA backend (NVCC targets Ampere arch):
cmake -B build -DGGML_CUDA=ON -DCMAKE_CUDA_ARCHITECTURES=87
# Orin SM = 87 (Ampere-class)
```

## GGUF Quantization Formats

```
# GGUF quantization — file sizes for a 7B parameter model:
Format    File Size   Perplexity Delta   Use Case
-------   ---------   ----------------   --------
Q4_K_M    ~4.5 GB     +0.05 ppl          Best balance — recommended default
Q5_K_M    ~5.3 GB     +0.035 ppl         Better quality, still fits 12GB VRAM
Q8_0      ~8.5 GB     <2% vs FP16       Near-lossless, GPU with 12GB+ only
Q3_K_M    ~3.5 GB     +0.1 ppl           SBC only — RPi5 with 8GB
Q2_K      ~2.8 GB     significant loss   Last resort for extreme RAM limits

# K-quant suffix meaning:
# K_S = small (fewer bits for attention weights)
# K_M = medium (mixed precision — best quality/size ratio)
# K_L = large (more bits preserved)

# For 3B models (RPi5 primary):
Llama-3.2-3B Q4_K_M: ~2.0 GB  — fits easily, 4-5 t/s
Phi-4-mini Q4_K_M:   ~2.5 GB  — fits, 3-4 t/s
Gemma-3-1B Q4_K_M:   ~0.8 GB  — fastest, 18-22 t/s

# Download quantized models:
# HuggingFace Hub (Bartowski, unsloth, TheBloke namespaces):
pip install huggingface-hub
huggingface-cli download bartowski/Llama-3.2-3B-Instruct-GGUF \
  --include "Llama-3.2-3B-Instruct-Q4_K_M.gguf" \
  --local-dir ./models
```

## Ollama — Install & Configuration

```
# Install Ollama (Linux):
curl -fsSL https://ollama.com/install.sh | sh

# Start service:
ollama serve  # or systemctl start ollama

# Pull models:
ollama pull llama3.2:3b          # 2.0 GB — RPi5 default
ollama pull qwen2.5:7b           # 4.5 GB — GPU rigs
ollama pull phi4-mini            # 2.5 GB — strong reasoning
ollama pull gemma3:1b            # 0.8 GB — fastest on RPi5

# Run interactive:
ollama run llama3.2:3b

# List local models:
ollama list

# Key environment variables:
export OLLAMA_HOST=127.0.0.1:11434   # bind to localhost only (OPSEC)
export OLLAMA_MODELS=/data/ollama    # custom model store path
export OLLAMA_NUM_PARALLEL=1         # limit parallel requests (RAM)
export OLLAMA_MAX_LOADED_MODELS=1    # only one model in memory
```

### Ollama REST API

```
# Generate endpoint (simple completion):
curl http://localhost:11434/api/generate -d '{
  "model": "llama3.2:3b",
  "prompt": "Analyze this nmap output: ...",
  "stream": false,
  "options": {"num_ctx": 8192}
}'

# Chat endpoint (messages array):
curl http://localhost:11434/api/chat -d '{
  "model": "llama3.2:3b",
  "messages": [
    {"role": "system", "content": "You are a penetration testing assistant."},
    {"role": "user", "content": "What ports should I investigate first?"}
  ],
  "stream": false
}'

# OpenAI-compatible endpoint (drop-in replacement):
curl http://localhost:11434/v1/chat/completions \
  -H "Content-Type: application/json" \
  -d '{
    "model": "llama3.2:3b",
    "messages": [{"role": "user", "content": "Hello"}]
  }'

# Tool calling via /api/chat:
curl http://localhost:11434/api/chat -d '{
  "model": "qwen2.5:7b",
  "messages": [{"role": "user", "content": "Scan 192.168.1.0/24"}],
  "tools": [{
    "type": "function",
    "function": {
      "name": "run_nmap",
      "description": "Run nmap port scan",
      "parameters": {
        "type": "object",
        "properties": {
          "target": {"type": "string", "description": "IP or CIDR"},
          "flags": {"type": "string", "description": "nmap flags"}
        },
        "required": ["target"]
      }
    }
  }]
}'

# Tool call response structure:
# message.tool_calls[0].function.name  → "run_nmap"
# message.tool_calls[0].function.arguments → '{"target": "192.168.1.0/24"}'
```

### Ollama systemd Service (OPSEC)

```
# /etc/systemd/system/ollama.service — OPSEC-hardened:
[Unit]
Description=Ollama Service
After=network-online.target

[Service]
ExecStart=/usr/local/bin/ollama serve
User=ollama
Group=ollama
Restart=always
Environment="OLLAMA_HOST=127.0.0.1:11434"
Environment="OLLAMA_NUM_PARALLEL=1"
StandardOutput=null     # disable logging
StandardError=null      # disable error logging

[Install]
WantedBy=multi-user.target

# Reload & enable:
sudo systemctl daemon-reload
sudo systemctl enable --now ollama
```

## llama.cpp — Build & Deployment

```
# Clone and build (SBC — CPU + OpenBLAS):
git clone https://github.com/ggerganov/llama.cpp
cd llama.cpp
cmake -B build \
  -DGGML_BLAS=ON \
  -DGGML_BLAS_VENDOR=OpenBLAS \
  -DCMAKE_BUILD_TYPE=Release
cmake --build build --config Release -j$(nproc)

# Build for CUDA (GPU rigs):
cmake -B build \
  -DGGML_CUDA=ON \
  -DCMAKE_CUDA_ARCHITECTURES=86   # RTX 3060/4070 = Ampere sm_86
cmake --build build --config Release -j$(nproc)

# Run inference (CLI):
./build/bin/llama-cli \
  -m ./models/llama-3.2-3b-instruct-q4_k_m.gguf \
  -p "You are a red team assistant. Analyze: " \
  -n 512 \
  --ctx-size 8192 \
  --threads 4         # RPi5: use 4 threads (A76 cores)

# GPU offload flags:
-ngl 33    # offload 33 layers to GPU (full 7B offload at 12GB)
-ngl 99    # offload all layers (use when VRAM allows)
-ts 0,1    # tensor split across multiple GPUs

# Run as OpenAI-compatible server:
./build/bin/llama-server \
  -m ./models/llama-3.2-3b-instruct-q4_k_m.gguf \
  --host 127.0.0.1 \
  --port 8080 \
  --ctx-size 8192 \
  --threads 4 \
  -ngl 0       # set to 33 for GPU

# API is OpenAI-compatible:
# POST http://localhost:8080/v1/chat/completions
# Use with openai Python SDK: base_url="http://localhost:8080/v1"
```

### SBC Thermal Management

```
# Monitor RPi5 temperature:
vcgencmd measure_temp
# or:
cat /sys/class/thermal/thermal_zone0/temp  # divide by 1000 for °C

# Watch throttling status:
vcgencmd get_throttled
# 0x0 = normal, 0x50005 = throttled (critical)

# Set performance governor (RPi5):
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor

# Monitor during inference:
watch -n1 'vcgencmd measure_temp; vcgencmd get_throttled'

# Check memory pressure:
free -h
# swap usage indicates RAM exhaustion — reduce num_ctx or use smaller model

# Recommended active cooler: Pimoroni Fan SHIM or official RPi5 active cooler
# Target: keep CPU below 75°C during sustained inference
```

## Sub-8B Model Recommendations

```
# Model comparison (2024-2025 sub-8B landscape):
Model              Params  Context  RPi5 t/s  GPU t/s  Best For
----------------   ------  -------  --------  -------  --------
Gemma-3-1B         1.0B    128K     18-22     150+     Fast summaries, quick analysis
Llama-3.2-3B       3.0B    128K     4-5       80-120   Tool calling, recon agent loops
Phi-4-mini         3.8B    128K     3-4       70-100   Complex reasoning, BloodHound
Qwen2.5-7B         7.2B    128K     NOT RPi5  40-80    Best reasoning, GPU only
Mistral-7B-v0.3    7.2B    32K      NOT RPi5  40-70    Instruction following, reports

# For RPi5 drop-box deployments:
Primary:   Llama-3.2-3B — tool calling support, 128K context, 4-5 t/s
Fallback:  Gemma-3-1B  — 18+ t/s for rapid classification
Heavy:     Phi-4-mini  — better reasoning for BloodHound analysis

# For GPU rigs (12GB VRAM):
Primary:   Qwen2.5-7B Q4_K_M — best reasoning quality at this size
Secondary: Llama-3.2-3B Q4_K_M — faster loops, tool calling

# Tool calling support (as of 2025):
Supported: Llama3.x, Qwen2.5, Mistral (Ollama enforces schema)
Limited:   Phi-4-mini, Gemma-3 (function calling via system prompt)
None:      Most 1B models (use CodeAgent/structured prompting instead)
```

## Offline Model Caching

```
# Download for offline use (before air-gap):
pip install huggingface-hub

# Download specific GGUF file:
huggingface-cli download \
  bartowski/Llama-3.2-3B-Instruct-GGUF \
  "Llama-3.2-3B-Instruct-Q4_K_M.gguf" \
  --local-dir /opt/models

# Create Ollama Modelfile for custom GGUF:
cat > /tmp/Modelfile <<'EOF'
FROM /opt/models/Llama-3.2-3B-Instruct-Q4_K_M.gguf
SYSTEM "You are an expert penetration tester."
PARAMETER num_ctx 8192
PARAMETER temperature 0.1
EOF

ollama create redteam-3b -f /tmp/Modelfile
ollama run redteam-3b

# Export Ollama model store for transfer to air-gapped system:
# Models stored in: ~/.ollama/models/ (Linux)
tar -czf ollama-models.tar.gz ~/.ollama/models/
# Transfer via USB, then extract on target:
tar -xzf ollama-models.tar.gz -C ~/

# Verify model integrity after transfer:
ollama list  # should show transferred models
```

## Resources

- Ollama — `ollama.com` — model library and documentation
- llama.cpp — `github.com/ggerganov/llama.cpp`
- GGUF model hub — `huggingface.co/bartowski`
- RKLLM toolkit — `github.com/airockchip/rknn-llm`
- RPi5 performance guide — `github.com/geerlingguy/pi-benchmarks`
