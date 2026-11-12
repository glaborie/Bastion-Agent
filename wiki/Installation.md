# Installation Guide

## Prerequisites

- Docker Engine 24+ with Compose v2.24+
- NVIDIA Container Toolkit + a CUDA GPU (for local `llama-cpp` service)
- A GGUF model in `./models/` (default: `qwen2.5-7b-instruct-q4_k_m.gguf`)

## Quick Start

```bash
# 1. Clone & enter directory
cd /home/glaborie/projects/Bastion-Agent

# 2. Configure environment
cp .env.example .env

# 3. Download the local inference model (once; ~4.7 GB)
uvx --from huggingface_hub hf download \
  bartowski/Qwen2.5-7B-Instruct-GGUF \
  Qwen2.5-7B-Instruct-Q4_K_M.gguf --local-dir models

mv models/Qwen2.5-7B-Instruct-Q4_K_M.gguf models/qwen2.5-7b-instruct-q4_k_m.gguf

# 4. Start full stack
docker compose up -d

# 5. Register the routing aliases
uv run python scripts/omniroute_bootstrap.py --write-env
docker compose up -d --no-deps gateway worker

# 6. Access Command Control Center
# Gateway & Dashboard: http://localhost:8000/dashboard
# Keycloak SSO:        http://localhost:8080
# OmniRoute:           http://localhost:8001
```

## Local Development (without Docker)

```bash
uv sync                      # installs the project + dev group
docker compose up -d db redis   # only the dependencies you need

uv run uvicorn gateway.main:app --reload
uv run arq agent.runtime.WorkerSettings
```

---
*This wiki is synchronized from the docs/ directory of the main repository.*
