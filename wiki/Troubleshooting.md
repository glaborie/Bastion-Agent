# Troubleshooting

## Common Issues

### `llama-cpp` restarts with "failed to open GGUF file"

**Cause**: The model file is missing or not in the correct location.

**Fix**:
```bash
# Verify the model file exists and has content
ls -lh models/

# If file is 0 bytes, re-download
uvx --from huggingface_hub hf download \
  bartowski/Qwen2.5-7B-Instruct-GGUF \
  Qwen2.5-7B-Instruct-Q4_K_M.gguf --local-dir models

# Rename to match expected filename
mv models/Qwen2.5-7B-Instruct-Q4_K_M.gguf models/qwen2.5-7b-instruct-q4_k_m.gguf
```

### Redis port conflict (WSL2 + Docker Desktop)

**Cause**: Windows reserved port ranges conflict with Docker Desktop.

**Fix**:
```bash
# Check excluded port ranges
powershell.exe -NoProfile -Command "netsh int ipv4 show excludedportrange protocol=tcp"

# Update .env with an available port
REDIS_PORT=26379
REDIS_URL=redis://:@localhost:26379/0
```

### Authentication fails with 401

**Cause**: Keycloak is not running or the OIDC configuration is incorrect.

**Fix**:
```bash
# Ensure Keycloak is running
docker compose up -d keycloak

# Check Keycloak logs
docker logs bastion-agent-keycloak-1

# Verify the realm configuration
curl http://localhost:8080/realms/master
```

### Model routing goes to wrong provider

**Cause**: OmniRoute configuration mismatch or missing API key.

**Fix**:
```bash
# Regenerate routing configuration
uv run python scripts/omniroute_bootstrap.py --write-env

# Verify routing
curl http://localhost:8001/health

# Check model aliases
curl http://localhost:8001/v1/models
```

## Health Checks

```bash
# Check all services
docker compose ps

# Gateway health
curl http://localhost:8000/health

# Keycloak health
curl http://localhost:8080/health

# OmniRoute health
curl http://localhost:8001/health
```

---
*This page is synchronized from the [`wiki/`](https://github.com/glaborie/Bastion-Agent/tree/master/wiki) directory of the main repository.*
