# Development

## Local Development Setup

### Prerequisites

- Python 3.11+ (using `uv`)
- Docker + Docker Compose
- NVIDIA Container Toolkit (for GPU support)
- A GGUF model for local inference

### Getting Started

```bash
# Clone the repository
git clone https://github.com/glaborie/Bastion-Agent.git
cd Bastion-Agent

# Install dependencies with uv
uv sync --group dev

# Start development stack (database, redis)
docker compose up -d db redis

# Run the gateway
uv run uvicorn gateway.main:app --reload

# Run the agent worker
uv run arq agent.runtime.WorkerSettings
```

## Testing

```bash
# Run linting
uv run ruff check .

# Run type checking
uv run mypy gateway/*.py agent/*.py

# Run unit tests
uv run pytest -m "not integration"

# Run integration tests (requires test database)
docker run --rm -d --name bastion-test-db -p 55433:5432 \
  -e POSTGRES_USER=bastion -e POSTGRES_PASSWORD=bastion \
  -e POSTGRES_DB=bastion_test postgres:16-alpine

TEST_DATABASE_URL=postgresql+asyncpg://bastion:bastion@localhost:55433/bastion_test \
  uv run pytest -m integration
```

## Code Quality

- **Format**: ruff
- **Type check**: mypy
- **Tests**: pytest with DeepEval regression gates
- **CI**: All gates must pass before merge

---
*This wiki is synchronized from the docs/ directory of the main repository.*
