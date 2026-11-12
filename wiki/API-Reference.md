# API Reference

## Gateway Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/docs` | OpenAPI/Swagger UI |
| GET | `/health` | Health check |
| GET | `/health/ready` | Readiness probe |
| POST | `/auth/login` | Initiate OIDC login |
| POST | `/auth/callback` | OIDC callback |

### Agent Operations

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST | `/v1/chat/completions` | Chat completions with tool calling |
| GET | `/v1/models` | List available models |
| POST | `/v1/chat/escrow` | Retrieve input escrow (pre-production only) |

### Dashboard & Admin

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/dashboard` | Command Control Center (HTMX) |
| GET | `/api/approvals` | Pending approvals list |
| POST | `/api/approvals/{id}/action` | Approve or reject tool request |
| GET | `/api/audit/verify` | Audit chain verification |

### Observability

| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/metrics` | Prometheus metrics |
| GET | `/api/evals/latest` | Latest eval results |

## Authentication & Authorization

### JWT Claims

| Claim | Description |
|-------|-------------|
| `sub` | Unique subject identifier |
| `realm_access.roles` | Roles: `admin`, `operator`, `analyst`, `readonly` |
| `tenant_id` | Tenant identifier (configurable) |

### Tool Access

Tools are decorated with required roles:

```python
@tool(name="read_file", required_role="operator")
def read_file(path: str) -> str:
    ...
```

---
*This wiki is synchronized from the docs/ directory of the main repository.*
