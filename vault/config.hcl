# =============================================================================
# Vault configuration - Bastion-Agent
# Environment: dev (with path to staging/prod in comments)
# Storage:     Integrated Storage (Raft) - single node for dev
# Listener:    HTTPS with self-signed cert (replace with real cert in prod)
# =============================================================================

storage "raft" {
  path    = "/vault/data"
  node_id = "bastion-dev-1"
}

# ---- Staging/Prod: add additional raft nodes and set retry_join ----------
# retry_join {
#   leader_api_addr = "https://vault-bastion.example.com:8200"
# }
# storage "raft" { ... } per node with unique node_id
# --------------------------------------------------------------------------

listener "tcp" {
  address         = "0.0.0.0:8200"
  cluster_address = "0.0.0.0:8201"
  tls_cert_file   = "/etc/vault/certs/vault.crt"
  tls_key_file    = "/etc/vault/certs/vault.key"
}

api_addr     = "https://vault:8200"
cluster_addr = "https://vault:8201"

# ---- Staging/Prod: point at the real FQDN --------------------------------
# api_addr     = "https://vault-bastion.example.com:8200"
# cluster_addr = "https://vault-bastion.example.com:8200"
# --------------------------------------------------------------------------

ui = true

log_level = "info"
