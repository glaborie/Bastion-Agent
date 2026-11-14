# ACL policy for the omniroute LLM gateway.
# Reads provider API keys only - no DB, no JWT, no infra creds.
path "bastion/data/api/*" { capabilities = ["read"] }
