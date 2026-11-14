# =============================================================================
# Vault Dockerfile - Bastion-Agent
# Official HashiCorp Vault image + bootstrap helper (dev mode, self-signed TLS).
# Production: swap the entrypoint for the same image with a real config + storage
# backend, and inject the unseal keys via a secrets manager or hardware module.
# =============================================================================
FROM hashicorp/vault:1.17.0

# Copy config + policies + generated certs at build time.
COPY vault/config.hcl /etc/vault.d/config.hcl
COPY vault/policies/ /etc/vault.d/policies/
COPY vault/certs/ /etc/vault/certs/

# bootstrap.py runs in this image once the server is healthy. Vault needs the
# cert/key readable but NOT the private key world-readable.
RUN apk add --no-cache python3 && \
    chown root:vault /etc/vault/certs/vault.key && chmod 640 /etc/vault/certs/vault.key && \
    chmod 644 /etc/vault/certs/vault.crt && \
    chmod 644 /etc/vault.d/policies/*.hcl

# Label the path the raft volume mounts on: a new named volume inherits this
# ownership, so the server (su-exec vault) can write to it.
RUN mkdir -p /vault/data && chown vault:vault /vault/data && chmod 700 /vault/data


EXPOSE 8200

# Default: dev server. Override in compose for production.
CMD ["server", "-config=/etc/vault.d/config.hcl"]