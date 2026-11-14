# ACL policy for the keycloak service.
# Reads its own admin + realm client secrets.
path "bastion/data/db/keycloak" { capabilities = ["read"] }
