# ACL policy for the gateway + worker services.
# Reads the secrets they need at boot + per request.
path "bastion/data/db/*"    { capabilities = ["read"] }
path "bastion/data/redis/*" { capabilities = ["read"] }
path "bastion/data/jwt/*"   { capabilities = ["read"] }
path "bastion/data/oauth/*" { capabilities = ["read"] }
path "bastion/data/app/*"   { capabilities = ["read"] }
