# ACL policy for the postgres service.
# Reads only its own credentials - least privilege.
path "bastion/data/db/postgres" { capabilities = ["read"] }
