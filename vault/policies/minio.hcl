# ACL policy for the minio / audit-witness service.
path "bastion/data/db/minio" { capabilities = ["read"] }
