# ACL policy for the redis service.
path "bastion/data/db/redis" { capabilities = ["read"] }
