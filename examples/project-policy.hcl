# Replace both the KV mount and project prefix consistently for each project.
path "secret/data/projects/demo/*" {
  capabilities = ["read"]
}
path "secret/metadata/projects/demo" {
  capabilities = ["list"]
}
path "secret/metadata/projects/demo/*" {
  capabilities = ["list"]
}
path "auth/token/lookup-self" {
  capabilities = ["read"]
}
path "auth/token/renew-self" {
  capabilities = ["update"]
}
path "auth/token/revoke-self" {
  capabilities = ["update"]
}
