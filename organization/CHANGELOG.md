# Changelog

## Unreleased

- Preserve the exact observed receipt prefix and original error when an
  interrupted directory batch has unobserved children. The partial result
  cannot advance the SSO checkpoint.

- Select exact SCIM Group/User edge mappings for one tenant, organization,
  provider, connection and mapping version. Preserve original ordered
  child IDs. The optional SSO contributor validates authoritative child
  receipts but does not own the command journal or provisioning cursor.
