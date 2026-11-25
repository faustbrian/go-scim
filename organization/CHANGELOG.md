# Changelog

## Unreleased

- Add an explicit, exact-scope Group role mapper. Retain original child
  commands and require a configured custom role for every selected team.
  No role or authority is inferred from source identifiers.

- Add an opt-in, exact-scope User mapper for explicit organization admission
  and inactive/deleted source withdrawals. Preserve source revisions and child
  commands, snapshot bounded member mappings, and return no partial output
  for denied or unsupported batches. Mapping conveys no execution authority.

- Preserve the exact observed receipt prefix and original error when an
  interrupted directory batch has unobserved children. The partial result
  cannot advance the SSO checkpoint.

- Select exact SCIM Group/User edge mappings for one tenant, organization,
  provider, connection and mapping version. Preserve original ordered
  child IDs. The optional SSO contributor validates authoritative child
  receipts but does not own the command journal or provisioning cursor.
