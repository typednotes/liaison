# Connector credential lifecycle

See [backend configuration and operations](../../docs/secrets.md) and the
[connector authorization contract](../../docs/connector-permissions.md).

- **S1** The selected backend supplies separate credential, connection,
  organization and run documents. Connection policy absence can select legacy
  read defaults. Required policy absence or a store error refuses authority.
- **S2** Only due OAuth credentials reach the fixed issuer token endpoint.
  An updated credential becomes usable after persistence. Within one broker
  process, the scan and request paths serialize refreshes for the same
  credential and retry a pending write while the original record still matches.
  OpenBao updates use the revision from the read.
- **S3** The periodic worker discovers connector credential paths from the
  backend inventory and excludes policy documents. A failed inventory read
  preserves the last complete snapshot and marks it stale. Static credentials
  are never refreshed.
- **S4** The operator route is disabled by default. Successful authentication
  reveals a read-only snapshot with identifiers, health, expiration times, and
  counts. It carries no credential values, authenticated HTTP headers,
  or provider response contents. Responses use `Cache-Control: no-store`.
