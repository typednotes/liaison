# Connector credential storage and status

Select one backend with `SECRETS_BACKEND`. Liaison reads the selected backend for
credentials, connection policies, live organization policies, and run
projections. The authority checks in [the connector contract](connector-permissions.md)
apply in every mode.

| Backend | Configuration | Inventory source |
| --- | --- | --- |
| `typednotes` (default) | `SECRETS_HOST` and `SECRETS_USERNAME` with `SECRETS_PASSWORD`, or `SECRETS_TOKEN` | `GET /v1/secret/metadata/thirdparty/` |
| `keychain` | `SECRETS_KEYCHAIN_INDEX` and optional `SECRETS_KEYCHAIN_SERVICE` | The JSON index of connector paths |
| `openbao` | `SECRETS_HOST`, `SECRETS_TOKEN`, and optional `SECRETS_MOUNT` (default `secret`) | KV v2 metadata under `thirdparty/` |

Both network backends use HTTPS on port 443 by default. `SECRETS_PORT` sets the
port, and `SECRETS_INSECURE=1` selects local HTTP fixtures. Use a credential
scoped to read the broker's documents and update its OAuth credential entries.
Grant list access to the metadata prefix for the broker's connector namespace
to enable discovery. Existing typednotes/secrets userpass sessions reauthenticate
before their lease is due.

## Document paths

Provision all documents in the selected backend. The connection and run
authoring service must use that same backend or supply the documents through a
trusted operator. Switching the broker's backend does not copy existing data.

| Document | Path |
| --- | --- |
| Connector credential | `thirdparty/<provider>/<owner>/<connection>` |
| Connection policy | `thirdparty/<provider>/<owner>/<connection>/permissions` |
| Organization policy | `connector-policy/<org>/<provider>/<connection>` |
| Run projection | `connector-authority/<org>/<run>/<warrant>` |

For [OpenBao KV v2](https://openbao.org/docs/secrets/kv/kv-v2/), use these paths
relative to the configured mount. Liaison sends `X-Vault-Token` and includes
the read version in every refresh write. Grant `list` on the metadata directory
`thirdparty` and its provider and owner subdirectories. Store the existing
credential and policy JSON objects as the KV data, retaining the types of nested
arrays and objects.

For the OS keychain, use a generic-password entry per document. Use the service
`typednotes.liaison` or the configured `SECRETS_KEYCHAIN_SERVICE`, the logical
document path as the account, and the document's JSON as the password. Liaison
uses the macOS Keychain, Linux Secret Service, or Windows Credential Manager
through Linen. On Linux the broker must run in a session that can access and
unlock the selected collection.

To provision entries through the same portable keychain API, a local Lean
program can read one JSON document from standard input and write the entry.
Run it using `lake env lean --run` from this checkout with the service and
document path as the program's two arguments.

```lean
import Linen.System.Keychain

def main (args : List String) : IO Unit := do
  let [service, path] := args
    | throw (IO.userError "expected a service name and document path")
  let json ← (← IO.getStdin).getLine
  if json.trimAscii.isEmpty then throw (IO.userError "expected a JSON document on stdin")
  (System.Keychain.Entry.new service path).setPassword json
```

Set `SECRETS_KEYCHAIN_INDEX` to a JSON file containing every connector
credential path that Liaison should monitor, for example
`["thirdparty/github/local-owner/local-connection"]`. The index contains
identifiers only. Maintain it when onboarding or removing keychain credentials.
The broker re-reads it each scan. This index supplies discovery because Linen's
keychain API retrieves entries by name.

## Refresh and monitoring

The broker scans at startup, then waits `SECRETS_REFRESH_INTERVAL_SECONDS`
(default 30) after each completed scan. Zero disables periodic work. Authorized
requests still refresh due OAuth credentials immediately before use. Configure
the relevant `{GOOGLE,DROPBOX,GITLAB,MICROSOFT}_CLIENT_ID` and `_CLIENT_SECRET`
for every OAuth issuer in use. A token enters the refresh window 60 seconds
before its expiry. Static credentials do not receive refresh attempts.

The foreground and background share the same refresh coordinator. It rechecks
storage under the credential's lock, saves rotated tokens before using them,
and retries unsuccessful write-backs within the process. A restart during a
failed rotation can require reconnecting the credential. Run a single broker
process per set of refreshable credentials so independent processes do not
redeem the same rotating token concurrently. OpenBao CAS guards its writes
against concurrent changes.

Set `SECRETS_STATUS_PASSWORD` to enable `GET /_secrets`. Sign in as `liaison`
with that password. Put this route behind HTTPS or use a local connection and
choose a strong password dedicated to operator access. The page reports
credential identities, kinds, health, UTC expiries and scan totals. It omits
secret values, backend tokens, errors that could contain secrets, and policy
documents. It serves its latest completed snapshot, including a warning if
discovery failed on a later scan.

The integration fixture runs against local HTTP store responses and an empty
keychain namespace.

```sh
python3 LiaisonTest/integration/secrets_status.py --temp-root "$(mktemp -d)"
```
