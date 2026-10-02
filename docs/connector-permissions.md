# Native connector authorization

This is the native `Eff` broker contract for the coordinated **Liaison 0.6.0 /
Linen 1.10.0** release line, integrated with **Lode/Lun 0.3.0** and
**Typednotes 0.6.0**. The release owner manages version files, dependency pins,
commits and tags; the contracts and local handoffs are verified together.

The [native writer contract](native-writer.md) additionally specifies current
conversation/function-tool replay, Radius Pi/SSE and atomic repository modes.

Patch 0.6.3 adds bounded repository browsing and metadata selection for Typednotes
0.9.0. `repositories.list`, resource `[]`, accepts optional canonical decimal-text
`page` 1–100; requests/replies are limited to 100 entries. `repositories.read`,
exact resource `[owner,repo]`, accepts `{"view":"metadata"}`; the returned identity
must match a private checked `Metadata` witness. GitHub/GitLab transports use
fixed provider endpoints and deterministic ordering. Operation IDs, structured
scope semantics, presets and OAuth scope ceilings are unchanged. No arbitrary
URL, organization-directory access or broader authority is introduced. See
[the patch contract and verification](release-0.6.3.md).

## HTTP and authority contract

`POST /v0/egress` retains its warrant/request envelope. Its native call is:

```json
{"kind":"connector","account":"user/connection","operation":"objects.read",
 "resource":["reports","invoice.json"],"payload":"{}"}
```

The HMAC-verified warrant must explicitly bind provider, named operation,
connection, run, expiry, and budget. The request's organization must equal the
warrant's organization. Expiry uses the broker's clock; wire `now` is not trusted.
The call operation must equal the signed action and the account's connection
must equal the signed resource. A trusted run document additionally binds the
credential **owner**, so another user's connection with the same leaf ID cannot
be substituted. A `Reserved` budget witness is required for all credential use.

The broker derives methods, URLs, authentication, headers, and selectors.
Payloads cannot override those fields. Unknown operations/providers, ambiguous
JSON, unexpected fields, invalid arities, and invalid selectors fail closed.
Selectors are at most 32 nonempty components, at most 255 UTF-8 bytes each;
separators, percent escapes, dot segments, and C0/C1 controls are refused.
Literal query punctuation and Unicode are percent-encoded as UTF-8, never
concatenated as raw paths or queries.

The common credentialed native HTTP API builder adds `User-Agent:
typednotes-liaison` when there is no nonblank user agent. Its private
`NativeHeaders` witness carries either membership of that fixed header pair or
the successful check of an existing nonblank user agent. Explicit identities
such as `typednotes-lode` in bound model calls are preserved. This covers GitHub
inventory, relationship preflights, immutable blob/tree reads and REST/GraphQL
publication; adding the header only to `repositories.list` would leave the
follow-up paths broken. GitHub requires a valid User-Agent, as documented in
[its REST troubleshooting guide](https://docs.github.com/en/rest/using-the-rest-api/troubleshooting-the-rest-api#user-agent-required).
Raw caller-selected headers remain forbidden. No operation, scope, credential,
warrant or wire format is widened by this transport fix.

Regression coverage includes a fixture which returns GitHub's 403 for missing
User-Agent, assertions on every GitHub API request (including atomic publication),
blank/case-insensitive header normalization, and preservation of model-provider
identities. The missing-header fixture fails against the previous binary; the
fixed broker passes all 655 native HTTP cases and the Lean test suite.

## Three independently stored policy documents

All paths below are KV paths beneath `/v1/secret/data/`. The vault HTTP response
wraps each document as `{"data": document}`.

* `thirdparty/{provider}/{owner}/{connection}/permissions`: connection ceiling.
* `connector-policy/{org}/{provider}/{connection}`: live organization ceiling.
* `connector-authority/{org}/{run}/{warrant-id}`: trusted run/minting projection
  with independently bounded cell and warrant ceilings and the credential owner.

Organization and connection documents have exactly these required fields:

```json
{"scopes":[{"operation":"objects.read","root":["reports"],"descendants":true}],
 "maxRequestBytes":1048576,"maxResponseBytes":16777216}
```

The basic run projection has these required fields; its strict optional
`conversation` and `publication` extensions are specified in the writer contract:

```json
{"account":"user/connection",
 "cell":{"provider":"s3","connection":"connection",
         "scopes":[{"operation":"objects.read","root":["reports"],"descendants":true}],
         "maxRequestBytes":1048576,"maxResponseBytes":16777216},
 "warrant":{"provider":"s3","connection":"connection",
            "scopes":[{"operation":"objects.read","root":["reports"],"descendants":true}],
            "maxRequestBytes":1048576,"maxResponseBytes":16777216}}
```

Each scope requires `operation`, `root`, and `descendants`. Byte limits are
integral numbers from 1 to 67,108,864. There are at most 128 grants per ceiling.
Missing scope fields never inherit a permissive default. Duplicate and unknown
fields are rejected, including inside run capabilities. Fractional limits are
checked before the JSON bridge can round them. Empty scopes grant nothing.

Only an actual **404** on a connection policy enables provider-filtered read
defaults (1 MiB request, 16 MiB response). A malformed policy, an inaccessible
vault, or an authorization error never enables defaults. Organization/run
documents are always mandatory. Each call fetches fresh documents; in-flight
calls execute against their fetched policy and credential snapshots.

Cell/generated/session code must not be able to write the organization or run
namespaces, or widen a connection ceiling. Vault ACLs and the trusted minting
service are part of the explicitly trusted boundary. All four ceilings intersect
again at the broker; the client cannot supply its own authority document.

### Hot-policy and run-projection revocation

The trusted app closes live organization/connection gates and deletes tracked
run projections before acknowledging permission or declaration edits/deletes.
Every subsequent broker call reloads those independent documents and denies a
missing mandatory projection or an empty/intersected-away grant. This also
revokes otherwise correctly signed, unexpired warrants: HMAC validity is not a
substitute for current authority. Application publication/revocation uses its
per-organization transaction lock and separated write-only vault permissions.

This is not a separate token-ID/tag blacklist. A call already authorized against
fetched snapshots is not retroactively cancelled; expiry is checked at admission.
The legacy connection-only 404 default does not supply missing organization/run
authority, and the app explicitly materializes ceilings for current connections.

## Supported native operations and selectors

`Connector.operations` is the actual broker support catalog. The tests compare
it to positive native-plan fixtures and the sibling Rust catalog.

* **S3 / Azure**: `objects.list/read/write/delete`. The stored base pins the
  bucket/container. Components form a key/prefix inside it. Listing `reports`
  derives `reports/`, excluding `reports-private`. Writes accept UTF-8
  `contents`; no caller-selected headers, signing parameters, or overwrite URLs.
* **Google Drive**: `files.list/read/create/update/delete/share`. A single
  component is an actual file/folder ID. `[folder,file]` requires provider-owned
  parent membership and a strong ETag; longer mutable ancestry is refused.
  Listing/creation takes one folder ID. Creation creates an empty file with
  `name`; update renames the selected item. Read downloads ordinary binary
  file content (`alt=media`), not Workspace exports. Sharing appends one email
  component and grants that user reader access. Folder deletion and folder
  sharing are refused because they have unrepresented recursive effects.
* **Dropbox**: `files.list/read/create/update/delete/share`. Components form
  paths beneath the credential's namespace; sharing appends one email.
  Upload create uses add/strict-conflict without autorename; update requires
  `revision`. Delete resolves a file (not a folder), checks `path_lower`, and
  sends the original path plus `parent_rev`, avoiding recursive substitution
  and moved-file-ID races. Sharing requires **recursive account authority**
  because the sharing endpoint lacks an atomic path condition. Only the exact
  production base `https://api.dropboxapi.com` derives the fixed
  `https://content.dropboxapi.com` origin for download/upload. Custom gateways
  retain their stored origin; no arbitrary host override is introduced.
* **Google / Microsoft calendars**: `calendars.list`,
  `events.read/create/update/delete/invite`. Inventory targets `[]`. Read takes
  `[calendar]` or `[calendar,event]`; create takes `[calendar]`; update/delete
  take `[calendar,event]`; invite takes `[calendar,event,email]`. Event objects
  expose only allowlisted text/time fields, never attendees, external links,
  organizers, or another calendar. Preflight verifies current attendees for
  **independent invitation authority**, uses a strong ETag, and merges rather
  than replaces attendees. An update/delete of an event with attendees also
  requires authority on those invitation recipients.
* **CalDAV**: `calendars.list`, `events.read/create/update/delete`. Inventory is
  a depth-one PROPFIND. Events take `[calendar,filename.ics]`. Bodies are broker
  generated, not caller-supplied iCalendar. Create uses `If-None-Match: *`;
  update/delete require one strong `etag`. Preflight refuses scheduling objects
  (attendee/organizer/method), verifies the ETag, and preserves the observed UID.
* **Gmail / Outlook / JMAP**: `mailboxes.list`, `messages.read/search`,
  `drafts.create`, `messages.send/update/delete`, `attachments.read`. The first
  component is `me` for Gmail/Outlook or an actual JMAP account ID. The next is a
  label/folder/mailbox. Message and attachment IDs follow it. A move additionally
  supplies its destination as a fourth component, with independent authority on
  `[account,destination]`. Gmail/JMAP message membership is validated on the
  **actual disclosed response**, not on a prior observation followed by another
  unvalidated read. Outlook paths include the actual folder selector. JMAP
  update/delete bind the observed state with `ifInState`; deletion requires
  permission on all current mailboxes. Gmail label-conditioned mutations and
  attachment reads have no atomic label condition and therefore require
  recursive authority at `[me]`. Scoped Gmail reads/search remain available.
  Drafts have no recipients; JMAP validates the target mailbox's drafts role.
  Gmail/Outlook send takes `[me,SENT-or-sentitems,email]` and broker-generated
  subject/text. JMAP send takes `[account,mailbox,email-id,recipient,identity]`;
  the broker verifies recipient/identity and supplies explicit envelope
  `mailFrom` and **one** `rcptTo`, never relying on inferred To/Cc/Bcc delivery.
* **Notion**: `pages.read/create/update/delete`, `databases.query`,
  `comments.create`. Page operations take one page/parent ID and expose only
  title/plain comment text. Delete means `in_trash` and requires recursive
  account authority because page archival affects an ID-based subtree.
  Database queries resolve its provider-owned `data_sources` using the current
  Notion API. `[database]` works only with one source; `[database,source]`
  selects a verified member of a multi-source database. No arbitrary query
  source, filter, parent, or URL comes from payload data.
* **Slack**: `channels.list`, `messages.read/send/update/delete`. Inventory uses
  `[]`; history/send use `[channel]`; update/delete use `[channel,timestamp]`.
  Message payloads contain text only, never channel or recipient overrides.
* **Signal / WhatsApp**: `messages.send` only, with `[sender-account,recipient]`
  and text. Both identities are in the granted selector; the payload cannot
  replace either. Read/edit/delete/file history are not silently simulated.
* **GitHub / GitLab**: `repositories.list/read/write/delete`, `issues.read/write`,
  `pull_requests.write`. Resources start with `[owner,repo]`; file components or
  a positive issue/PR number follow. Reads specify `ref`; writes specify
  branch/message/contents (GitHub optional `sha`). GitHub reads resolve a
  nontruncated tree and fetch the immutable blob, avoiding `/contents` symlink
  following. Branch/tree/ancestry and payload-indexed atomic commit modes are
  documented in the writer contract. Deletes are independently scoped; write
  never implies delete. PR writes update title/text only, not merge or branch.
* **AI providers**: `models.list` and inline `inference.generate`, with a
  model selector and endpoint shaping for Chat/Messages/Responses/Gemini.
  TypeSafe supports `classification.evaluate` instead of generation; Opencode
  additionally supports classifier models. Radius supports bounded native Pi
  generation and terminal-validated SSE. Only trusted-run-authorized inline local
  function metadata/replay is accepted; payloads cannot select another model,
  remote file/URL retrieval, hosted tools, fallback providers, or routing.
  Request and generated-body sizes are checked
  independently (for example MIME/base64 expansion counts toward the bound).

Inventory/list grants target a collection; they do not grant a different read,
write, sharing, invitation, sending, or deletion operation on its contents.
Exact grants never become recursive grants: native effects that require a whole
account subtree consume proved recursive attenuation against **all four**
ceilings, rather than accepting an exact grant on an empty/account selector.

## Types, proofs, and trusted correspondence

`Authorized` carries verified HMAC, caveat permission, organization equality,
and explicit execution bindings. `Reserved` carries the authorized request and
its real SQL hold. `Prepared` has a private constructor and carries the original
four-ceiling `AuthorizedResource`, exact native derivation, payload/body bounds,
secondary-selector evidence, and semantic recursive attenuation proofs.
Its `organization_permits`, `connection_permits`, `cell_permits`,
`warrant_permits`, and `secondary_permits` theorems are kernel checked.
The private `Resolved` witness preserves ordinary-adapter method/account,
checked origin and body bounds after provider-owned preflight transformations.
Repository publication consumes a payload-indexed `AuthorizedPlan` with branch,
project and per-change operation evidence; function and SSE witnesses retain
their validation evidence. `BoundedUsage` prevents settlement beyond the hold.

These proofs establish the local authority model; they do not prove a remote
provider tells the truth, implements documented nested-resource routes, or
honors ETags/revision/state conditions. Those are explicit trusted API boundaries.
Missing, weak, wildcard, or multiple ETags fail closed. Snapshot relationships
for immutable blobs and database sources are not promises of transactionally
freezing a remote service. Long mutable Drive ancestry and native effects
without suitable atomic scope conditions are refused or require recursive
account authority as specified above.

Responses are parser-bounded on cumulative wire input (body limit plus 64 KiB
framing allowance) and body size. Redirects are not followed. The socket/TLS
reader, HMAC implementation, vault ACLs, SQL/ledger, and native provider semantics
remain trusted boundaries. The existing documented concurrent-reservation race
is not solved by this connector work. Live paid-provider conformance and OAuth
refresh are not claimed by the local integration suite.

Tag comparison uses `Crypto.ConstantTime.eq`. Its correctness is tested, but
compiled timing behavior is not kernel-proved. Successful native calls charge
their declared request cost, not measured tokens/provider usage; the settlement
proof bounds that declared charge rather than establishing a metered price.

## Verified caller integration and release handoff

The trusted app provisions named-operation warrants, independent ceilings and
run projections with graph/owner/session binding. Connection probes, model
listing/generation, writers, repository workflows and runtime callers use
native connector requests. Deprecated raw transport and `kind: inference`
entries remain refusals, not alternate execution paths.

The shared catalog and catalog-driven UI match **54 providers / 165 supported
pairs**, including Radius generation and independently grantable GitHub/GitLab
deletion. Validation agrees on component bytes, control/percent rejection,
mandatory fields and exact-versus-recursive semantics. Real selector
correspondence remains broker/runtime enforced, not merely UI checked.
CalDAV invitation, Slack file read and Signal/WhatsApp history/edit/delete stay
unadvertised. Drive creation means an empty named file, not an arbitrary-content
sink; JMAP mailbox calls require an actual account/API endpoint. Unsupported
shapes remain refusals rather than latent caller workflow promises.

App-to-writer-to-broker-to-runtime handoffs are verified. Deployment migration
history, separated vault ACLs and coordinated sibling releases/pins remain
operator/release-owner responsibilities, not unfinished adapter code.

## Reproducing verification

From the local override workspace (all four sibling dependencies resolve to
their working trees):

```sh
LIAISON_ROOT_KEY=0000000000000000000000000000000000000000000000000000000000000000 lake build liaison:exe +LiaisonTest
```

The fixed key is an isolated test fixture, not a deployment credential. Build
the compiled Lode caller fixture, then run the broker cases:

```sh
# From liaison/LiaisonTest/integration/client:
lake build writerClient
```

```sh
PATH=/opt/homebrew/opt/postgresql@16/bin:$PATH python3 LiaisonTest/integration/connectors.py --temp-root /var/folders/83/bq8tqpf57rv3ff7ftlnmh6k80000gp/T/opencode
```

Use the directory containing the actual `postgres` server, not Homebrew libpq's
client-only `initdb`. On Linux, use the equivalent installed PostgreSQL bin path.
The script creates a disposable private cluster, starts the compiled broker and
local vault/upstream HTTP fixtures, exercises HMAC and SQL holds/audit, and cleans
everything on exit. All keys are generated fixture data; no paid provider is
contacted. Catalog drift is checked against `--catalog` (the sibling Rust file
by default), with zero unsupported advertised pairs. Every supported
provider/operation pair has a real-handler positive fixture and narrow-grant
coverage where safe, with zero upstream requests on policy/warrant/payload
denials. Relationship failures can perform bounded metadata reads but never
perform the rejected write or disclose unvalidated message data.

The independent broker suite passes **655 real HTTP cases**, including writer,
checkout and publication. Coordinated local verification also reports **99 API
tests, 24 browser groups and 69 compiled-runtime cases**, including trusted
provisioning, source/tool recovery, declaration-bound revocation, shared-owner
requests and complete app handoffs. See the writer contract for supported modes,
native boundaries and reproducible verification; these fixtures are not claims
of live paid-provider or cross-platform container conformance.
