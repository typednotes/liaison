# Bounded writer and repository native modes

The broker implements the current URL-free Lode requests in
`Lode.Model`, `Lode.Liaison` and `Lode.Workspace`, including conversation/tool
replay and checkout/publication. These modes consume the same verified warrant,
real SQL reservation and four independently owned ceilings as other connectors.
The coordinated release line is Liaison 0.6.0 / Linen 1.10.0, with Lode/Lun
0.3.0 and Typednotes 0.6.0; versions, pins and tags are release-owner managed.

## Trusted run extensions

The existing run projection remains `account`, `cell`, `warrant`. It additionally
accepts these **strict optional server-owned fields**, never caller payload grants:

```json
{
  "conversation": {
    "sessionId": "actual-persisted-lode-session",
    "allowedTools": ["read", "todo"]
  },
  "publication": {
    "branch": "main",
    "root": ["typednotes", "graph-slug"]
  }
}
```

The session is distinct from the warrant's run ID. `allowedTools` contains at
most 128 unique plain function names (64 characters each). Both fields and their
nested fields reject unknown keys. Removing a tool also removes its replay
authority: a fresh request containing that retired function's definition or
historical call is denied, even if a previous run permitted it. Lode's
`Model.boundedHistory` recovers after the retired tool's latest exchange, removes
its call/result references and retains the user task. Still-permitted opaque
replay remains intact. This recovery is exercised with real Chat/Radius broker
requests and cannot restore a retired tool or falsify the initiator.

`publication.root` is relative to the selected repository. The actual repository
is fixed by the primary resource and all four capabilities; publication cannot
use this relative root as authority on another repository. The root must prefix
the primary project's components, and every full changed selector must separately
pass the four-ceiling check. The app's current provisioning fields match these
schemas exactly.

## Conversation context and function metadata

`call.context` is now part of the pure `Liaison.Wire.ConnectorCall` SDK:

```json
{"sessionId":"actual-persisted-lode-session","initiator":"agent","client":"typednotes-lode"}
```

It is accepted only on `inference.generate`, is bounded to plain session IDs,
requires initiator `user` or `agent`, requires the truthful fixed client, and must
match the trusted run's conversation session. Context cannot provide arbitrary
headers. Broker-derived headers identify `typednotes-lode`; OpenCode/Go receive
`x-opencode-session`, and Copilot receives `x-initiator` and the supported
`x-intent: conversation-panel`. Authentication stays solely credential-owned.

The native selector fixes the model; provider and connection remain signed and
policy-bound. Lode's existing model stripping is required: a payload `model`
field is refused, even if its text happens to equal the selected model.

Supported bounded model bodies:

* **Messages**: inline user/assistant text, text blocks, ephemeral caching,
  allowlisted local function definitions, `tool_use` and paired `tool_result`,
  signed `thinking` and `redacted_thinking`. Thinking replay is preserved, not
  rewritten. Tools expose name/description/inline input schema only.
* **Chat**: inline system/user/assistant/tool text, local `type:function`
  definitions, assistant function calls with object JSON arguments, paired
  `tool_call_id` results and `reasoning_content` replay.
* **Responses**: inline text/message items, local function definitions with
  `strict:false`, `function_call` and matched `function_call_output`, full inline
  reasoning items with encrypted content and ordered message replay. The broker
  forces `store:false`; the only permitted include is
  `reasoning.encrypted_content`. `item_reference`, provider-hosted tools, remote
  retrieval and previous stored response selectors are refused.
* **Gemini**: inline text/thought parts, signed `thoughtSignature`, local
  `functionDeclarations`, `functionCall` and name/ID-corresponding
  `functionResponse`. Sequential calls without native IDs are resolved
  unambiguously; an anonymous ambiguous result is refused. No file/URL retrieval
  part is accepted.
* **Radius Pi**: broker-owned `POST /messages`, `accept:text/event-stream`,
  model derived from the selector, bounded options/session and normalized
  system/user/assistant/tool-result transcript. Local `toolsAdded`, text/thinking/
  tool signatures and function references are validated. Replay provider/API/
  model fields must match Radius/Pi/the selected model; options session must
  match `call.context`. Root model/routing overrides are still refused.

Every declared **and replayed** function name requires current trusted run
authority. IDs are unique within a replay, every result resolves to a prior
call, and unanswered calls are refused. At most 2,048 transcript messages/items
and 4,096 function references are accepted. Function schemas permit only local
fragment references, never remote or dynamic schema lookup. Byte ceilings bound
both payload and generated native body; output token limits are at most 128,000.
These are metadata for Lode's local tools, not instructions for broker-side
shell/IO execution.

Pi responses are buffered and parser-bounded, with at most 65,536 SSE lines and
4,096 content indices. Start/delta/end correspondence, named local tools,
matching tool IDs/names, complete blocks and a recognized terminal event are
required. Error, truncated, duplicate, mismatched or post-terminal data is
refused before relay. The privately constructed `CheckedSse` carries its
validation evidence; successful relay preserves the stream for Lode's Pi parser.

## Repository views

Only GitHub/GitLab with the unambiguous `[owner,repo]` selector are supported.
No archives, credentialed clone URLs, user-selected methods, raw Git objects,
packs or GraphQL programs can be supplied.

* `repositories.read`, `[owner,repo]`, `{"view":"branch","ref":"branch"}`:
  returns the native immutable branch head (`commit.sha` / `commit.id`). Branch
  strings cannot contain traversal/revision-expression/control syntax.
* Same operation/resource, `{"view":"tree","ref":"40-character-commit"}`:
  returns complete normalized `{"truncated":false,"tree":[...]}` entries. It
  requires **recursive** read authority at that repository in every ceiling;
  an exact repository grant does not authorize a whole-tree inventory. GitHub
  resolves the commit's tree, rejects truncation and fetches the immutable tree.
  GitLab uses fixed, bounded page numbers and authoritative next-page metadata,
  rejects ambiguous/incomplete pagination, and bounds cumulative page bytes.
* Same operation/resource,
  `{"view":"ancestry","ref":"commit","branch":"branch"}`: validates native
  compare/merge-base correspondence, returning GitHub `behind`/`identical` or
  GitLab `id == ref`. An unrelated commit is refused.
* Per-file `repositories.read` keeps the existing base64 native transport at
  `[owner,repo,...file-components]`, with immutable checkout references. GitHub
  reads blobs rather than following `/contents` symlinks.

Trees are bounded to 10,000 entries. Symlinks, submodules, invalid/malformed
hashes, bookkeeping paths, duplicate or case-alias paths are refused. Only
regular modes `100644`/`100755` and directory entries are admitted. Nested
GitLab namespaces and SHA-256 repositories remain explicit unsupported shapes.

## Atomic commit mode

The migrated Workspace schema is accepted unchanged:

```json
{"view":"commit","branch":"main","expectedHead":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
 "message":"Writer change","changes":[
   {"resource":["Main.lean"],"contents":"UTF-8 text","mode":"100644","delete":false}
 ]}
```

The main operation is `repositories.write`; the primary selector is
`[owner,repo,...project-components]`. Every relative change becomes a full
selector by appending it to this same primary selector. A second project,
bookkeeping path, traversal, symlink, duplicate path, path-parent conflict or
replacement of an unselected file/directory is refused. There are at most 1,000
changes and a 16-KiB message, within the existing byte bounds. Executable mode is
preserved and independently selectable for regular files.

**Deletion is an independently grantable named operation.** A deleted change
requires `repositories.delete` on its full selector in all four ceilings, with
`contents:null`, `mode:"000000"`, `delete:true`. Write permission never implies
delete permission. A deletion-only commit can use a `repositories.delete`
warrant and requires no write grant. A mixed commit uses `repositories.write`
but its trusted projection also carries independently granted, scoped delete
authority for removed paths. The shared catalog exposes deletion as an explicit
advanced grant and excludes it from the read/write preset.

The broker resolves the observed head, checks it equals `expectedHead`, builds
the exact patched regular-file tree while preserving unselected files and then
publishes with a native atomic head condition:

* **GitHub** uses fixed REST Git Data tree/commit creation followed by the
  broker-fixed GraphQL `updateRefs` mutation with `beforeOid:expectedHead` and
  `force:false`. The patched tree hash is independently reconstructed locally
  and checked against the provider's returned tree; the commit's sole parent
  and tree must match. The mutation variables are derived; no caller-selected
  GraphQL text is accepted. Plain REST `PATCH /git/refs` is insufficient to
  protect an exact head against a concurrent rollback and is not used.
* **GitLab** REST commits provide no exact branch-head CAS. The broker generates
  a bounded SHA-1 Git pack from this validated plan and uses the fixed same-host
  smart-HTTP repository route, authenticating internally with the stored GitLab
  token. Ref discovery must advertise the exact expected old head and
  `report-status`. A single update command carries the expected old OID, new
  commit and one bound branch; native receive-pack performs the atomic CAS.
  Only exact successful unpack/ref status is accepted. There is no raw pack or
  ref endpoint exposed to callers, no redirect following and no git-push process.

Both return `{"commit":"immutable-new-commit"}`. Stale heads and concurrent
rewinds fail closed. GitLab's protocol route is a fixed provider-owned origin
mapping (`/api/v4` to the same host's repository route), not generic HTTP scope
widening. Zlib pack compression uses Linen's existing FFI; the consumer link
names the macOS SDK stub or Linux zlib library, and the image requires `zlib1g`.

`AuthorizedPlan` is payload-indexed and privately constructed. It carries the
exact parse derivation, trusted branch/root and every changed selector's
operation permission, including independent deletions. Credentialed publication
consumes this witness. `Prepared.function_allowed` and the local tool reference
theorems establish allowlist membership; `Prepared` and `Resolved` retain the
existing native derivation/origin/byte witnesses. Remote API honesty, Git ref CAS,
SHA-1 identity and zlib/socket/TLS correspondence remain explicit native trusted
boundaries, additionally exercised against actual local Git.

Hot organization/connection ceilings and mandatory run projections are reloaded
on every call. The app closes gates and removes tracked projections before
acknowledging policy/declaration changes; a valid HMAC cannot revive that
authority. In-flight calls retain their fetched snapshot. An independent
token-ID/tag blacklist is not implemented. `verifyTag` uses
`Crypto.ConstantTime.eq`; compiled cryptographic/timing behavior remains a native
trusted boundary. Billing retains declared per-operation cost rather than token
or provider-usage metering, with `BoundedUsage` proving the settlement bound.

## Runtime-local grant groups

PostgreSQL and graph secrets are local Lun handlers, not raw broker HTTP/SQL
transports. Their ceilings use the same strict schema and disjoint paths:

* PostgreSQL: provider `postgres`, connection `compute`, account
  `{execution-user}/compute`; operations `rows.select/insert/update/delete`,
  resources `[bound-schema,table]` (or a scoped schema descendant root).
* Graph secrets: provider `vault`, connection `{graph}`, account
  `{execution-user}/{graph}`; operations
  `secrets.describe/read/write/list`, with relative graph-secret components.

Provision organization policy at
`connector-policy/{org}/{provider}/{connection}`, connection ceiling at
`thirdparty/{provider}/{execution-user}/{connection}/permissions`, and fresh
run projections at `connector-authority/{org}/{run}/{warrant}`. The execution
user must remain distinct from a shared third-party credential owner. Actual
compute credentials stay at `compute/{org}/{execution-user}`; graph values stay
under `graph/{org}/{graph}`. Lun owns role/host/database/schema and graph-path
correspondence, typed SQL AST execution, fresh policy checks and recovery.

`policyOperations` recognizes those local families without advertising remote
adapters. A request to the broker with raw SQL or a graph-secret selector is
refused before credential reads; there is no local-effect raw-call fallback.

## Verified caller integration

The app's writer projection fields match, Radius/Pi production generation is
enabled, and GitHub/GitLab deletion is independently provisioned. Writer opening
obtains the actual persisted session ID before the app binds model/repository
projections and starts generation. Native SDK requests preserve model stripping,
truthful context, monotone tool narrowing and the local runtime grant paths above.
No model/protocol or repository-mode migration remains outstanding.

Coordinated real fixtures cover app provisioning, compiled Lode/Workspace
checkout, model tool execution, Lake checks, refusal of ungranted deletion,
exact-file advanced deletion, atomic native publication, Lun adoption and source
type constraints. Chat/Radius recovery after tool retirement is also exercised.
These handoffs use the actual broker and runtime, not only fake-peer tests.

Reproduce locally:

```sh
# Local override workspace:
LIAISON_ROOT_KEY=0000000000000000000000000000000000000000000000000000000000000000 lake build liaison:exe +LiaisonTest +Lode.Model +Lode.Workspace
# liaison/LiaisonTest/integration/client:
lake build writerClient
# liaison:
PATH=/opt/homebrew/opt/postgresql@16/bin:$PATH python3 LiaisonTest/integration/connectors.py --temp-root "$APPROVED_TEMP_ROOT"
```

The fixture compiles and executes real Lode SDK, model serializers/reply parsers
and Workspace code. Its broker handler, HMAC, vault HTTP and Postgres hold/audit
path are real; provider APIs are local controlled fixtures. Git fixtures use
actual local object/index/commit/ref and receive-pack processing, including
rollback races, executable files, independently permitted deletions, mixed
commits and unchanged files outside the project. No provider payment, personal
key or remote git push is involved. Positive tests include all five model
protocols with reasoning/signature and multiple function-result continuations,
OpenCode/Go/Copilot headers, both checkouts and both atomic publication modes.
Negative tests cover policy/session/tool/name/replay/byte/selector bounds,
malformed SSE, exact-only tree grants, unsafe entries, stale heads, concurrent
rewinds, ungranted deletion and raw local-effect requests.

Local macOS executable and full Lean tests pass. The Linux linking recipe/image
dependency is updated but a Linux container build is not claimed by these local
tests. With the coordinated native handoffs verified, versions, commits, tags
and dependency pins are release-owner managed; deployment migrations and
separated vault ACLs remain operator responsibilities.

Current local verification: full Lean tests and both executable links pass;
**655 real broker HTTP cases**, **54 providers / 165 supported pairs**, with
zero unsupported advertised pairs. The coordinated report additionally records
**99 API tests, 24 browser groups and 69 real compiled-runtime cases**, with
complete native app/writer/broker/runtime handoffs. Provider endpoints remain
local controlled fixtures; live provider behavior is a trusted conformance
boundary rather than a kernel-proved property.
