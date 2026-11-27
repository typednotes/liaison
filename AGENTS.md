# AGENTS.md — liaison

<!-- agents-md standard v6 — github.com/ngrislain/agents. Refresh with the agents-md skill. -->

Instructions for coding agents (Claude Code, Codex, pi, opencode, …) and for humans working on
this project. `CLAUDE.md` imports this file; edit this one.

## Project

`liaison` implements the native delegation broker
described in `typednotes/typednotes`'s `docs/services/broker.md` and
`docs/services/ledger.md`: verify a macaroon-style warrant, enforce a credit
hold, execute (or refuse) a bounded native operation, record the attempt.
The original coordinated connector release used Liaison **0.6.0**, Linen
**1.10.0**, Lode/Lun **0.3.0** and Typednotes **0.6.0**. This checkout builds
against Linen **4.1.0**. The release owner manages versions, dependency pins,
commits and tags together.

| Task | Command |
| --- | --- |
| Install | Lean toolchain from `lean-toolchain` via [elan](https://github.com/leanprover/elan); `brew install libpq pkg-config openssl` plus the macOS Command Line Tools SDK (macOS), or the `apt-get` line in `Dockerfile` (Debian/Ubuntu); `lake build` fetches the dependencies pinned in `lake-manifest.json` |
| Type-check | `lake build --wfail` (library and `liaison` executable; no root key needed) |
| Test | `LIAISON_ROOT_KEY=$(openssl rand -hex 32) lake test`; `bash ci/test-require-main-ci.sh`; `cargo test --locked --manifest-path native/paired/Cargo.toml`; `cargo clippy --locked --manifest-path native/<crate>/Cargo.toml --all-targets -- -D warnings` for `paired`, `signal`, `whatsapp` and `fixture` (also `--features whatsapp`); integration (Postgres, Rust fixtures): `python3 LiaisonTest/integration/connectors.py --temp-root <dir> …` as in the `native-contracts` job of `.github/workflows/lean_action_ci.yml` |
| Build / release | `lake build liaison`; `docker build -t liaison .`; release: a `v*.*.*` tag push triggers `.github/workflows/docker-publish.yml` (push only when explicitly requested) |
| CLI (applications) | `LIAISON_ROOT_KEY=... DATABASE_URL=... SECRETS_HOST=... lake exe liaison` (no subcommands or `--help`; configured by environment, see `README.md`) |

Before declaring a change done, run type-check, tests and lint, and report their real output.

## Permissions: what to do freely, when asked, and only after confirming

**Do freely** — reversible and local:
- read, search, and run type-checkers, tests, linters, formatters and local builds;
- edit files in the working tree within the scope of the task, including `docs/`, `reviews/`,
  `NOTES.md`, `TODO.md`, specs and tests;
- create scratch files in git-ignored directories (`output/`, `.cache/`, `tmp/`);
- read shell history and logs to spot repetitive work (see "Suggest automating repeated work").

**Only when the user asks** — do not initiate:
- `git commit`, creating or switching branches, stashing, rebasing a local branch;
- adding, removing or upgrading dependencies (propose the change and why);
- changing the machine outside the repository — global installs, dotfiles, symlinks, services,
  shell profiles — and recording each change in the manifest (see "Manifest of system changes");
- runs that are long (> ~10 min), costly (GPU, cluster, cloud, paid APIs) or touch shared
  resources (shared caches, staging data);
- clearing `.cache/` or `output/`, or forcing a cache refresh, when the content is slow or costly
  to produce again.

**Confirm explicitly every time**, even if a similar action was approved earlier — approval does
not carry over to a new context:
- `git push` only when explicitly requested by the user for that operation. Direct pushes to
  `main`/`master` are permitted only when explicitly specified. A request specifying the push
  scope (repositories, remote, branches and any tags), including an explicit command or batch,
  counts as confirmation; do not ask again for the same operation. Approval does not extend to
  later pushes. Never force-push or rewrite pushed history;
- opening, merging or closing a PR/MR, posting review comments, tagging, releasing, publishing a
  package or image;
- deploying to any environment (dev, staging, prod);
- publishing outside the repo: Confluence, Google Docs/Sheets, Slack, email, issue trackers;
- deleting or overwriting anything not recreated by a command in this repo: branches, remote
  resources, datasets, buckets, tables, experiment outputs;
- changing infrastructure, permissions, secrets or credentials.

**Never**: commit secrets or customer data; skip hooks (`--no-verify`); rewrite pushed history;
weaken a type-check, a test or a lint rule to make it pass; claim a check passed without running it.

## Repository layout and the documents it keeps

| Path | Audience | Content | Keep in sync with |
| --- | --- | --- | --- |
| `docs/` | humans, high level | project, architecture, algorithms, code map — a hierarchy of Markdown files illustrated with SVG figures | the code, every change |
| `README.md` (root and per package) | users and contributors, close to the code | install, usage, examples, how the code is organised | the code it sits next to |
| `SPEC.md` (per module/package) | humans first | the contract the code must fulfil | types and tests check it |
| `scripts/` | contributors | repository-maintenance helpers, including `rebase-on-main.sh` | developer workflow and tests |
| `reviews/` (git-ignored) | reviewers | reviews of commits and PRs: explanation, SVG figures, suggested comments and fixes | — (dated snapshots) |
| `output/` (git-ignored) | users of the application | large, binary or reproducible outputs of runs | — (regenerated by the CLI) |
| `.cache/` (git-ignored) | the code | cached results of slow downloads and computations | — (safe to delete) |
| `CHANGELOG.md` | users of a released artifact | one entry per version, newest on top | every release |
| `LOGBOOK.md` | humans re-running experiments | one entry per experiment, newest on top, with repeatability info | every experiment |
| `TODO.md` | everyone | planned but not executed work | when planning or finishing work |
| `NOTES.md` (anywhere) | humans and agents | things worth knowing that are not definitive documentation | when something surprising is learned |

### `docs/` — high-level documentation

- A hierarchy with an index at `docs/README.md` linking every page. Typical sections:
  `docs/project/` (goals, scope, decisions, roadmap), `docs/architecture/` (components, data
  flow, deployment), `docs/algorithms/` (methods, math, complexity, trade-offs), `docs/code/`
  (module map, key types, extension points).
- Illustrate with SVG figures stored next to the page that uses them (`docs/architecture/figures/`).
  SVG is the editable source: hand-written or generated by a committed script, legible at page
  width, in light and dark backgrounds, with a `<title>` and `<desc>`. Do not commit rendered PNGs.
- `docs/` explains *why* and *how it fits together*; `README.md` files explain *how to use and
  modify* the code next to them. Link rather than repeat; one canonical page per subject.
- Keep `docs/` in sync: a change to behaviour, architecture, an algorithm or a public interface
  updates the affected pages and figures **in the same change**. Separate measured results from
  expectations and proposals.

### `scripts/` — repository maintenance

- All runnable helpers follow the same interface standard as the application CLI:
  a colourful, structured terminal UI (plain when piped, `TERM=dumb` or `NO_COLOR` is set),
  self-documenting `--help` with examples and effective defaults plus their sources, and
  actionable errors. Missing arguments use safe defaults or prompt interactively on a TTY;
  non-interactive runs never hang waiting for input and identify any required flag explicitly.
- Keep editable defaults in a TOML file, normally `scripts/defaults.toml`, grouped by command.
  If a script manages multiple runs/sessions, organise their defaults under named TOML tables
  and select them explicitly with `--run` / `--session`; do not duplicate scripts or hard-code
  session settings. Document precedence: flags > environment > selected run/session >
  command defaults > built-in fallbacks. Help shows the resolved values and their sources.
- State-changing helpers show the resolved plan, prompt before applying it and support `--yes`
  for non-interactive use and `--dry-run` for a non-mutating preview. Defaults never bypass
  confirmation or the Permissions section.
- Git repositories keep an executable `scripts/rebase-on-main.sh`: fast-forward local `main`
  from `origin/main`, return to the original branch, and rebase it onto the updated `main`.
  Allow an explicit remote override; on `main`, only fast-forward it. In a monorepo, share one
  helper at the Git root rather than adding a copy per package.
- Provide `--help` and a non-mutating `--dry-run`. Refuse a dirty working tree (including
  untracked files), detached HEAD, and unfinished Git operations. Never stash, reset, discard
  changes or push automatically. If updating `main` fails, return to the original branch;
  if rebasing conflicts, stop there and explain `git rebase --continue` / `--abort`.
- Document how to invoke it and test it against temporary local repositories, never the working
  checkout. Preserve existing helpers rather than overwriting them blindly. Creating the helper
  is not permission to execute a rebase: the Permissions section still applies.

### `SPEC.md` — one contract per module/package

- Every module, package or component with a public surface has a `SPEC.md` beside its code: a short,
  human-readable statement of what it guarantees — purpose, inputs/outputs, invariants, error
  behaviour, performance bounds, what it explicitly does not do.
- The spec is the source of truth. Types encode as much of it as the language allows; tests check
  the rest. When code and spec disagree, fix one of them deliberately and say which.
- Number the clauses (`S1`, `S2`, …) so tests and reviews can cite them.

### `reviews/` — reviews of commits and PRs

One directory per review, `reviews/YYYY-MM-DD-<slug>/`, with a `README.md` (summary, walkthrough,
findings ranked by severity, suggested comments ready to paste, suggested fixes as diffs) and
`figures/*.svg`. A video only when the user asks for one. `reviews/` is **git-ignored**: reviews
are local working documents, not project history. Posting them anywhere requires confirmation
(see Permissions).

### `output/` — generated results, git-ignored

What an application produces that is large, not text (images, videos, models, archives, binary
tables) or reproducible from the code and its inputs goes to `output/`, which is **git-ignored**.
Organise it by command and run (`output/<command>/<run-id>/`), write next to each result what
produced it (command, parameters, commit), and make the location a CLI option with `output/` as
the default. Anything worth keeping is either reproducible from the repo (then it stays in
`output/`) or published deliberately (a release, a bucket, a document — see Permissions); small,
reviewed, hand-curated text results may be committed elsewhere, e.g. in `docs/`.

### `.cache/` — caching slow objects, git-ignored

Anything slow or costly to obtain — a large download, a long computation, a remote query — is
cached under `.cache/` (**git-ignored**), with the most idiomatic library of the language: in
Python `joblib.Memory` for function results, Parquet (or JSON for small, human-readable data) for
tables keyed by their parameters; elsewhere the equivalent (`cacache`/file caches in JS, `cached`
or file caches in Rust, …).
- The cache key covers everything that determines the result: parameters, input versions or
  checksums, and a code version. Cache only results that cannot change for a given key — never
  "the latest" of something live (pin a date, a version or a completed time window instead).
- Deleting `.cache/` must always be safe: it costs time, never correctness. Downloads are
  verified (checksum or size) before being cached.
- The CLI offers `--no-cache` and `--refresh`, and the location is configurable (config file or
  environment variable), with `.cache/` as the default.

### `CHANGELOG.md` — only if the project is released as a versioned artifact

Library, image, executable, model: one section per version, newest on top, following
[Keep a Changelog](https://keepachangelog.com) and [SemVer](https://semver.org). Unreleased changes
accumulate under `## [Unreleased]`. Bump the version and the changelog in the same change.

### `LOGBOOK.md` — only if the project runs experiments

One entry per experiment, newest on top, readable by a human who was not there: date, question,
setup, result (with numbers), conclusion, and how to repeat it — commit hash, exact command,
parameters, seeds, data snapshot, links to outputs and dashboards. Failed and inconclusive
experiments are logged too.

### `TODO.md` and `NOTES.md`

- `TODO.md`: planned but not executed work, as a checklist grouped by theme, with enough context to
  pick an item up cold. Remove items when done (the history is in git and the changelog).
- `NOTES.md`: anywhere something should be known by a human or an agent and is not definitive
  documentation — gotchas, findings, dead ends, external constraints, open questions. Promote a note
  to `docs/` or a `README.md` once it becomes definitive.

## Code

### Types: use the strongest standard checking the language offers, maximally

- Use the standard type-checker of the language/framework in its strictest practical mode, run it in
  CI, and keep it at zero errors. In this project: Lean 4 (toolchain `leanprover/lean4:v4.36.0`, pinned in `lean-toolchain`), type-checked by `lake build`, with every theorem checked by Lean's kernel. `autoImplicit` stays on (Lean's default: it only automates implicit binders, which are still fully checked), and CI builds with `--wfail` (`leanprover/lean-action@v1` `build-args`): warnings, including `declaration uses 'sorry'`, fail the build. Run `lake build --wfail` locally. "No `partial def`" remains a project convention (see Project-specific notes), not a compiler-enforced setting. The Rust crates under `native/` (`paired`, `signal`, `whatsapp`, `fixture` with and without its `whatsapp` feature) are built and tested in CI with `cargo build --locked` / `cargo test --locked` and linted with `cargo clippy --locked --all-targets -- -D warnings` (toolchain 1.97.1): clippy warnings fail CI.
- Make illegal states unrepresentable: precise types, enums/sum types over strings and flags, new
  types for identifiers and units, immutable data by default. Avoid `Any`, casts and ignores; when
  one is unavoidable, scope it narrowly and justify it in a comment.

### Modularity and docstrings

- Organise the code in cohesive modules with explicit, minimal public interfaces and acyclic
  dependencies. One canonical implementation per concern; delete dead paths rather than keep them.
- Every public module, class and function has a docstring written for a human user: what it is
  for, how to call it, what it returns or raises, and an example when usage is not obvious. Explain
  *why* in comments, not *what*.

### One CLI per application

An application project (anything run rather than imported) exposes **a single command-line entry
point** with a short name, e.g. `uv run liaison <command>` in Python (a `[project.scripts]` entry),
`npx liaison`, `cargo run --bin liaison`. Every operation — run, train, evaluate, serve, inspect,
publish — is a subcommand of it, not a loose script. Repository-maintenance helpers in
`scripts/` are a narrow exception, not alternative application entry points.

- **Self-documented**: `liaison`, `liaison --help` and `liaison <command> --help` at every level list
  the commands, arguments, defaults and an example. Running a command with no arguments prints help
  rather than doing something surprising.
- **No dead ends on missing arguments**: each argument either has a default or is asked for
  interactively. Defaults live preferably in a TOML config (`liaison.toml`, or `[tool.liaison]` in
  `pyproject.toml`), with hard-coded fallbacks in the code; precedence is
  flag > environment variable > config file > hard-coded default, and `--help` shows the effective
  value and where it came from.
- Interactive prompts only when stdin is a TTY; otherwise (CI, agents, pipes) fail fast with a message
  naming the missing flag. Destructive or outward-facing commands ask for confirmation and accept
  `--yes` and `--dry-run`.
- **Rich, colourful terminal UI** preferably: coloured and structured help, tables, progress bars,
  spinners, syntax-highlighted output and interactive prompts/selections (Python: `rich` +
  `rich-argparse`, Typer, Textual for full TUIs; JS: `@clack/prompts`, `ink`; Rust: `clap` with
  colours, `indicatif`, `ratatui`; Go: Charm's `bubbletea`/`lipgloss`). Degrade gracefully: plain
  output when not a TTY, and honour `NO_COLOR`.
- Large, binary or reproducible results go to `output/` (overridable with `--output`); slow
  intermediate results are cached in `.cache/` (`--no-cache`, `--refresh`) — see above.
- Data goes to stdout, logs and progress to stderr; exit codes are non-zero on failure. Offer
  `--json` where the output is consumed by other programs.

### Tests

- Tests do two jobs: **illustrate** every unit and higher-level functionality working (they are
  executable examples — readable, named after the behaviour), and **check** that the code fulfils its
  `SPEC.md` (cite clause ids, e.g. `test_s3_rejects_empty_window`).
- Cover unit, integration and end-to-end levels as relevant; prefer property-based tests for
  invariants. Every bug fix comes with a regression test. Tests are deterministic and fast by default;
  slow or networked tests are marked and opt-in.

## Working style

- Keep changes focused on the task; mention unrelated issues in `TODO.md` or `NOTES.md` instead of
  fixing them silently.
- Update code, types, tests, `SPEC.md`, `docs/`, `README.md`, `CHANGELOG.md` and figures together.
- Report faithfully: what was run, what passed, what failed, what was skipped.

### Manifest of system changes

Changes to the machine outside the repository are recorded so they can be tracked and reverted:
installing or upgrading tools globally (`brew`, `uv tool`, `pipx`, `npm -g`, `cargo install`),
editing dotfiles and configuration under `$HOME`, creating symlinks, services, launch agents or
cron jobs, changing shell profiles or system settings. (Changes inside the repo are tracked by
git; cloud resources by their own infrastructure-as-code.)
- **Where**: the XDG state directory, `${XDG_STATE_HOME:-~/.local/state}/<tool>/` — an
  application uses its own name; an agent acting by hand uses `agents/`, appending one JSON
  object per line to `manifest.jsonl`:
  `{"time": "…", "project": "…", "command": "…", "changes": ["…"], "revert": "…"}`.
- **What**: the exact command, every path or setting it changed, and what reverting needs — the
  inverse command, the backup path or the previous value. Back up a file before overwriting it.
- **Applications** that make such changes (installers, linkers, setup commands) write the
  manifest themselves and offer `history` and `revert` subcommands. A revert undoes newest first,
  skips an action whose path changed since, and is itself recorded.

### Undo log for mutating actions

An application whose actions mutate state — files, configuration, links, services, databases,
anything not regenerated by a command — keeps an **undo log**: one record per mutation, enough to
revert it.
- **At the scope of what changed**, so the log sits next to the state it can restore:

  | Scope of the mutation | Undo log |
  | --- | --- |
  | system-wide (`/etc`, `/usr/local`, system services) | `/var/lib/<app>/undo.jsonl` (Linux), `/Library/Application Support/<app>/undo.jsonl` (macOS) |
  | user-wide (`$HOME`, dotfiles, user services) | `${XDG_STATE_HOME:-~/.local/state}/<app>/undo.jsonl` |
  | project or folder (files under a working directory) | `<folder>/.<app>/undo.jsonl`, git-ignored — not in `.cache/`, which must stay safe to delete |

  An action spanning several scopes writes a record in each.
- **A record** holds: id, time, the command and run it belongs to, the target (path, key, row),
  its state before (a backup path, the previous value, or "absent") and after, and the inverse
  operation. Back up anything overwritten or deleted, next to the log (`backups/<id>/`).
- **Write-ahead**: write the record *before* mutating and mark it done after, so an interrupted
  action can still be undone or completed.
- **Undo** (`<cli> undo [id|run]`, default: the latest run): newest first, only if the target
  is still in its recorded "after" state — otherwise skip and say why; the undo is itself
  logged. Backups are kept until the user prunes them (`<cli> undo --prune …`).

### Suggest automating repeated work

Look out for tasks the user does by hand again and again, and propose to automate them.
- **Where to look**: the current session (the same commands or edits requested several times);
  the shell history (`~/.zsh_history`, `~/.bash_history`), for commands touching this project;
  CI and run logs; `LOGBOOK.md`, `NOTES.md` and `README.md` steps that are long manual sequences;
  `git log` (recurring chore commits, repeated fix-ups).
- **History and logs are sensitive**: read them locally and only for this purpose, extract
  command *patterns*, and never copy secrets, tokens, hostnames of customers or personal data into
  files, messages or suggestions.
- **Suggest, don't impose**: at a natural break, propose briefly what is repeated, how often, the
  automation (preferably a subcommand of the project's CLI; otherwise a script, a git hook, a CI
  job, a scheduled job or an agent skill) and what it saves. Implement it only if the user agrees;
  note accepted-but-deferred ideas in `TODO.md`, and do not repeat a suggestion the user declined.

## Project-specific notes

### Overrides of the standard rules above

These project rules take precedence over the Permissions section above.

- **Push only when explicitly requested by the user**, following the push-specific
  confirmation rules in Permissions above. Commits are fine when asked for.

### Layout

- `Liaison/Warrant/Caveat.lean` — the `Caveat` inductive and `permits`
  (ported from `broker.md` §4 near-verbatim).
- `Liaison/Warrant/Core.lean` — `Warrant`, `attenuate`, `attenuate_monotone`.
- `Liaison/Warrant/Tag.lean` — the HMAC-SHA256 tag chain (`mintTag`,
  `recomputeTag`, `verifyTag`). **Deviation from `broker.md`:** `orgId` is
  folded into `s₀` alongside the warrant id (`mintingInput`), so a warrant
  cannot be re-attached to a different org without invalidating its tag.
  `broker.md` does not fold `orgId` into the tag at all. Documented here and
  in the module's own doc comment.
  Verification compares tags with `Crypto.ConstantTime.eq`; the native HMAC
  implementation and machine-code timing behavior remain trusted boundaries.
- `Liaison/Auth.lean` — `Authorized`, `authorize` (verify tag, then check
  `permits`, in that order — an unverified warrant's caveats are not
  trustworthy input).
- `Liaison/Budget.lean` — `Reserved`, `BoundedUsage`, `withReservation`, and
  credit-hold SQL (ported from `ledger.md` §7's conditional-insert pattern).
- `Liaison/Clock.lean` — `nowUnixSeconds`, liaison's own wall clock (via
  `linen`'s `Data.Time.getCurrentTime` → `Std.Time.Timestamp.now`; no FFI).
- `Liaison/Egress/Credential.lean` — the typed credential of
  `typednotes/typednotes`'s `docs/connections.md` §3.3 (`CredentialAuth`:
  `bearer`/`header`/`oauth` (issuer `google`/`dropbox`/`gitlab`)/`s3`/
  `azureSas`; `Credential.parse`, `setHeaderNames`, `refreshed`). No
  `Repr`/`ToString` on credentials, deliberately (`OAuthIssuer` has one: it
  is not secret).
- `Liaison/Egress/Policy.lean` — pure request policy (`connections.md` §5):
  `checkCallerHeaders`, `urlWithinBase`/`checkUrl`/
  `parseTarget`, `reservedQueryKeys`/`checkCallerQuery`/`appendQuery` (the
  SAS a credential appends), `needsRefresh`.
- `Liaison/Egress/Secrets.lean` — `typednotes/secrets` HTTP client
  (`SecretsConfig` with `userpass` login + cached token or static token,
  `fetchCredential`, `writeCredential`) and independent connection, organization
  and warrant-keyed run policy reads on every native call. The same logical
  paths work in the OS keychain and OpenBao KV v2. See `docs/secrets.md`.
- `Liaison/Egress/OAuth.lean` — refresh for Google, Dropbox, GitLab and Microsoft
  (`OAuthClients`, one optional client per issuer from
  `{GOOGLE,DROPBOX,GITLAB,MICROSOFT}_CLIENT_ID`/`_SECRET`; token endpoints fixed per
  issuer; `refreshForm`, `parseTokenResponse`, `refreshToken`).
- `Liaison/Egress/Refresh.lean` and `Inventory.lean` — OAuth write-back and
  refresh coordination, credential discovery, and the operator status page.
- `Liaison/Egress/S3.lean` — SigV4 for `s3` credentials over `linen`'s
  `Crypto.SigV4.sign` (`s3Canonical`, `s3AuthHeaders`).
- `Liaison/Egress/Provider.lean` — `EgressConfig`, native `callConnector`, private
  credential use, scoped relationship preflights and bounded native execution.
  Deprecated URL/method and `kind: inference` entries are structured refusals,
  not alternative execution paths.
- `Liaison/Egress/Connector.lean` — strict policy schemas, supported operations,
  native request derivation and private `Prepared` witnesses. Read
  `docs/connector-permissions.md` before changing a connector contract.
- `Liaison/Egress/Inference.lean`, `Repository.lean`, `GitPack.lean` — bounded
  writer protocols and local function-reference authorization; payload-indexed
  publication witnesses and immutable tree/CAS transport. The exact caller
  contract and native trusted boundaries are in `docs/native-writer.md`.
  `LiaisonTest/integration/client` builds a real Lode SDK/Workspace fixture;
  `native_writer.py` runs it through the compiled broker and actual local Git.
- `Liaison/Audit.lean` — `recordAttempt`, writing to `audit_log`.
- `sql/0001_audit_log.sql` — the `audit_log` table, the one table `liaison`
  owns (`credit_holds`/`credit_ledger` are `ledger`'s).
  `typednotes-infra` reads `sql/*.sql` from GitHub at the release tag and
  applies it as an `infra` `postgresMigrations` history; `liaison` itself
  never migrates. Shipped migrations are append-only — add a new
  `sql/NNNN_*.sql` file instead of editing one.
- `Liaison/Wire.lean` — **the wire format, and liaison's Lean SDK**: the
  `POST /v0/egress` body (`Body`, `Body.parse`/`decode`/`encode`, the
  warrant/caveat/call codecs), `validAccount`/`accountMatchesResource`,
  `Request.ofWarrant` (the request a warrant determines, with
  `Request.ofWarrant_unique`), `Body.connector`, typed `NativeContext`, and
  the replies (`Response`, `encodeResponse`, `encodeRefusal`, `Reply`,
  `decodeReply`). Pure, and importing only the warrant *types*: a client
  (`lun`) imports it without linking the HMAC, Postgres or egress code.
  Keep it that way — nothing here may import `Warrant.Tag`, `Budget`,
  `Audit`, `Egress.*` or `Server`. Its format is pinned literally by
  `LiaisonTest/Liaison/WireTest.lean`'s `golden`; changing a field is a
  wire change for every client (and for `typednotes`'s Rust caller, which
  has its own copy).
- `Liaison/Server.lean` — the HTTP boundary: decodes the body with
  `Liaison.Wire`, uses the broker clock, calls `authorize` → `withReservation` →
  `callConnector`, records the attempt and shapes the response.
- `Main.lean` — reads `LIAISON_ROOT_KEY`, `DATABASE_URL`,
  `SECRETS_HOST`/`SECRETS_PORT`/`SECRETS_INSECURE`, `SECRETS_USERNAME`+
  `SECRETS_PASSWORD` (or the fallback `SECRETS_TOKEN`), the optional
  `{GOOGLE,DROPBOX,GITLAB,MICROSOFT}_CLIENT_ID`/`_CLIENT_SECRET`, `LIAISON_PORT`
  (default `8080`),
  then serves `Liaison.application` (`POST /v0/egress`, `GET /_health`).

### Running tests

```
LIAISON_ROOT_KEY=$(openssl rand -hex 32) lake test
```

The env var is required: `RootKey`'s only constructor is `RootKey.fromEnv`,
and Lean has no `setenv` — an env-sourced value cannot be driven end to end
from *inside* a `#eval` (the same limitation `linen`'s own
`LinenTest/Linen/Cloud/CredentialsTest.lean` documents). `LiaisonTest/Liaison/Warrant/TagTest.lean`
and `LiaisonTest/Liaison/AuthTest.lean` are the two files that need it; every
other test file is pure `#guard`s or signature-pinning `example`s and builds
without it.

`lake build` (no target) builds everything, including the `liaison`
executable, and does not require the env var (the executable itself only
calls `RootKey.fromEnv` at process start, not at build time).

### Guarantees, revocation and remaining limits

`Authorized` carries verified HMAC, explicit bindings, caveat permission and
organization equality. `Reserved` carries the real hold; `BoundedUsage` proves
settlement is bounded by the reservation. Native `Prepared`/`Resolved`,
payload-indexed `AuthorizedPlan`, function-reference witnesses and `CheckedSse`
retain the evidence their execution paths consume. Resource intersection,
attenuation, secondary-selector, function-name and local byte/arithmetic proofs
are checked by Lean's kernel. Tests additionally verify parser, HTTP/SQL, FFI and
remote-protocol correspondence; they do not replace those proofs.

Every call reloads separate hot organization/connection ceilings and a mandatory
run projection. The trusted app closes ceilings and deletes tracked projections
before acknowledging policy/declaration changes. A still-valid HMAC therefore
does not restore revoked authority. This is independent policy/projection
revocation, **not a separate warrant-ID/tag blacklist**. In-flight calls use
their fetched snapshots, and expiry is checked at the HTTP authorization boundary.

The following are actual limits, not completed native workflow blockers:

- **Outside this release:** rate limiter, circuit breaker, OpenTelemetry,
  human-in-the-loop policy and a per-token blacklist. Native model routing and
  provider-shaped writer protocols are implemented through `callConnector`.
- **Concurrent reservation isolation remains unresolved.** The conditional
  reserve statement can overspend under concurrent `READ COMMITTED` requests;
  it does not take a per-org lock or set `SERIALIZABLE`. No Lean theorem proves
  no-double-spend. The shared ledger contract must supply the isolation fix.
- **Paid provider conformance and live OAuth refresh are untested.** The
  optional `LiaisonTest/integration/connectors.py` suite exercises compiled
  HTTP, real HMAC and disposable Postgres with local vault/upstream fixtures,
  including native SigV4/SAS, hot-policy/projection revocation, holds and audit.
  Supported shapes and native trusted boundaries are explicit in
  `docs/connector-permissions.md`.
- **Native calls charge declared cost, not measured usage.** `BoundedUsage`
  carries the settlement inequality; there is no token/usage-based cost model.
- **`Denial` does not distinguish infra failure from a real denial**:
  `reserveHold` in `Liaison/Budget.lean` returns
  `.error .budgetUnavailable` both when the balance is insufficient and when
  the Postgres call itself failed. No separate `Denial` variant exists for
  "the database is down." The same code is used when an exception escapes
  `withReservation` (a failed settle/release): `Server.lean` catches it and
  audits `budget_unavailable` — even if the provider call itself happened
  (its response is then not returned).
- **The wire format (`Liaison/Wire.lean`)** is the one `connections.md` §5
  fixes for requests, but the success envelope (hex body) is still liaison's
  own design. The codecs and actual HTTP/Postgres connector path are tested
  locally. Typednotes' Rust client keeps a matching native format; migration of
  app/writer/runtime callers is complete. HTTP expiry uses the broker clock.
- **OAuth refresh coordination is process-local.** Run one broker per set of
  refreshable credentials. OpenBao conditional writes protect storage against
  concurrent edits. Rotation recovery after a failed write can require
  reconnecting if the broker exits before persisting the new token.
- **S3 requests sign only `host`, `x-amz-content-sha256`, `x-amz-date`**;
  native headers (e.g. `content-type`) and the credential's static headers
  are sent unsigned, so a static `x-amz-*` header in an `s3` credential would
  be rejected by S3.

The coordinated local handoffs pass: **99 API tests, 24 browser groups, 655 real
broker cases and 69 real compiled-runtime cases**, plus Lean proofs/tests and
executable links. The catalog has **54 providers / 165 supported pairs** and
zero unsupported advertised operations. Remote API honesty, vault ACLs, SQL
isolation/durability, container/process isolation, cryptographic/native FFI and
socket/TLS behavior remain explicit trusted boundaries. These local fixtures do
not claim paid-provider, live OAuth or Linux container conformance.

### Releasing

For a new release commit, the user can push main and its version tag together.
The publisher waits up to two hours for that exact commit's latest push-to-main
CI success; all existing main CI jobs remain required. Failed/cancelled CI,
invalid evidence, API errors and timeout stop publication. Existing tags retain
their original workflows and must not be moved to adopt this behavior.

### Deviations from the plan/docs, and why

- **`connections.md` §5 caller-header list, extended**: besides the listed
  names, `transfer-encoding` and `connection` are refused
  (`Policy.forbiddenHeaderNames`) — both would let a caller desynchronise the
  framing (`Content-Length`/`Connection: close`) `linen`'s HTTP client writes.
  Malformed header names/values (non-token names, CR/LF in values) are
  `header_denied` too.
- **URL rule, hardened**: besides the string-prefix rule, the URL must parse
  as an RFC 3986 `http(s)` URI with no userinfo, no fragment and no `.`/`..`
  segment (encoded or not), and its scheme/host/port must equal the base's —
  otherwise `url_denied`. A trailing `/` on a stored `base_url` is ignored.
- **OAuth write-back path**: the refreshed credential is written back to
  the path it was read from (`thirdparty/{provider}/{account}`), e.g.
  `thirdparty/gdrive/{account}` for every `google_oauth` credential the app
  writes, `thirdparty/gitlab/{account}` for `gitlab_oauth`.
- **GitLab rotates refresh tokens**: every refresh invalidates the stored
  one, so a failed write-back (or two concurrent refreshes) leaves the
  connection unusable until it is reconnected. Google and Dropbox keep
  theirs.
- **Native transport is broker-owned.** Callers select a named operation and
  scoped components, never a method/URL/header. Fixed Dropbox content and
  GitLab same-host Git mappings are explicit native adapters, not unrestricted
  origin grants. Deprecated raw calls remain denied.
- **Connection/operation checks precede reservation; live authority and owner
  checks precede credential use.** Native account/connection and signed-operation
  mismatch denies before a hold. Inside the hold, the broker loads policies,
  constructs authority and validates scoped resources, payload/context/tools
  and derived transport;
  refusals release the hold.

- **`Tag.lean` folds `orgId` into the root HMAC input** (`s₀ = HMAC(rootKey,
  id⧺orgId)`), which `broker.md`'s tag chain does not do. This is a
  deliberate hardening: without it, a warrant's tag would still verify after
  changing its `orgId` in transit, since `orgId` never entered the HMAC input
  at all. Pinned by `LiaisonTest/Liaison/Warrant/TagTest.lean`'s "Tamper 3"
  case.
