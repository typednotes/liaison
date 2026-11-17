# Liaison v0.7.1 — strict type checking and native lints

Released on the user's request: agent instructions and strict type checking only;
no user-visible change. The 0.7.0 native paired-messaging contract, the pure
`Liaison.Wire` envelope and every connector operation, permission and preset are
unchanged.

## Changes

- `lakefile.lean` turns `autoImplicit` and `relaxedAutoImplicit` off for the
  package, and both CI lean-action builds use `--wfail`: any warning, including
  `declaration uses 'sorry'`, fails the build. Three declarations gained the
  type binders they had implicitly auto-bound (`Liaison.Wire`'s `orErr` and
  `findSome?_of_permits`, a test helper in `ConnectorTest`); no statement changed.
- CI runs `cargo clippy --locked --all-targets -- -D warnings` on the native
  crates it already builds: `paired`, `signal`, `whatsapp`, and `fixture` with
  and without its `whatsapp` feature. Four findings were fixed without behavior
  change: a needless `return` (`paired`), a collapsible `if let` and two owned
  string comparisons (`whatsapp`).
- `AGENTS.md` follows the agents-md standard v3; the "never run `git push`"
  override remains.

## Verification

Locally (macOS, Rust 1.97.1): `lake build --wfail`, `lake build --wfail
LiaisonTest` and `lake test` (with a random `LIAISON_ROOT_KEY`) passed with no
warnings; the offline release-gate regressions (50 cases) passed; clippy with
`-D warnings` was clean on all five crate configurations; `cargo test` on
`native/paired` passed (5 tests); and `native/check_libraries.py` loaded both
real adapters and passed their refusal/offline/teardown checks.

Not run locally: the `native-contracts` job (`LiaisonTest/integration/connectors.py`
with PostgreSQL and the writer SDK fixture), which needs sibling checkouts at
its pinned CI refs; Linux clippy runs in CI.

## Publication

The release commit and annotated `v0.7.1` tag are prepared locally; publication
is the user's action. Push main and `v0.7.1` together; the image publisher waits
for that exact commit's main CI. Existing tags remain immutable.
