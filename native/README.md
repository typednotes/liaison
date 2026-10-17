# In-process paired messaging

Liaison loads Rust `cdylib` adapters. No CLI, shell command, Java daemon, Go
service or public adapter listener is used. The common C shim loads only absolute
operator-configured paths with `RTLD_LOCAL`. The pure Lean SDK does not link Rust.

Build each adapter separately (their SQLite ABI versions differ):

```sh
cargo build --locked --release --manifest-path native/signal/Cargo.toml
cargo build --locked --release --manifest-path native/whatsapp/Cargo.toml
lake build liaison
```

Set `LIAISON_SIGNAL_LIBRARY` and `LIAISON_WHATSAPP_LIBRARY` to the absolute paths
of the resulting `.so` files (`.dylib` on macOS). Set `LIAISON_PAIRED_DIR` to an
existing, broker-owned, persistent directory. It must be on an **encrypted
volume**: Signal uses SQLCipher and the shared inbox is XChaCha20-Poly1305
encrypted with a per-connection vault key, but WhatsApp's protocol SQLite store
uses the library's ordinary SQLite backend. Do not put this directory on an
ephemeral serverless filesystem. Shared inbox/lock files use 0600; per-connection
directories use 0700. Protocol-store file creation is library-owned inside them.
An exclusive per-device file lock refuses concurrent ownership across replicas;
route requests for a device to its owning broker. There is a 128-active-device
process limit. The HTTP health check `/_health/paired` reports loadable adapters
without opening provider connections. Library absence fails closed.

The app writes a random key as `{"kind":"paired_device",
"base_url":"https://paired.typednotes.invalid","key":"64 lowercase hex digits"}`.
That sentinel is never an HTTP destination or a fallback origin. Device stores
are confined to `provider/org/credential-owner/connection` below the configured
root. Only the broker reads the key. An adapter starts/restores lazily on an
authorized control or message call; the app's scheduled inbox polling keeps
active project sources running after a broker restart.

## Contracts

`POST /v0/device` uses the existing signed warrant envelope with a connector call,
empty resource and exactly `"{}"` payload. Its closed control actions are
`device.pair:{owner}`, `device.status:{owner}`, `device.unlink:{owner}`. The
owner suffix is part of the HMAC-bound action; run IDs remain UUIDs for ledger
and audit compatibility. The private Lean `Control` witness carries the
verified reservation, provider/action/connection/owner binding and empty-input
proofs. Only the authenticated app's owner/admin flow mints these warrants;
they are not notebook operations or part of permission presets. Ordinary cell
warrants cannot become device-control warrants through attenuation. Control
does not grant or widen messaging permissions. Attempts retain broker audit and
reservation handling, at declared cost zero.

`messages.read` and `messages.send` remain four-ceiling connector effects.
Private `Paired.Plan` and `Execution` witnesses carry the `Prepared` resource
evidence and bind it to the signed provider/action/connection. Read uses
`[sender]` or `[sender,peer]`, optional canonical decimal-string `after`; send
uses `[sender,peer]`, payload `{"text":"..."}` (1–4000 characters). Sender
must equal the persisted paired identity. Reads filter the exact peer before
serializing. Cursors are local delivery sequence numbers, not remote history
promises. Pages contain at most 100 messages; the encrypted inbox retains at
most 2048 messages/8 MiB of text. Delivery can replay; the app deduplicates before
advancing its per-selector cursor. This is bounded recent delivery, not a full
archive. Oversized messages/pages refuse instead of silently truncating.

This release exposes **direct text only**. Media, group management, contact
inventory, edits, deletion and arbitrary history retrieval are not advertised.
Signal peers are canonical account IDs; synchronized contact phone numbers can
also be resolved for sending. WhatsApp peers are phone digits or direct LIDs.
The libraries perform required protocol synchronization, encryption and receipts
inside this trusted boundary, not as extra cell-authorized actions.

Unlink first closes app grants, cancels the actor, requests remote device
unlinking, and erases local state only after its protocol tasks stop. Signal
unlink failure keeps keys for retry. WhatsApp's library logout is best-effort;
the user can also remove Typednotes from the phone's Linked devices screen.
Tenant/account deletion invokes the same cleanup before vault/SQL deletion.

The Lean kernel proves authority and signed-plan bindings, not the protocol
implementations, C ABI, cryptography, filesystem isolation, provider behavior or
deployment volume encryption. These remain explicit trusted boundaries.

## Dependencies and verification

Signal pins Presage commit `07815e7e2f649396f2fdd8f44c722688b612c854`
(AGPL-3.0-only), and WhatsApp pins `whatsapp-rust` 0.7.0 (MIT). Preserve their
license notices and provide the corresponding source as required when hosting
or distributing them. Each dependency closure has its own checked-in lockfile.

```sh
LIAISON_TEST_TEMP=/approved/scratch cargo test --manifest-path native/paired/Cargo.toml
cargo check --locked --manifest-path native/signal/Cargo.toml
cargo check --locked --manifest-path native/whatsapp/Cargo.toml
LIAISON_ROOT_KEY=<test-key> lake test
python3 native/check_libraries.py --temp-root /approved/scratch \
  --signal /absolute/path/libliaison_signal.so --whatsapp /absolute/path/libliaison_whatsapp.so
```

Live QR scans, send/receive interoperability and revocation on real phones are
separate from these local checks and require user-controlled accounts.
