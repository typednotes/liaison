# Liaison v0.7.0 — native paired messaging

Coordinated with Typednotes **v0.12.0**, app migration **0016**, and the existing
stateless Lun/Linen contracts. The pure `Liaison.Wire` envelope remains compatible;
existing operations and legacy messaging transports retain their previous behavior.

## Changes

- Load Presage and `whatsapp-rust` adapters as native Rust libraries inside the
  broker. There are no provider CLI subprocesses or new public adapter listeners.
- Add `messages.read` for bounded direct-text paired-device delivery. Reads and
  sends retain organization/connection/cell/warrant intersection, exact sender/
  peer selectors and byte ceilings. Private Lean `Plan`/`Execution` witnesses
  preserve authorization and signed-provider/action/connection correspondence.
- Add `paired_device` vault credentials and a separate `/v0/device` provisioning
  route. Private `Control` witnesses bind signed owner-qualified actions, the
  connection and empty selector/payload/context. These actions are absent from
  notebook operation catalogs and presets.
- Persist isolated device state under the broker-owned storage root, encrypt the
  shared recent-delivery inbox and use SQLCipher for Signal. Device locks prevent
  overlapping workers; restart/unlink restores before remote logout and waits
  for protocol tasks before deleting local state.
- Package both real adapters in the broker image and add native build/load,
  storage/lifecycle and compiled broker/C/Rust tests to CI.

## Verification

Lean tests/proofs and the broker executable build passed. The real HTTP suite
passed **701 cases**, with **54 providers / 167 supported pairs** and zero catalog
gaps. Five native storage/lifecycle tests and simultaneous offline loading of
both real protocol libraries passed, including Signal SQLCipher verification.
Real Typednotes callers and compiled Lun handlers reached the native adapters;
independent narrowing denied calls before credential use.

Actual phone pairing/send/receive and the Linux image were not exercised locally.
Protocol implementations, native ABI, crypto/storage, process/filesystem isolation
and remote provider behavior remain trusted boundaries, alongside the Lean-proved
authority model. See [the full adapter contract](../native/README.md), including
dependency licenses and source obligations.

## Publication and deployment

The release commit/tag are prepared locally; publication is the user's action.
Publish main and v0.7.0 together, verify exact-commit main CI and image publication,
then deploy this broker before enabling the matching app's QR path. Configure
`LIAISON_PAIRED_DIR` on **persistent encrypted storage** owned by the broker,
and route each device to its owning worker. An ephemeral serverless filesystem
does not provide the required device-key persistence. App v0.12.0 additionally
requires its append-only migration 0016 before serving.
