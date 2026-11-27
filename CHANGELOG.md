# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases before 0.7.1 are described in their git tags and in `docs/release-*.md`.

## [Unreleased]

## [0.8.2] — 2026-11-27

### Changed

- Build with [Linen 5.0.0](https://github.com/typednotes/linen/releases/tag/v5.0.0).

## [0.8.1] — 2026-11-27

### Changed

- Update the Linen dependency to [4.1.0](https://github.com/typednotes/linen/releases/tag/v4.1.0).

## [0.8.0] — 2026-11-26

### Added

- Periodic connector OAuth refresh alongside refresh before use.
- A password-protected credential status page with expiry and refresh counts.
- OS keychain and OpenBao KV v2 credential storage alongside typednotes/secrets.

### Changed

- Package Linen's keychain shim and its runtime dependency in the Docker image.

## [0.7.2] — 2026-11-26

### Changed

- Upgrade to Linen 3.0.0. Lake links the PostgreSQL and zlib shims through
  imports, and the Docker runtime includes both shared libraries.
- Restored Lean's default implicit binders. Lean still checks their types,
  and warnings still fail the build (`lake build --wfail`).

## [0.7.1] — 2026-11-17

### Changed

- Builds are stricter: implicit auto-bound variables are disabled, CI treats
  every compiler warning as an error, and the native Signal/WhatsApp crates must
  pass Clippy with no warnings. No behavior, wire or permission change.
