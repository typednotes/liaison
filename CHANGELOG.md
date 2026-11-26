# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases before 0.7.1 are described in their git tags and in `docs/release-*.md`.

## [Unreleased]

## [0.8.0] — 2026-11-26

### Added

- Periodic connector OAuth refresh alongside refresh before use.
- A password-protected credential status page with expiry and refresh counts.
- OS keychain and OpenBao KV v2 credential storage alongside typednotes/secrets.

### Changed

- Upgrade to Linen 3.0.0. Lake links the native shims through imports,
  and the Docker runtime includes the PostgreSQL, zlib and keychain libraries.
- `autoImplicit` is back to Lean's default (on): it automates implicit binders,
  which are still fully checked, so it is not a weakening (agents-md standard v4).
  Warnings still fail the build (`lake build --wfail`).

## [0.7.1] — 2026-11-17

### Changed

- Builds are stricter: implicit auto-bound variables are disabled, CI treats
  every compiler warning as an error, and the native Signal/WhatsApp crates must
  pass Clippy with no warnings. No behavior, wire or permission change.
