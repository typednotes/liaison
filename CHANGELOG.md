# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases before 0.7.1 are described in their git tags and in `docs/release-*.md`.

## [Unreleased]

## [0.7.3] — 2026-11-27

### Changed

- Build with Linen 4.0.0 at its [release commit](https://github.com/typednotes/linen/commit/037925bc5068c54efd86690b78b258b9c6787959).

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

[Unreleased]: https://github.com/typednotes/liaison/compare/v0.7.3...HEAD
[0.7.3]: https://github.com/typednotes/liaison/compare/v0.7.2...v0.7.3
[0.7.2]: https://github.com/typednotes/liaison/compare/v0.7.1...v0.7.2
