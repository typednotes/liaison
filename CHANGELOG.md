# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this
project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases before 0.7.1 are described in their git tags and in `docs/release-*.md`.

## [Unreleased]

## [0.7.1] — 2026-11-17

### Changed

- Builds are stricter: implicit auto-bound variables are disabled, CI treats
  every compiler warning as an error, and the native Signal/WhatsApp crates must
  pass Clippy with no warnings. No behavior, wire or permission change.
