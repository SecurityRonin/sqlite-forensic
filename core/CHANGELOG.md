# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.10.3](https://github.com/SecurityRonin/sqlite-forensic/compare/sqlite-core-v0.10.2...sqlite-core-v0.10.3) - 2026-07-25

### Fixed

- cap overflow-payload alloc against untrusted payload_len (fuzz alloc bomb)
- free_regions guards lo>=hi (clamp panicked on inverted range; fuzz-found panic-free violation)
# Changelog

All notable changes to `sqlite-core` are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).
Releases are prepared by [release-plz](https://release-plz.dev/) from conventional commits.
