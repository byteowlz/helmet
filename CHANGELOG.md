# Changelog

All notable changes to this project will be documented in this file.

## Unreleased

- Added policy engine with configurable actions (passthrough/redact/sanitize/quarantine/reject)
- Added policy output formatting (tags, line prefixes, template placeholders)
- Added scan and eval commands to helmet-cli with streaming and policy presets
- Added HuggingFace dataset playground to helmet-tui with side-by-side policy outputs
- Added eval support for HuggingFace datasets via datasets-server API
- Added support for custom/ignore patterns in configuration and external pattern files
- Updated justfile to use remote-build for build/check/test/clippy

