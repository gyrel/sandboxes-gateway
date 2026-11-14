# Changelog

## Unreleased

### Added

- Add a clone-mode Git daemon forwarder that allocates and returns a held IPv4
  loopback port for the fixed guest endpoint `192.168.127.3:9418`.
- Reconcile port forwards by local address, protocol, and guest endpoint; keep
  managed Git forwarding during ordinary port updates and withdraw it only by
  its recorded ownership tuple.

### Security and limitations

- Git forwarding requires the matching patched gvproxy build; package tests do
  not establish a live VM or host Git remote lifecycle.

## v0.0.11 — 2026-11-03

### Added

- Add a Windows gateway host layer with private named-pipe ACL checks and Windows contract tests.
- Publish a CycloneDX module SBOM as a CI artifact.

### Changed

- Normalize the Go module path to the lowercase `github.com/quoiner/sandboxes-gateway` namespace.

### Compatibility

- Windows gateway host support does not establish a Windows VM backend or end-to-end Windows sandbox support.
