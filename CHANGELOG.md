# Changelog

## v0.0.21 — 2026-11-16

### Changed

- Remove the mandatory external release-review gate while retaining candidate validation, CI, and immutable release-tag protections.
- Accept an `Unreleased` heading before the newest version during release validation.

## Unreleased

### Added

- Add HTTP policy conditions to the policy model and gateway config rendering:
  exact case-insensitive methods (including `ANY`), path globs with documented
  `*`, `?`, character-class, and whole-segment `**` syntax, ordered
  `name=value` query requirements with value globs, and an optional protocol.
- Match conditional denies before allows in `policy.Check`; a conditional rule
  never matches a non-HTTP flow or a request with no HTTP metadata.
- Parse a bounded HTTP/1.x request line into method, path, and query matching
  metadata without reading a body.
- Add a clone-mode Git daemon forwarder that allocates and returns a held IPv4
  loopback port for the fixed guest endpoint `192.168.127.3:9418`.
- Reconcile port forwards by local address, protocol, and guest endpoint; keep
  managed Git forwarding during ordinary port updates and withdraw it only by
  its recorded ownership tuple.
- Pass optional operation and request correlation ids (`opID`/`reqID`) through
  policy provisioning so gvproxy can stamp audit lines with the daemon's
  operation identity. `policy.Policy` gains `OpID`/`ReqID`, and
  `Manager.SetCorrelation` records the most recent ids for a sandbox handle so a
  per-revision policy push that omits them still stamps the last known pair.
  Ids are evidence-only: values outside `^[A-Za-z0-9_-]{1,64}$` are omitted from
  the rendered config rather than sanitized, and they never influence policy
  enforcement.

### Security and limitations

- HTTP conditions are validated and rendered, but live gvproxy enforcement is
  not verified in this module; `policy.Check` is a local matcher. CONNECT
  enforcement also remains unimplemented.
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
