# sandboxes-gateway

<img src="docs/assets/rheic-shark.png" alt="Rheic shark logo" width="180">


## Import path migration

The canonical Go module path is now `github.com/rheic/sandboxes-gateway` (previously `github.com/quoiner/sandboxes-gateway`). Update imports and `go.mod` requirements when moving to a release that includes this change. The old module path is not kept as a compatibility alias.

Status: pre-alpha.

Host network policy gateway. The experimental gvproxy integration supports
IPv4 TCP/UDP CIDR rules and domain-only TCP rules with DNS and TLS SNI checks.
Domain UDP rules require the experimental QUIC capability; without it they are
rejected. Domain denies overlapping a direct IP allow are also rejected.
Experimental IPv6 policy and guest loopback forwarding require an explicit
capability flag; QUIC policy requires its own explicit flag. The default keeps
all of them disabled. HTTP method, path, and query conditions are modeled,
validated, and rendered; live gvproxy HTTP enforcement and CONNECT enforcement
are not verified. Audit failure behavior has not been fully validated.

Policy DNS queries use the configured upstream; a hostname in that configuration
may require host DNS for bootstrap. Use a numeric upstream address to avoid that
lookup. `policy.Check` evaluates rules locally and does not prove that a DNS
binding exists or that a subsequent TLS connection will pass SNI checks.

The `registryauth` package provides host-side parsing, scoped token exchange,
and restricted transport primitives. These primitives do not authenticate a
sandbox, enforce guest egress, or enable guest registry pulls on their own.

## Policy HTTP conditions

A `policy.Rule` may carry HTTP conditions in addition to its domain or CIDR
selector and optional protocol. The model is additive: a rule with no HTTP
conditions keeps matching every transport selected by its domain or CIDR.

- `Methods` is an exact, case-insensitive list of `GET`, `HEAD`, `POST`, `PUT`,
  `PATCH`, `DELETE`, `OPTIONS`, `CONNECT`, or `TRACE`. `ANY` matches every
  method while keeping the rule HTTP-only. An empty list means no method
  restriction. Empty entries and unknown methods are rejected.
- `Path` is an absolute path glob. `*` matches any run of characters inside one
  segment, `?` matches one character, `[abc]` and `[!abc]` are character
  classes, and `**` as a whole segment matches zero or more segments. The
  default is `/**`, which matches every path. A path must start with `/`;
  query strings, fragments, whitespace, escapes, and `..` segments are
  rejected.
- `Query` is an ordered list of `name=value` requirements. The name is exact;
  the value may be a glob using the same single-segment syntax. Every listed
  parameter must be present, but extra request parameters are allowed. A
  repeated name matches when any of its values matches.
- `Protocol` remains optional. HTTP conditions are evaluated only for TCP
  requests; a UDP flow or a request with no HTTP metadata never matches a
  conditional rule.

Parse conditions with `policy.ParseMethods`, `policy.ParsePath`,
`policy.ParseQuery`, and `policy.ParseQueryList`, or validate a rule with
`policy.Rule.ValidateHTTPConditions`. Invalid conditions are rejected at
validation time; `policy.Check` and the gateway config writer fail closed
instead of widening a conditional rule.

`policy.ParseHTTPRequestHead` parses the bounded request line of an HTTP/1.x
request and returns `Method`, `Path`, `RawQuery`, and parsed `Query` metadata
for `policy.Check`. It reads no body and caps the inspected head at
`policy.MaxHTTPRequestHeadBytes`.

Deny rules are evaluated before allow rules, so a matching conditional deny
wins over an allow. `policy.Check` is a local matcher: it does not prove that a
DNS binding exists or that the pinned gvproxy datapath enforces HTTP
conditions. That live datapath behavior remains unverified.

## Boundaries

- separate process from the daemon;
- default deny;
- every deny needs a positive control in tests;
- unsupported paths are explicitly disabled, not silently allowed.


## Gateway manager

`Manager` starts one pinned `gvproxy` process per sandbox with:

- dedicated Unixgram socket;
- default-deny egress policy;
- audit log path;
- policy reload rewrites the config, sends SIGHUP, and verifies the patched gvproxy's appended `egress policy reloaded revision=N` log acknowledgement; a missing acknowledgement stops the gateway and fails closed;
- TCP port forwards;
- `SetGitDaemon` allocates an assigned IPv4 loopback port for the fixed guest upload-pack endpoint, verifies the full tuple, and returns the port; disabling it removes only the process-owned mapping;
- deterministic MAC and nerdbox network annotations.

The manager requires a supervisor executable and a patched gvproxy supporting
the owner-lease flag. Without either component gateway startup fails closed.
The matching daemon entry point and gvproxy build patch must be deployed
together; this module alone does not supply a runnable supervisor binary.

Windows work adds a private bearer-token file for the TCP services API, a
kill-on-close process Job Object, and policy reload over the authenticated
services endpoint with an exact revision ACK. `Manager.Start` still fails
closed on Windows: QEMU's network socket is TCP without endpoint
authentication. A bearer token on the separate services API does not
authenticate packet-channel clients.

Current tests cover config rendering, MAC derivation, validation, and safe stop.
An opt-in local test starts and stops a supplied patched gvproxy; it does not
test a VM or establish policy enforcement. The Git daemon API's unit tests use
a fake services endpoint; live VM reachability and host Git remote ownership
remain unverified. The opt-in live gateway test is not part of CI.
