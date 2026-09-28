# Security

OllamaGate puts a local Ollama server on the internet, so it is built to fail closed.
This file describes the threat model and what is (and isn't) protected. It is
updated after every build phase.

## Threat model

**Attacker:** anyone on the internet who can reach the listening port, including
someone who knows the address, scans for Ollama, or sniffs the network.

**Assets:** the models and GPU time, the prompts/responses of paired devices,
and the host machine itself.

## What's protected (Phase 1)

- **No anonymous access.** Every route except `/healthz` requires a device token;
  unknown paths return `404`, missing/wrong tokens return a generic `401` with no
  server or version details. There is no `Server` header and no OpenAPI/docs route.
- **Tokens.** 256-bit random (`secrets`), prefixed `og_dev_` so leaks are easy to
  spot. Only the SHA-256 hash is stored, and comparison is constant time. Tokens
  are never logged; the audit log records only a non-secret display prefix.
- **Ollama stays local.** The upstream URL must be loopback. `doctor` and the
  startup check warn if Ollama's port answers on any non-loopback interface.
- **Header hygiene.** Only `Content-Type` and `Accept` are forwarded to Ollama
  (never `Authorization`, cookies or `X-Forwarded-*`); only `Content-Type` comes
  back. Query strings are dropped.
- **Endpoint allowlist.** Only known inference endpoints are forwarded; model
  management is denied (`403`) unless granted per device.
- **Resource limits.** Request bodies are capped (20 MB default). Upstream
  connect/read timeouts are enforced.
- **Streams can be cut.** Client disconnects abort the upstream request, and
  revoking a device terminates its active streams immediately.
- **TLS.** TLS 1.2 minimum with forward-secret AEAD ciphers only; plain HTTP is
  refused on any non-loopback interface. Self-signed keys are written `0600`.
- **Client IPs.** `X-Forwarded-For` / `CF-Connecting-IP` are ignored unless the
  direct peer is a configured trusted proxy.
- **Security headers.** `nosniff`, `X-Frame-Options: DENY`, a `default-src 'none'`
  CSP, `no-referrer`, `no-store`, and HSTS when TLS is on.

## Not yet protected (planned)

- Brute-force auto-bans and per-device rate limits/quotas (Phase 4).
- Pairing flows and their rate limits (Phase 2).
- The `--dev-token` flag is for development only and will be removed once
  pairing exists.

## Known limitations

- A self-signed certificate makes browsers warn; pin the fingerprint in API
  clients or use Tailscale / a real certificate (Phase 5).
- On Windows, POSIX file modes don't apply; the key relies on the per-user
  profile directory ACLs.
- All state is in memory by design: a restart revokes every device.

## Reporting

Please report vulnerabilities privately to the repository owner rather than in a
public issue.
