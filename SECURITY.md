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

- **No anonymous access.** Every route except `/healthz` requires a device token.
  Requests to `/api/*` and `/v1/*` without a valid token get a generic `401`
  (no hint whether the path exists); every other path returns `404`. There is no
  `Server` header, no OpenAPI/docs route, and no trailing-slash redirects.
- **Tokens.** 256-bit random (`secrets`), prefixed `og_dev_` so leaks are easy to
  spot. Only the SHA-256 hash is stored, and comparison is constant time. Tokens
  are never written to logs or the audit log.
- **Revocation is immediate.** A device's requests are tracked from the moment
  they are authenticated - including while the request body is still uploading -
  and revoking, suspending, rotating (without grace) or expiring a device aborts
  them. The credential is re-checked after the body arrives, before anything is
  sent to Ollama. A killed stream is cut even if the client has stopped reading.
- **Ollama stays local.** The upstream URL must be loopback. `doctor` and the
  startup check warn if Ollama's port answers on any non-loopback interface.
- **Header hygiene.** Only `Content-Type` and `Accept` are forwarded to Ollama
  (never `Authorization`, cookies or `X-Forwarded-*`); only `Content-Type` comes
  back. Query strings are dropped.
- **Endpoint allowlist.** Only known inference endpoints are forwarded (exact
  method + path; model names reject `.`/`..` segments); model management is
  denied (`403`) unless granted per device.
- **Resource limits.** Request headers must arrive within 15 s and bodies within
  120 s; bodies are capped at 20 MB; at most 512 connections in total and 32 per
  IP; each device gets a small number of concurrent requests (default 2). Upstream
  connect/read timeouts are enforced, and the upstream connection pool is bounded.
- **Clean shutdown.** Active streams are terminated as soon as shutdown starts.
- **TLS.** TLS 1.2 minimum with forward-secret AEAD ciphers only; plain HTTP is
  refused on any non-loopback interface. Self-signed keys are written `0600`.
- **Client IPs.** `X-Forwarded-For` / `CF-Connecting-IP` are ignored unless the
  direct peer is a configured trusted proxy (all `X-Forwarded-For` headers are
  considered, walking from the right).
- **Security headers.** `nosniff`, `X-Frame-Options: DENY`, a `default-src 'none'`
  CSP, `no-referrer`, `no-store`, and HSTS when TLS is on.
- **Audit log.** Bounded ring buffer; long fields (paths, user agents) are truncated.
- **Supply chain.** Dependencies are pinned with hashes (`requirements.lock`) and
  audited with `pip-audit` in CI.

## Not yet protected (planned)

- Brute-force auto-bans, per-device rate limits and token quotas (Phase 4).
  Until then, repeated failed logins are only recorded in the audit log.
- Pairing flows and their rate limits (Phase 2).
- The `--dev-token` flag (loopback only, 24 h expiry) prints a token to the
  terminal; it exists for development and will be removed once pairing exists.
- Ollama error bodies and `/api/show` output are passed through unchanged and
  may reveal local file paths of model files to paired devices.

## Known limitations

- A self-signed certificate makes browsers warn; pin the fingerprint in API
  clients or use Tailscale / a real certificate (Phase 5).
- On Windows, POSIX file modes don't apply; the key relies on the per-user
  profile directory ACLs.
- All state is in memory by design: a restart revokes every device.

## Reporting

Please report vulnerabilities privately to the repository owner rather than in a
public issue.
