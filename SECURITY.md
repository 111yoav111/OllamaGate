# Security

OllamaGate puts a local Ollama server on the internet, so it is built to fail closed.
This file describes the threat model and what is (and isn't) protected. It is
updated after every build phase.

## Threat model

**Attacker:** anyone on the internet who can reach the listening port, including
someone who knows the address, scans for Ollama, or sniffs the network.

**Assets:** the models and GPU time, the prompts/responses of paired devices,
and the host machine itself.

## What's protected (Phases 1-3)

- **No anonymous access.** Every route except `/healthz` (and `/pair*` while the
  owner has a pairing window open) requires a device token.
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
- **Pairing.** Closed by default; while closed every `/pair*` route is an
  ordinary `404`. A window lasts 5 minutes, pairs exactly one device and
  self-destructs after 5 wrong attempts. Code: 8 Crockford base32 characters
  (40 bits, safe given the attempt cap and TTL). QR and link: separate 128-bit
  secrets carried in the URL **fragment**, so they never reach server logs or
  `Referer` headers; the page removes them from the address bar. Only SHA-256
  hashes of the secrets are kept, compared in constant time. Claims are
  rate-limited per client (10/min; IPv6 clients per /64), must be same-origin
  JSON (no cross-site form posts), and every open/fail/success/expiry is
  audited with IP and user agent. Device names are NFKC-normalised and
  stripped of control, bidi and combining characters.
- **Attempt budgets.** 5 wrong *codes* disable the code; the unguessable QR/link
  secrets have a separate, larger budget (50 wrong guesses). This deviates
  slightly from "5 attempts destroy the window" on purpose: otherwise anyone who
  notices a window is open could kill it with five junk requests. The window is
  destroyed once every method is used up.
- **Certificate fingerprint.** Pairing links carry `fp=<sha256>` and the pairing
  page displays it. Only a client that checks the TLS certificate itself can use
  it for pinning; the pairing page cannot detect a man-in-the-middle, so compare
  the fingerprint in the browser's certificate viewer with the one on the
  server's screen if you are on an untrusted network.
- **Terminal safety.** Paths, user agents and other client-supplied text are
  stored with control characters escaped and escaped again on output, so no
  one can inject terminal escape sequences into the owner's CLI.
- **Audit log flooding.** Events that unauthenticated clients can trigger
  (failed logins, rate-limit hits) are capped at 10 per client per minute; the
  rest are only counted, so real events aren't flushed out.
- **Admin channel.** CLI administration uses a `0600` Unix socket in a `0700`
  directory (Windows: `127.0.0.1` on a random port) *and* a 256-bit secret from
  an owner-only file, compared in constant time. Replies carry an HMAC proof over
  a client nonce, so a process squatting on a stale port can't feed the CLI fake
  pairing links. The run directory must be a real, owner-owned directory (no
  symlinks). A second instance using the same config directory is refused.
  There is no remote admin API. Admin actions are audited. Device views never
  include token hashes.
- **Admin TUI.** Runs inside the server process and acts only through the same
  audited admin service as the CLI; it has no network surface. Client-supplied
  text (device names, user agents, paths, model names) is rendered as literal
  text, never as Rich/Textual markup, with control characters escaped. Logs go
  to an in-memory buffer shown on the dashboard, never to the terminal under
  the TUI. Revoke, rotate, lockdown and quit ask for confirmation, and the
  default button is "No".
- **Lockdown** (`Ctrl+L` / `ollamagate lockdown on`) rejects every proxied
  request before authentication, cuts all streams and refuses pairing while
  keeping all devices.
- **Runtime settings** are limited to a small allowlist (public URL, pairing
  TTL/attempts, default concurrency, default model-management grant), are
  validated like the config file, audited, and never written to disk.
- **Supply chain.** Dependencies are pinned with hashes (`requirements.lock`) and
  audited with `pip-audit` in CI.

## Not yet protected (planned)

- Brute-force auto-bans, per-device rate limits and token quotas (Phase 4).
  Until then, repeated failed logins are only recorded in the audit log.
- Browser cookie sessions and CSRF tokens arrive with the `/app` chat UI
  (Phase 4); until then browsers only display the token for use in apps.
- Ollama error bodies and `/api/show` output are passed through unchanged and
  may reveal local file paths of model files to paired devices.

## Known limitations

- A self-signed certificate makes browsers warn; pin the fingerprint in API
  clients or use Tailscale / a real certificate (Phase 5).
- On Windows, POSIX file modes don't apply; the key relies on the per-user
  profile directory ACLs.
- All state is in memory by design: a restart revokes every device.
- `ollamagate devices rotate` prints the new token on the owner's terminal; it
  must be delivered to the device out of band.
- The admin channel writes two runtime files (`run/admin.json`, `run/admin.sock`)
  that are removed on shutdown. They exist only because CLI commands need to
  reach the in-memory state of the running server.
- Anyone who can act as your OS user can administer OllamaGate (by design).
- On Windows the admin secret file relies on the per-user profile ACLs; keep the
  config directory in your profile (the default `%APPDATA%`).

## Reporting

Please report vulnerabilities privately to the repository owner rather than in a
public issue.
