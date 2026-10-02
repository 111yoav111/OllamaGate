# Security

OllamaGate puts a local Ollama server on the internet, so it is built to fail closed.
This file describes the threat model and what is (and isn't) protected. It is
updated after every build phase.

## Threat model

**Attacker:** anyone on the internet who can reach the listening port, including
someone who knows the address, scans for Ollama, or sniffs the network.

**Assets:** the models and GPU time, the prompts/responses of paired devices,
and the host machine itself.

## What's protected

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
  text, never as Rich/Textual markup (toasts included), with control characters
  escaped and long values cut *before* escaping. Logs, including uvicorn's, go
  to an in-memory buffer shown on the dashboard, never to the terminal under
  the TUI. Revoke, rotate, suspend, kick, lockdown and quit (also Ctrl+Q) ask
  for confirmation, and the default button is "No". If the TUI ever crashes,
  the server keeps running headless instead of dropping every device. Redraws
  are throttled to once a second and limited to the visible tab, so a request
  flood can't starve the proxy through the shared event loop.
- **Lockdown** (`Ctrl+L` / `ollamagate lockdown on`) rejects every request
  before authentication - `/healthz` included, so the host doesn't even look
  alive - cuts all streams and refuses pairing while keeping all devices.
- **Runtime settings** are limited to a small allowlist (public URL, pairing
  TTL/attempts, and the concurrency / model-management defaults for devices
  paired from then on - existing devices keep their own limits), are
  validated like the config file, audited, and never written to disk.
  `server.public_url` must be `https://host[:port]` (plain `http` only for
  loopback) with no path, query, fragment or credentials, since it is embedded
  in pairing links and QR codes.
- **Per-device limits.** Token quotas (day/month), requests per minute and
  concurrency are enforced before anything reaches Ollama (`429` +
  `Retry-After`); `num_ctx` (when requested), `num_predict` / `max_tokens`
  (always, and never more than the tokens left in a quota) and `keep_alive`
  are clamped server-side; models outside a device's allowlist are refused and
  hidden from listings (`/api/tags`, `/api/ps`, `/v1/models`; failing closed).
  Because Ollama's Go JSON decoder matches keys case-insensitively, request
  keys at the levels it decodes into structs must be plain lowercase - so
  `"MODEL"` or `"ſtream"` can't smuggle a second value past the checks.
  Token usage comes from Ollama's own counts, and interrupted streams are
  charged an estimate so quotas can't be dodged by disconnecting early. A
  global priority queue (with a wait limit) keeps one device from
  monopolising Ollama.
- **Auto-bans.** Repeated failed logins or pairing attempts ban the client
  (fail2ban-style, doubling on repeat, IPv6 per /64). Only *distinct* wrong
  bearer tokens / pairing codes count: anonymous requests don't (any website
  can make its visitors send those, which would turn bans into a weapon), and
  neither does a device retrying its old token after a restart. Banned clients
  are refused before any routing, `/healthz` included - unless the request
  carries a valid device credential, so paired devices behind the same NAT as
  an attacker keep working. Loopback is never auto-banned.
- **Browser chat (`/app`).** A browser that pairs gets an `HttpOnly`, `Secure`,
  `SameSite=Strict`, `__Host-` session cookie holding its device token. Cookie-authenticated
  requests must also carry a CSRF header (an HMAC of the token under a
  per-process key), which cross-site pages can neither read nor forge; there is
  no CORS. `/app` and its assets require a valid session (generic `401`
  otherwise), have a strict CSP with no external resources, and render model
  output as text only. Revoking the device ends the session.
- **Network modes.** In `tailscale` mode OllamaGate binds only to the Tailscale
  address (never the LAN or `0.0.0.0`), so a device needs tailnet access *and*
  a device token. In `cloudflare` mode it stays on loopback and trusts only the
  local tunnel for client IPs (so a local process could spoof client IPs - it
  would already be on your machine). Renewed certificates (Tailscale, Let's
  Encrypt) are validated on a scratch context before being loaded into the live
  one, so a half-written or mismatched renewal never breaks TLS. Only
  self-signed certificates are pinned in pairing links (CA-issued ones change
  on renewal).
- **Notifications** are opt-in, carry metadata only (device name in quotes, IP,
  reason), and are asynchronous so they can't slow requests down. Pairing and
  lockdown alerts always go out; bans (which an attacker can mass-produce) are
  summarised once a minute, and dropped messages are reported. Request URLs are
  never logged (the Telegram URL contains the bot token). ntfy topics are readable by
  anyone who knows the name: use a long random one or your own server.
- **Service install** always installs a per-user service (systemd user unit,
  LaunchAgent, or the user's Startup folder on Windows) and refuses to run as
  root/Administrator; `serve` refuses too unless given `--allow-root`. Paths in
  the systemd unit are escaped (`%`, `$`), and control characters are refused.
- **mTLS (opt-in, `tls.client_certs`).** At pairing each device also gets a
  client certificate (ECDSA P-256, `clientAuth` only) signed by a CA whose key
  exists only in process memory and is regenerated (with a new name, so
  clients don't offer stale certificates) on every start. The server keeps only
  the certificate's SHA-256; the key is sent once in the pairing response.
  Outside a pairing window the TLS handshake itself requires a certificate from
  that CA, so scanners never reach the HTTP stack; during a window a missing
  certificate is allowed so `/pair` works. Every authentication check (API,
  `/me`, `/app` cookie, ban bypass, the mid-request re-check) then requires the
  certificate that belongs to the token's device. TLS 1.3 only (1.2 sends the
  client certificate in the clear), no session tickets (a resumed session would
  skip the certificate check), and the certificate subject is random, so it
  identifies nothing. A token presented without its certificate gets the
  generic 401 and an `auth_failed reason=no_cert` audit entry (a sign the
  token leaked), but doesn't count toward bans: the caller had the right token.
  The certificate is issued before the device is created, so a failure can't
  leave a token-only device. Revoking the device revokes the certificate.
  The `.p12` uses legacy 3DES/SHA-1 wrapping because iOS and older Android
  can't import the modern format; its password is random (80 bits).
  **Limit:** the key is generated by the server and arrives in the same
  response as the token, so mTLS protects against a token that leaks *later on
  its own* (logs, config files, shoulder-surfing), not against someone who
  captured the pairing response or controls the device.
- **Host paths stay private.** Ollama names model files by absolute path in
  `/api/show` (`FROM /path/to/blob`), in `details.parent_model` of
  `/api/tags`, `/api/ps` and `/api/show`, and in raw Go error messages. Those
  responses are buffered and scrubbed: the `FROM` path becomes the model name,
  `ADAPTER` paths and `parent_model` are blanked, and an error whose message
  contains a path is replaced by a generic `upstream error`. Anything that isn't
  the JSON shape expected is replaced too (fail closed). Errors that arrive
  *inside* a 200 stream are not rewritten (the status line is already sent).
- **Supply chain.** Dependencies are pinned with hashes (`requirements.lock`) and
  audited with `pip-audit` in CI.

## Not yet protected (planned)

- TOTP for admin actions and offline GeoIP (need
  new dependencies; not added without the owner's approval).

## Known limitations

- A self-signed certificate makes browsers warn; pin the fingerprint in API
  clients or use Tailscale / a real certificate (Phase 5).
- On Windows, POSIX file modes don't apply; the key relies on the per-user
  profile directory ACLs.
- All state is in memory by design: a restart revokes every device, and also
  resets usage counters and bans.
- Token quotas are only as exact as Ollama's own counts; interrupted streams
  are estimated (about one token per streamed chunk).
- The browser chat keeps conversations only in the page (lost on reload);
  nothing is stored server-side.
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
