# OllamaGate

A secure pairing proxy that lets your own devices use the Ollama models on your
home PC over the internet. Knowing the server's address gives no access: a device
has to **pair** first (code, QR or link), then it gets its own revocable token.

> **Status:** Phase 1 (foundation) is done: config, in-memory state, self-signed
> TLS, and a streaming passthrough to Ollama with per-device bearer tokens.
> Pairing, the admin TUI and quotas come in later phases (see `ROADMAP` below).

## Requirements

- Python 3.11+
- Ollama running on the same machine, bound to loopback (`OLLAMA_HOST=127.0.0.1`)

## Install (development)

```bash
python -m venv .venv
.venv/bin/pip install -e ".[dev]"      # Windows: .venv\Scripts\pip install -e ".[dev]"
```

## Run

```bash
ollamagate serve --dev-token   # prints a throwaway device token (Phase 1 only)
curl --cacert ~/.config/ollamagate/tls/cert.pem \
     -H "Authorization: Bearer og_dev_..." https://127.0.0.1:8443/api/tags
ollamagate doctor              # checks Ollama binding, file permissions, TLS
```

On first run a self-signed ECDSA P-256 certificate is created in the config
directory (`tls/cert.pem`, `tls/key.pem`). Its SHA-256 fingerprint is printed at
startup so clients can pin it.

## Configuration

Copy `config.example.toml` to your config directory as `config.toml`:

| OS | Config dir |
|---|---|
| Linux | `~/.config/ollamagate/` |
| macOS | `~/Library/Application Support/ollamagate/` |
| Windows | `%APPDATA%\ollamagate\` |

Every value can be overridden with `OLLAMAGATE_<SECTION>__<KEY>` env vars, e.g.
`OLLAMAGATE_SERVER__PORT=9443`. `OLLAMAGATE_CONFIG_DIR` changes the directory.

## What's exposed

| Route | Auth | |
|---|---|---|
| `GET /healthz` | none | returns `ok` |
| `/api/*` | device token | Ollama native API (allowlisted endpoints only) |
| `/v1/*` | device token | OpenAI-compatible API (allowlisted endpoints only) |

Everything else returns `404`. Model management (`pull`, `push`, `delete`,
`create`, `copy`, blobs) is blocked unless granted per device.

All state is in memory: restarting the server forgets every device.

## Tests

```bash
.venv/bin/python -m pytest -q
```

## Roadmap

1. ~~Foundation~~
2. Pairing (code / QR / link) and device management CLI
3. Admin TUI
4. Quotas, rate limits, auto-bans, lockdown
5. Tailscale / Cloudflare / Let's Encrypt modes, service install, packaging
