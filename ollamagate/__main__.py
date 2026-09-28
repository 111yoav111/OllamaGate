"""Command-line entry point."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Optional

import typer

from .config import ConfigError, load_config

cli = typer.Typer(add_completion=False, no_args_is_help=True, help="OllamaGate - secure pairing proxy for Ollama")

ConfigOption = typer.Option(None, "--config", "-c", help="Path to config.toml", exists=True, dir_okay=False)


def _load(config_path: Optional[Path]):
    try:
        return load_config(config_path)
    except ConfigError as exc:
        typer.secho(f"Config error: {exc}", fg=typer.colors.RED, err=True)
        raise typer.Exit(2)


@cli.command()
def serve(
    config_path: Optional[Path] = ConfigOption,
    no_tui: bool = typer.Option(False, "--no-tui", help="Run headless (no admin TUI)"),
    dev_token: bool = typer.Option(
        False, "--dev-token", help="Create a throwaway device and print its token (development only)"
    ),
) -> None:
    """Run the proxy server."""
    from . import doctor
    from .server import auth
    from .server.app import create_app
    from .server.runner import build_server, prepare_tls
    from .server.tls import format_fingerprint
    from .state import State

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config = _load(config_path)
    state = State(config.logging.audit_size, config.logging.request_log_size)
    tls_info = prepare_tls(config)

    typer.echo(f"OllamaGate listening on {config.base_url}")
    if tls_info:
        typer.echo(f"TLS certificate SHA-256: {format_fingerprint(tls_info.fingerprint)}")
    for finding in doctor.check_ollama_binding(config):
        if finding.level != "ok":
            typer.secho(f"WARNING: {finding.title}. {finding.fix}", fg=typer.colors.RED, err=True)
    if dev_token:
        token = auth.new_device_token()
        state.add_device(
            name="dev", token_hash=auth.hash_token(token), token_prefix=auth.display_prefix(token), paired_via="dev"
        )
        typer.secho(f"Dev token (shown once): {token}", fg=typer.colors.YELLOW)

    app = create_app(config, state)
    server = build_server(config, app, tls_info)
    asyncio.run(server.serve())


@cli.command()
def doctor(config_path: Optional[Path] = ConfigOption) -> None:
    """Check for insecure setups (Ollama exposure, file permissions, TLS)."""
    from . import doctor as doc

    config = _load(config_path)
    colors = {"ok": typer.colors.GREEN, "warn": typer.colors.YELLOW, "error": typer.colors.RED}
    worst = "ok"
    for f in doc.run_all(config):
        typer.secho(f"[{f.level.upper():5}] {f.title}", fg=colors[f.level])
        if f.fix:
            typer.echo(f"        fix: {f.fix}")
        if f.level == "error" or (f.level == "warn" and worst == "ok"):
            worst = f.level
    raise typer.Exit(1 if worst == "error" else 0)


def main() -> None:
    cli()


if __name__ == "__main__":
    main()
