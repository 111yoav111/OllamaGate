"""Keep the shipped docs and example config in step with the code."""

from __future__ import annotations

import dataclasses
import re
import tomllib
from pathlib import Path

import typer.main

import ollamagate
from ollamagate.__main__ import cli
from ollamagate.config import SECTIONS, Config, load_config

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")


def test_example_config_loads_and_matches_defaults() -> None:
    cfg = load_config(ROOT / "config.example.toml", env={})
    assert cfg == Config(config_dir=cfg.config_dir)


def test_example_config_documents_every_key() -> None:
    data = tomllib.loads((ROOT / "config.example.toml").read_text(encoding="utf-8"))
    assert set(data) == set(SECTIONS)
    defaults = Config()
    for section in SECTIONS:
        keys = {f.name for f in dataclasses.fields(getattr(defaults, section))}
        assert set(data[section]) == keys, section


def test_readme_cli_commands_exist() -> None:
    root = typer.main.get_command(cli)
    assert hasattr(root, "commands")
    seen = 0
    for line in re.findall(r"(?:^\s*|`)ollamagate ([a-z][a-z -]*)", README, re.M):
        words = line.split()
        group = root
        for word in words:
            if not hasattr(group, "commands"):  # a leaf command; the rest are its arguments
                break
            sub = group.commands.get(word)
            assert sub is not None, f"README mentions unknown command: ollamagate {line.strip()}"
            group = sub
        seen += 1
    assert seen >= 20  # the README's command reference is still being checked


def test_readme_anchors_resolve() -> None:
    def slug(heading: str) -> str:
        return re.sub(r"[^\w\- ]", "", heading.strip().lower()).replace(" ", "-")

    anchors = {slug(h) for h in re.findall(r"^#{1,6} (.+)$", README, re.M)}
    for target in re.findall(r"\]\(#([^)]+)\)", README):
        assert target in anchors, target


def test_version_is_single_sourced() -> None:
    pyproject = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert "version" not in pyproject["project"]
    assert pyproject["tool"]["setuptools"]["dynamic"]["version"] == {"attr": "ollamagate.__version__"}
    assert re.fullmatch(r"\d+\.\d+\.\d+", ollamagate.__version__)
