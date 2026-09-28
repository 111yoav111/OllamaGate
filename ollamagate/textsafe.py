"""Make attacker-controlled text safe to show in a terminal.

Paths, user agents and similar values come from the internet. Printed raw,
escape sequences in them could rewrite the owner's screen, hide audit lines,
set the window title or write to the clipboard (OSC 52). Every such value is
escaped when it is stored, and again when it is displayed.
"""

from __future__ import annotations

import unicodedata
from typing import Any


def safe_text(value: str, limit: int | None = None) -> str:
    """Replace control/format characters (incl. ESC, C1, bidi overrides) with ``\\xNN`` escapes."""
    truncated = limit is not None and len(value) > limit
    if truncated:
        value = value[:limit]  # slice first: never walk a huge attacker-sized string
    out = []
    for ch in value:
        if unicodedata.category(ch)[0] == "C":
            out.append(f"\\x{ord(ch):02x}" if ord(ch) < 0x100 else f"\\u{ord(ch):04x}")
        else:
            out.append(ch)
    text = "".join(out)
    if limit is not None and len(text) > limit:
        text = text[:limit]
    return text + "…" if truncated else text


def safe(value: Any) -> str:
    """``str(value)`` made terminal-safe; for CLI/TUI output."""
    return safe_text(value if isinstance(value, str) else str(value))
