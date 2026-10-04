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
    """Replace control/format characters (incl. ESC, C1, bidi overrides) and the
    Unicode line/paragraph separators with ``\\xNN`` / ``\\uNNNN`` escapes."""
    truncated = limit is not None and len(value) > limit
    if truncated:
        value = value[:limit]  # slice first: never walk a huge attacker-sized string
    out = []
    for ch in value:
        cat = unicodedata.category(ch)
        if cat[0] == "C" or cat in ("Zl", "Zp"):  # U+2028/U+2029 break lines in many viewers
            code = ord(ch)
            out.append(f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}" if code < 0x10000 else f"\\U{code:08x}")
        else:
            out.append(ch)
    text = "".join(out)
    if limit is not None and len(text) > limit:
        text, truncated = text[:limit], True
    return text + "…" if truncated else text


def safe(value: Any) -> str:
    """``str(value)`` made terminal-safe; for CLI/TUI output."""
    return safe_text(value if isinstance(value, str) else str(value))
