"""QR code rendering for terminals (Unicode half blocks) and SVG files."""

from __future__ import annotations

from pathlib import Path

import qrcode
import qrcode.image.svg


def _matrix(data: str, border: int = 2) -> list[list[bool]]:
    qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, border=border)
    qr.add_data(data)
    qr.make(fit=True)
    return qr.get_matrix()


def render_text(data: str, invert: bool = True) -> str:
    """Render ``data`` as a QR code using half-block characters (two rows per line).

    ``invert`` draws dark modules as spaces, which scans best on dark terminals.
    """
    matrix = _matrix(data)
    if len(matrix) % 2:
        matrix.append([False] * len(matrix[0]))
    chars = {
        (False, False): "█",
        (True, False): "▄",
        (False, True): "▀",
        (True, True): " ",
    }
    if not invert:
        chars = {k: {"█": " ", " ": "█", "▄": "▀", "▀": "▄"}[v] for k, v in chars.items()}
    lines = []
    for top, bottom in zip(matrix[0::2], matrix[1::2]):
        lines.append("".join(chars[(t, b)] for t, b in zip(top, bottom)))
    return "\n".join(lines)


def write_svg(data: str, path: Path) -> None:
    img = qrcode.make(data, image_factory=qrcode.image.svg.SvgPathImage, border=2)
    with open(path, "wb") as fh:
        img.save(fh)
