"""Locate the nitrobox-core Go binary."""

from __future__ import annotations

import os
import threading
from pathlib import Path

_PKG_DIR = Path(__file__).resolve().parent  # src/nitrobox/
_PROJECT_ROOT = _PKG_DIR.parent.parent      # project root (dev layout)

_BIN: str | None = None
_BIN_LOCK = threading.Lock()


def gobin() -> str:
    """Return path to the nitrobox-core Go binary.

    Search order:
    1. ``NITROBOX_CORE_BIN`` environment variable
    2. ``<package>/_vendor/nitrobox-core`` (installed wheel)
    3. ``<project_root>/go/nitrobox-core`` (dev layout)
    4. ``nitrobox-core`` on PATH
    """
    global _BIN
    if _BIN is None:
        with _BIN_LOCK:
            if _BIN is None:
                _BIN = _find()
                os.environ["NITROBOX_CORE_BIN"] = _BIN
    return _BIN


def _find() -> str:
    for p in [
        os.environ.get("NITROBOX_CORE_BIN", ""),
        str(_PKG_DIR / "_vendor" / "nitrobox-core"),
        str(_PROJECT_ROOT / "go" / "nitrobox-core"),
    ]:
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return "nitrobox-core"
