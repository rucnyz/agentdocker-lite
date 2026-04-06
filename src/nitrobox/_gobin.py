"""Locate the nitrobox-core Go binary."""

from __future__ import annotations

import os
import threading
from pathlib import Path

# Project root: src/nitrobox/_gobin.py → parent.parent.parent = project root
_PROJECT_ROOT = Path(__file__).resolve().parent.parent.parent

_BIN: str | None = None
_BIN_LOCK = threading.Lock()


def gobin() -> str:
    """Return path to the nitrobox-core Go binary.

    Search order:
    1. ``NITROBOX_CORE_BIN`` environment variable
    2. ``<project_root>/go/nitrobox-core`` (dev layout)
    3. ``nitrobox-core`` on PATH
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
        str(_PROJECT_ROOT / "go" / "nitrobox-core"),
    ]:
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    return "nitrobox-core"
