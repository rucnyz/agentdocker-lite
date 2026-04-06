"""Backend selector: Rust (_core) or Go (_go_core).

Set NITROBOX_USE_GO=1 to use the Go backend.
"""

from __future__ import annotations

import os

if os.environ.get("NITROBOX_USE_GO", "").strip() in ("1", "true", "yes"):
    from nitrobox._go_core import *  # noqa: F401, F403
    from nitrobox._go_core import PySpawnResult  # noqa: F401
else:
    from nitrobox._core import *  # noqa: F401, F403
    from nitrobox._core import PySpawnResult  # noqa: F401
