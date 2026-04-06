"""OCI whiteout detection and conversion to overlayfs-native format."""

from __future__ import annotations

import logging
import os
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)


def _detect_whiteout_strategy() -> str:
    """Detect the best whiteout conversion strategy for this environment.

    Returns:
        ``"root"``  — real root: mknod(0,0) + trusted.overlay.* (any kernel)
        ``"xattr"`` — kernel >= 6.7: user.overlay.whiteout xattr, no mknod
        ``"userns"`` — kernel >= 5.11: mknod(0,0) inside unshare --user
        ``"none"``  — unsupported: layer caching unavailable
    """
    if os.geteuid() == 0:
        return "root"

    major, minor = _kernel_version()

    if (major, minor) >= (6, 7):
        return "xattr"
    if (major, minor) >= (5, 11):
        return "userns"
    return "none"


def _kernel_version() -> tuple[int, int]:
    """Return (major, minor) kernel version."""
    release = os.uname().release  # e.g. "6.19.8-1-cachyos"
    parts = release.split(".")
    try:
        return int(parts[0]), int(parts[1])
    except (IndexError, ValueError):
        return 0, 0


def _convert_whiteouts_in_layer(layer_dir: Path, strategy: str = "") -> None:
    """Convert OCI whiteout files to overlayfs-native whiteouts.

    OCI uses ``.wh.<name>`` sentinel files for deletions.
    The conversion strategy depends on the environment:

    - ``"root"``: mknod(0,0) + trusted.overlay.opaque (standard)
    - ``"xattr"``: user.overlay.whiteout xattr (kernel >= 6.7, no root)
    - ``"userns"``: mknod(0,0) inside unshare --user (kernel >= 5.11)
    """
    if not strategy:
        strategy = _detect_whiteout_strategy()

    if strategy == "userns":
        _convert_whiteouts_in_userns(layer_dir)
        return

    # Use Rust implementation: direct setxattr/mknod syscalls,
    # ~100x faster than spawning setfattr per file.
    from nitrobox._backend import py_convert_whiteouts
    py_convert_whiteouts(str(layer_dir), strategy == "xattr")


def _convert_whiteouts_in_userns(layer_dir: Path) -> None:
    """Convert whiteouts by running mknod inside a user namespace.

    Kernel >= 5.11: fake CAP_MKNOD in userns allows creating (0,0) device.
    Uses user.overlay.opaque for opaque dirs (userns can't set trusted.*).
    """
    # Build a small script that does the conversion inside a userns
    script = (
        "import os, subprocess, sys\n"
        "from pathlib import Path\n"
        "layer_dir = Path(sys.argv[1])\n"
        "for dirpath, _dns, fnames in os.walk(layer_dir):\n"
        "    dp = Path(dirpath)\n"
        "    for fname in fnames:\n"
        "        if not fname.startswith('.wh.'): continue\n"
        "        wh = dp / fname\n"
        "        if fname == '.wh..wh..opq':\n"
        "            wh.unlink()\n"
        "            subprocess.run(['setfattr','-n','user.overlay.opaque','-v','y',str(dp)],capture_output=True)\n"
        "        else:\n"
        "            target = dp / fname[4:]\n"
        "            wh.unlink()\n"
        "            os.mknod(str(target), 0o600|0o020000, os.makedev(0,0))\n"
    )
    result = subprocess.run(
        ["unshare", "--user", "--map-root-user",
         "python3", "-c", script, str(layer_dir)],
        capture_output=True, text=True, timeout=60,
    )
    if result.returncode != 0:
        logger.warning("userns whiteout conversion failed: %s", result.stderr.strip())
