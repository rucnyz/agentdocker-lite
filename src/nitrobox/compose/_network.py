"""Shared network namespace (Podman-style pod networking) and health-check helpers."""

from __future__ import annotations

import logging
import os
import re
import shlex
import time
from typing import Any

from nitrobox.sandbox import Sandbox

logger = logging.getLogger(__name__)


class SharedNetwork:
    """Shared userns + netns for compose network isolation.

    Creates a sentinel process that holds a user namespace (with full
    uid mapping) and a network namespace.  Other sandboxes join the
    sentinel's namespaces via ``nsenter``.

    This mirrors Podman's pod infra container: one shared userns+netns
    per pod, individual mount/pid namespaces per container.
    """

    def __init__(self, name: str = "default") -> None:
        import subprocess as _subprocess

        self.name = name
        # Detect subuid range (reuse rootless sandbox logic)
        self._subuid_range = Sandbox._detect_subuid_range()

        # Create sentinel with userns + netns
        unshare_cmd = ["unshare", "--user", "--net", "--fork"]
        if not self._subuid_range:
            unshare_cmd.insert(2, "--map-root-user")
        unshare_cmd.extend(["--", "sleep", "infinity"])

        self._sentinel = _subprocess.Popen(
            unshare_cmd,
            start_new_session=True,
            stdout=_subprocess.DEVNULL,
            stderr=_subprocess.DEVNULL,
        )

        try:
            # Wait for child to enter new userns
            if self._subuid_range:
                my_userns = os.readlink("/proc/self/ns/user")
                for _ in range(1000):
                    try:
                        child_userns = os.readlink(
                            f"/proc/{self._sentinel.pid}/ns/user"
                        )
                        if child_userns != my_userns:
                            break
                    except (FileNotFoundError, PermissionError):
                        pass
                    time.sleep(0.001)
                else:
                    raise RuntimeError("Timeout waiting for sentinel userns")

                # Set up full uid/gid mapping
                outer_uid, sub_start, sub_count = self._subuid_range
                outer_gid = os.getgid()
                pid = self._sentinel.pid
                _subprocess.run(
                    ["newuidmap", str(pid),
                     "0", str(outer_uid), "1",
                     "1", str(sub_start), str(sub_count)],
                    check=True, capture_output=True,
                )
                _subprocess.run(
                    ["newgidmap", str(pid),
                     "0", str(outer_gid), "1",
                     "1", str(sub_start), str(sub_count)],
                    check=True, capture_output=True,
                )
        except Exception:
            self.destroy()
            raise

    @property
    def userns_path(self) -> str:
        """Path to the sentinel's user namespace."""
        return f"/proc/{self._sentinel.pid}/ns/user"

    @property
    def netns_path(self) -> str:
        """Path to the sentinel's network namespace."""
        return f"/proc/{self._sentinel.pid}/ns/net"

    @property
    def alive(self) -> bool:
        return self._sentinel.poll() is None

    def destroy(self) -> None:
        """Kill the sentinel, releasing the shared namespaces."""
        if self._sentinel.poll() is None:
            import signal as _signal
            try:
                os.killpg(self._sentinel.pid, _signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                try:
                    self._sentinel.kill()
                except Exception:
                    pass
            try:
                self._sentinel.wait(timeout=5)
            except Exception:
                pass

    def __repr__(self) -> str:
        state = "alive" if self.alive else "dead"
        return f"SharedNetwork({self.name!r}, {state})"


# ------------------------------------------------------------------ #
#  Duration parsing                                                    #
# ------------------------------------------------------------------ #


def _parse_duration(s: str | int | float) -> float:
    """Parse compose duration string (e.g. ``"30s"``, ``"2m"``) to seconds."""
    if isinstance(s, (int, float)):
        return float(s)
    s = str(s).strip()
    m = re.match(r"^(\d+(?:\.\d+)?)\s*(s|ms|m|h)?$", s)
    if not m:
        return 30.0
    val = float(m.group(1))
    unit = m.group(2) or "s"
    return val * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[unit]


# ------------------------------------------------------------------ #
#  Health check                                                        #
# ------------------------------------------------------------------ #


def _healthcheck_cmd(test: Any) -> str:
    """Convert healthcheck test to a shell command string."""
    if isinstance(test, str):
        return test
    if isinstance(test, list) and test:
        if test[0] == "CMD":
            return shlex.join(test[1:])
        if test[0] == "CMD-SHELL":
            return " ".join(test[1:])
        # NONE disables
        if test[0] == "NONE":
            return ""
        return shlex.join(test)
    return ""
