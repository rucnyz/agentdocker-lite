"""User-namespace-based sandbox (rootless mode).

Provides the same namespace + overlayfs + chroot isolation as
RootfulSandbox, but without requiring real root privileges.
Uses ``unshare --user --map-root-user`` to get fake root inside
a user namespace (requires kernel >= 5.11).

cgroup resource limits are applied via systemd delegation
(``systemd-run --user --scope``).
"""

from __future__ import annotations

from agentdocker_lite.backends.base import SandboxConfig
from agentdocker_lite.backends.rootful import RootfulSandbox


class RootlessSandbox(RootfulSandbox):
    """Rootless sandbox using user namespaces.

    Inherits all functionality from RootfulSandbox but forces user
    namespace mode (``_userns = True``).  The Sandbox() factory
    creates this class when not running as root.

    Example::

        from agentdocker_lite import Sandbox, SandboxConfig

        config = SandboxConfig(image="ubuntu:22.04", working_dir="/workspace")
        sb = Sandbox(config, name="worker-0")   # RootlessSandbox if not root
        output, ec = sb.run("echo hello world")
        sb.reset()
        sb.delete()
    """

    def __init__(self, config: SandboxConfig, name: str = "default"):
        # Skip RootfulSandbox.__init__ — it would try rootful mode.
        # We directly initialize in userns mode.
        self._config = config
        self._name = name
        self._userns = True
        self._init_userns(config, name)
        self._register(self)
