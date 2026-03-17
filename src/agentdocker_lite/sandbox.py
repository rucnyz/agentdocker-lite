"""Factory function for creating sandbox instances.

Auto-selects RootfulSandbox (real root) or RootlessSandbox (user namespace)
based on whether the process is running as root.
"""

from __future__ import annotations

from agentdocker_lite.backends.base import SandboxBase, SandboxConfig


def Sandbox(config: SandboxConfig, name: str = "default") -> SandboxBase:
    """Create a sandbox instance.

    When running as root, creates a RootfulSandbox with direct mount/cgroup
    operations.  Otherwise, creates a RootlessSandbox that uses user
    namespaces for the same isolation without root (requires kernel >= 5.11).

    Args:
        config: Sandbox configuration.
        name: Unique name for this sandbox instance.

    Returns:
        A sandbox instance (RootfulSandbox or RootlessSandbox).
    """
    import os

    if os.geteuid() == 0:
        from agentdocker_lite.backends.rootful import RootfulSandbox

        return RootfulSandbox(config, name)
    else:
        from agentdocker_lite.backends.rootless import RootlessSandbox

        return RootlessSandbox(config, name)
