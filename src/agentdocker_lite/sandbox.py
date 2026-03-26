"""Factory function for creating sandbox instances.

Auto-selects RootfulSandbox (real root) or RootlessSandbox (user namespace)
based on whether the process is running as root.
"""

from __future__ import annotations

import logging

from agentdocker_lite.backends.base import SandboxBase, SandboxConfig

logger = logging.getLogger(__name__)


def _apply_image_defaults(config: SandboxConfig) -> None:
    """Fill unset config fields from the OCI image config.

    User-specified values always take precedence.  ``working_dir``,
    ``environment``, and ``entrypoint`` are backfilled from the image.
    """
    if not config.image:
        return
    from agentdocker_lite.rootfs import get_image_config

    img_cfg = get_image_config(config.image)
    if not img_cfg:
        return

    # working_dir: backfill only if user left the default "/"
    img_wd = img_cfg.get("working_dir")
    if img_wd and config.working_dir == "/":
        config.working_dir = img_wd
        logger.debug("Applied image WORKDIR: %s", img_wd)

    # environment: image env as base, user env overrides
    img_env = img_cfg.get("env") or {}
    if img_env:
        merged = dict(img_env)
        merged.update(config.environment)  # user wins
        config.environment = merged
        logger.debug("Merged %d image ENV vars", len(img_env))

    # entrypoint: backfill only if user didn't set one explicitly
    img_ep = img_cfg.get("entrypoint")
    if img_ep and config.entrypoint is None:
        config.entrypoint = img_ep
        logger.debug("Applied image ENTRYPOINT: %s", img_ep)


def Sandbox(config: SandboxConfig, name: str = "default") -> SandboxBase:
    """Create a sandbox instance.

    When running as root, creates a RootfulSandbox with direct mount/cgroup
    operations.  Otherwise, creates a RootlessSandbox that uses user
    namespaces for the same isolation without root (requires kernel >= 5.11).

    Automatically applies OCI image defaults (``WORKDIR``, ``ENV``) from
    the image config.  User-specified values always take precedence.

    Args:
        config: Sandbox configuration.
        name: Unique name for this sandbox instance.

    Returns:
        A sandbox instance (RootfulSandbox or RootlessSandbox).
    """
    import os

    _apply_image_defaults(config)

    if os.geteuid() == 0:
        from agentdocker_lite.backends.rootful import RootfulSandbox

        return RootfulSandbox(config, name)
    else:
        from agentdocker_lite.backends.rootless import RootlessSandbox

        return RootlessSandbox(config, name)
