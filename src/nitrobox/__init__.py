"""nitrobox: Lightweight Linux namespace sandbox for high-frequency workloads."""

from nitrobox._errors import (
    SandboxConfigError,
    SandboxError,
    SandboxInitError,
    SandboxKernelError,
    SandboxTimeoutError,
)
from nitrobox.config import SandboxConfig
from nitrobox.sandbox import Sandbox
from nitrobox.checkpoint import CheckpointManager
from nitrobox.rootfs import get_image_config
from nitrobox.vm import QemuVM

try:
    from nitrobox.compose import ComposeProject, SharedNetwork
except ImportError:
    ComposeProject = None  # type: ignore[assignment,misc]
    SharedNetwork = None  # type: ignore[assignment,misc]

__all__ = [
    "Sandbox",
    "SandboxConfig",
    "SandboxError",
    "SandboxInitError",
    "SandboxTimeoutError",
    "SandboxKernelError",
    "SandboxConfigError",
    "CheckpointManager",
    "ComposeProject",
    "SharedNetwork",
    "QemuVM",
    "get_image_config",
]
__version__ = "0.0.5"
