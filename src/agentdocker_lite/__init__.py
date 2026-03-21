"""agentdocker-lite: Lightweight Linux namespace sandbox for high-frequency workloads."""

from agentdocker_lite.backends.base import SandboxBase, SandboxConfig
from agentdocker_lite.checkpoint import CheckpointManager
from agentdocker_lite.rootfs import get_image_config
from agentdocker_lite.sandbox import Sandbox

__all__ = [
    "Sandbox",
    "SandboxConfig",
    "SandboxBase",
    "CheckpointManager",
    "get_image_config",
]
__version__ = "0.0.1"
