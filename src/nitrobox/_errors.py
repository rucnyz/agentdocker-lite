"""Structured error types for nitrobox."""


class SandboxError(Exception):
    """Base exception for all nitrobox errors."""


class SandboxInitError(SandboxError):
    """Sandbox failed to initialize (image, rootfs, shell startup)."""


class SandboxTimeoutError(SandboxError):
    """Command or operation timed out."""


class SandboxKernelError(SandboxError):
    """Required kernel feature is unavailable (overlayfs, userns, Landlock, etc.)."""


class SandboxConfigError(SandboxError):
    """Invalid sandbox configuration."""
