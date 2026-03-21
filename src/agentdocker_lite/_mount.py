"""Overlay mount helpers using kernel syscalls.

Provides ``mount_overlay()`` which automatically selects the best
available mount strategy:

1. **New mount API** (kernel >= 6.8): ``fsopen`` + ``fsconfig`` with
   ``lowerdir+`` per-layer append.  No length limit per layer.
2. **Legacy mount(2)** fallback: single syscall with all options in one
   string, limited to PAGE_SIZE (~4096 bytes) total.

Background: util-linux >= 2.39 switched ``mount(8)`` to the new mount
API (``fsconfig``), which has a **256-byte** hard limit per parameter
value (``fs/fsopen.c: strndup_user(_value, 256)``).  Multi-layer
overlayfs ``lowerdir=A:B:C:...`` easily exceeds this.  The kernel
added ``lowerdir+`` (one path per call) in v6.8 to work around it,
but ``mount(8)`` doesn't split automatically.  We call the syscalls
directly to bypass both limitations.

Reference:
- https://github.com/util-linux/util-linux/issues/2287
- kernel fs/fsopen.c strndup_user 256 limit
- kernel fs/overlayfs/params.c Opt_lowerdir_add (lowerdir+)
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os
import platform

logger = logging.getLogger(__name__)

# --- syscall numbers (x86_64 / aarch64) -----------------------------------

_ARCH = platform.machine()

if _ARCH == "x86_64":
    _SYS_MOVE_MOUNT = 429
    _SYS_FSOPEN = 430
    _SYS_FSCONFIG = 431
    _SYS_FSMOUNT = 432
elif _ARCH == "aarch64":
    _SYS_MOVE_MOUNT = 30
    _SYS_FSOPEN = 430
    _SYS_FSCONFIG = 431
    _SYS_FSMOUNT = 432
else:
    # Unsupported arch — will fall back to legacy mount
    _SYS_MOVE_MOUNT = _SYS_FSOPEN = _SYS_FSCONFIG = _SYS_FSMOUNT = 0

# --- fsconfig constants ----------------------------------------------------

_FSCONFIG_SET_STRING = 1
_FSCONFIG_CMD_CREATE = 6
_FSOPEN_CLOEXEC = 0x00000001
_FSMOUNT_CLOEXEC = 0x00000001
_MOVE_MOUNT_F_EMPTY_PATH = 0x00000004
_AT_FDCWD = -100

# --- libc ------------------------------------------------------------------

_libc_name = ctypes.util.find_library("c")
_libc = ctypes.CDLL(_libc_name, use_errno=True) if _libc_name else None


def _syscall(*args: object) -> int:
    """Raw syscall wrapper. Returns result or raises OSError."""
    if _libc is None:
        raise OSError("libc not found")
    ret = _libc.syscall(*args)
    if ret < 0:
        errno = ctypes.get_errno()
        raise OSError(errno, os.strerror(errno))
    return ret


# --- public API ------------------------------------------------------------

# Cache: None = not tested, True/False = tested
_new_api_supported: bool | None = None


def _check_new_mount_api() -> bool:
    """Test if fsopen + lowerdir+ is available (kernel >= 6.8)."""
    global _new_api_supported
    if _new_api_supported is not None:
        return _new_api_supported

    if not _SYS_FSOPEN:
        _new_api_supported = False
        return False

    try:
        fd = _syscall(_SYS_FSOPEN, b"overlay", _FSOPEN_CLOEXEC)
        # Try lowerdir+ — if kernel < 6.8, this will EINVAL
        try:
            _syscall(
                _SYS_FSCONFIG, fd,
                _FSCONFIG_SET_STRING, b"lowerdir+", b"/", 0,
            )
            _new_api_supported = True
        except OSError:
            _new_api_supported = False
        os.close(fd)
    except OSError:
        _new_api_supported = False

    logger.debug("New mount API (lowerdir+): %s", _new_api_supported)
    return _new_api_supported


def _mount_overlay_new_api(
    lower_dirs: list[str],
    upper_dir: str,
    work_dir: str,
    target: str,
) -> None:
    """Mount overlayfs using fsopen/fsconfig with lowerdir+ per-layer append."""
    fd = _syscall(_SYS_FSOPEN, b"overlay", _FSOPEN_CLOEXEC)
    try:
        # Add each lower layer individually (bottom-to-top order expected
        # by caller; lowerdir+ appends in top-to-bottom order for overlayfs,
        # so we reverse)
        for layer_path in lower_dirs:
            _syscall(
                _SYS_FSCONFIG, fd,
                _FSCONFIG_SET_STRING, b"lowerdir+", layer_path.encode(), 0,
            )

        _syscall(
            _SYS_FSCONFIG, fd,
            _FSCONFIG_SET_STRING, b"upperdir", upper_dir.encode(), 0,
        )
        _syscall(
            _SYS_FSCONFIG, fd,
            _FSCONFIG_SET_STRING, b"workdir", work_dir.encode(), 0,
        )
        _syscall(_SYS_FSCONFIG, fd, _FSCONFIG_CMD_CREATE, None, None, 0)

        mnt_fd = _syscall(_SYS_FSMOUNT, fd, _FSMOUNT_CLOEXEC, 0)
        try:
            _syscall(
                _SYS_MOVE_MOUNT, mnt_fd, b"",
                _AT_FDCWD, target.encode(),
                _MOVE_MOUNT_F_EMPTY_PATH,
            )
        finally:
            os.close(mnt_fd)
    finally:
        os.close(fd)


def _mount_overlay_legacy(
    lowerdir_spec: str,
    upper_dir: str,
    work_dir: str,
    target: str,
) -> None:
    """Mount overlayfs using legacy mount(2) syscall (PAGE_SIZE limit)."""
    if _libc is None:
        raise OSError("libc not found")
    options = f"lowerdir={lowerdir_spec},upperdir={upper_dir},workdir={work_dir}"
    ret = _libc.mount(
        b"overlay", target.encode(), b"overlay", 0, options.encode(),
    )
    if ret != 0:
        errno = ctypes.get_errno()
        raise OSError(errno, f"mount(2) overlay failed: {os.strerror(errno)}")


def mount_overlay(
    lowerdir_spec: str,
    upper_dir: str,
    work_dir: str,
    target: str,
) -> None:
    """Mount overlayfs, auto-selecting the best available method.

    Uses the new mount API with ``lowerdir+`` (kernel >= 6.8) to bypass
    the 256-byte fsconfig limit.  Falls back to legacy ``mount(2)`` which
    supports up to PAGE_SIZE (~4096 bytes).

    Args:
        lowerdir_spec: Colon-separated lower directories (top:...:bottom),
            as used in standard overlayfs ``lowerdir=`` option.
        upper_dir: Writable upper directory.
        work_dir: Overlayfs work directory.
        target: Mount point.
    """
    lower_dirs = lowerdir_spec.split(":")

    if _check_new_mount_api():
        try:
            _mount_overlay_new_api(lower_dirs, upper_dir, work_dir, target)
            return
        except OSError as e:
            logger.warning(
                "New mount API failed, falling back to legacy mount(2): %s", e,
            )

    _mount_overlay_legacy(lowerdir_spec, upper_dir, work_dir, target)
