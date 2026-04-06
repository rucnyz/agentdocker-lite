"""Go-based backend for nitrobox core operations.

Drop-in replacement for the Rust _core extension module. Each function
calls the `nitrobox-core` Go binary via subprocess with JSON stdin/stdout.

Functions that are Phase 2+ (security, namespace, spawn) raise
NotImplementedError until those phases are implemented.
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Any

# Locate the Go binary. Prefer an explicit env var, then check adjacent to
# the Python package, then fall back to PATH.
_BIN_SEARCH = [
    os.environ.get("NITROBOX_CORE_BIN", ""),
    str(Path(__file__).resolve().parent.parent.parent / "go" / "nitrobox-core"),
]


def _find_bin() -> str:
    for p in _BIN_SEARCH:
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
    # Fall back to PATH
    return "nitrobox-core"


_BIN: str | None = None
_BIN_LOCK = threading.Lock()


def _bin() -> str:
    global _BIN
    if _BIN is None:
        with _BIN_LOCK:
            if _BIN is None:
                _BIN = _find_bin()
    return _BIN


def _call(subcmd: str, payload: dict[str, Any] | None = None) -> Any:
    """Call a nitrobox-core subcommand with JSON stdin, return parsed JSON stdout."""
    inp = json.dumps(payload or {}).encode()
    r = subprocess.run(
        [_bin(), subcmd],
        input=inp,
        capture_output=True,
        check=False,
    )
    if r.returncode != 0:
        err = r.stderr.decode().strip()
        raise OSError(f"nitrobox-core {subcmd} failed: {err}")
    out = r.stdout.decode().strip()
    if not out:
        return None
    return json.loads(out)


# ======================================================================
# Mount operations
# ======================================================================


def py_check_new_mount_api() -> bool:
    return _call("check-new-mount-api")


def py_mount_overlay(
    lowerdir_spec: str, upper_dir: str, work_dir: str, target: str
) -> None:
    _call(
        "mount-overlay",
        {
            "lowerdir_spec": lowerdir_spec,
            "upper_dir": upper_dir,
            "work_dir": work_dir,
            "target": target,
            "extra_opts": [],
        },
    )


def py_bind_mount(source: str, target: str) -> None:
    _call("bind-mount", {"source": source, "target": target})


def py_rbind_mount(source: str, target: str) -> None:
    _call("rbind-mount", {"source": source, "target": target})


def py_make_private(target: str) -> None:
    _call("make-private", {"target": target})


def py_remount_ro_bind(target: str) -> None:
    _call("remount-ro-bind", {"target": target})


def py_umount(target: str) -> None:
    _call("umount", {"target": target})


def py_umount_lazy(target: str) -> None:
    _call("umount-lazy", {"target": target})


def py_umount_recursive_lazy(target: str) -> None:
    _call("umount-recursive-lazy", {"target": target})


# ======================================================================
# Cgroup operations
# ======================================================================


def py_cgroup_v2_available() -> bool:
    return _call("cgroup-v2-available")


def py_create_cgroup(name: str) -> str:
    return _call("create-cgroup", {"name": name})


def py_apply_cgroup_limits(cgroup_path: str, limits: dict[str, str]) -> None:
    _call("apply-cgroup-limits", {"cgroup_path": cgroup_path, "limits": limits})


def py_cgroup_add_process(cgroup_path: str, pid: int) -> None:
    _call("cgroup-add-process", {"cgroup_path": cgroup_path, "pid": pid})


def py_cleanup_cgroup(cgroup_path: str) -> None:
    _call("cleanup-cgroup", {"cgroup_path": cgroup_path})


def py_convert_cpu_shares(shares: int) -> int:
    return _call("convert-cpu-shares", {"shares": shares})


# ======================================================================
# Pidfd operations
# ======================================================================


def py_pidfd_open(pid: int) -> int | None:
    return _call("pidfd-open", {"pid": pid})


def py_pidfd_send_signal(pidfd: int, sig: int) -> bool:
    return _call("pidfd-send-signal", {"pidfd": pidfd, "sig": sig})


def py_pidfd_is_alive(pidfd: int) -> bool:
    return _call("pidfd-is-alive", {"pidfd": pidfd})


def py_process_madvise_cold(pidfd: int) -> bool:
    return _call("process-madvise-cold", {"pidfd": pidfd})


# ======================================================================
# Process helpers
# ======================================================================


def py_fuser_kill(target_path: str) -> int:
    return _call("fuser-kill", {"target_path": target_path})


# ======================================================================
# QMP
# ======================================================================


def py_qmp_send(
    socket_path: str, command_json: str, timeout_secs: int = 30
) -> str:
    return _call(
        "qmp-send",
        {
            "socket_path": socket_path,
            "command_json": command_json,
            "timeout_secs": timeout_secs,
        },
    )


# ======================================================================
# Whiteout conversion
# ======================================================================


def py_convert_whiteouts(layer_dir: str, use_user_xattr: bool = True) -> int:
    return _call(
        "convert-whiteouts",
        {"layer_dir": layer_dir, "use_user_xattr": use_user_xattr},
    )


# ======================================================================
# Image store (in-memory — Python-side for Go backend)
# ======================================================================

_IMAGE_STORE: dict[str, str] = {}
_IMAGE_STORE_LOCK = threading.Lock()


def py_image_store_get(image_name: str) -> str | None:
    with _IMAGE_STORE_LOCK:
        return _IMAGE_STORE.get(image_name)


def py_image_store_put(image_name: str, config_json: str) -> None:
    with _IMAGE_STORE_LOCK:
        _IMAGE_STORE[image_name] = config_json
        # Also index by image_id
        try:
            config = json.loads(config_json)
            image_id = config.get("image_id", "")
            if image_id and image_id != image_name:
                _IMAGE_STORE[image_id] = config_json
        except json.JSONDecodeError:
            pass


def py_image_store_clear() -> None:
    with _IMAGE_STORE_LOCK:
        _IMAGE_STORE.clear()


# ======================================================================
# Image reference parsing
# ======================================================================


def py_parse_image_ref(image: str) -> tuple[str, str, str]:
    result = _call("parse-image-ref", {"image": image})
    return tuple(result)


# ======================================================================
# Landlock
# ======================================================================


def py_landlock_abi_version() -> int:
    return _call("landlock-abi-version")


# ======================================================================
# Security (Phase 2 — implemented)
# ======================================================================


def py_build_seccomp_bpf() -> bytes:
    """Generate seccomp BPF bytecode (raw bytes, not JSON)."""
    r = subprocess.run(
        [_bin(), "build-seccomp-bpf"],
        capture_output=True,
        check=False,
    )
    if r.returncode != 0:
        raise OSError(f"build-seccomp-bpf failed: {r.stderr.decode().strip()}")
    return r.stdout


def py_apply_seccomp_filter() -> None:
    _call("apply-seccomp-filter")


def py_drop_capabilities(
    extra_keep: list[int] | None = None,
    extra_drop: list[int] | None = None,
) -> int:
    return _call(
        "drop-capabilities",
        {"extra_keep": extra_keep or [], "extra_drop": extra_drop or []},
    )


def py_apply_landlock(
    read_paths: list[str] | None = None,
    write_paths: list[str] | None = None,
    allowed_tcp_ports: list[int] | None = None,
    strict: bool = False,
) -> bool:
    return _call(
        "apply-landlock",
        {
            "read_paths": read_paths or [],
            "write_paths": write_paths or [],
            "allowed_tcp_ports": allowed_tcp_ports or [],
            "strict": strict,
        },
    )


def py_nsenter_preexec(target_pid: int) -> None:
    _call("nsenter-preexec", {"target_pid": target_pid})


def py_userns_preexec(
    target_pid: int, rootfs: str, working_dir: str
) -> None:
    _call(
        "userns-preexec",
        {"target_pid": target_pid, "rootfs": rootfs, "working_dir": working_dir},
    )


def py_userns_fixup_for_delete(userns_pid: int, dir_path: str) -> int:
    return _call(
        "userns-fixup-for-delete",
        {"userns_pid": userns_pid, "dir_path": dir_path},
    )


def py_extract_tar_in_userns(
    tar_path: str,
    dest: str,
    outer_uid: int,
    outer_gid: int,
    sub_start: int,
    sub_count: int,
) -> None:
    _call(
        "extract-tar-in-userns",
        {
            "tar_path": tar_path,
            "dest": dest,
            "outer_uid": outer_uid,
            "outer_gid": outer_gid,
            "sub_start": sub_start,
            "sub_count": sub_count,
        },
    )


def py_rmtree_in_userns(
    path: str,
    outer_uid: int,
    outer_gid: int,
    sub_start: int,
    sub_count: int,
) -> None:
    _call(
        "rmtree-in-userns",
        {
            "path": path,
            "outer_uid": outer_uid,
            "outer_gid": outer_gid,
            "sub_start": sub_start,
            "sub_count": sub_count,
        },
    )


class PySpawnResult:
    """Placeholder for Phase 4 spawn result."""

    __slots__ = (
        "pid",
        "stdin_fd",
        "stdout_fd",
        "signal_r_fd",
        "signal_w_fd_num",
        "master_fd",
        "pidfd",
        "err_r_fd",
    )

    def __init__(
        self,
        pid: int,
        stdin_fd: int,
        stdout_fd: int,
        signal_r_fd: int,
        signal_w_fd_num: int,
        master_fd: int | None,
        pidfd: int | None,
        err_r_fd: int,
    ) -> None:
        self.pid = pid
        self.stdin_fd = stdin_fd
        self.stdout_fd = stdout_fd
        self.signal_r_fd = signal_r_fd
        self.signal_w_fd_num = signal_w_fd_num
        self.master_fd = master_fd
        self.pidfd = pidfd
        self.err_r_fd = err_r_fd


def py_spawn_sandbox(config: dict) -> PySpawnResult:
    raise NotImplementedError("py_spawn_sandbox: Phase 4 (spawn)")
