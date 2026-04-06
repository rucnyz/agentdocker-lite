"""Go-based backend for nitrobox core operations.

Drop-in replacement for the Rust _core extension module. Uses in-process
FFI via CFFI to call the Go c-shared library (libnitrobox.so), giving
the same ~1μs call overhead as Rust pyo3.

Spawn is the exception — it uses subprocess because Go's c-shared library
runs in the Python process, making fork unsafe (Go runtime is multi-threaded).
"""

from __future__ import annotations

import json
import os
import subprocess
import threading
from pathlib import Path
from typing import Any

import cffi

# ======================================================================
# Library loading
# ======================================================================

_CDEF = """
void NbxSetCoreBin(char* path);
void NbxFree(char* p);

// Mount
int NbxCheckNewMountAPI(void);
char* NbxMountOverlay(char* lowerdirSpec, char* upperDir, char* workDir, char* target);
char* NbxBindMount(char* source, char* target);
char* NbxRbindMount(char* source, char* target);
char* NbxMakePrivate(char* target);
char* NbxRemountROBind(char* target);
char* NbxUmount(char* target);
char* NbxUmountLazy(char* target);
char* NbxUmountRecursiveLazy(char* target);

// Cgroup
int NbxCgroupV2Available(void);
char* NbxCreateCgroup(char* name, char** outPath);
char* NbxApplyCgroupLimits(char* cgroupPath, char* limitsJSON);
char* NbxCgroupAddProcess(char* cgroupPath, unsigned int pid);
char* NbxCleanupCgroup(char* cgroupPath);
long unsigned int NbxConvertCPUShares(long unsigned int shares);

// Pidfd
int NbxPidfdOpen(int pid, int* outFd);
int NbxPidfdSendSignal(int pfd, int sig);
int NbxPidfdIsAlive(int pfd);
int NbxProcessMadviseCold(int pfd);

// Proc
char* NbxFuserKill(char* targetPath, unsigned int* outCount);

// QMP
char* NbxQmpSend(char* socketPath, char* commandJSON, long unsigned int timeoutSecs, char** outResp);

// Whiteout
char* NbxConvertWhiteouts(char* layerDir, int useUserXattr, unsigned int* outCount);

// Image ref
char* NbxParseImageRef(char* image, char** outDomain, char** outRepo, char** outTag);

// Security
unsigned int NbxLandlockABIVersion(void);
void NbxBuildSeccompBPF(void** outBuf, int* outLen);
char* NbxApplySeccompFilter(void);
char* NbxDropCapabilities(char* extraKeepJSON, char* extraDropJSON, unsigned int* outDropped);
char* NbxApplyLandlock(char* readPathsJSON, char* writePathsJSON, char* portsJSON, int strict, int* outApplied);

// Namespace
char* NbxUsernFixupForDelete(int usernsPid, char* dirPath, unsigned int* outCount);
"""

_ffi = cffi.FFI()
_ffi.cdef(_CDEF)

# Find libnitrobox.so
_SO_SEARCH = [
    os.environ.get("NITROBOX_LIB", ""),
    str(Path(__file__).resolve().parent.parent.parent / "go" / "libnitrobox.so"),
]

_lib = None
_lib_lock = threading.Lock()


def _get_lib():
    global _lib
    if _lib is None:
        with _lib_lock:
            if _lib is None:
                for p in _SO_SEARCH:
                    if p and os.path.isfile(p):
                        _lib = _ffi.dlopen(p)
                        # Tell Go where to find nitrobox-core for re-exec.
                        # Must use NbxSetCoreBin (not os.environ) because Go's
                        # os.Getenv doesn't see runtime Python env var changes.
                        _go_dir = str(Path(p).parent)
                        _bin_path = os.path.join(_go_dir, "nitrobox-core")
                        if os.path.isfile(_bin_path):
                            _lib.NbxSetCoreBin(_ffi.new("char[]", _bin_path.encode()))
                            os.environ["NITROBOX_CORE_BIN"] = _bin_path
                        break
                if _lib is None:
                    raise RuntimeError("libnitrobox.so not found")
    return _lib


def _check_err(err_ptr):
    """Check a returned char* error. Raises OSError if non-null, frees the string."""
    if err_ptr != _ffi.NULL:
        msg = _ffi.string(err_ptr).decode()
        _get_lib().NbxFree(err_ptr)
        raise OSError(msg)


def _c(s: str):
    """Convert Python str to C char*."""
    return _ffi.new("char[]", s.encode())


# ======================================================================
# Subprocess helper (for spawn only)
# ======================================================================

_BIN_SEARCH = [
    os.environ.get("NITROBOX_CORE_BIN", ""),
    str(Path(__file__).resolve().parent.parent.parent / "go" / "nitrobox-core"),
]


def _find_bin() -> str:
    for p in _BIN_SEARCH:
        if p and os.path.isfile(p) and os.access(p, os.X_OK):
            return p
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


# ======================================================================
# Mount operations
# ======================================================================


def py_check_new_mount_api() -> bool:
    return _get_lib().NbxCheckNewMountAPI() != 0


def py_mount_overlay(
    lowerdir_spec: str, upper_dir: str, work_dir: str, target: str
) -> None:
    _check_err(_get_lib().NbxMountOverlay(
        _c(lowerdir_spec), _c(upper_dir), _c(work_dir), _c(target),
    ))


def py_bind_mount(source: str, target: str) -> None:
    _check_err(_get_lib().NbxBindMount(_c(source), _c(target)))


def py_rbind_mount(source: str, target: str) -> None:
    _check_err(_get_lib().NbxRbindMount(_c(source), _c(target)))


def py_make_private(target: str) -> None:
    _check_err(_get_lib().NbxMakePrivate(_c(target)))


def py_remount_ro_bind(target: str) -> None:
    _check_err(_get_lib().NbxRemountROBind(_c(target)))


def py_umount(target: str) -> None:
    _check_err(_get_lib().NbxUmount(_c(target)))


def py_umount_lazy(target: str) -> None:
    _check_err(_get_lib().NbxUmountLazy(_c(target)))


def py_umount_recursive_lazy(target: str) -> None:
    _check_err(_get_lib().NbxUmountRecursiveLazy(_c(target)))


# ======================================================================
# Cgroup operations
# ======================================================================


def py_cgroup_v2_available() -> bool:
    return _get_lib().NbxCgroupV2Available() != 0


def py_create_cgroup(name: str) -> str:
    out = _ffi.new("char**")
    _check_err(_get_lib().NbxCreateCgroup(_c(name), out))
    result = _ffi.string(out[0]).decode()
    _get_lib().NbxFree(out[0])
    return result


def py_apply_cgroup_limits(cgroup_path: str, limits: dict[str, str]) -> None:
    _check_err(_get_lib().NbxApplyCgroupLimits(
        _c(cgroup_path), _c(json.dumps(limits)),
    ))


def py_cgroup_add_process(cgroup_path: str, pid: int) -> None:
    _check_err(_get_lib().NbxCgroupAddProcess(_c(cgroup_path), pid))


def py_cleanup_cgroup(cgroup_path: str) -> None:
    _check_err(_get_lib().NbxCleanupCgroup(_c(cgroup_path)))


def py_convert_cpu_shares(shares: int) -> int:
    return _get_lib().NbxConvertCPUShares(shares)


# ======================================================================
# Pidfd operations
# ======================================================================


def py_pidfd_open(pid: int) -> int | None:
    out = _ffi.new("int*")
    if _get_lib().NbxPidfdOpen(pid, out) == 0:
        return out[0]
    return None


def py_pidfd_send_signal(pidfd: int, sig: int) -> bool:
    return _get_lib().NbxPidfdSendSignal(pidfd, sig) != 0


def py_pidfd_is_alive(pidfd: int) -> bool:
    return _get_lib().NbxPidfdIsAlive(pidfd) != 0


def py_process_madvise_cold(pidfd: int) -> bool:
    return _get_lib().NbxProcessMadviseCold(pidfd) != 0


# ======================================================================
# Process helpers
# ======================================================================


def py_fuser_kill(target_path: str) -> int:
    out = _ffi.new("unsigned int*")
    _check_err(_get_lib().NbxFuserKill(_c(target_path), out))
    return out[0]


# ======================================================================
# QMP
# ======================================================================


def py_qmp_send(
    socket_path: str, command_json: str, timeout_secs: int = 30
) -> str:
    out = _ffi.new("char**")
    _check_err(_get_lib().NbxQmpSend(
        _c(socket_path), _c(command_json), timeout_secs, out,
    ))
    result = _ffi.string(out[0]).decode()
    _get_lib().NbxFree(out[0])
    return result


# ======================================================================
# Whiteout conversion
# ======================================================================


def py_convert_whiteouts(layer_dir: str, use_user_xattr: bool = True) -> int:
    out = _ffi.new("unsigned int*")
    _check_err(_get_lib().NbxConvertWhiteouts(
        _c(layer_dir), 1 if use_user_xattr else 0, out,
    ))
    return out[0]


# ======================================================================
# Image store (in-memory — Python-side)
# ======================================================================

_IMAGE_STORE: dict[str, str] = {}
_IMAGE_STORE_LOCK = threading.Lock()


def py_image_store_get(image_name: str) -> str | None:
    with _IMAGE_STORE_LOCK:
        return _IMAGE_STORE.get(image_name)


def py_image_store_put(image_name: str, config_json: str) -> None:
    try:
        config = json.loads(config_json)
    except json.JSONDecodeError as e:
        raise ValueError(str(e)) from e
    with _IMAGE_STORE_LOCK:
        _IMAGE_STORE[image_name] = config_json
        image_id = config.get("image_id", "")
        if image_id and image_id != image_name:
            _IMAGE_STORE[image_id] = config_json


def py_image_store_clear() -> None:
    with _IMAGE_STORE_LOCK:
        _IMAGE_STORE.clear()


# ======================================================================
# Image reference parsing
# ======================================================================


def py_parse_image_ref(image: str) -> tuple[str, str, str]:
    d = _ffi.new("char**")
    r = _ffi.new("char**")
    t = _ffi.new("char**")
    _check_err(_get_lib().NbxParseImageRef(_c(image), d, r, t))
    result = (
        _ffi.string(d[0]).decode(),
        _ffi.string(r[0]).decode(),
        _ffi.string(t[0]).decode(),
    )
    lib = _get_lib()
    lib.NbxFree(d[0])
    lib.NbxFree(r[0])
    lib.NbxFree(t[0])
    return result


# ======================================================================
# Security
# ======================================================================


def py_landlock_abi_version() -> int:
    return _get_lib().NbxLandlockABIVersion()


def py_build_seccomp_bpf() -> bytes:
    buf = _ffi.new("void**")
    length = _ffi.new("int*")
    _get_lib().NbxBuildSeccompBPF(buf, length)
    result = _ffi.buffer(buf[0], length[0])[:]
    _get_lib().NbxFree(_ffi.cast("char*", buf[0]))
    return result


def py_apply_seccomp_filter() -> None:
    _check_err(_get_lib().NbxApplySeccompFilter())


def py_drop_capabilities(
    extra_keep: list[int] | None = None,
    extra_drop: list[int] | None = None,
) -> int:
    out = _ffi.new("unsigned int*")
    keep_json = _c(json.dumps(extra_keep or []))
    drop_json = _c(json.dumps(extra_drop or []))
    _check_err(_get_lib().NbxDropCapabilities(keep_json, drop_json, out))
    return out[0]


def py_apply_landlock(
    read_paths: list[str] | None = None,
    write_paths: list[str] | None = None,
    allowed_tcp_ports: list[int] | None = None,
    strict: bool = False,
) -> bool:
    out = _ffi.new("int*")
    _check_err(_get_lib().NbxApplyLandlock(
        _c(json.dumps(read_paths or [])),
        _c(json.dumps(write_paths or [])),
        _c(json.dumps(allowed_tcp_ports or [])),
        1 if strict else 0,
        out,
    ))
    return out[0] != 0


# ======================================================================
# Namespace operations
# ======================================================================


def py_nsenter_preexec(target_pid: int) -> None:
    # nsenter_preexec is called from Python's preexec_fn (after fork, before exec).
    # Can't use CFFI here because Go runtime in the forked child is broken.
    # This needs to be replaced with nsenter-exec subcommand in sandbox.popen().
    raise NotImplementedError(
        "py_nsenter_preexec not supported via FFI — use nsenter-exec subcommand"
    )


def py_userns_preexec(
    target_pid: int, rootfs: str, working_dir: str
) -> None:
    raise NotImplementedError(
        "py_userns_preexec not supported via FFI — use nsenter-exec subcommand"
    )


def py_userns_fixup_for_delete(userns_pid: int, dir_path: str) -> int:
    out = _ffi.new("unsigned int*")
    _check_err(_get_lib().NbxUsernFixupForDelete(userns_pid, _c(dir_path), out))
    return out[0]



# ======================================================================
# Spawn — via subprocess (fork not safe in Go c-shared)
# ======================================================================


class PySpawnResult:
    """Spawn result matching Rust PySpawnResult attributes."""

    __slots__ = (
        "pid", "stdin_fd", "stdout_fd", "signal_r_fd",
        "signal_w_fd_num", "master_fd", "pidfd", "err_r_fd",
    )

    def __init__(
        self, pid: int, stdin_fd: int, stdout_fd: int,
        signal_r_fd: int, signal_w_fd_num: int,
        master_fd: int | None, pidfd: int | None, err_r_fd: int,
    ) -> None:
        self.pid = pid
        self.stdin_fd = stdin_fd
        self.stdout_fd = stdout_fd
        self.signal_r_fd = signal_r_fd
        self.signal_w_fd_num = signal_w_fd_num
        self.master_fd = master_fd
        self.pidfd = pidfd
        self.err_r_fd = err_r_fd


_subreaper_set = False


def py_spawn_sandbox(config: dict) -> PySpawnResult:
    """Spawn via subprocess (Go binary). Fork is not safe in c-shared mode.

    Sets PR_SET_CHILD_SUBREAPER so that the sandbox shell (grandchild of
    the Go subprocess) gets reparented to this Python process when the Go
    subprocess exits. Without this, waitpid() on the shell PID fails.
    """
    global _subreaper_set
    if not _subreaper_set:
        import ctypes
        libc = ctypes.CDLL("libc.so.6", use_errno=True)
        libc.prctl(36, 1, 0, 0, 0)  # PR_SET_CHILD_SUBREAPER = 36
        _subreaper_set = True

    stdin_r, stdin_w = os.pipe2(os.O_CLOEXEC)
    stdout_r, stdout_w = os.pipe2(os.O_CLOEXEC)
    signal_r, signal_w = os.pipe2(os.O_CLOEXEC)
    err_r, err_w = os.pipe2(os.O_CLOEXEC)

    spawn_config = dict(config)
    spawn_config["pre_stdin_r"] = stdin_r
    spawn_config["pre_stdin_w"] = stdin_w
    spawn_config["pre_stdout_r"] = stdout_r
    spawn_config["pre_stdout_w"] = stdout_w
    spawn_config["pre_signal_r"] = signal_r
    spawn_config["pre_signal_w"] = signal_w
    spawn_config["pre_err_r"] = err_r
    spawn_config["pre_err_w"] = err_w

    if "subuid_range" in spawn_config and spawn_config["subuid_range"] is not None:
        spawn_config["subuid_range"] = list(spawn_config["subuid_range"])

    pass_fds = (stdin_r, stdin_w, stdout_r, stdout_w, signal_r, signal_w, err_r, err_w)
    inp = json.dumps(spawn_config).encode()

    proc = subprocess.Popen(
        [_bin(), "spawn"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        pass_fds=pass_fds,
    )
    go_stdout, go_stderr = proc.communicate(input=inp, timeout=30)

    os.close(stdin_r)
    os.close(stdout_w)
    os.close(err_w)

    if proc.returncode != 0:
        for fd in (stdin_w, stdout_r, signal_r, signal_w, err_r):
            try:
                os.close(fd)
            except OSError:
                pass
        raise OSError(f"nitrobox-core spawn failed: {go_stderr.decode().strip()}")

    result = json.loads(go_stdout.decode().strip())

    return PySpawnResult(
        pid=result["pid"],
        stdin_fd=stdin_w,
        stdout_fd=stdout_r,
        signal_r_fd=signal_r,
        signal_w_fd_num=signal_w,
        master_fd=result.get("master_fd"),
        pidfd=result.get("pidfd"),
        err_r_fd=err_r,
    )
