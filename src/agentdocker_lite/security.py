"""Kernel-level security hardening: seccomp-bpf + Landlock via ctypes.

Applied inside the sandbox child process before executing user commands.
No external libraries needed — direct syscall interface.

Inspired by github.com/multikernel/sandlock.
"""

from __future__ import annotations

import ctypes
import ctypes.util
import logging
import os

logger = logging.getLogger(__name__)

# ======================================================================
# libc
# ======================================================================

_libc_name = ctypes.util.find_library("c")
_libc = ctypes.CDLL(_libc_name, use_errno=True) if _libc_name else None

# prctl constants
PR_SET_NO_NEW_PRIVS = 38
PR_SET_SECCOMP = 22
SECCOMP_MODE_FILTER = 2
PR_CAPBSET_DROP = 24

# Docker default: capabilities to KEEP (everything else is dropped).
_DOCKER_DEFAULT_CAPS = {
    0,   # CHOWN
    1,   # DAC_OVERRIDE
    3,   # FOWNER
    4,   # FSETID
    5,   # KILL
    6,   # SETGID
    7,   # SETUID
    8,   # SETPCAP
    10,  # NET_BIND_SERVICE
    18,  # SYS_CHROOT
    27,  # MKNOD
    29,  # AUDIT_WRITE
    31,  # SETFCAP
}
# Total number of capabilities in current kernels.
_CAP_LAST_CAP = 41


def drop_capabilities() -> bool:
    """Drop all capabilities except Docker defaults from the bounding set.

    Uses prctl(PR_CAPBSET_DROP, cap) for each capability to drop.
    Must be called with CAP_SETPCAP in the effective set (available
    as fake root in user namespaces or as real root).
    """
    if not _libc:
        return False
    dropped = 0
    for cap in range(_CAP_LAST_CAP + 1):
        if cap not in _DOCKER_DEFAULT_CAPS:
            ret = _libc.prctl(PR_CAPBSET_DROP, cap, 0, 0, 0)
            if ret == 0:
                dropped += 1
    logger.debug("Dropped %d capabilities from bounding set", dropped)
    return dropped > 0


# ======================================================================
# seccomp-bpf: block dangerous syscalls
# ======================================================================

# BPF instruction encoding
BPF_LD = 0x00
BPF_W = 0x00
BPF_ABS = 0x20
BPF_JMP = 0x05
BPF_JEQ = 0x10
BPF_JSET = 0x40
BPF_K = 0x00
BPF_RET = 0x06

SECCOMP_RET_ALLOW = 0x7FFF0000
SECCOMP_RET_ERRNO = 0x00050000
SECCOMP_RET_KILL_PROCESS = 0x80000000
# ENOSYS causes glibc to fall back to the older syscall variant
SECCOMP_RET_ENOSYS = SECCOMP_RET_ERRNO | 38  # ENOSYS = 38

AUDIT_ARCH_X86_64 = 0xC000003E
AUDIT_ARCH_AARCH64 = 0xC00000B7

# --- Syscall tables (name → number) ---

_BLOCKED_X86_64: dict[str, int] = {
    # Privilege escalation / sandbox escape
    "ptrace": 101,
    "mount": 165,
    "umount2": 166,
    "pivot_root": 155,
    "unshare": 272,
    "setns": 308,
    # Kernel module loading
    "init_module": 175,
    "finit_module": 313,
    "delete_module": 176,
    "kexec_load": 246,
    "kexec_file_load": 320,
    # System state
    "reboot": 169,
    "sethostname": 170,
    "setdomainname": 171,
    "swapon": 167,
    "swapoff": 168,
    "acct": 163,
    # Process introspection escape
    "process_vm_readv": 310,
    "process_vm_writev": 311,
    "open_by_handle_at": 304,
    "name_to_handle_at": 303,
    # Dangerous subsystems
    "bpf": 321,
    "perf_event_open": 298,
    "userfaultfd": 323,
    # Key management
    "keyctl": 250,
    "add_key": 248,
    "request_key": 249,
    # I/O privilege (x86 only)
    "ioperm": 173,
    "iopl": 172,
    # io_uring — operations execute in kernel threads, bypass seccomp entirely
    "io_uring_setup": 425,
    "io_uring_enter": 426,
    "io_uring_register": 427,
}

# clone3 — flags are in a struct (not a register), so BPF can't inspect them.
# Return ENOSYS instead of EPERM so glibc falls back to clone(2), which we
# CAN filter by flag.  This allows threading (OpenBLAS, numpy) while still
# blocking namespace creation via clone(2) flag inspection.
_CLONE3_X86_64 = 435
_CLONE3_AARCH64 = 435

_BLOCKED_AARCH64: dict[str, int] = {
    "ptrace": 117,
    "mount": 40,
    "umount2": 39,
    "pivot_root": 41,
    "unshare": 97,
    "setns": 268,
    "init_module": 105,
    "finit_module": 273,
    "delete_module": 106,
    "kexec_load": 104,
    "kexec_file_load": 294,
    "reboot": 142,
    "sethostname": 161,
    "setdomainname": 162,
    "swapon": 224,
    "swapoff": 225,
    "acct": 89,
    "process_vm_readv": 270,
    "process_vm_writev": 271,
    "open_by_handle_at": 265,
    "name_to_handle_at": 264,
    "bpf": 280,
    "perf_event_open": 241,
    "userfaultfd": 282,
    "keyctl": 219,
    "add_key": 217,
    "request_key": 218,
    "io_uring_setup": 425,
    "io_uring_enter": 426,
    "io_uring_register": 427,
}

# clone(2) namespace flags — block these via arg-level filtering
_CLONE_NS_FLAGS = (
    0x00020000 |  # CLONE_NEWNS
    0x04000000 |  # CLONE_NEWUTS
    0x08000000 |  # CLONE_NEWIPC
    0x10000000 |  # CLONE_NEWUSER
    0x20000000 |  # CLONE_NEWPID
    0x40000000 |  # CLONE_NEWNET
    0x00000080    # CLONE_NEWCGROUP
)

# clone syscall numbers
_CLONE_X86_64 = 56
_CLONE_AARCH64 = 220

# ioctl TIOCSTI — terminal injection
_IOCTL_X86_64 = 16
_IOCTL_AARCH64 = 29
_TIOCSTI = 0x5412


class _SockFilterInsn(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilterInsn)),
    ]


def _bpf_stmt(code: int, k: int) -> _SockFilterInsn:
    return _SockFilterInsn(code=code, jt=0, jf=0, k=k)


def _bpf_jump(code: int, k: int, jt: int, jf: int) -> _SockFilterInsn:
    return _SockFilterInsn(code=code, jt=jt, jf=jf, k=k)


def build_seccomp_bpf() -> bytes | None:
    """Build seccomp BPF bytecode and return as raw bytes.

    Returns None if the architecture is unsupported.
    Used by the adl-seccomp static helper binary (rootful mode).
    """
    machine = os.uname().machine
    if machine == "x86_64":
        arch, blocked = AUDIT_ARCH_X86_64, _BLOCKED_X86_64
        clone_nr, ioctl_nr = _CLONE_X86_64, _IOCTL_X86_64
        clone3_nr = _CLONE3_X86_64
    elif machine in ("aarch64", "arm64"):
        arch, blocked = AUDIT_ARCH_AARCH64, _BLOCKED_AARCH64
        clone_nr, ioctl_nr = _CLONE_AARCH64, _IOCTL_AARCH64
        clone3_nr = _CLONE3_AARCH64
    else:
        return None

    syscall_nrs = sorted(blocked.values())
    insns: list[_SockFilterInsn] = []

    # 1. Check architecture
    insns.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 4))         # load arch
    insns.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0))
    insns.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))

    # 2. clone(2): allow threads, block namespace creation
    insns.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0))         # load syscall nr
    insns.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, clone_nr, 0, 4))
    insns.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16))        # load arg0 (flags)
    insns.append(_bpf_jump(BPF_JMP | BPF_JSET | BPF_K, _CLONE_NS_FLAGS, 0, 1))
    insns.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1))  # EPERM
    insns.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0))         # reload syscall nr

    # 3. clone3: return ENOSYS so glibc falls back to clone(2)
    insns.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, clone3_nr, 0, 1))
    insns.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ENOSYS))

    # 4. ioctl(TIOCSTI): block terminal injection
    insns.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, ioctl_nr, 0, 4))
    insns.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16))        # load arg1
    insns.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, _TIOCSTI, 0, 1))
    insns.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1))
    insns.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0))         # reload syscall nr

    # 5. Block dangerous syscalls
    for i, nr in enumerate(syscall_nrs):
        insns.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, len(syscall_nrs) - i, 0))
    insns.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))
    insns.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1))
    arr = (_SockFilterInsn * len(insns))(*insns)
    return bytes(arr)


def apply_seccomp_filter() -> bool:
    """Apply a seccomp-bpf filter that blocks dangerous syscalls.

    - Wrong arch (x32/compat) → KILL_PROCESS
    - clone() with namespace flags → EPERM
    - clone3() → ENOSYS (glibc falls back to clone, which we can filter)
    - ioctl(TIOCSTI) → EPERM
    - Blocked syscalls → EPERM
    - Everything else → ALLOW
    """
    if not _libc:
        logger.warning("seccomp: libc not found, skipping")
        return False

    machine = os.uname().machine
    if machine == "x86_64":
        arch = AUDIT_ARCH_X86_64
        blocked = _BLOCKED_X86_64
        clone_nr = _CLONE_X86_64
        ioctl_nr = _IOCTL_X86_64
        clone3_nr = _CLONE3_X86_64
    elif machine in ("aarch64", "arm64"):
        arch = AUDIT_ARCH_AARCH64
        blocked = _BLOCKED_AARCH64
        clone_nr = _CLONE_AARCH64
        ioctl_nr = _IOCTL_AARCH64
        clone3_nr = _CLONE3_AARCH64
    else:
        logger.warning("seccomp: unsupported arch %s, skipping", machine)
        return False

    syscall_nrs = sorted(blocked.values())
    insns: list[_SockFilterInsn] = []

    # --- 1. Arch check: KILL on wrong arch (prevents x32 ABI bypass) ---
    insns.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 4))  # load arch
    insns.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, arch, 1, 0))
    insns.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS))

    # --- 2. Load syscall number ---
    insns.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0))

    # --- 3. clone(2): allow fork/threads, block NS flags ---
    insns.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, clone_nr, 0, 4))
    insns.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16))  # load arg0 (flags)
    insns.append(_bpf_jump(BPF_JMP | BPF_JSET | BPF_K, _CLONE_NS_FLAGS, 0, 1))
    insns.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1))  # EPERM
    insns.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0))  # reload syscall nr

    # --- 4. clone3: ENOSYS → glibc falls back to clone(2) ---
    insns.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, clone3_nr, 0, 1))
    insns.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ENOSYS))

    # --- 5. ioctl(TIOCSTI): block terminal injection ---
    insns.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, ioctl_nr, 0, 4))
    insns.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16))  # arg0 = ioctl cmd
    insns.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, _TIOCSTI, 0, 1))
    insns.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1))
    insns.append(_bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0))  # reload syscall nr

    # --- 6. Simple blocklist ---
    for i, nr in enumerate(syscall_nrs):
        jump_to_eperm = len(syscall_nrs) - i
        insns.append(_bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, nr, jump_to_eperm, 0))

    # --- 7. Default: allow ---
    insns.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW))
    # --- 8. Block: EPERM ---
    insns.append(_bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1))

    # Install filter
    arr = (_SockFilterInsn * len(insns))(*insns)
    prog = _SockFprog(len=len(insns), filter=arr)

    ret = _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
    if ret != 0:
        logger.warning("seccomp: prctl(NO_NEW_PRIVS) failed")
        return False

    ret = _libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.byref(prog))
    if ret != 0:
        logger.warning("seccomp: prctl(SET_SECCOMP) failed: errno=%d", ctypes.get_errno())
        return False

    logger.debug("seccomp: blocked %d syscalls + clone NS flags + ioctl TIOCSTI", len(blocked))
    return True


# ======================================================================
# Landlock: filesystem + network restrictions
# ======================================================================

# Landlock syscall numbers (same on x86_64 and aarch64)
LANDLOCK_CREATE_RULESET = 444
LANDLOCK_ADD_RULE = 445
LANDLOCK_RESTRICT_SELF = 446

# Flags for landlock_create_ruleset
LANDLOCK_CREATE_RULESET_VERSION = 1 << 0
LANDLOCK_CREATE_RULESET_ERRATA = 1 << 1   # ABI v7 (kernel 6.15)

# FS access flags by ABI version
LANDLOCK_ACCESS_FS_EXECUTE = 1 << 0
LANDLOCK_ACCESS_FS_WRITE_FILE = 1 << 1
LANDLOCK_ACCESS_FS_READ_FILE = 1 << 2
LANDLOCK_ACCESS_FS_READ_DIR = 1 << 3
LANDLOCK_ACCESS_FS_REMOVE_DIR = 1 << 4
LANDLOCK_ACCESS_FS_REMOVE_FILE = 1 << 5
LANDLOCK_ACCESS_FS_MAKE_CHAR = 1 << 6
LANDLOCK_ACCESS_FS_MAKE_DIR = 1 << 7
LANDLOCK_ACCESS_FS_MAKE_REG = 1 << 8
LANDLOCK_ACCESS_FS_MAKE_SOCK = 1 << 9
LANDLOCK_ACCESS_FS_MAKE_FIFO = 1 << 10
LANDLOCK_ACCESS_FS_MAKE_BLOCK = 1 << 11
LANDLOCK_ACCESS_FS_MAKE_SYM = 1 << 12
LANDLOCK_ACCESS_FS_REFER = 1 << 13       # ABI v2 (kernel 5.19)
LANDLOCK_ACCESS_FS_TRUNCATE = 1 << 14    # ABI v3 (kernel 6.2)
LANDLOCK_ACCESS_FS_IOCTL_DEV = 1 << 15   # ABI v5 (kernel 6.10)

# Network access flags (ABI v4, kernel 6.7)
LANDLOCK_ACCESS_NET_BIND_TCP = 1 << 0
LANDLOCK_ACCESS_NET_CONNECT_TCP = 1 << 1

# Scope flags (ABI v6, kernel 6.12)
LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET = 1 << 0
LANDLOCK_SCOPE_SIGNAL = 1 << 1

LANDLOCK_RULE_PATH_BENEATH = 1
LANDLOCK_RULE_NET_PORT = 2

# Flags for landlock_restrict_self
LANDLOCK_RESTRICT_SELF_LOG_SAME_EXEC_OFF = 1 << 0   # ABI v7, kernel 6.15
LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON = 1 << 1     # ABI v7
LANDLOCK_RESTRICT_SELF_LOG_SUBDOMAINS_OFF = 1 << 2  # ABI v7
LANDLOCK_RESTRICT_SELF_TSYNC = 1 << 3               # ABI v8, kernel 6.18

# Permission sets
FS_READ = (
    LANDLOCK_ACCESS_FS_EXECUTE |
    LANDLOCK_ACCESS_FS_READ_FILE |
    LANDLOCK_ACCESS_FS_READ_DIR
)
_FS_WRITE_V1 = (
    FS_READ |
    LANDLOCK_ACCESS_FS_WRITE_FILE |
    LANDLOCK_ACCESS_FS_REMOVE_DIR |
    LANDLOCK_ACCESS_FS_REMOVE_FILE |
    LANDLOCK_ACCESS_FS_MAKE_CHAR |
    LANDLOCK_ACCESS_FS_MAKE_DIR |
    LANDLOCK_ACCESS_FS_MAKE_REG |
    LANDLOCK_ACCESS_FS_MAKE_SOCK |
    LANDLOCK_ACCESS_FS_MAKE_FIFO |
    LANDLOCK_ACCESS_FS_MAKE_BLOCK |
    LANDLOCK_ACCESS_FS_MAKE_SYM
)


def _syscall(nr: int, *args) -> int:
    if not _libc:
        return -1
    return _libc.syscall(nr, *[ctypes.c_ulong(a) for a in args])


def _landlock_abi_version() -> int:
    """Query the kernel's Landlock ABI version. Returns 0 if unavailable."""
    ret = _syscall(LANDLOCK_CREATE_RULESET, 0, 0, LANDLOCK_CREATE_RULESET_VERSION)
    return ret if ret > 0 else 0


def _fs_write_mask(abi: int) -> int:
    """Build FS write mask adjusted for kernel ABI version."""
    mask = _FS_WRITE_V1
    if abi >= 2:
        mask |= LANDLOCK_ACCESS_FS_REFER
    if abi >= 3:
        mask |= LANDLOCK_ACCESS_FS_TRUNCATE
    if abi >= 5:
        mask |= LANDLOCK_ACCESS_FS_IOCTL_DEV
    return mask


class _LandlockRulesetAttr(ctypes.Structure):
    _fields_ = [
        ("handled_access_fs", ctypes.c_uint64),
        ("handled_access_net", ctypes.c_uint64),
        ("scoped", ctypes.c_uint64),  # ABI v6
    ]


class _LandlockPathBeneathAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("parent_fd", ctypes.c_int),
    ]


class _LandlockNetPortAttr(ctypes.Structure):
    _fields_ = [
        ("allowed_access", ctypes.c_uint64),
        ("port", ctypes.c_uint64),
    ]


def _add_path_rule(ruleset_fd: int, path: str, access: int) -> None:
    if not os.path.exists(path):
        return
    flags = os.O_PATH | os.O_CLOEXEC
    if os.path.isdir(path):
        flags |= os.O_DIRECTORY
    fd = os.open(path, flags)
    try:
        rule = _LandlockPathBeneathAttr(allowed_access=access, parent_fd=fd)
        _syscall(LANDLOCK_ADD_RULE, ruleset_fd, LANDLOCK_RULE_PATH_BENEATH,
                 ctypes.addressof(rule), 0)
    finally:
        os.close(fd)


def apply_landlock(
    read_paths: list[str] | None = None,
    write_paths: list[str] | None = None,
    allowed_tcp_ports: list[int] | None = None,
    strict: bool = False,
) -> bool:
    """Apply Landlock filesystem + network restrictions.

    Args:
        read_paths: Paths allowed for read + execute.
        write_paths: Paths allowed for read + write + execute.
        allowed_tcp_ports: TCP ports allowed for connect (None = no restriction).
        strict: If True, raise RuntimeError on failure instead of returning False.
    """
    if not _libc:
        if strict:
            raise RuntimeError("Landlock: libc not found")
        return False

    abi = _landlock_abi_version()
    if abi == 0:
        msg = "Landlock not available (kernel < 5.13 or CONFIG_SECURITY_LANDLOCK=n)"
        if strict:
            raise RuntimeError(msg)
        logger.debug(msg)
        return False

    logger.debug("Landlock ABI version: %d", abi)

    # Build handled_access_fs mask adjusted for ABI
    fs_write = _fs_write_mask(abi)
    handled_fs = fs_write  # We handle all FS access types we know about

    handled_net = 0
    if allowed_tcp_ports is not None and abi >= 4:
        handled_net = LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP

    scoped = 0
    if abi >= 6:
        scoped = LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL

    attr = _LandlockRulesetAttr(
        handled_access_fs=handled_fs,
        handled_access_net=handled_net,
        scoped=scoped,
    )

    ruleset_fd = _syscall(
        LANDLOCK_CREATE_RULESET, ctypes.addressof(attr), ctypes.sizeof(attr), 0,
    )
    if ruleset_fd < 0:
        msg = f"landlock_create_ruleset failed: errno={ctypes.get_errno()}"
        if strict:
            raise RuntimeError(msg)
        logger.warning(msg)
        return False

    try:
        for path in (read_paths or []):
            _add_path_rule(ruleset_fd, path, FS_READ)

        for path in (write_paths or []):
            _add_path_rule(ruleset_fd, path, fs_write)

        for port in (allowed_tcp_ports or []):
            if abi < 4:
                break
            rule = _LandlockNetPortAttr(
                allowed_access=LANDLOCK_ACCESS_NET_CONNECT_TCP, port=port,
            )
            _syscall(LANDLOCK_ADD_RULE, ruleset_fd, LANDLOCK_RULE_NET_PORT,
                     ctypes.addressof(rule), 0)

        _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)

        restrict_flags = 0
        if abi >= 7:
            restrict_flags |= LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON
        if abi >= 8:
            restrict_flags |= LANDLOCK_RESTRICT_SELF_TSYNC

        ret = _syscall(LANDLOCK_RESTRICT_SELF, ruleset_fd, restrict_flags)
        if ret < 0 and (restrict_flags & LANDLOCK_RESTRICT_SELF_TSYNC):
            # TSYNC not supported — retry without it.
            restrict_flags &= ~LANDLOCK_RESTRICT_SELF_TSYNC
            ret = _syscall(LANDLOCK_RESTRICT_SELF, ruleset_fd, restrict_flags)
        if ret < 0:
            msg = f"landlock_restrict_self failed: errno={ctypes.get_errno()}"
            if strict:
                raise RuntimeError(msg)
            logger.warning(msg)
            return False
    finally:
        os.close(ruleset_fd)

    logger.debug("Landlock (ABI v%d): %d read, %d write paths, %d TCP ports, "
                 "scoped=%d, restrict_flags=%d",
                 abi, len(read_paths or []), len(write_paths or []),
                 len(allowed_tcp_ports or []), scoped, restrict_flags)
    return True
