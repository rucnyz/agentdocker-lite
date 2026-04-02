"""Sandbox configuration, parsers, and Docker compatibility constructors."""

from __future__ import annotations

import logging
import os
import re
import shlex
import stat
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Linux capability name → number mapping (include/uapi/linux/capability.h)
CAP_NAME_TO_NUM: dict[str, int] = {
    "CHOWN": 0, "DAC_OVERRIDE": 1, "DAC_READ_SEARCH": 2, "FOWNER": 3,
    "FSETID": 4, "KILL": 5, "SETGID": 6, "SETUID": 7, "SETPCAP": 8,
    "LINUX_IMMUTABLE": 9, "NET_BIND_SERVICE": 10, "NET_BROADCAST": 11,
    "NET_ADMIN": 12, "NET_RAW": 13, "IPC_LOCK": 14, "IPC_OWNER": 15,
    "SYS_MODULE": 16, "SYS_RAWIO": 17, "SYS_CHROOT": 18, "SYS_PTRACE": 19,
    "SYS_PACCT": 20, "SYS_ADMIN": 21, "SYS_BOOT": 22, "SYS_NICE": 23,
    "SYS_RESOURCE": 24, "SYS_TIME": 25, "SYS_TTY_CONFIG": 26,
    "MKNOD": 27, "LEASE": 28, "AUDIT_WRITE": 29, "AUDIT_CONTROL": 30,
    "SETFCAP": 31, "MAC_OVERRIDE": 32, "MAC_ADMIN": 33, "SYSLOG": 34,
    "WAKE_ALARM": 35, "BLOCK_SUSPEND": 36, "AUDIT_READ": 37,
    "PERFMON": 38, "BPF": 39, "CHECKPOINT_RESTORE": 40,
}


def cap_names_to_numbers(names: list[str]) -> list[int]:
    """Convert capability names (e.g. ``["NET_RAW"]``) to numbers."""
    nums = []
    for name in names:
        n = name.upper().removeprefix("CAP_")
        if n in CAP_NAME_TO_NUM:
            nums.append(CAP_NAME_TO_NUM[n])
        else:
            logger.warning("Unknown capability: %s", name)
    return nums


# ====================================================================== #
#  Configuration                                                          #
# ====================================================================== #


def _parse_size(value: str) -> str:
    """Parse human-readable size to bytes string.

    Supports: "512m", "2g", "1.5G", "10mb", "1gb", "4096", "536870912".
    Returns the value as a string of bytes for cgroup writes.
    """
    value = value.strip()
    if not value:
        return value
    suffixes = {"k": 1024, "m": 1024**2, "g": 1024**3, "t": 1024**4}
    # Strip trailing "b"/"B" so "10mb" → "10m", "1gb" → "1g"
    lowered = value.lower()
    if len(lowered) >= 2 and lowered[-1] == "b" and lowered[-2] in suffixes:
        value = value[:-1]
    last = value[-1].lower()
    if last in suffixes:
        return str(int(float(value[:-1]) * suffixes[last]))
    return value


_CPU_PERIOD = 100_000  # 100ms in microseconds


def _parse_cpu_max(value: str) -> str:
    """Parse human-friendly CPU limit to cgroup v2 ``cpu.max`` format.

    Accepts:
      - ``"0.5"``  → ``"50000 100000"`` (50% of one core)
      - ``"2"``    → ``"200000 100000"`` (2 cores)
      - ``"50%"``  → ``"50000 100000"`` (50% of one core)
      - ``"50000 100000"`` → passed through unchanged
    """
    value = value.strip()
    if " " in value:
        return value
    if value.endswith("%"):
        fraction = float(value[:-1]) / 100.0
    else:
        fraction = float(value)
    quota = int(fraction * _CPU_PERIOD)
    if quota < 1:
        quota = 1
    return f"{quota} {_CPU_PERIOD}"


_IO_PARAM_RE = re.compile(r"((?:r|w)(?:bps|iops))=(\S+)")


def _parse_io_max(value: str) -> str:
    """Parse human-friendly I/O limit to cgroup v2 ``io.max`` format.

    Accepts:
      - ``"/dev/sda 10mb"``           → ``"MAJ:MIN wbps=10485760"``
      - ``"/dev/sda wbps=10mb"``      → ``"MAJ:MIN wbps=10485760"``
      - ``"/dev/sda rbps=5mb wbps=10mb"`` → ``"MAJ:MIN rbps=5242880 wbps=10485760"``
      - ``"259:0 wbps=10485760"``     → passed through unchanged

    When a bare size is given (no ``wbps=``/``rbps=`` prefix), it is
    treated as ``wbps=<size>``.
    """
    value = value.strip()
    parts = value.split()
    if len(parts) < 2:
        return value

    dev = parts[0]
    # Resolve /dev/xxx to MAJ:MIN
    if dev.startswith("/dev/"):
        dev_path = Path(dev)
        if dev_path.exists():
            st = dev_path.stat()
            if stat.S_ISBLK(st.st_mode):
                dev = f"{os.major(st.st_rdev)}:{os.minor(st.st_rdev)}"
        # If the device doesn't exist, leave as-is (will fail at cgroup write)

    rest = parts[1:]
    # Check if any part has key=value format
    has_params = any("=" in p for p in rest)
    if has_params:
        # Parse each key=value, converting sizes
        params = []
        for p in rest:
            m = _IO_PARAM_RE.match(p)
            if m:
                params.append(f"{m.group(1)}={_parse_size(m.group(2))}")
            else:
                params.append(p)
        return f"{dev} {' '.join(params)}"
    else:
        # Bare size: treat as wbps limit
        raw_size = _parse_size(rest[0])
        return f"{dev} wbps={raw_size}"


def _convert_cpu_shares(shares: int) -> int:
    """Convert Docker ``--cpu-shares`` to cgroup v2 ``cpu.weight``."""
    from nitrobox._core import py_convert_cpu_shares
    return int(py_convert_cpu_shares(shares))


# ------------------------------------------------------------------ #
#  Docker format converters (used by from_docker / from_docker_run)    #
# ------------------------------------------------------------------ #

def _convert_docker_volumes(raw: Any) -> list[str]:
    """Convert Docker SDK volume format to SandboxConfig volume list.

    Accepts:
      - dict: ``{"/host": {"bind": "/container", "mode": "ro"}}``
      - list: ``["/host:/container:ro"]`` (passed through)
    """
    if isinstance(raw, list):
        return raw
    result = []
    for host_path, spec in raw.items():
        bind = spec.get("bind", host_path) if isinstance(spec, dict) else spec
        mode = spec.get("mode", "rw") if isinstance(spec, dict) else "rw"
        result.append(f"{host_path}:{bind}:{mode}")
    return result


def _convert_docker_ports(raw: Any) -> list[str]:
    """Convert Docker SDK port format to SandboxConfig port_map list.

    Accepts:
      - dict: ``{"80/tcp": 8080}`` or ``{"80/tcp": [8080, 8081]}``
      - list: ``["8080:80"]`` (passed through)
    """
    if isinstance(raw, list):
        return raw
    result = []
    for container_spec, host_spec in raw.items():
        container_port = str(container_spec).split("/")[0]
        if host_spec is None:
            continue
        if isinstance(host_spec, (list, tuple)):
            for hp in host_spec:
                result.append(f"{hp}:{container_port}")
        else:
            result.append(f"{host_spec}:{container_port}")
    return result


def _convert_docker_env(raw: Any) -> dict[str, str]:
    """Convert Docker SDK environment format to dict.

    Accepts:
      - dict: ``{"KEY": "VALUE"}`` (passed through)
      - list: ``["KEY=VALUE"]``
    """
    if isinstance(raw, dict):
        return raw
    result = {}
    for entry in raw:
        k, _, v = entry.partition("=")
        result[k] = v
    return result


@dataclass
class SandboxConfig:
    """Configuration for a sandbox instance.

    Args:
        image: Path to a rootfs directory, or a Docker image name
            (e.g. ``"ubuntu:22.04"``).  If a Docker image name is given,
            it will be auto-exported to a rootfs directory on first use.
        working_dir: Initial working directory inside the sandbox.
        environment: Extra environment variables for commands.
        volumes: Volume mount specs as ``["host:container:mode", ...]``.
        fs_backend: Filesystem backend: ``"overlayfs"`` (default) or ``"btrfs"``.
        env_base_dir: Base directory for per-sandbox state.
        rootfs_cache_dir: Directory to cache auto-prepared rootfs images.
            Defaults to ``$XDG_CACHE_HOME/nitrobox/rootfs``
            (typically ``~/.cache/nitrobox/rootfs``).
        cpu_max: CPU limit.  Accepts a fraction of cores (``"0.5"`` = half
            a core, ``"2"`` = two cores), a percentage (``"50%"``), or the
            raw cgroup v2 ``cpu.max`` format (``"50000 100000"``).
        memory_max: Memory limit.  Accepts human-readable sizes
            (``"512m"``, ``"2g"``) or raw bytes (``"536870912"``).
        pids_max: cgroup v2 ``pids.max`` value.
        tty: Use a pseudo-terminal instead of pipes for command I/O.
            Enables ``write_stdin()`` for interactive programs.  Default
            ``False`` preserves the fast pipe-based path.
        net_isolate: Create a separate network namespace (loopback only).
            Default ``False`` inherits the host network.
        devices: Host device paths to bind-mount into the sandbox
            (e.g. ``["/dev/kvm"]``).
        seccomp: Enable seccomp-bpf filter to block dangerous syscalls
            (ptrace, mount, kexec, bpf, etc.). Default ``True``.
        hostname: Hostname inside the sandbox (UTS namespace).
            ``None`` uses the host's hostname.
        dns: Custom DNS servers (e.g. ``["8.8.8.8", "1.1.1.1"]``).
            Writes ``/etc/resolv.conf`` inside the sandbox.
            ``None`` inherits from host.
        read_only: Make the root filesystem read-only.  Writes are
            only allowed to volumes and tmpfs mounts.
        io_max: Disk I/O throttle.  Accepts human-readable forms like
            ``"/dev/sda 10mb"`` (10 MB/s write limit) or
            ``"/dev/sda rbps=5mb wbps=10mb"``.  Also accepts raw cgroup v2
            ``io.max`` format (``"259:0 wbps=10485760"``).
        net_ns: Path to an existing network namespace file to join
            (e.g. ``"/proc/123/ns/net"``).  The sandbox shares the
            network stack with other processes in the same netns.
            Mutually exclusive with ``net_isolate`` and ``port_map``.
        port_map: Port mappings as ``["host_port:container_port", ...]``.
            Requires ``pasta`` (from the ``passt`` package). Automatically
            enables network isolation with NAT'd internet access.
        shm_size: Size of ``/dev/shm`` tmpfs mount (e.g. ``"256m"``,
            ``"2g"``).  Default 256MB (generous for QEMU/PyTorch;
            tmpfs is demand-paged so unused space costs nothing).
        cpu_shares: Relative CPU weight (Docker ``--cpu-shares``).
            Converted to cgroup v2 ``cpu.weight``.  Default 1024 = normal.
        memory_swap: Total memory + swap limit (Docker semantics).
            ``"-1"`` for unlimited swap.  Converted to cgroup v2
            ``memory.swap.max`` (swap-only portion).
        tmpfs: Additional tmpfs mounts as ``["/run:size=100m", ...]``.
    """

    # -- Core --
    image: str = ""
    working_dir: str = "/"
    environment: dict[str, str] = field(default_factory=dict)
    volumes: list[str] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)
    tty: bool = False
    entrypoint: list[str] | None = None  # OCI ENTRYPOINT; auto-filled from image config
    hostname: str | None = None
    dns: list[str] | None = None

    # -- Filesystem --
    fs_backend: str = "overlayfs"
    env_base_dir: str = ""  # resolved in __post_init__
    rootfs_cache_dir: str = ""  # resolved in __post_init__
    read_only: bool = False
    tmpfs: list[str] = field(default_factory=list)
    shm_size: str | None = None

    # -- Resource limits (cgroup v2) --
    cpu_max: str | None = None
    memory_max: str | None = None
    pids_max: str | None = None
    io_max: str | None = None
    oom_score_adj: int | None = None
    cpuset_cpus: str | None = None
    cpu_shares: int | None = None  # Docker compat → cpu.weight
    memory_swap: str | None = None  # Docker compat → memory.swap.max
    ulimits: dict[str, tuple[int, int]] = field(default_factory=dict)

    # -- Networking --
    net_isolate: bool = False
    net_ns: str | None = None
    shared_userns: str | None = None
    port_map: list[str] | None = None
    ipv6: bool = False  # pasta IPv4-only by default

    # -- Security --
    seccomp: bool = True
    cap_add: list[str] = field(default_factory=list)
    writable_paths: list[str] | None = None  # Landlock
    readable_paths: list[str] | None = None  # Landlock
    allowed_ports: list[int] | None = None  # Landlock

    # -- Special modes --
    vm_mode: bool = False  # Relaxed init for QEMU/KVM workloads

    def __post_init__(self) -> None:
        if not self.env_base_dir:
            self.env_base_dir = f"/tmp/nitrobox_{os.getuid()}"
        if not self.rootfs_cache_dir:
            cache_home = os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
            self.rootfs_cache_dir = os.path.join(cache_home, "nitrobox", "rootfs")
        # Parse human-readable resource limits.
        if self.memory_max:
            self.memory_max = _parse_size(self.memory_max)
        if self.cpu_max:
            self.cpu_max = _parse_cpu_max(self.cpu_max)
        if self.io_max:
            self.io_max = _parse_io_max(self.io_max)
        if self.shm_size:
            self.shm_size = _parse_size(self.shm_size)
        if self.memory_swap:
            if self.memory_swap == "-1":
                self.memory_swap = "max"
            elif self.memory_swap == "0":
                self.memory_swap = None  # Docker: 0 means unset
            else:
                swap_total = int(_parse_size(self.memory_swap))
                mem_max = int(self.memory_max) if self.memory_max else 0
                self.memory_swap = str(max(0, swap_total - mem_max))
        # cap_add with privileged capabilities disables seccomp
        _privileged_caps = {"SYS_ADMIN", "ALL", "SYS_PTRACE", "SYS_RAWIO"}
        if self.cap_add and _privileged_caps & set(self.cap_add):
            self.seccomp = False

    # ------------------------------------------------------------------ #
    #  Docker compatibility constructors                                   #
    # ------------------------------------------------------------------ #

    @classmethod
    def from_docker(cls, image: str, **kwargs: Any) -> SandboxConfig:
        """Create a SandboxConfig from Docker Python SDK parameters.

        Accepts the same keyword arguments as
        ``docker.containers.run()`` and maps them to SandboxConfig
        fields.  Unsupported parameters are silently ignored with a
        logged warning.

        Example::

            # Before (Docker SDK):
            client.containers.run("python:3.11", cpus=0.5,
                mem_limit="512m", ports={"80/tcp": 8080})

            # After (nitrobox):
            cfg = SandboxConfig.from_docker("python:3.11", cpus=0.5,
                mem_limit="512m", ports={"80/tcp": 8080})
            sb = Sandbox(cfg)
        """
        cfg_kwargs: dict[str, Any] = {"image": image}

        # --- CPU ---
        if "cpus" in kwargs:
            cfg_kwargs["cpu_max"] = str(kwargs.pop("cpus"))
        if "cpuset_cpus" in kwargs:
            cfg_kwargs["cpuset_cpus"] = kwargs.pop("cpuset_cpus")

        # --- Memory ---
        if "mem_limit" in kwargs:
            v = kwargs.pop("mem_limit")
            cfg_kwargs["memory_max"] = str(v)
        if "pids_limit" in kwargs:
            cfg_kwargs["pids_max"] = str(kwargs.pop("pids_limit"))

        # --- Filesystem ---
        if "read_only" in kwargs:
            cfg_kwargs["read_only"] = kwargs.pop("read_only")
        if "working_dir" in kwargs:
            cfg_kwargs["working_dir"] = kwargs.pop("working_dir")

        # --- Volumes: dict or list ---
        if "volumes" in kwargs:
            raw = kwargs.pop("volumes")
            cfg_kwargs["volumes"] = _convert_docker_volumes(raw)

        # --- Ports: dict ---
        if "ports" in kwargs:
            raw = kwargs.pop("ports")
            cfg_kwargs["port_map"] = _convert_docker_ports(raw)

        # --- Environment: dict or list ---
        if "environment" in kwargs:
            raw = kwargs.pop("environment")
            cfg_kwargs["environment"] = _convert_docker_env(raw)

        # --- Networking ---
        if "hostname" in kwargs:
            cfg_kwargs["hostname"] = kwargs.pop("hostname")
        if "dns" in kwargs:
            cfg_kwargs["dns"] = kwargs.pop("dns")
        if "network_mode" in kwargs:
            mode = kwargs.pop("network_mode")
            if mode == "none":
                cfg_kwargs["net_isolate"] = True

        # --- Devices ---
        if "devices" in kwargs:
            raw = kwargs.pop("devices")
            cfg_kwargs["devices"] = [d.split(":")[0] for d in raw]

        # --- Security ---
        if "security_opt" in kwargs:
            opts = kwargs.pop("security_opt")
            for opt in opts:
                if opt in ("no-new-privileges", "no-new-privileges:true"):
                    pass  # already default
                if opt == "seccomp=unconfined":
                    cfg_kwargs["seccomp"] = False
        if "privileged" in kwargs:
            if kwargs.pop("privileged"):
                cfg_kwargs["seccomp"] = False
                cfg_kwargs["cap_add"] = list(CAP_NAME_TO_NUM.keys())

        # --- TTY ---
        if "tty" in kwargs:
            cfg_kwargs["tty"] = kwargs.pop("tty")

        # --- OOM ---
        if "oom_score_adj" in kwargs:
            cfg_kwargs["oom_score_adj"] = kwargs.pop("oom_score_adj")

        # --- Shared memory ---
        if "shm_size" in kwargs:
            cfg_kwargs["shm_size"] = str(kwargs.pop("shm_size"))

        # --- CPU shares ---
        if "cpu_shares" in kwargs:
            cfg_kwargs["cpu_shares"] = int(kwargs.pop("cpu_shares"))

        # --- Memory swap ---
        if "memswap_limit" in kwargs:
            cfg_kwargs["memory_swap"] = str(kwargs.pop("memswap_limit"))

        # --- Tmpfs ---
        if "tmpfs" in kwargs:
            raw = kwargs.pop("tmpfs")
            if isinstance(raw, dict):
                cfg_kwargs["tmpfs"] = [
                    f"{p}:{o}" if o else p for p, o in raw.items()
                ]
            elif isinstance(raw, list):
                cfg_kwargs["tmpfs"] = list(raw)

        # --- Capabilities ---
        if "cap_add" in kwargs:
            cfg_kwargs["cap_add"] = list(kwargs.pop("cap_add"))
        kwargs.pop("cap_drop", None)  # not mapped (we drop all by default)

        # --- Ulimits ---
        if "ulimits" in kwargs:
            raw = kwargs.pop("ulimits")
            # Docker SDK format: {"nofile": {"soft": 65536, "hard": 65536}}
            # or docker.types.Ulimit objects with .name, .soft, .hard
            ulimits: dict[str, tuple[int, int]] = {}
            if isinstance(raw, dict):
                for name, spec in raw.items():
                    if isinstance(spec, dict):
                        ulimits[name] = (spec.get("soft", 0), spec.get("hard", 0))
                    elif isinstance(spec, int):
                        ulimits[name] = (spec, spec)
                    else:
                        # docker.types.Ulimit object
                        ulimits[getattr(spec, "name", name)] = (
                            getattr(spec, "soft", 0), getattr(spec, "hard", 0),
                        )
            elif isinstance(raw, list):
                for item in raw:
                    ulimits[item.name] = (item.soft, item.hard)
            if ulimits:
                cfg_kwargs["ulimits"] = ulimits

        # --- Entrypoint ---
        if "entrypoint" in kwargs:
            ep = kwargs.pop("entrypoint")
            if isinstance(ep, str):
                ep = [ep]
            if ep:
                cfg_kwargs["entrypoint"] = list(ep)

        # Pop known-but-unsupported params silently
        _docker_ignored = {
            "command", "name", "detach", "remove",
            "auto_remove", "stdout", "stderr", "stream", "user",
            "labels", "log_config", "nano_cpus", "network",
            "network_disabled", "platform", "runtime",
            "stdin_open", "stop_signal",
            "mem_swappiness",
            "restart_policy", "healthcheck", "init", "ipc_mode",
            "isolation", "pid_mode", "publish_all_ports",
        }
        for key in _docker_ignored:
            kwargs.pop(key, None)

        if kwargs:
            logger.warning(
                "SandboxConfig.from_docker: ignoring unsupported params: %s",
                ", ".join(sorted(kwargs)),
            )

        return cls(**cfg_kwargs)

    @classmethod
    def from_docker_run(cls, cmd: str) -> SandboxConfig:
        """Create a SandboxConfig by parsing a ``docker run`` command string.

        Example::

            cfg = SandboxConfig.from_docker_run(
                "docker run --cpus=0.5 -m 512m -v /data:/data:ro "
                "-p 8080:80 --hostname worker python:3.11"
            )
            sb = Sandbox(cfg)
        """
        args = shlex.split(cmd)
        # Strip leading "docker" and "run"
        while args and args[0] in ("docker", "sudo"):
            args.pop(0)
        if args and args[0] == "run":
            args.pop(0)

        kwargs: dict[str, Any] = {}
        volumes: list[str] = []
        ports: list[str] = []
        env: dict[str, str] = {}
        devices: list[str] = []
        dns: list[str] = []
        image: str = ""

        i = 0
        while i < len(args):
            a = args[i]

            # Split --key=value
            if a.startswith("--") and "=" in a:
                key, _, val = a.partition("=")
                a = key
            else:
                val = ""

            def _take() -> str:
                """Return val if present, otherwise consume next arg."""
                nonlocal i
                if val:
                    return val
                i += 1
                return args[i]

            if a in ("-v", "--volume"):
                volumes.append(_take())
            elif a in ("-p", "--publish"):
                ports.append(_take())
            elif a in ("-e", "--env"):
                k, _, v = _take().partition("=")
                env[k] = v
            elif a == "--device":
                devices.append(_take().split(":")[0])
            elif a == "--dns":
                dns.append(_take())
            elif a in ("--cpus",):
                kwargs["cpu_max"] = _take()
            elif a in ("-m", "--memory"):
                kwargs["memory_max"] = _take()
            elif a == "--pids-limit":
                kwargs["pids_max"] = _take()
            elif a == "--cpuset-cpus":
                kwargs["cpuset_cpus"] = _take()
            elif a in ("-h", "--hostname"):
                kwargs["hostname"] = _take()
            elif a in ("-w", "--workdir"):
                kwargs["working_dir"] = _take()
            elif a == "--read-only":
                kwargs["read_only"] = True
            elif a == "--shm-size":
                kwargs["shm_size"] = _take()
            elif a == "--cpu-shares":
                kwargs["cpu_shares"] = int(_take())
            elif a == "--memory-swap":
                kwargs["memory_swap"] = _take()
            elif a == "--tmpfs":
                kwargs.setdefault("tmpfs", []).append(_take())
            elif a == "--cap-add":
                kwargs.setdefault("cap_add", []).append(_take())
            elif a == "--ulimit":
                # Format: "nofile=65536:65536" or "nofile=65536"
                spec = _take()
                name, _, limits = spec.partition("=")
                if ":" in limits:
                    soft, _, hard = limits.partition(":")
                    kwargs.setdefault("ulimits", {})[name] = (int(soft), int(hard))
                elif limits:
                    kwargs.setdefault("ulimits", {})[name] = (int(limits), int(limits))
            elif a == "--entrypoint":
                ep = _take()
                kwargs["entrypoint"] = [ep]
            elif a == "--privileged":
                kwargs["seccomp"] = False
                kwargs.setdefault("cap_add", []).extend(CAP_NAME_TO_NUM.keys())
            elif a == "--oom-score-adj":
                kwargs["oom_score_adj"] = int(_take())
            elif a == "--env-file":
                path = Path(_take())
                if path.exists():
                    for line in path.read_text().splitlines():
                        line = line.strip()
                        if line and not line.startswith("#") and "=" in line:
                            k, _, v = line.partition("=")
                            env[k.strip()] = v.strip()
            elif a == "--security-opt":
                opt = _take()
                if opt in ("seccomp=unconfined", "seccomp:unconfined"):
                    kwargs["seccomp"] = False
            elif a == "--network":
                if _take() == "none":
                    kwargs["net_isolate"] = True
            elif a == "--name":
                _take()  # skip
            elif a in ("-d", "--detach", "--rm", "-i", "--interactive",
                       "-t", "--tty", "--init"):
                if a in ("-t", "--tty"):
                    kwargs["tty"] = True
            elif a.startswith("-") and not a.startswith("--") and len(a) > 2:
                # Combined short boolean flags like -dit, -it
                _bool_flags = set("ditPq")
                if all(c in _bool_flags for c in a[1:]):
                    if "t" in a:
                        kwargs["tty"] = True
                else:
                    if i + 1 < len(args) and not args[i + 1].startswith("-"):
                        i += 1
            elif a.startswith("-"):
                # Unknown flag — skip its value if it looks like a flag+arg
                if not val and i + 1 < len(args) and not args[i + 1].startswith("-"):
                    i += 1
            else:
                # Positional: image (first), then command (rest ignored)
                if not image:
                    image = a
                # command args after image are ignored
            i += 1

        if not image:
            raise ValueError("No image found in docker run command")

        if volumes:
            kwargs["volumes"] = volumes
        if ports:
            kwargs["port_map"] = ports
        if env:
            kwargs["environment"] = env
        if devices:
            kwargs["devices"] = devices
        if dns:
            kwargs["dns"] = dns

        return cls(image=image, **kwargs)
