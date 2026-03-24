"""Base classes for agentdocker-lite sandboxes."""

from __future__ import annotations

import abc
import logging
import os
import re
import shlex
import shutil
import stat
import subprocess
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from agentdocker_lite._shell import _PersistentShell

logger = logging.getLogger(__name__)


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
    """Convert Docker ``--cpu-shares`` to cgroup v2 ``cpu.weight``.

    Docker uses a range of 2-262144 (default 1024).
    cgroup v2 uses 1-10000 (default 100).
    """
    return max(1, min(10000, 1 + ((shares - 2) * 9999) // 262142))


# ------------------------------------------------------------------ #
#  Docker format converters (used by from_docker / from_docker_run)    #
# ------------------------------------------------------------------ #

def _convert_docker_volumes(raw) -> list[str]:
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


def _convert_docker_ports(raw) -> list[str]:
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


def _convert_docker_env(raw) -> dict[str, str]:
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
            Defaults to ``$XDG_CACHE_HOME/agentdocker_lite/rootfs``
            (typically ``~/.cache/agentdocker_lite/rootfs``).
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

    image: str = ""
    working_dir: str = "/"
    environment: dict[str, str] = field(default_factory=dict)
    volumes: list[str] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)
    fs_backend: str = "overlayfs"
    env_base_dir: str = ""  # resolved in __post_init__
    rootfs_cache_dir: str = ""  # resolved in __post_init__
    cpu_max: Optional[str] = None
    memory_max: Optional[str] = None
    pids_max: Optional[str] = None
    io_max: Optional[str] = None
    tty: bool = False
    net_isolate: bool = False
    seccomp: bool = True
    hostname: Optional[str] = None
    dns: Optional[list[str]] = None
    read_only: bool = False
    net_ns: Optional[str] = None
    shared_userns: Optional[str] = None
    port_map: Optional[list[str]] = None
    ipv6: bool = False  # pasta IPv4-only by default; localhost works.
    # Set True for IPv6 networking (localhost may fail — use 127.0.0.1).
    writable_paths: Optional[list[str]] = None
    readable_paths: Optional[list[str]] = None
    allowed_ports: Optional[list[int]] = None
    oom_score_adj: Optional[int] = None
    cpuset_cpus: Optional[str] = None
    shm_size: Optional[str] = None
    cpu_shares: Optional[int] = None
    memory_swap: Optional[str] = None
    tmpfs: list[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.env_base_dir:
            self.env_base_dir = f"/tmp/agentdocker_lite_{os.getuid()}"
        if not self.rootfs_cache_dir:
            cache_home = os.environ.get("XDG_CACHE_HOME", os.path.expanduser("~/.cache"))
            self.rootfs_cache_dir = os.path.join(cache_home, "agentdocker_lite", "rootfs")
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

    # ------------------------------------------------------------------ #
    #  Docker compatibility constructors                                   #
    # ------------------------------------------------------------------ #

    @classmethod
    def from_docker(cls, image: str, **kwargs) -> SandboxConfig:
        """Create a SandboxConfig from Docker Python SDK parameters.

        Accepts the same keyword arguments as
        ``docker.containers.run()`` and maps them to SandboxConfig
        fields.  Unsupported parameters are silently ignored with a
        logged warning.

        Example::

            # Before (Docker SDK):
            client.containers.run("python:3.11", cpus=0.5,
                mem_limit="512m", ports={"80/tcp": 8080})

            # After (agentdocker-lite):
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

        # Pop known-but-unsupported params silently
        _docker_ignored = {
            "command", "entrypoint", "name", "detach", "remove",
            "auto_remove", "stdout", "stderr", "stream", "user",
            "labels", "log_config", "nano_cpus", "network",
            "network_disabled", "platform", "runtime",
            "stdin_open", "stop_signal", "ulimits",
            "mem_swappiness", "cap_add", "cap_drop",
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
            elif a == "--privileged":
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


# ====================================================================== #
#  Abstract base                                                          #
# ====================================================================== #


class SandboxBase(abc.ABC):
    """Abstract base class for sandbox implementations.

    Concrete shared methods (run, read_file, write_file, etc.) delegate
    to ``self._persistent_shell``.  Subclasses must implement
    ``reset()`` and ``delete()`` as well as their own ``__init__``.
    """

    # -- global registry for atexit cleanup -------------------------------- #
    _live_instances: list[SandboxBase] = []
    _atexit_registered: bool = False

    @classmethod
    def _register(cls, instance: SandboxBase) -> None:
        """Track a live sandbox for atexit cleanup."""
        cls._live_instances.append(instance)
        if not cls._atexit_registered:
            import atexit
            atexit.register(cls._atexit_cleanup)
            cls._atexit_registered = True

    @classmethod
    def _unregister(cls, instance: SandboxBase) -> None:
        """Remove a sandbox from the live registry."""
        try:
            cls._live_instances.remove(instance)
        except ValueError:
            pass

    @classmethod
    def _atexit_cleanup(cls) -> None:
        """Delete all live sandboxes on process exit."""
        for sb in list(cls._live_instances):
            try:
                sb.delete()
            except Exception:
                pass
        cls._live_instances.clear()

    # -- attributes set by subclass __init__ ------------------------------- #
    _config: SandboxConfig
    _name: str
    _rootfs: Path
    _env_dir: Path
    _shell: str
    _cached_env: dict[str, str]
    _persistent_shell: _PersistentShell
    _bg_handles: dict[str, str]
    _userns: bool

    # ------------------------------------------------------------------ #
    #  Public API                                                          #
    # ------------------------------------------------------------------ #

    def run(
        self, command: str | list[str], timeout: Optional[int] = None
    ) -> tuple[str, int]:
        """Run a command inside the sandbox.

        Args:
            command: Shell command string or list of arguments.
            timeout: Timeout in seconds (None = no timeout).

        Returns:
            ``(stdout_output, exit_code)`` tuple.
        """
        t0 = time.monotonic()
        if isinstance(command, list):
            cmd_str = shlex.join(command)
        else:
            cmd_str = command

        output, exit_code = self._persistent_shell.execute(cmd_str, timeout=timeout)

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.debug("cmd (%.1fms exit=%d): %.200s", elapsed_ms, exit_code, cmd_str)
        return output, exit_code

    async def arun(
        self, command: str | list[str], timeout: Optional[int] = None
    ) -> tuple[str, int]:
        """Async version of :meth:`run`."""
        import asyncio
        return await asyncio.to_thread(self.run, command, timeout)

    async def areset(self) -> None:
        """Async version of :meth:`reset`."""
        import asyncio
        await asyncio.to_thread(self.reset)

    async def adelete(self) -> None:
        """Async version of :meth:`delete`."""
        import asyncio
        await asyncio.to_thread(self.delete)

    def write_stdin(self, data: str | bytes) -> None:
        """Write raw data to the sandbox shell's stdin (PTY mode only).

        Use this to send input to interactive programs.  Requires
        ``SandboxConfig(tty=True)``.

        Example::

            sb.run("cat")         # blocks waiting for stdin
            sb.write_stdin("hello\\n")
        """
        self._persistent_shell.write_stdin(data)

    # -- background processes ---------------------------------------------- #

    def run_background(self, command: str | list[str]) -> str:
        """Start a command in the background inside the sandbox.

        Returns a handle string to use with :meth:`check_background` and
        :meth:`stop_background`.  The command runs asynchronously; the
        persistent shell remains available for ``run()`` calls.

        Example::

            handle = sb.run_background("python -m http.server 8080")
            time.sleep(1)
            output, running = sb.check_background(handle)
        """
        if isinstance(command, list):
            command = shlex.join(command)
        handle = uuid.uuid4().hex[:8]
        out_file = f"/tmp/.bg_{handle}.out"
        pid_file = f"/tmp/.bg_{handle}.pid"
        self.run(
            f"nohup bash -c {shlex.quote(command)} > {out_file} 2>&1 & echo $! > {pid_file}"
        )
        pid_str, _ = self.run(f"cat {pid_file} 2>/dev/null")
        self._bg_handles[handle] = pid_str.strip()
        return handle

    def check_background(self, handle: str) -> tuple[str, bool]:
        """Check a background process started with :meth:`run_background`.

        Returns ``(output_so_far, is_running)`` tuple.
        """
        out_file = f"/tmp/.bg_{handle}.out"
        pid = self._bg_handles.get(handle, "")
        output, _ = self.run(f"cat {out_file} 2>/dev/null")
        if pid:
            _, ec = self.run(f"kill -0 {pid} 2>/dev/null")
            running = ec == 0
        else:
            running = False
        return output, running

    def list_background(self) -> dict[str, dict]:
        """List all background processes and their status.

        Returns a dict mapping handle to ``{"pid": str, "running": bool}``.
        """
        result = {}
        for handle, pid in self._bg_handles.items():
            if pid:
                _, ec = self.run(f"kill -0 {pid} 2>/dev/null")
                running = ec == 0
            else:
                running = False
            result[handle] = {"pid": pid, "running": running}
        return result

    def stop_background(self, handle: str) -> str:
        """Stop a background process and return its final output."""
        out_file = f"/tmp/.bg_{handle}.out"
        pid_file = f"/tmp/.bg_{handle}.pid"
        pid = self._bg_handles.pop(handle, "")
        if pid:
            self.run(f"kill {pid} 2>/dev/null; kill -9 {pid} 2>/dev/null")
        output, _ = self.run(f"cat {out_file} 2>/dev/null")
        self.run(f"rm -f {out_file} {pid_file}")
        return output

    # -- interactive processes --------------------------------------------- #

    def popen(
        self,
        command: str | list[str],
        **kwargs,
    ) -> subprocess.Popen:
        """Start an interactive process inside the sandbox with stdio pipes.

        Unlike :meth:`run` (which aggregates output) and :meth:`run_background`
        (which redirects to a file), this returns a :class:`subprocess.Popen`
        object with direct ``stdin``/``stdout``/``stderr`` pipes for
        bidirectional communication.

        Useful for long-running interactive processes like LSP servers, REPLs,
        or any protocol that requires streaming stdin/stdout (e.g. JSON-RPC).

        The process runs inside the sandbox's namespace (PID + mount isolation)
        and chroot, sharing the same filesystem view as :meth:`run`.

        Args:
            command: Command string or argument list to execute.
            **kwargs: Additional keyword arguments passed to
                :class:`subprocess.Popen` (e.g. ``stderr=subprocess.PIPE``).
                ``stdin``, ``stdout``, and ``env`` are set automatically
                unless explicitly overridden.

        Returns:
            :class:`subprocess.Popen` with ``stdin`` and ``stdout`` pipes.

        Example::

            # Start an LSP server inside the sandbox
            proc = sb.popen(["pyright-langserver", "--stdio"])
            proc.stdin.write(b'...')  # send JSON-RPC request
            proc.stdin.flush()
            response = proc.stdout.readline()  # read response
            proc.terminate()
        """
        if isinstance(command, list):
            cmd_args = command
        else:
            cmd_args = ["bash", "-c", command]

        shell_pid = self._persistent_shell._process.pid

        if getattr(self, "_userns", False):
            # User namespace mode: use os.setns() in preexec_fn to enter
            # namespaces directly.  Avoids nsenter's setgroups() issue
            # (user namespaces require setgroups=deny, but nsenter calls it).
            _rootfs = str(self._rootfs)
            _wd = self._config.working_dir or "/"

            def _userns_preexec() -> None:
                # Enter user namespace first (grants all capabilities)
                with open(f"/proc/{shell_pid}/ns/user") as f:
                    os.setns(f.fileno(), 0)
                # Enter mount namespace (overlayfs visible here)
                with open(f"/proc/{shell_pid}/ns/mnt") as f:
                    os.setns(f.fileno(), 0)
                # Chroot + chdir into the sandbox
                os.chroot(_rootfs)
                os.chdir(_wd)

            defaults = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "env": self._cached_env,
            }
            defaults.update(kwargs)

            proc = subprocess.Popen(cmd_args, preexec_fn=_userns_preexec, **defaults)
        else:
            # Rootful mode: use nsenter into the sandbox's namespaces.
            # After pivot_root, the mount namespace root IS the rootfs,
            # so no chroot is needed — just enter the namespace.
            full_cmd = [
                "nsenter",
                f"--target={shell_pid}",
                "--pid",
                "--mount",
                "--root",
                "--wd=/",
                "--",
            ] + cmd_args

            defaults = {
                "stdin": subprocess.PIPE,
                "stdout": subprocess.PIPE,
                "stderr": subprocess.PIPE,
                "env": self._cached_env,
            }
            defaults.update(kwargs)

            proc = subprocess.Popen(full_cmd, **defaults)

        logger.debug("popen pid=%d in sandbox: %s", proc.pid, cmd_args)
        return proc

    # -- file operations --------------------------------------------------- #

    def copy_to(self, local_path: str, container_path: str) -> None:
        """Copy a file from host into the sandbox."""
        host_dst = self._host_path_write(container_path)
        host_dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(local_path, str(host_dst))

    def copy_from(self, container_path: str, local_path: str) -> None:
        """Copy a file from the sandbox to host."""
        host_src = self._host_path(container_path)
        if not host_src.exists():
            raise FileNotFoundError(
                f"File {container_path} does not exist in the sandbox."
            )
        os.makedirs(os.path.dirname(local_path), exist_ok=True)
        shutil.copy2(str(host_src), local_path)

    def read_file(self, container_path: str) -> str:
        """Read file content from the sandbox."""
        host_path = self._host_path(container_path)
        if not host_path.exists():
            raise FileNotFoundError(
                f"File {container_path} does not exist in the sandbox."
            )
        return host_path.read_text(encoding="latin-1")

    def write_file(self, container_path: str, content: str | bytes) -> None:
        """Write content to a file inside the sandbox."""
        host_path = self._host_path_write(container_path)
        host_path.parent.mkdir(parents=True, exist_ok=True)
        if isinstance(content, bytes):
            host_path.write_bytes(content)
        else:
            host_path.write_text(content)

    @property
    def rootfs(self) -> Path:
        """Path to the sandbox's rootfs on the host."""
        return self._rootfs

    # -- cgroup pressure (PSI) --------------------------------------------- #

    def pressure(self) -> dict[str, dict[str, float]]:
        """Read cgroup v2 Pressure Stall Information for this sandbox.

        Returns per-resource pressure as avg10/avg60/avg300 percentages::

            {
                "cpu":    {"avg10": 5.0, "avg60": 3.2, "avg300": 1.1},
                "memory": {"avg10": 0.0, "avg60": 0.0, "avg300": 0.0},
                "io":     {"avg10": 12.5, "avg60": 8.0, "avg300": 4.0},
            }

        Returns empty dict if cgroup v2 or PSI is not available.
        """
        cg = getattr(self, "_cgroup_path", None)
        if not cg:
            return {}
        result: dict[str, dict[str, float]] = {}
        for resource in ("cpu", "memory", "io"):
            psi_file = cg / f"{resource}.pressure"
            if not psi_file.exists():
                continue
            try:
                # Parse "some avg10=X avg60=Y avg300=Z total=T" line.
                line = psi_file.read_text().split("\n")[0]
                vals: dict[str, float] = {}
                for part in line.split():
                    if "=" in part:
                        k, v = part.split("=", 1)
                        if k.startswith("avg"):
                            vals[k] = float(v)
                if vals:
                    result[resource] = vals
            except (OSError, ValueError):
                continue
        return result

    # -- memory management ------------------------------------------------- #

    def reclaim_memory(self) -> bool:
        """Hint the kernel to reclaim this sandbox's memory.

        Uses ``process_madvise(pidfd, MADV_COLD)`` to mark the sandbox
        process's memory as cold, so the kernel can swap it out when
        memory pressure rises.  The process keeps running — memory is
        paged back in transparently on next access.

        Useful in RL training: call on idle sandboxes while the GPU
        is busy with a training step, then resume normally.

        Returns True if the hint was accepted, False if unsupported.
        """
        shell = self._persistent_shell
        pidfd = getattr(shell, "_pidfd", None)
        if pidfd is None:
            return False

        import ctypes
        import ctypes.util
        import platform

        SYS_PROCESS_MADVISE = {"x86_64": 440, "aarch64": 440}.get(
            platform.machine()
        )
        MADV_COLD = 20

        if SYS_PROCESS_MADVISE is None:
            return False

        libc_name = ctypes.util.find_library("c")
        if not libc_name:
            return False
        libc = ctypes.CDLL(libc_name, use_errno=True)

        # process_madvise(pidfd, iovec, iovcnt, advice, flags)
        # We pass a zero-length iovec — the kernel applies the hint
        # to the entire process address space when iovec is empty.

        class Iovec(ctypes.Structure):
            _fields_ = [("iov_base", ctypes.c_void_p), ("iov_len", ctypes.c_size_t)]

        # Warn once if no swap is available.
        if not getattr(SandboxBase, "_swap_warned", False):
            try:
                with open("/proc/meminfo") as f:
                    for line in f:
                        if line.startswith("SwapTotal:"):
                            if int(line.split()[1]) == 0:
                                logger.warning(
                                    "reclaim_memory: no swap available, "
                                    "hint will have no effect. Enable swap "
                                    "or zram for memory reclamation to work."
                                )
                            SandboxBase._swap_warned = True
                            break
            except (OSError, ValueError):
                pass

        iov = Iovec(0, 0)
        ret = libc.syscall(SYS_PROCESS_MADVISE, pidfd, ctypes.byref(iov), 1, MADV_COLD, 0)
        return ret >= 0

    # -- Docker image export ----------------------------------------------- #

    def save_as_image(self, image_name: str) -> None:
        """Save current sandbox state as a Docker image.

        Tars the sandbox rootfs (base + all changes) and imports it via
        ``docker import``.  The resulting image can be used with both
        ``docker run`` and ``SandboxConfig(image=...)``.

        Args:
            image_name: Docker image name with optional tag
                (e.g. ``"my-app:cached"``).

        Example::

            sb = Sandbox(SandboxConfig(image="ubuntu:22.04"))
            sb.run("apt-get update && apt-get install -y python3")
            sb.save_as_image("my-app:with-python")

            # Later — fast start, no apt-get needed:
            sb2 = Sandbox(SandboxConfig(image="my-app:with-python"))
        """
        rootfs = self._rootfs
        if not rootfs or not rootfs.exists():
            raise RuntimeError("No rootfs available to export")

        tar_proc = subprocess.Popen(
            ["tar", "-C", str(rootfs), "-c", "."],
            stdout=subprocess.PIPE,
        )
        import_proc = subprocess.Popen(
            ["docker", "import", "--change", "CMD /bin/sh", "-", image_name],
            stdin=tar_proc.stdout,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if tar_proc.stdout is not None:
            tar_proc.stdout.close()
        _, stderr_bytes = import_proc.communicate()
        stderr = (stderr_bytes or b"").decode(errors="replace")

        if import_proc.returncode != 0:
            raise RuntimeError(f"docker import failed: {stderr.strip()}")
        logger.info("Saved sandbox as Docker image: %s", image_name)

    # -- abstract methods -------------------------------------------------- #

    @abc.abstractmethod
    def reset(self) -> None:
        """Reset the sandbox filesystem to its initial state."""
        ...

    @abc.abstractmethod
    def delete(self) -> None:
        """Delete the sandbox and clean up all resources."""
        ...

    def fs_snapshot(self, path: str) -> None:
        """Save current filesystem state to a directory.

        Copies the overlayfs upper layer (all changes since creation/reset)
        to *path*.  Use :meth:`fs_restore` to return to this state later.
        Does not capture running process state — use
        :class:`~agentdocker_lite.CheckpointManager` for full process
        checkpoint/restore.

        Args:
            path: Directory to save the snapshot to (must not exist).
        """
        upper = getattr(self, "_upper_dir", None)
        if not upper or not upper.exists():
            raise RuntimeError("fs_snapshot() requires overlayfs (not available in this mode)")
        shutil.copytree(str(upper), path)
        logger.debug("FS snapshot saved: %s -> %s", upper, path)

    def fs_restore(self, path: str) -> None:
        """Restore filesystem state from a snapshot.

        Kills the persistent shell, replaces the overlayfs upper layer
        with the snapshot, and restarts the shell.  Running process state
        is lost — use :class:`~agentdocker_lite.CheckpointManager` for
        full process checkpoint/restore.

        Args:
            path: Directory containing a previous :meth:`fs_snapshot`.
        """
        upper = getattr(self, "_upper_dir", None)
        if not upper:
            raise RuntimeError("restore() requires overlayfs (not available in this mode)")
        if not Path(path).exists():
            raise FileNotFoundError(f"Snapshot not found: {path}")

        self._persistent_shell.kill()

        # Unmount overlayfs to flush kernel dentry cache (rootful only).
        # In userns mode, the setup script remounts fresh on shell restart.
        rootfs = getattr(self, "_rootfs", None)
        base_rootfs = getattr(self, "_base_rootfs", None)
        if not self._userns and rootfs:
            subprocess.run(["umount", str(rootfs)], capture_output=True)

        # Clear upper and replace with snapshot
        if self._userns:
            for child in upper.iterdir():
                try:
                    child.chmod(0o700)
                except OSError:
                    pass
        if upper.exists():
            shutil.rmtree(upper)
        shutil.copytree(path, str(upper))

        # Clear work dir
        work = getattr(self, "_work_dir", None)
        if work and work.exists():
            if self._userns:
                for child in work.iterdir():
                    try:
                        child.chmod(0o700)
                    except OSError:
                        pass
            shutil.rmtree(work)
            work.mkdir(parents=True)

        # Remount overlayfs (rootful only).
        lowerdir_spec = getattr(self, "_lowerdir_spec", None) or base_rootfs
        if not self._userns and rootfs and lowerdir_spec and work:
            from agentdocker_lite._mount import mount_overlay

            mount_overlay(
                lowerdir_spec=str(lowerdir_spec),
                upper_dir=str(upper),
                work_dir=str(work),
                target=str(rootfs),
            )

        # Re-write seccomp helper for userns mode (upper dir was replaced).
        if self._config.seccomp and self._userns:
            from agentdocker_lite.security import build_seccomp_bpf
            bpf_bytes = build_seccomp_bpf()
            if bpf_bytes and upper:
                tmp_dir = upper / "tmp"
                tmp_dir.mkdir(parents=True, exist_ok=True)
                (tmp_dir / ".adl_seccomp.bpf").write_bytes(bpf_bytes)
                vendor_dir = Path(__file__).parent / "_vendor"
                helper_src = vendor_dir / "adl-seccomp"
                if helper_src.exists():
                    import shutil as _shutil
                    _shutil.copy2(str(helper_src), str(tmp_dir / ".adl_seccomp"))
                    (tmp_dir / ".adl_seccomp").chmod(0o755)

        # Re-write Landlock config for userns mode (upper dir was replaced).
        if self._userns and upper:
            ll_config = self._build_landlock_config(self._config)
            if ll_config:
                tmp_dir = upper / "tmp"
                tmp_dir.mkdir(parents=True, exist_ok=True)
                (tmp_dir / ".adl_landlock").write_text(ll_config)

        self._persistent_shell.start()
        logger.debug("Snapshot restored: %s -> %s", path, upper)

    # -- High-level snapshot API ---------------------------------------- #

    _snapshot_counter: int = 0

    def snapshot(self, tag: str | int | None = None) -> str | int:
        """Save current filesystem state, returning a snapshot ID or tag.

        Args:
            tag: Optional name for the snapshot (e.g. ``"before_test"``).
                If ``None``, uses an auto-incrementing integer.

        Returns:
            The tag (str) or auto-assigned ID (int).
        """
        snap_dir = self._env_dir / "snapshots"
        snap_dir.mkdir(parents=True, exist_ok=True)

        if tag is None:
            tag = self._snapshot_counter
            self._snapshot_counter += 1

        self.fs_snapshot(str(snap_dir / str(tag)))
        logger.debug("Snapshot saved: %s", tag)
        return tag

    def restore(self, tag: str | int | None = None) -> None:
        """Restore filesystem to a previously saved snapshot.

        Args:
            tag: Snapshot tag or ID. If ``None``, restores to the
                most recent snapshot.
        """
        if tag is None:
            snaps = self.list_snapshots()
            if not snaps:
                raise FileNotFoundError("No snapshots available")
            tag = snaps[-1]

        snap_path = self._env_dir / "snapshots" / str(tag)
        if not snap_path.exists():
            raise FileNotFoundError(
                f"Snapshot {tag!r} not found. "
                f"Available: {self.list_snapshots()}"
            )
        self.fs_restore(str(snap_path))
        if isinstance(tag, int):
            self._snapshot_counter = tag + 1
        logger.debug("Restored to snapshot: %s", tag)

    def list_snapshots(self) -> list[str | int]:
        """Return sorted list of available snapshot tags/IDs."""
        snap_dir = self._env_dir / "snapshots"
        if not snap_dir.exists():
            return []
        result: list[str | int] = []
        for p in sorted(snap_dir.iterdir()):
            if p.is_dir():
                result.append(int(p.name) if p.name.isdigit() else p.name)
        return result

    def delete_snapshot(self, tag: str | int) -> None:
        """Delete a specific snapshot to free disk space."""
        snap_path = self._env_dir / "snapshots" / str(tag)
        if snap_path.exists():
            shutil.rmtree(snap_path)
            logger.debug("Deleted snapshot: %s", tag)

    async def asnapshot(self, tag: str | int | None = None) -> str | int:
        """Async version of :meth:`snapshot`."""
        import asyncio
        return await asyncio.to_thread(self.snapshot, tag)

    async def arestore(self, tag: str | int | None = None) -> None:
        """Async version of :meth:`restore`."""
        import asyncio
        await asyncio.to_thread(self.restore, tag)

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _host_path(self, container_path: str) -> Path:
        """Resolve container_path to host filesystem (for reads)."""
        return self._rootfs / container_path.lstrip("/")

    def _host_path_write(self, container_path: str) -> Path:
        """Resolve container_path to host filesystem (for writes).

        Overridden in RootfulSandbox/RootlessSandbox to write to the
        overlay upper dir in user namespace mode.
        """
        return self._rootfs / container_path.lstrip("/")

    @staticmethod
    def _build_landlock_config(config: SandboxConfig) -> str | None:
        """Build Landlock config file content from SandboxConfig.

        Returns None if no Landlock params are configured.
        Raises RuntimeError if params are set but kernel doesn't support Landlock.
        Format: first line = mode flags (r/w/p), then R/W/P rules.
        """
        if not any([config.writable_paths, config.readable_paths, config.allowed_ports]):
            return None

        from agentdocker_lite.security import _landlock_abi_version
        abi = _landlock_abi_version()
        if abi == 0:
            raise RuntimeError(
                "Landlock not available (kernel < 5.13 or CONFIG_SECURITY_LANDLOCK=n), "
                "but writable_paths/readable_paths/allowed_ports were set. "
                "Remove these params or upgrade to kernel >= 5.13."
            )
        if config.allowed_ports is not None and abi < 4:
            raise RuntimeError(
                f"Landlock network port rules require ABI v4+ (kernel 6.7+), "
                f"but this kernel only supports ABI v{abi}. "
                f"Remove allowed_ports or upgrade your kernel."
            )

        mode = ""
        if config.readable_paths is not None:
            mode += "r"
        if config.writable_paths is not None:
            mode += "w"
        if config.allowed_ports is not None:
            mode += "p"

        lines = [mode]

        # Essential writable paths (always included when restricting writes)
        essential_writable = {"/dev", "/proc", "/tmp"}

        writable_set: set[str] = set()
        if config.writable_paths is not None:
            writable_set = set(config.writable_paths) | essential_writable
            for p in sorted(writable_set):
                lines.append(f"W {p}")

        if config.readable_paths is not None:
            essential_readable = {"/dev", "/proc", "/sys", "/tmp"}
            all_readable = set(config.readable_paths) | essential_readable
            for p in sorted(all_readable):
                if p not in writable_set:
                    lines.append(f"R {p}")

        if config.allowed_ports is not None:
            for port in config.allowed_ports:
                lines.append(f"P {port}")

        return "\n".join(lines) + "\n"

    def _build_env(self) -> dict[str, str]:
        env = {
            "HOME": "/root",
            "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "TERM": "xterm-256color",
            "LANG": "C.UTF-8",
        }
        if self._config.tty:
            env["TERM"] = "dumb"
            env["NO_COLOR"] = "1"
        env.update(self._config.environment)
        return env

    def __del__(self):
        try:
            if hasattr(self, "_persistent_shell"):
                self._persistent_shell.kill()
            if not getattr(self, "_userns", False):
                self._unmount_all()
        except Exception:
            pass

    def _unmount_all(self):
        """Default no-op; overridden in RootfulSandbox."""
        pass

    def __repr__(self) -> str:
        return f"Sandbox(name={self._name!r}, fs={self._fs_backend}, rootfs={self._rootfs})"

    # ------------------------------------------------------------------ #
    #  Stale sandbox cleanup                                               #
    # ------------------------------------------------------------------ #

    @staticmethod
    def cleanup_stale(env_base_dir: str = "") -> int:
        """Clean up orphaned sandboxes left by crashed processes.

        Scans *env_base_dir* for sandbox directories, checks if the owner
        process is still alive (via the ``.pid`` file written at creation),
        and cleans up dead ones (unmount, remove cgroup, remove directory).

        Returns:
            Number of cleaned-up sandboxes.
        """
        if not env_base_dir:
            env_base_dir = f"/tmp/agentdocker_lite_{os.getuid()}"
        base = Path(env_base_dir)
        if not base.exists():
            return 0

        cleaned = 0
        for entry in base.iterdir():
            if not entry.is_dir():
                continue

            pid_file = entry / ".pid"
            if not pid_file.exists():
                # No .pid file — orphaned sandbox dir (partial cleanup).
                # If it has sandbox-like subdirs, clean it up.
                if (entry / "work").exists() or (entry / "upper").exists():
                    logger.info("Cleaning up orphaned sandbox dir %s (no .pid)", entry.name)
                    for child in entry.rglob("*"):
                        try:
                            child.chmod(0o700)
                        except OSError:
                            pass
                    shutil.rmtree(entry, ignore_errors=True)
                    cleaned += 1
                continue

            try:
                pid = int(pid_file.read_text().strip())
            except (ValueError, OSError):
                logger.debug("Skipping %s (unreadable .pid file)", entry)
                continue

            # Check if process is alive (and not a zombie).
            # Zombies still respond to kill(0) and pidfd_open, so we
            # read /proc/{pid}/status to check the actual state.
            alive = False
            try:
                with open(f"/proc/{pid}/status") as _f:
                    for _line in _f:
                        if _line.startswith("State:"):
                            alive = "Z" not in _line and "X" not in _line
                            break
                    else:
                        alive = True  # couldn't find State line, assume alive
            except (FileNotFoundError, PermissionError):
                alive = False

            if alive:
                logger.debug("Sandbox %s owner pid %d still alive, skipping", entry.name, pid)
                continue

            # Process is dead — clean up
            logger.info("Cleaning up stale sandbox %s (pid %d dead)", entry.name, pid)

            # Unmount everything under the rootfs
            rootfs_dir = entry / "rootfs"
            if rootfs_dir.exists():
                subprocess.run(
                    ["umount", "-R", "-l", str(rootfs_dir)],
                    capture_output=True,
                )

            # Clean up netns bind mount left by pasta
            netns_path = Path(f"/run/netns/adl-{entry.name}")
            if netns_path.exists():
                subprocess.run(["fuser", "-k", str(netns_path)], capture_output=True)
                subprocess.run(["umount", str(netns_path)], capture_output=True)
                try:
                    netns_path.unlink()
                except OSError:
                    pass

            # Remove cgroup
            cgroup_path = Path(f"/sys/fs/cgroup/agentdocker_lite/{entry.name}")
            if cgroup_path.exists():
                # Kill remaining processes in the cgroup
                kill_file = cgroup_path / "cgroup.kill"
                if kill_file.exists():
                    try:
                        kill_file.write_text("1")
                    except OSError:
                        pass
                procs_file = cgroup_path / "cgroup.procs"
                if procs_file.exists():
                    try:
                        for p in procs_file.read_text().strip().split():
                            try:
                                os.kill(int(p), 9)
                            except (ProcessLookupError, ValueError):
                                pass
                    except OSError:
                        pass
                try:
                    cgroup_path.rmdir()
                except OSError as e:
                    logger.debug("cgroup cleanup for %s (non-fatal): %s", entry.name, e)

            # Fix 000-perm dirs left by overlayfs kernel before rmtree
            for child in entry.rglob("*"):
                try:
                    child.chmod(0o700)
                except OSError:
                    pass
            shutil.rmtree(entry, ignore_errors=True)
            cleaned += 1

        if cleaned:
            logger.info("Cleaned up %d stale sandbox(es) under %s", cleaned, env_base_dir)
        return cleaned
