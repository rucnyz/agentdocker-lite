"""Docker Compose compatibility layer.

Parses ``docker-compose.yml`` files and manages each service as an
agentdocker-lite :class:`Sandbox`.  Supports the subset of the Compose
spec used by real-world projects (DecodingTrust-Agent, etc.).

Usage::

    from agentdocker_lite import ComposeProject

    proj = ComposeProject("docker-compose.yml", env={"API_PORT": "8030"})
    proj.up()
    proj.services["web"].run("curl localhost:8030/health")
    proj.reset()   # filesystem-level reset for all services
    proj.down()
"""

from __future__ import annotations

import logging
import os
import re
import shlex
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

import yaml

from agentdocker_lite.backends.base import SandboxConfig
from agentdocker_lite.sandbox import Sandbox

logger = logging.getLogger(__name__)

# ------------------------------------------------------------------ #
#  Variable substitution                                               #
# ------------------------------------------------------------------ #

# Matches ${VAR}, ${VAR:-default}, ${VAR-default}, and $$
_VAR_RE = re.compile(r"\$\$|\$\{([^}]+)\}|\$([A-Za-z_]\w*)")


def _substitute(text: str, env: dict[str, str]) -> str:
    """Resolve ``${VAR:-default}`` patterns in *text*."""

    def _repl(m: re.Match) -> str:
        if m.group(0) == "$$":
            return "$"
        name = m.group(1) or m.group(2)
        # Handle ${VAR:-default} and ${VAR-default}
        for sep in (":-", "-"):
            if sep in name:
                var, default = name.split(sep, 1)
                return env.get(var, default)
        return env.get(name, "")

    return _VAR_RE.sub(_repl, text)


def _sub_value(value: Any, env: dict[str, str]) -> Any:
    """Recursively substitute variables in strings, lists, dicts."""
    if isinstance(value, str):
        return _substitute(value, env)
    if isinstance(value, list):
        return [_sub_value(v, env) for v in value]
    if isinstance(value, dict):
        return {k: _sub_value(v, env) for k, v in value.items()}
    return value


# ------------------------------------------------------------------ #
#  Compose parser                                                      #
# ------------------------------------------------------------------ #


@dataclass
class _Service:
    """Parsed service definition."""

    name: str
    image: Optional[str] = None
    build: Optional[dict] = None
    command: Optional[str | list] = None
    entrypoint: Optional[str | list] = None
    environment: dict[str, str] = field(default_factory=dict)
    volumes: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)
    depends_on: list[str] = field(default_factory=list)
    healthcheck: Optional[dict] = None
    network_mode: Optional[str] = None
    dns: Optional[list[str]] = None
    hostname: Optional[str] = None
    working_dir: Optional[str] = None
    restart: Optional[str] = None
    security_opt: list[str] = field(default_factory=list)
    cap_add: list[str] = field(default_factory=list)
    privileged: bool = False
    stop_grace_period: Optional[str] = None
    ulimits: dict[str, tuple[int, int]] = field(default_factory=dict)
    # maps resource name → (soft, hard), e.g. {"nofile": (65535, 65535)}
    networks: list[str] = field(default_factory=list)
    # compose networks this service belongs to (empty → "default")


def _parse_environment(raw: Any) -> dict[str, str]:
    """Parse environment from list or dict format."""
    if isinstance(raw, dict):
        return {k: str(v) if v is not None else "" for k, v in raw.items()}
    if isinstance(raw, list):
        env: dict[str, str] = {}
        for item in raw:
            item = str(item)
            if "=" in item:
                k, v = item.split("=", 1)
                env[k] = v
            else:
                env[item] = os.environ.get(item, "")
        return env
    return {}


def _parse_depends_on(raw: Any) -> list[str]:
    """Parse depends_on from list or dict format."""
    if isinstance(raw, list):
        return list(raw)
    if isinstance(raw, dict):
        return list(raw.keys())
    return []


def _parse_ulimits(raw: Any) -> dict[str, tuple[int, int]]:
    """Parse ulimits from compose format.

    Supports both ``nproc: 65535`` (single value) and
    ``nofile: {soft: 65535, hard: 65535}`` (dict) forms.
    """
    if not isinstance(raw, dict):
        return {}
    result: dict[str, tuple[int, int]] = {}
    for name, val in raw.items():
        if isinstance(val, dict):
            soft = int(val.get("soft", val.get("hard", 0)))
            hard = int(val.get("hard", soft))
            result[name] = (soft, hard)
        else:
            v = int(val)
            result[name] = (v, v)
    return result


def _parse_ports(raw: Any) -> list[str]:
    """Parse ports into ``host:container`` strings."""
    if not raw:
        return []
    result: list[str] = []
    for p in raw:
        p = str(p)
        # Strip protocol suffix for port_map (pasta handles TCP)
        p = re.sub(r"/(tcp|udp)$", "", p)
        result.append(p)
    return result


# Fields we parse and map to SandboxConfig
_SUPPORTED_SERVICE_KEYS = frozenset({
    "image", "build", "command", "entrypoint", "environment",
    "volumes", "ports", "devices", "depends_on", "healthcheck",
    "network_mode", "dns", "hostname", "working_dir", "restart",
    "security_opt", "cap_add", "privileged", "stop_grace_period",
    "ulimits",
    # Parsed but not mapped (informational / ignored safely)
    "container_name", "profiles", "stdin_open", "tty",
    "env_file", "extra_hosts", "labels", "logging",
    # Not needed: host networking replaces custom networks
    "networks",
})


def _parse_compose(
    compose_file: Path,
    env: dict[str, str],
) -> tuple[dict[str, _Service], list[str]]:
    """Parse a docker-compose.yml and return (services, named_volumes).

    Warns on unsupported service-level fields.
    """
    text = compose_file.read_text()
    # Substitute variables in the raw YAML text
    text = _substitute(text, env)
    data = yaml.safe_load(text) or {}

    services_raw = data.get("services", {})
    named_volumes = list((data.get("volumes") or {}).keys())

    services: dict[str, _Service] = {}
    for name, svc in services_raw.items():
        if not isinstance(svc, dict):
            continue

        # Reject unsupported fields
        unsupported = [k for k in svc if k not in _SUPPORTED_SERVICE_KEYS]
        if unsupported:
            raise ValueError(
                f"service {name!r}: unsupported compose fields: "
                f"{', '.join(sorted(unsupported))}. "
                f"Supported: {', '.join(sorted(_SUPPORTED_SERVICE_KEYS))}"
            )

        services[name] = _Service(
            name=name,
            image=svc.get("image"),
            build=svc.get("build") if isinstance(svc.get("build"), dict) else (
                {"context": svc["build"]} if svc.get("build") else None
            ),
            command=svc.get("command"),
            entrypoint=svc.get("entrypoint"),
            environment=_parse_environment(svc.get("environment")),
            volumes=[str(v) for v in (svc.get("volumes") or [])],
            ports=_parse_ports(svc.get("ports")),
            devices=[str(d) for d in (svc.get("devices") or [])],
            depends_on=_parse_depends_on(svc.get("depends_on")),
            healthcheck=svc.get("healthcheck"),
            network_mode=svc.get("network_mode"),
            dns=svc.get("dns"),
            hostname=svc.get("hostname"),
            working_dir=svc.get("working_dir"),
            restart=svc.get("restart"),
            security_opt=[str(s) for s in (svc.get("security_opt") or [])],
            cap_add=[str(c) for c in (svc.get("cap_add") or [])],
            privileged=bool(svc.get("privileged")),
            stop_grace_period=svc.get("stop_grace_period"),
            ulimits=_parse_ulimits(svc.get("ulimits")),
            networks=list(svc["networks"]) if isinstance(svc.get("networks"), (list, dict)) else [],
        )

    return services, named_volumes


def _topo_sort(services: dict[str, _Service]) -> list[str]:
    """Topological sort by depends_on (depth-first)."""
    visited: set[str] = set()
    order: list[str] = []

    def _visit(name: str) -> None:
        if name in visited:
            return
        visited.add(name)
        svc = services.get(name)
        if svc:
            for dep in svc.depends_on:
                _visit(dep)
        order.append(name)

    for name in services:
        _visit(name)
    return order


# ------------------------------------------------------------------ #
#  Shared network namespace (Podman-style pod networking)               #
# ------------------------------------------------------------------ #


class SharedNetwork:
    """Shared userns + netns for compose network isolation.

    Creates a sentinel process that holds a user namespace (with full
    uid mapping) and a network namespace.  Other sandboxes join the
    sentinel's namespaces via ``nsenter``.

    This mirrors Podman's pod infra container: one shared userns+netns
    per pod, individual mount/pid namespaces per container.
    """

    def __init__(self, name: str = "default") -> None:
        import subprocess as _subprocess

        self.name = name
        # Detect subuid range (reuse rootless sandbox logic)
        from agentdocker_lite.backends.rootless import RootlessSandbox
        self._subuid_range = RootlessSandbox._detect_subuid_range()

        # Create sentinel with userns + netns
        unshare_cmd = ["unshare", "--user", "--net", "--fork"]
        if not self._subuid_range:
            unshare_cmd.insert(2, "--map-root-user")
        unshare_cmd.extend(["--", "sleep", "infinity"])

        self._sentinel = _subprocess.Popen(
            unshare_cmd,
            start_new_session=True,
            stdout=_subprocess.DEVNULL,
            stderr=_subprocess.DEVNULL,
        )

        try:
            # Wait for child to enter new userns
            if self._subuid_range:
                my_userns = os.readlink("/proc/self/ns/user")
                for _ in range(1000):
                    try:
                        child_userns = os.readlink(
                            f"/proc/{self._sentinel.pid}/ns/user"
                        )
                        if child_userns != my_userns:
                            break
                    except (FileNotFoundError, PermissionError):
                        pass
                    time.sleep(0.001)
                else:
                    raise RuntimeError("Timeout waiting for sentinel userns")

                # Set up full uid/gid mapping
                outer_uid, sub_start, sub_count = self._subuid_range
                outer_gid = os.getgid()
                pid = self._sentinel.pid
                _subprocess.run(
                    ["newuidmap", str(pid),
                     "0", str(outer_uid), "1",
                     "1", str(sub_start), str(sub_count)],
                    check=True, capture_output=True,
                )
                _subprocess.run(
                    ["newgidmap", str(pid),
                     "0", str(outer_gid), "1",
                     "1", str(sub_start), str(sub_count)],
                    check=True, capture_output=True,
                )
        except Exception:
            self.destroy()
            raise

    @property
    def userns_path(self) -> str:
        """Path to the sentinel's user namespace."""
        return f"/proc/{self._sentinel.pid}/ns/user"

    @property
    def netns_path(self) -> str:
        """Path to the sentinel's network namespace."""
        return f"/proc/{self._sentinel.pid}/ns/net"

    @property
    def alive(self) -> bool:
        return self._sentinel.poll() is None

    def destroy(self) -> None:
        """Kill the sentinel, releasing the shared namespaces."""
        if self._sentinel.poll() is None:
            import signal as _signal
            try:
                os.killpg(self._sentinel.pid, _signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                try:
                    self._sentinel.kill()
                except Exception:
                    pass
            try:
                self._sentinel.wait(timeout=5)
            except Exception:
                pass

    def __repr__(self) -> str:
        state = "alive" if self.alive else "dead"
        return f"SharedNetwork({self.name!r}, {state})"


# ------------------------------------------------------------------ #
#  Duration parsing                                                    #
# ------------------------------------------------------------------ #


def _parse_duration(s: str | int | float) -> float:
    """Parse compose duration string (e.g. ``"30s"``, ``"2m"``) to seconds."""
    if isinstance(s, (int, float)):
        return float(s)
    s = str(s).strip()
    m = re.match(r"^(\d+(?:\.\d+)?)\s*(s|ms|m|h)?$", s)
    if not m:
        return 30.0
    val = float(m.group(1))
    unit = m.group(2) or "s"
    return val * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[unit]


# ------------------------------------------------------------------ #
#  Health check                                                        #
# ------------------------------------------------------------------ #


def _healthcheck_cmd(test: Any) -> str:
    """Convert healthcheck test to a shell command string."""
    if isinstance(test, str):
        return test
    if isinstance(test, list) and test:
        if test[0] == "CMD":
            return shlex.join(test[1:])
        if test[0] == "CMD-SHELL":
            return " ".join(test[1:])
        # NONE disables
        if test[0] == "NONE":
            return ""
        return shlex.join(test)
    return ""


# ------------------------------------------------------------------ #
#  ComposeProject                                                      #
# ------------------------------------------------------------------ #


class ComposeProject:
    """Manage a ``docker-compose.yml`` as a set of agentdocker-lite sandboxes.

    Each service becomes an independent :class:`Sandbox` instance.
    Services using ``network_mode: host`` get ``net_isolate=False``
    (the default).  For other services, ``/etc/hosts`` entries map
    service names to ``127.0.0.1``.

    Args:
        compose_file: Path to ``docker-compose.yml``.
        project_name: Project name (used as sandbox name prefix).
            Defaults to the parent directory name of the compose file.
        env: Environment variables for ``${VAR:-default}`` substitution.
        env_base_dir: Base directory for sandbox state.
        rootfs_cache_dir: Directory to cache rootfs images.
    """

    def __init__(
        self,
        compose_file: str | Path,
        *,
        project_name: Optional[str] = None,
        env: Optional[dict[str, str]] = None,
        env_base_dir: Optional[str] = None,
        rootfs_cache_dir: Optional[str] = None,
    ) -> None:
        self._compose_file = Path(compose_file).resolve()
        if not self._compose_file.exists():
            raise FileNotFoundError(f"Compose file not found: {self._compose_file}")

        self._project_name = project_name or self._compose_file.parent.name
        self._env = {**os.environ, **(env or {})}
        self._env_base_dir = env_base_dir
        self._rootfs_cache_dir = rootfs_cache_dir

        self._defs, self._named_volumes = _parse_compose(
            self._compose_file, self._env,
        )
        self._startup_order = _topo_sort(self._defs)
        self._sandboxes: dict[str, Sandbox] = {}
        self._bg_handles: dict[str, str] = {}  # service → bg handle
        self._volume_dir: Optional[Path] = None
        # network name → SharedNetwork instance
        self._shared_nets: dict[str, SharedNetwork] = {}

    # -- public API ---------------------------------------------------- #

    @property
    def services(self) -> dict[str, Sandbox]:
        """Map of service name → running :class:`Sandbox`."""
        return dict(self._sandboxes)

    def up(self, *, timeout: int = 120) -> None:
        """Start all services in dependency order.

        Creates sandboxes, runs service commands, and waits for health
        checks to pass.

        Args:
            timeout: Default health-check timeout per service (seconds).
        """
        if self._sandboxes:
            raise RuntimeError("Project already running. Call down() first.")

        # Create volume directories for named volumes
        base = self._env_base_dir or f"/tmp/agentdocker_lite_{os.getuid()}"
        self._volume_dir = Path(base) / f"{self._project_name}_volumes"
        self._volume_dir.mkdir(parents=True, exist_ok=True)

        # Collect all service names for /etc/hosts
        hosts_entries = {name: "127.0.0.1" for name in self._defs}

        try:
            for name in self._startup_order:
                svc = self._defs[name]
                sb = self._create_sandbox(svc, hosts_entries)
                self._sandboxes[name] = sb
                self._start_service(name, svc)
                self._wait_healthy(name, svc, timeout)
        except Exception:
            # Clean up on partial failure
            self.down()
            raise

        logger.info(
            "ComposeProject %s: %d services started",
            self._project_name,
            len(self._sandboxes),
        )

    def down(self) -> None:
        """Stop and delete all sandboxes."""
        # Reverse order for graceful shutdown
        for name in reversed(self._startup_order):
            sb = self._sandboxes.pop(name, None)
            if sb:
                try:
                    sb.delete()
                except Exception as e:
                    logger.warning("Failed to delete sandbox %s: %s", name, e)
            self._bg_handles.pop(name, None)

        # Destroy shared network namespaces
        for sn in self._shared_nets.values():
            try:
                sn.destroy()
            except Exception as e:
                logger.warning("Failed to destroy SharedNetwork %s: %s", sn.name, e)
        self._shared_nets.clear()

        # Clean up named volume directories
        if self._volume_dir and self._volume_dir.exists():
            import shutil
            shutil.rmtree(self._volume_dir, ignore_errors=True)
            self._volume_dir = None

        logger.info("ComposeProject %s: all services stopped", self._project_name)

    def reset(self) -> None:
        """Reset all sandboxes and restart service commands.

        Filesystem-level reset: clears all changes, restarts service
        processes.  No application-level reset endpoints needed.
        """
        hosts_entries = {name: "127.0.0.1" for name in self._defs}

        for name in self._startup_order:
            sb = self._sandboxes.get(name)
            if sb:
                sb.reset()
                # Re-write /etc/hosts (cleared by upper dir reset)
                self._write_hosts(sb, hosts_entries)

        # Re-start all service commands after reset
        for name in self._startup_order:
            svc = self._defs[name]
            self._start_service(name, svc)

    def run(
        self,
        service: str,
        command: str,
        **kwargs: Any,
    ) -> tuple[str, int]:
        """Run a command in a service's sandbox."""
        sb = self._sandboxes.get(service)
        if sb is None:
            raise KeyError(f"Service {service!r} not found or not running")
        return sb.run(command, **kwargs)

    # -- internals ----------------------------------------------------- #

    def _resolve_image(self, svc: _Service) -> str:
        """Resolve the Docker image name for a service."""
        if svc.image:
            return svc.image
        if svc.build:
            # When only build is specified, the image must be pre-built.
            # Compose convention: project_service
            generated = f"{self._project_name}_{svc.name}"
            logger.info(
                "Service %s has no image field, trying %s "
                "(run 'docker compose build' first if not built)",
                svc.name,
                generated,
            )
            return generated
        raise ValueError(
            f"Service {svc.name!r}: no 'image' or 'build' specified"
        )

    def _resolve_volumes(self, svc: _Service) -> list[str]:
        """Resolve volume specs, mapping named volumes to host dirs."""
        result: list[str] = []
        compose_dir = self._compose_file.parent

        for vol in svc.volumes:
            parts = vol.split(":")
            if len(parts) < 2:
                continue

            source = parts[0]
            rest = ":".join(parts[1:])

            if source.startswith("/") or source.startswith("./") or source.startswith(".."):
                # Bind mount — resolve relative to compose file dir
                if not source.startswith("/"):
                    source = str((compose_dir / source).resolve())
                result.append(f"{source}:{rest}")
            elif source in self._named_volumes:
                # Named volume → host directory
                vol_path = self._volume_dir / source
                vol_path.mkdir(parents=True, exist_ok=True)
                result.append(f"{str(vol_path)}:{rest}")
            else:
                # Assume named volume not declared (treat same way)
                vol_path = self._volume_dir / source
                vol_path.mkdir(parents=True, exist_ok=True)
                result.append(f"{str(vol_path)}:{rest}")

        return result

    def _create_sandbox(
        self,
        svc: _Service,
        hosts: dict[str, str],
    ) -> Sandbox:
        """Create a Sandbox for a single compose service."""
        image = self._resolve_image(svc)
        volumes = self._resolve_volumes(svc)

        # Port mapping: only needed for non-host networking
        port_map = None
        if svc.network_mode != "host" and svc.ports:
            port_map = svc.ports

        # seccomp: disabled if security_opt includes seccomp:unconfined
        # or if privileged
        seccomp = True
        if svc.privileged or "seccomp:unconfined" in svc.security_opt:
            seccomp = False

        # Network namespace strategy:
        # - network_mode: host → share host network directly
        # - Otherwise → shared userns+netns per compose network (Podman
        #   pod model).  Services on the same network share a netns and
        #   can communicate via localhost.  Different networks are
        #   isolated (different netns).
        shared_userns = None
        net_ns = None
        net_isolate = False

        if svc.network_mode != "host":
            net_names = svc.networks or ["default"]
            primary_net = net_names[0]
            if primary_net not in self._shared_nets:
                self._shared_nets[primary_net] = SharedNetwork(primary_net)
            sn = self._shared_nets[primary_net]
            shared_userns = sn.userns_path
            net_ns = sn.netns_path

        sandbox_name = f"{self._project_name}_{svc.name}"

        config_kwargs: dict[str, Any] = dict(
            image=image,
            working_dir=svc.working_dir or "/",
            environment=svc.environment,
            volumes=volumes,
            devices=svc.devices,
            net_isolate=net_isolate,
            net_ns=net_ns,
            shared_userns=shared_userns,
            port_map=port_map,
            seccomp=seccomp,
            hostname=svc.hostname or svc.name,
            dns=svc.dns,
        )
        if self._env_base_dir:
            config_kwargs["env_base_dir"] = self._env_base_dir
        if self._rootfs_cache_dir:
            config_kwargs["rootfs_cache_dir"] = self._rootfs_cache_dir

        config = SandboxConfig(**config_kwargs)
        sb = Sandbox(config, name=sandbox_name)

        self._write_hosts(sb, hosts)
        return sb

    @staticmethod
    def _write_hosts(sb: Sandbox, hosts: dict[str, str]) -> None:
        """Write /etc/hosts entries for service name resolution."""
        hosts_lines = "\n".join(f"{ip}\t{name}" for name, ip in hosts.items())
        try:
            existing = sb.read_file("/etc/hosts")
        except Exception:
            existing = ""
        sb.write_file("/etc/hosts", existing.rstrip() + "\n" + hosts_lines + "\n")

    def _cmd_string(self, svc: _Service) -> Optional[str]:
        """Build the shell command to start a service."""
        cmd = svc.command or svc.entrypoint
        if cmd is None:
            return None
        if isinstance(cmd, list):
            return shlex.join(cmd)
        return str(cmd)

    @staticmethod
    def _ulimit_prefix(ulimits: dict[str, tuple[int, int]]) -> str:
        """Build ``ulimit`` shell commands from parsed ulimits."""
        # Map compose names → bash ulimit flags
        flag_map = {"nofile": "-n", "nproc": "-u", "core": "-c",
                    "fsize": "-f", "memlock": "-l", "stack": "-s"}
        parts: list[str] = []
        for name, (soft, hard) in ulimits.items():
            flag = flag_map.get(name)
            if not flag:
                continue
            if soft == hard:
                parts.append(f"ulimit {flag} {soft}")
            else:
                parts.append(f"ulimit {flag}S {soft}; ulimit {flag}H {hard}")
        return "; ".join(parts)

    def _start_service(self, name: str, svc: _Service) -> None:
        """Start a service's command as a background process."""
        cmd = self._cmd_string(svc)
        if not cmd:
            return
        sb = self._sandboxes.get(name)
        if sb is None:
            return

        # Apply ulimits before the service command
        prefix = self._ulimit_prefix(svc.ulimits)
        if prefix:
            cmd = f"{prefix}; {cmd}"

        handle = sb.run_background(cmd)
        self._bg_handles[name] = handle

    def _wait_healthy(
        self,
        name: str,
        svc: _Service,
        default_timeout: int,
    ) -> None:
        """Wait for a service's health check to pass."""
        hc = svc.healthcheck
        if not hc:
            return

        test = hc.get("test")
        if not test:
            return

        cmd = _healthcheck_cmd(test)
        if not cmd:
            return

        interval = _parse_duration(hc.get("interval", "10s"))
        hc_timeout = _parse_duration(hc.get("timeout", "5s"))
        retries = int(hc.get("retries", 3))
        start_period = _parse_duration(hc.get("start_period", "0s"))

        sb = self._sandboxes[name]

        if start_period > 0:
            time.sleep(start_period)

        for attempt in range(retries):
            try:
                _, ec = sb.run(cmd, timeout=int(hc_timeout) or 5)
                if ec == 0:
                    logger.debug("Health check passed for %s", name)
                    return
            except Exception:
                pass
            if attempt < retries - 1:
                time.sleep(interval)

        raise RuntimeError(
            f"Health check failed for service {name!r} "
            f"after {retries} retries"
        )

    # -- context manager ----------------------------------------------- #

    def __enter__(self) -> ComposeProject:
        self.up()
        return self

    def __exit__(self, *exc: Any) -> None:
        self.down()

    def __repr__(self) -> str:
        running = list(self._sandboxes.keys())
        return (
            f"ComposeProject({self._project_name!r}, "
            f"services={running})"
        )
