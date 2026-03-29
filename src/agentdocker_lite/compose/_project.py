"""ComposeProject: manage a docker-compose.yml as a set of agentdocker-lite sandboxes.

Usage::

    from agentdocker_lite import ComposeProject

    proj = ComposeProject("docker-compose.yml", env={"API_PORT": "8030"})
    proj.up()
    proj.services["web"].run("curl localhost:8030/health")
    proj.reset()   # filesystem-level reset for all services
    proj.down()
"""

from __future__ import annotations

import json
import logging
import os
import re
import shlex
import subprocess
import time
from pathlib import Path
from typing import Any

from agentdocker_lite.config import SandboxConfig
from agentdocker_lite.sandbox import Sandbox
from agentdocker_lite.compose._parse import _Service, _parse_compose, _topo_sort
from agentdocker_lite.compose._network import SharedNetwork, _parse_duration, _healthcheck_cmd

logger = logging.getLogger(__name__)


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
        project_name: str | None = None,
        env: dict[str, str] | None = None,
        env_base_dir: str | None = None,
        rootfs_cache_dir: str | None = None,
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
        self._image_map = self._resolve_image_map()
        self._image_cmds: dict[str, list[str] | None] = {}  # service → image CMD
        self._image_entrypoints: dict[str, list[str] | None] = {}  # service → image ENTRYPOINT
        self._sandboxes: dict[str, Sandbox] = {}
        self._bg_handles: dict[str, str] = {}  # service → bg handle
        self._volume_dir: Path | None = None
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

    def _resolve_image_map(self) -> dict[str, str]:
        """Query ``docker compose config`` for resolved image names.

        Uses ``docker compose config --format json`` to get the exact
        image names that Docker Compose would use (including computed
        names for ``build:``-only services).  Automatically builds
        missing images for services that have a ``build:`` section.

        Falls back to the ``image`` field from our own parser if the
        Docker Compose CLI is unavailable.
        """
        mapping = self._query_compose_config()
        if not mapping:
            # Fallback: use image fields from our own parser.
            # For build-only services, infer {project}-{service} name.
            project = self._project_name or self._compose_file.parent.name
            fallback = {}
            for name, svc in self._defs.items():
                if svc.image:
                    fallback[name] = svc.image
                elif svc.build:
                    fallback[name] = f"{project}-{name}"
            return fallback

        # Build missing images for services that have build: context
        missing = [
            name for name in self._defs
            if self._defs[name].build
            and name in mapping
            and not self._image_exists_locally(mapping[name])
        ]
        if missing:
            logger.info("Building missing images for: %s", ", ".join(missing))
            build_cmd = [
                "docker", "compose",
                "-f", str(self._compose_file),
                "build",
            ] + missing
            if self._project_name:
                build_cmd[2:2] = ["-p", self._project_name]
            subprocess.run(
                build_cmd, check=True,
                env={**os.environ, **(self._env or {})},
            )

        return mapping

    def _query_compose_config(self) -> dict[str, str]:
        """Run ``docker compose config --format json`` and parse results."""
        cmd = [
            "docker", "compose",
            "-f", str(self._compose_file),
            "config", "--format", "json",
        ]
        if self._project_name:
            cmd[2:2] = ["-p", self._project_name]
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True, timeout=30,
                env={**os.environ, **(self._env or {})},
            )
            if result.returncode == 0:
                data = json.loads(result.stdout)
                project = data.get("name", self._project_name or "default")
                mapping = {}
                for name, svc in (data.get("services") or {}).items():
                    if svc.get("image"):
                        mapping[name] = svc["image"]
                    elif svc.get("build"):
                        # build-only service: docker compose tags as {project}-{service}
                        mapping[name] = f"{project}-{name}"
                return mapping
        except (FileNotFoundError, subprocess.TimeoutExpired,
                json.JSONDecodeError) as e:
            logger.debug("docker compose config unavailable: %s", e)
        return {}

    @staticmethod
    def _image_exists_locally(image: str) -> bool:
        """Check if a Docker/Podman image exists in the local store."""
        try:
            return subprocess.run(
                ["docker", "image", "inspect", image],
                capture_output=True, timeout=10,
            ).returncode == 0
        except (FileNotFoundError, subprocess.TimeoutExpired):
            return False

    def _resolve_image(self, svc: _Service) -> str:
        """Resolve the Docker image name for a service."""
        image = self._image_map.get(svc.name)
        if image:
            return image
        if svc.build:
            raise ValueError(
                f"Service {svc.name!r} uses 'build:' without 'image:'. "
                f"Install Docker and run 'docker compose build', or add "
                f"an explicit 'image:' field to the compose file."
            )
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
                assert self._volume_dir is not None
                vol_path = self._volume_dir / source
                vol_path.mkdir(parents=True, exist_ok=True)
                result.append(f"{str(vol_path)}:{rest}")
            else:
                # Assume named volume not declared (treat same way)
                assert self._volume_dir is not None
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

        # Fetch image config for entrypoint+CMD (used by _cmd_string)
        from agentdocker_lite.rootfs import get_image_config
        img_cfg = get_image_config(image) or {}
        self._image_cmds[svc.name] = img_cfg.get("cmd")
        self._image_entrypoints[svc.name] = img_cfg.get("entrypoint")

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
        if svc.shm_size:
            config_kwargs["shm_size"] = svc.shm_size
        if svc.tmpfs:
            config_kwargs["tmpfs"] = svc.tmpfs
        if svc.cpu_shares:
            config_kwargs["cpu_shares"] = svc.cpu_shares
        if svc.mem_limit:
            config_kwargs["memory_max"] = svc.mem_limit
        if svc.memswap_limit:
            config_kwargs["memory_swap"] = svc.memswap_limit
        # cap_add: merge explicit cap_add with privileged (all caps)
        caps = list(svc.cap_add) if svc.cap_add else []
        if svc.privileged:
            from agentdocker_lite.config import CAP_NAME_TO_NUM
            caps = list(CAP_NAME_TO_NUM.keys())
        if caps:
            config_kwargs["cap_add"] = caps
        # Don't use entrypoint as shell wrapper — run entrypoint+CMD
        # together as a background process in _cmd_string().  This avoids
        # passing unexpected args to non-wrapper entrypoints
        # (e.g. ENTRYPOINT ["python", "app.py"]).
        # Setting [] prevents _apply_image_defaults from backfilling.
        config_kwargs["entrypoint"] = []
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
        # Ensure localhost is always resolvable
        if "localhost" not in existing:
            existing = "127.0.0.1\tlocalhost\n::1\tlocalhost\n" + existing
        sb.write_file("/etc/hosts", existing.rstrip() + "\n" + hosts_lines + "\n")

    def _cmd_string(self, svc: _Service) -> str | None:
        """Build the shell command to start a service.

        Combines entrypoint and command, matching Docker semantics:
        ``ENTRYPOINT + CMD``.  Compose fields override image defaults.
        Both run together as a single background process — the
        entrypoint is NOT used as a shell wrapper.
        """
        # Resolve entrypoint: compose > image
        ep = svc.entrypoint
        if ep is None:
            ep = self._image_entrypoints.get(svc.name)

        # Resolve command: compose > image CMD
        cmd = svc.command
        if cmd is None:
            cmd = self._image_cmds.get(svc.name)

        # Combine entrypoint + cmd
        parts: list[str] = []
        if ep:
            parts.append(shlex.join(ep) if isinstance(ep, list) else str(ep))
        if cmd:
            parts.append(shlex.join(cmd) if isinstance(cmd, list) else str(cmd))

        return " ".join(parts) if parts else None

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

    @staticmethod
    def _wrap_restart(cmd: str, policy: str | None) -> str:
        """Wrap a command with a restart loop based on compose restart policy.

        Mimics Docker restart behaviour:
        - Exponential backoff: 1s → 2s → 4s → ... → 30s (cap)
        - Backoff resets if the process ran for more than 10 seconds
          (indicates successful startup, transient crash later)
        - ``on-failure``: only restart on non-zero exit
        - ``always`` / ``unless-stopped``: restart unconditionally
        """
        if not policy or policy in ("no", "never", '"no"'):
            return cmd
        # on-failure: stop loop on exit 0
        stop_on_ok = "[ $_rc -eq 0 ] && break; " if policy == "on-failure" else ""
        return (
            f"_d=1; while true; do "
            f"SECONDS=0; {cmd}; _rc=$?; "
            f"[ $SECONDS -gt 10 ] && _d=1; "  # reset backoff on long run
            f"{stop_on_ok}"
            f"sleep $_d; "
            f"_d=$((_d<30?_d*2:30)); "  # exponential backoff, cap 30s
            f"done"
        )

    def _start_service(self, name: str, svc: _Service) -> None:
        """Start a service's command as a background process."""
        cmd = self._cmd_string(svc)
        if not cmd:
            return
        sb = self._sandboxes.get(name)
        if sb is None:
            return

        # Apply restart policy
        cmd = self._wrap_restart(cmd, svc.restart)

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
        """Wait for a service's health check to pass.

        Uses ``default_timeout`` as the overall deadline.  The loop
        continues until the deadline expires — matching Docker Engine
        behaviour where a container keeps retrying its health check
        beyond the initial ``retries`` count.
        """
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
        start_period = _parse_duration(hc.get("start_period", "0s"))

        sb = self._sandboxes[name]

        if start_period > 0:
            time.sleep(start_period)

        deadline = time.monotonic() + default_timeout
        attempt = 0
        while time.monotonic() < deadline:
            attempt += 1
            try:
                _, ec = sb.run(cmd, timeout=int(hc_timeout) or 5)
                if ec == 0:
                    logger.debug("Health check passed for %s (attempt %d)", name, attempt)
                    return
            except Exception:
                pass
            if time.monotonic() + interval < deadline:
                time.sleep(interval)
            else:
                break

        raise RuntimeError(
            f"Health check failed for service {name!r} "
            f"after {attempt} attempts ({default_timeout}s timeout)"
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
