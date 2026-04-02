"""ComposeProject: manage a docker-compose.yml as a set of nitrobox sandboxes.

Usage::

    from nitrobox import ComposeProject

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
import threading
import time
from pathlib import Path
from typing import Any

from nitrobox.config import SandboxConfig
from nitrobox.sandbox import Sandbox
from nitrobox.compose._parse import _Service, _parse_compose, _topo_sort
from nitrobox.compose._network import SharedNetwork, _parse_duration, _healthcheck_cmd

logger = logging.getLogger(__name__)


# ------------------------------------------------------------------ #
#  Health monitor (background daemon, mirrors Docker Engine)          #
# ------------------------------------------------------------------ #

class _HealthMonitor:
    """Background health check daemon for a single service.

    Mirrors Docker Engine behaviour:

    * During ``start_period``, checks run every ``start_interval``
      (default 5 s) and failures do **not** count toward the
      consecutive-failure threshold.
    * After ``start_period``, checks run every ``interval`` and
      ``retries`` consecutive failures mark the service *unhealthy*.
    * Any successful check immediately sets status to *healthy* and
      resets the failure counter.

    The :meth:`ComposeProject._wait_healthy` method polls
    :attr:`status` every 500 ms (matching Docker Compose) instead of
    executing the check command itself.
    """

    def __init__(
        self,
        sb: Sandbox,
        cmd: str,
        *,
        interval: float = 30.0,
        timeout: float = 30.0,
        start_period: float = 0.0,
        start_interval: float = 5.0,
        retries: int = 3,
    ) -> None:
        self.status: str = "starting"
        self._sb = sb
        self._cmd = cmd
        self._interval = interval
        self._timeout = timeout
        self._start_period = start_period
        self._start_interval = start_interval
        self._retries = retries
        self._consecutive_failures = 0
        self._stop = threading.Event()
        self._t0 = time.monotonic()
        self._thread = threading.Thread(target=self._loop, daemon=True)
        self._thread.start()

    def _loop(self) -> None:
        while not self._stop.is_set():
            in_start = (time.monotonic() - self._t0) < self._start_period
            check_interval = self._start_interval if in_start else self._interval

            try:
                _, ec = self._sb.run(self._cmd, timeout=int(self._timeout) or 5)
                if ec == 0:
                    self._consecutive_failures = 0
                    self.status = "healthy"
                else:
                    self._consecutive_failures += 1
            except Exception:
                self._consecutive_failures += 1

            # During start_period, failures don't count
            if not in_start and self._consecutive_failures >= self._retries:
                self.status = "unhealthy"

            self._stop.wait(check_interval)

    def stop(self) -> None:
        self._stop.set()
        self._thread.join(timeout=5)


class ComposeProject:
    """Manage a ``docker-compose.yml`` as a set of nitrobox sandboxes.

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
        # service name → background health monitor
        self._health_monitors: dict[str, _HealthMonitor] = {}

    # -- public API ---------------------------------------------------- #

    @property
    def services(self) -> dict[str, Sandbox]:
        """Map of service name → running :class:`Sandbox`."""
        return dict(self._sandboxes)

    def up(self, *, timeout: int = 120, detach: bool = False) -> None:
        """Start all services in dependency order.

        Args:
            timeout: Health-check timeout (seconds).  Only used when
                *detach* is ``False`` (the default).
            detach: If ``True``, return as soon as all services are
                running — equivalent to ``docker compose up -d``.
                Health monitors are started in the background; call
                :meth:`wait_healthy` or poll :meth:`health_status`
                to check readiness.  If ``False`` (default), block
                until every health check passes (``--wait`` mode).
        """
        if self._sandboxes:
            raise RuntimeError("Project already running. Call down() first.")

        # Create volume directories for named volumes
        base = self._env_base_dir or f"/tmp/nitrobox_{os.getuid()}"
        self._volume_dir = Path(base) / f"{self._project_name}_volumes"
        self._volume_dir.mkdir(parents=True, exist_ok=True)

        # Collect all service names for /etc/hosts
        hosts_entries = {name: "127.0.0.1" for name in self._defs}

        try:
            for name in self._startup_order:
                svc = self._defs[name]

                # Wait for deps that require service_healthy before
                # starting this service (matches Docker Compose).
                if not detach:
                    for dep_name, condition in svc.depends_on.items():
                        if condition == "service_healthy":
                            self._wait_healthy(dep_name, timeout)

                sb = self._create_sandbox(svc, hosts_entries)
                self._sandboxes[name] = sb
                self._start_service(name, svc)
                self._start_health_monitor(name, svc)

            if not detach:
                # Block until every health check passes (--wait mode).
                self._wait_all_healthy(timeout)
        except Exception:
            # Clean up on partial failure
            self.down()
            raise

        logger.info(
            "ComposeProject %s: %d services started%s",
            self._project_name,
            len(self._sandboxes),
            " (detached)" if detach else "",
        )

    def health_status(self) -> dict[str, str]:
        """Return health status of each monitored service.

        Returns a dict mapping service name to status string:
        ``"healthy"``, ``"unhealthy"``, ``"starting"``, or
        ``"none"`` (no health check configured).

        This is the NitroBox equivalent of reading ``docker compose ps``
        health column.
        """
        result: dict[str, str] = {}
        for name in self._startup_order:
            mon = self._health_monitors.get(name)
            result[name] = mon.status if mon else "none"
        return result

    def wait_healthy(self, timeout: int = 120) -> None:
        """Block until all health checks pass.

        Equivalent to ``docker compose up --wait``.  Raises
        ``RuntimeError`` on timeout or if any service becomes
        unhealthy.
        """
        self._wait_all_healthy(timeout)

    def down(self) -> None:
        """Stop and delete all sandboxes."""
        # Stop health monitors first
        for mon in self._health_monitors.values():
            mon.stop()
        self._health_monitors.clear()

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
            svc = self._defs[name]
            if sb:
                sb.reset()
                # Re-write /etc/hosts (cleared by upper dir reset)
                self._write_hosts(sb, hosts_entries, svc.extra_hosts)
                self._apply_sysctls(sb, svc)

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
                # Docker treats "/data" as "/data:/data"
                if parts[0].startswith("/"):
                    result.append(f"{parts[0]}:{parts[0]}")
                else:
                    logger.warning("Skipping volume with no target: %s", vol)
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
        from nitrobox.rootfs import get_image_config
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
        security_opts_normalized = [s.replace(" ", "") for s in svc.security_opt]
        if svc.privileged or "seccomp:unconfined" in security_opts_normalized:
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
            from nitrobox.config import CAP_NAME_TO_NUM
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

        self._write_hosts(sb, hosts, svc.extra_hosts)
        self._apply_sysctls(sb, svc)
        return sb

    @staticmethod
    def _write_hosts(
        sb: Sandbox,
        hosts: dict[str, str],
        extra_hosts: list[str] | None = None,
    ) -> None:
        """Write /etc/hosts entries for service name resolution.

        Docker creates /etc/hosts, /etc/hostname, /etc/resolv.conf via
        bind mounts, bypassing the image filesystem.  We write from
        inside the sandbox (via ``run()``) to ensure the overlay mount
        sees the change immediately.

        *extra_hosts* are ``"host:ip"`` strings from the compose
        ``extra_hosts`` directive.
        """
        lines = ["127.0.0.1\tlocalhost", "::1\tlocalhost"]
        lines.extend(f"{ip}\t{name}" for name, ip in hosts.items())
        # Append compose extra_hosts (format: "hostname:ip")
        for entry in extra_hosts or []:
            if ":" in entry:
                host, ip = entry.split(":", 1)
                lines.append(f"{ip.strip()}\t{host.strip()}")
        content = "\\n".join(lines) + "\\n"
        # Write from inside the sandbox so overlayfs upper is updated
        # within the mount namespace.  Remove any stale whiteout first.
        try:
            sb.run(
                f"rm -rf /etc/hosts 2>/dev/null; printf '{content}' > /etc/hosts",
                timeout=5,
            )
        except Exception:
            pass

    @staticmethod
    def _apply_sysctls(sb: Sandbox, svc: _Service) -> None:
        """Apply ``sysctls`` by writing to ``/proc/sys/`` inside the sandbox."""
        for key, value in svc.sysctls.items():
            path = "/proc/sys/" + key.replace(".", "/")
            try:
                import shlex
                _, ec = sb.run(
                    f"printf '%s' {shlex.quote(str(value))} > {path} 2>/dev/null",
                    timeout=5,
                )
                if ec != 0:
                    logger.debug("sysctl %s=%s failed (ec=%d)", key, value, ec)
            except Exception:
                logger.debug("sysctl %s=%s: exception", key, value)

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

    def _start_health_monitor(self, name: str, svc: _Service) -> None:
        """Start a background health monitor for *name* (if configured).

        The monitor runs independently; call :meth:`_wait_healthy` to
        block until it reports *healthy*.
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

        # Stop any previous monitor (e.g. from a prior reset cycle)
        old = self._health_monitors.pop(name, None)
        if old is not None:
            old.stop()

        self._health_monitors[name] = _HealthMonitor(
            self._sandboxes[name],
            cmd,
            interval=_parse_duration(hc.get("interval", "30s")),
            timeout=_parse_duration(hc.get("timeout", "30s")),
            start_period=_parse_duration(hc.get("start_period", "0s")),
            start_interval=_parse_duration(hc.get("start_interval", "5s")),
            retries=int(hc.get("retries", 3)),
        )

    def _wait_healthy(self, name: str, timeout: int) -> None:
        """Block until *name*'s health monitor reports healthy.

        Polls the monitor status every 500 ms (matching Docker
        Compose's ``convergence.go`` ticker).  No-op if no monitor
        exists for *name*.
        """
        monitor = self._health_monitors.get(name)
        if monitor is None:
            return

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if monitor.status == "healthy":
                logger.debug("Health check passed for %s", name)
                return
            if monitor.status == "unhealthy":
                break
            time.sleep(0.5)

        monitor.stop()
        self._health_monitors.pop(name, None)
        raise RuntimeError(
            f"Health check failed for service {name!r} "
            f"({timeout}s timeout, last status: {monitor.status})"
        )

    def _wait_all_healthy(self, timeout: int) -> None:
        """Wait for **all** health monitors to report healthy (parallel).

        Equivalent to ``docker compose up --wait``.  Polls every 500 ms.
        """
        monitored = [n for n in self._startup_order if n in self._health_monitors]
        if not monitored:
            return

        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            all_ok = True
            for name in monitored:
                mon = self._health_monitors.get(name)
                if mon is None:
                    continue
                if mon.status == "unhealthy":
                    raise RuntimeError(
                        f"Health check failed for service {name!r}"
                    )
                if mon.status != "healthy":
                    all_ok = False
            if all_ok:
                logger.debug("All health checks passed")
                return
            time.sleep(0.5)

        not_ready = [
            n for n in monitored
            if (m := self._health_monitors.get(n)) and m.status != "healthy"
        ]
        raise RuntimeError(
            f"Health check timeout ({timeout}s) for: {', '.join(not_ready)}"
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
