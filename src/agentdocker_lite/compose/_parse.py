"""Compose file parsing: variable substitution, service model, YAML parser."""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

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
        name: str = m.group(1) or m.group(2) or ""
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
    image: str | None = None
    build: dict | None = None
    command: str | list | None = None
    entrypoint: str | list | None = None
    environment: dict[str, str] = field(default_factory=dict)
    volumes: list[str] = field(default_factory=list)
    ports: list[str] = field(default_factory=list)
    devices: list[str] = field(default_factory=list)
    depends_on: dict[str, str] = field(default_factory=dict)
    # service name → condition ("service_started" | "service_healthy" | ...)
    healthcheck: dict | None = None
    network_mode: str | None = None
    dns: list[str] | None = None
    hostname: str | None = None
    working_dir: str | None = None
    restart: str | None = None
    security_opt: list[str] = field(default_factory=list)
    cap_add: list[str] = field(default_factory=list)
    privileged: bool = False
    stop_grace_period: str | None = None
    ulimits: dict[str, tuple[int, int]] = field(default_factory=dict)
    # maps resource name → (soft, hard), e.g. {"nofile": (65535, 65535)}
    networks: list[str] = field(default_factory=list)
    # compose networks this service belongs to (empty → "default")
    shm_size: str | None = None
    tmpfs: list[str] = field(default_factory=list)
    cpu_shares: int | None = None
    mem_limit: str | None = None
    memswap_limit: str | None = None
    extra_hosts: list[str] = field(default_factory=list)
    # "host:ip" entries appended to /etc/hosts
    sysctls: dict[str, str] = field(default_factory=dict)
    # kernel sysctl key → value, written to /proc/sys/


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


def _parse_depends_on(raw: Any) -> dict[str, str]:
    """Parse depends_on, preserving condition (default: service_started)."""
    if isinstance(raw, list):
        return {str(name): "service_started" for name in raw}
    if isinstance(raw, dict):
        result: dict[str, str] = {}
        for name, config in raw.items():
            if isinstance(config, dict):
                result[str(name)] = config.get("condition", "service_started")
            else:
                result[str(name)] = "service_started"
        return result
    return {}


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
    "ulimits", "shm_size", "tmpfs", "cpu_shares",
    "mem_limit", "memswap_limit", "env_file",
    # Functional support
    "extra_hosts", "sysctls",
    # Parsed but not mapped (informational / ignored safely)
    "container_name", "profiles", "stdin_open", "tty",
    "labels", "logging",
    # Parsed, ignored with log (rootless makes these less meaningful,
    # or they need Rust core changes for real support)
    "init", "user", "pid", "ipc",
    # Not needed: host networking replaces custom networks
    "networks",
})


def _parse_env_file(filepath: Path) -> dict[str, str]:
    """Parse a Docker-style env file into a dict.

    Supports ``VAR=VAL``, ``VAR:VAL``, ``VAR=`` (empty), and ``VAR``
    (inherit from host).  Lines starting with ``#`` are comments.
    Quotes (single/double) around values are stripped.
    """
    env: dict[str, str] = {}
    if not filepath.exists():
        logger.warning("env_file not found: %s", filepath)
        return env
    for line in filepath.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        # Docker supports both = and : as delimiters
        for delim in ("=", ":"):
            if delim in line:
                k, _, v = line.partition(delim)
                v = v.strip()
                if len(v) >= 2 and v[0] == v[-1] and v[0] in ('"', "'"):
                    v = v[1:-1]
                env[k.strip()] = v
                break
        else:
            # No delimiter — inherit from host environment
            env[line] = os.environ.get(line, "")
    return env


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

        # Resolve env_file: load from file(s), then override with explicit env
        env_from_file: dict[str, str] = {}
        raw_env_file = svc.get("env_file")
        if raw_env_file:
            if isinstance(raw_env_file, str):
                raw_env_file = [raw_env_file]
            for ef in raw_env_file:
                env_from_file.update(_parse_env_file(compose_file.parent / ef))
        merged_env = {**env_from_file, **_parse_environment(svc.get("environment"))}

        # Parse tmpfs: can be string or list
        raw_tmpfs = svc.get("tmpfs")
        if isinstance(raw_tmpfs, str):
            raw_tmpfs = [raw_tmpfs]
        tmpfs_list = [str(t) for t in (raw_tmpfs or [])]

        services[name] = _Service(
            name=name,
            image=svc.get("image"),
            build=svc.get("build") if isinstance(svc.get("build"), dict) else (
                {"context": svc["build"]} if svc.get("build") else None
            ),
            command=svc.get("command"),
            entrypoint=svc.get("entrypoint"),
            environment=merged_env,
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
            shm_size=svc.get("shm_size"),
            tmpfs=tmpfs_list,
            cpu_shares=int(svc["cpu_shares"]) if svc.get("cpu_shares") else None,
            mem_limit=svc.get("mem_limit"),
            memswap_limit=svc.get("memswap_limit"),
            extra_hosts=[str(h) for h in (svc.get("extra_hosts") or [])],
            sysctls={str(k): str(v) for k, v in (svc.get("sysctls") or {}).items()},
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
