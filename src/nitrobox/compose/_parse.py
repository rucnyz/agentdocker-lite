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

# Matches ${VAR}, ${VAR:-default}, ${VAR-default}, ${VAR:+alt}, ${VAR+alt},
# ${VAR:?err}, ${VAR?err}, $VAR, and $$ (escape).
_VAR_RE = re.compile(r"\$\$|\$\{([^}]+)\}|\$([A-Za-z_]\w*)")


def _substitute(text: str, env: dict[str, str]) -> str:
    """Resolve compose-spec variable substitution patterns in *text*.

    Supported operators (matching compose-spec):
    - ``${VAR:-default}`` — default if unset **or empty**
    - ``${VAR-default}``  — default if unset only
    - ``${VAR:+replacement}`` — replacement if set **and non-empty**
    - ``${VAR+replacement}``  — replacement if set
    - ``${VAR:?error}`` — raise if unset **or empty**
    - ``${VAR?error}``  — raise if unset
    - ``$$`` → literal ``$``
    """

    def _repl(m: re.Match) -> str:
        if m.group(0) == "$$":
            return "$"
        name: str = m.group(1) or m.group(2) or ""

        # ${VAR:-default} — default if unset or empty
        if ":-" in name:
            var, default = name.split(":-", 1)
            val = env.get(var)
            return default if val is None or val == "" else val
        # ${VAR-default} — default if unset only
        if "-" in name:
            var, default = name.split("-", 1)
            return env.get(var, default)
        # ${VAR:+replacement} — replacement if set and non-empty
        if ":+" in name:
            var, repl = name.split(":+", 1)
            val = env.get(var)
            return repl if val is not None and val != "" else ""
        # ${VAR+replacement} — replacement if set (even if empty)
        if "+" in name:
            var, repl = name.split("+", 1)
            return repl if var in env else ""
        # ${VAR:?error} — error if unset or empty
        if ":?" in name:
            var, err = name.split(":?", 1)
            val = env.get(var)
            if val is None or val == "":
                raise ValueError(
                    f"Variable {var!r} is required: {err}"
                )
            return val
        # ${VAR?error} — error if unset
        if "?" in name:
            var, err = name.split("?", 1)
            if var not in env:
                raise ValueError(
                    f"Variable {var!r} is required: {err}"
                )
            return env[var]

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
    cap_drop: list[str] = field(default_factory=list)
    privileged: bool = False
    stop_signal: str | None = None
    stop_grace_period: str | None = None
    ulimits: dict[str, tuple[int, int]] = field(default_factory=dict)
    # maps resource name → (soft, hard), e.g. {"nofile": (65535, 65535)}
    networks: list[str] = field(default_factory=list)
    # compose networks this service belongs to (empty → "default")
    shm_size: str | None = None
    tmpfs: list[str] = field(default_factory=list)
    cpus: str | None = None  # deploy.resources.limits.cpus
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
    """Parse ports into ``host:container`` strings.

    Supports compose-spec short form (``"8080:80"``), long form
    (``{target: 80, published: 8080}``), and port ranges
    (``"8000-9000:8000-9000"``).
    """
    if not raw:
        return []
    result: list[str] = []
    for p in raw:
        if isinstance(p, dict):
            # Long form: {target: 80, published: 8080, protocol: tcp}
            target = p.get("target", "")
            published = p.get("published", target)
            result.append(f"{published}:{target}")
            continue
        p = str(p)
        # Strip protocol suffix for port_map (pasta handles TCP)
        p = re.sub(r"/(tcp|udp)$", "", p)
        # Expand port ranges: "8000-9000:8000-9000" → individual mappings
        m = re.match(
            r"^(?:(\S+):)?(\d+)-(\d+):(\d+)-(\d+)$", p,
        )
        if m:
            bind_addr = m.group(1)
            host_start, host_end = int(m.group(2)), int(m.group(3))
            cont_start, cont_end = int(m.group(4)), int(m.group(5))
            if host_end - host_start == cont_end - cont_start:
                for offset in range(host_end - host_start + 1):
                    hp, cp = host_start + offset, cont_start + offset
                    if bind_addr:
                        result.append(f"{bind_addr}:{hp}:{cp}")
                    else:
                        result.append(f"{hp}:{cp}")
                continue
        result.append(p)
    return result


# Fields we parse and map to SandboxConfig
_SUPPORTED_SERVICE_KEYS = frozenset({
    "image", "build", "command", "entrypoint", "environment",
    "volumes", "ports", "devices", "depends_on", "healthcheck",
    "network_mode", "dns", "hostname", "working_dir", "restart",
    "security_opt", "cap_add", "cap_drop", "privileged",
    "stop_signal", "stop_grace_period",
    "ulimits", "shm_size", "tmpfs", "cpu_shares",
    "mem_limit", "memswap_limit", "env_file",
    # Functional support
    "extra_hosts", "sysctls",
    # Cosmetic / informational — safe to ignore silently
    "container_name", "profiles", "stdin_open", "tty",
    "labels", "logging", "expose",
    # Not needed: host networking replaces custom networks
    "networks",
    # Docker Compose fields parsed for compatibility but mapped to
    # nitrobox equivalents where possible (deploy → cpu/memory limits)
    "deploy", "pull_policy",
})

# Fields that affect container semantics but are not (yet) supported.
# Accepted to avoid hard errors on common compose files, but a warning
# is emitted so users know the field has no effect.
_WARN_IGNORED_KEYS = frozenset({
    "init",   # PID 1 init process — rootless sandboxes always use bash
    "user",   # container user — sandbox runs as root in user namespace
    "pid",    # PID namespace sharing — not supported
    "ipc",    # IPC namespace sharing — not supported
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


def _deep_merge(base: dict, override: dict) -> dict:
    """Deep-merge *override* into *base* following docker compose rules.

    Mappings are recursively merged; scalars and sequences in *override*
    replace those in *base*.
    """
    merged = dict(base)
    for key, val in override.items():
        if (
            key in merged
            and isinstance(merged[key], dict)
            and isinstance(val, dict)
        ):
            merged[key] = _deep_merge(merged[key], val)
        else:
            merged[key] = val
    return merged


def _resolve_build_contexts(layer: dict, compose_dir: Path) -> None:
    """Resolve relative build context paths against the compose file's directory.

    Docker Compose resolves relative paths in each file relative to that
    file's parent directory.  We do this before merging so that each
    file's paths are absolute before they get overwritten.
    """
    for svc in (layer.get("services") or {}).values():
        if not isinstance(svc, dict):
            continue
        build = svc.get("build")
        if build is None:
            continue
        if isinstance(build, str):
            resolved = (compose_dir / build).resolve()
            svc["build"] = str(resolved)
        elif isinstance(build, dict) and "context" in build:
            ctx = build["context"]
            if not os.path.isabs(ctx):
                build["context"] = str((compose_dir / ctx).resolve())


def _parse_compose(
    compose_file: Path | list[Path],
    env: dict[str, str],
) -> tuple[dict[str, _Service], list[str]]:
    """Parse one or more docker-compose files and return (services, named_volumes).

    When *compose_file* is a list, files are merged left-to-right following
    ``docker compose -f a.yaml -f b.yaml`` semantics (later files override
    earlier ones).

    Warns on unsupported service-level fields.
    """
    files = [compose_file] if isinstance(compose_file, Path) else compose_file

    data: dict = {}
    for f in files:
        text = Path(f).read_text()
        text = _substitute(text, env)
        layer = yaml.safe_load(text) or {}
        # Resolve relative build context paths against this file's directory
        # BEFORE merging, so we know which file defined them.
        _resolve_build_contexts(layer, Path(f).parent)
        data = _deep_merge(data, layer)

    services_raw = data.get("services", {})
    named_volumes = list((data.get("volumes") or {}).keys())

    services: dict[str, _Service] = {}
    for name, svc in services_raw.items():
        if not isinstance(svc, dict):
            continue

        # Warn on fields that are accepted but have no effect.
        ignored = [k for k in svc if k in _WARN_IGNORED_KEYS]
        if ignored:
            logger.warning(
                "service %r: compose fields ignored (not supported in "
                "nitrobox): %s",
                name, ", ".join(sorted(ignored)),
            )

        # Reject truly unsupported fields
        all_known = _SUPPORTED_SERVICE_KEYS | _WARN_IGNORED_KEYS
        unsupported = [k for k in svc if k not in all_known]
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
            # Use the first compose file's parent as base for env_file paths
            base_dir = (files[0] if isinstance(files, list) else files).parent
            for ef in raw_env_file:
                env_from_file.update(_parse_env_file(base_dir / ef))
        merged_env = {**env_from_file, **_parse_environment(svc.get("environment"))}

        # Extract resource limits from deploy.resources.limits (docker compose v3)
        deploy = svc.get("deploy") or {}
        deploy_limits = (deploy.get("resources") or {}).get("limits") or {}
        deploy_cpus = deploy_limits.get("cpus")
        deploy_memory = deploy_limits.get("memory")

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
            cap_drop=[str(c) for c in (svc.get("cap_drop") or [])],
            privileged=bool(svc.get("privileged")),
            stop_signal=svc.get("stop_signal"),
            stop_grace_period=svc.get("stop_grace_period"),
            ulimits=_parse_ulimits(svc.get("ulimits")),
            networks=list(svc["networks"]) if isinstance(svc.get("networks"), (list, dict)) else [],
            shm_size=svc.get("shm_size"),
            tmpfs=tmpfs_list,
            cpus=str(deploy_cpus) if deploy_cpus else None,
            cpu_shares=int(svc["cpu_shares"]) if svc.get("cpu_shares") else None,
            mem_limit=svc.get("mem_limit") or (str(deploy_memory) if deploy_memory else None),
            memswap_limit=svc.get("memswap_limit"),
            extra_hosts=[str(h) for h in (svc.get("extra_hosts") or [])],
            sysctls={str(k): str(v) for k, v in (svc.get("sysctls") or {}).items()},
        )

    return services, named_volumes


def _topo_sort(services: dict[str, _Service]) -> list[str]:
    """Topological sort by depends_on (depth-first) with cycle detection.

    Raises ``ValueError`` if a dependency cycle is found (matching
    Docker Compose's ``dependencies.go`` cycle detection).
    """
    visited: set[str] = set()
    in_stack: set[str] = set()  # nodes currently on the recursion stack
    order: list[str] = []

    def _visit(name: str, path: list[str]) -> None:
        if name in in_stack:
            cycle = " -> ".join(path + [name])
            raise ValueError(f"Dependency cycle detected: {cycle}")
        if name in visited:
            return
        visited.add(name)
        in_stack.add(name)
        svc = services.get(name)
        if svc:
            for dep in svc.depends_on:
                _visit(dep, path + [name])
        in_stack.discard(name)
        order.append(name)

    for name in services:
        _visit(name, [])
    return order
