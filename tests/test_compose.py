"""Tests for docker-compose compatibility layer."""

from __future__ import annotations

import os
import subprocess
import textwrap
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from nitrobox.compose import (
    ComposeProject,
    _Service,
    _parse_compose,
    _substitute,
    _topo_sort,
)
from nitrobox.compose._project import _HealthMonitor


# ------------------------------------------------------------------ #
#  Variable substitution                                               #
# ------------------------------------------------------------------ #


class TestSubstitute:
    def test_simple_var(self):
        assert _substitute("${FOO}", {"FOO": "bar"}) == "bar"

    def test_var_with_default(self):
        assert _substitute("${FOO:-fallback}", {}) == "fallback"

    def test_var_overrides_default(self):
        assert _substitute("${FOO:-fallback}", {"FOO": "bar"}) == "bar"

    def test_dollar_escape(self):
        assert _substitute("$$HOME", {}) == "$HOME"

    def test_mixed(self):
        result = _substitute(
            "http://127.0.0.1:${PORT:-8080}/api",
            {"PORT": "9090"},
        )
        assert result == "http://127.0.0.1:9090/api"

    def test_multiple_vars(self):
        result = _substitute(
            "${HOST}:${PORT:-80}",
            {"HOST": "localhost"},
        )
        assert result == "localhost:80"

    def test_unset_var_empty(self):
        assert _substitute("${MISSING}", {}) == ""

    def test_empty_default(self):
        assert _substitute("${VAR:-}", {}) == ""


# ------------------------------------------------------------------ #
#  Compose parser                                                      #
# ------------------------------------------------------------------ #


class TestParseCompose:
    def test_basic_parse(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              web:
                image: nginx:latest
                ports:
                  - "8080:80"
                environment:
                  - APP_ENV=production
              db:
                image: postgres:16
                environment:
                  POSTGRES_PASSWORD: secret
                volumes:
                  - pgdata:/var/lib/postgresql/data
                healthcheck:
                  test: ["CMD", "pg_isready"]
                  interval: 5s
                  retries: 3
            volumes:
              pgdata:
        """))
        services, named_vols = _parse_compose(compose, {})
        assert set(services.keys()) == {"web", "db"}
        assert named_vols == ["pgdata"]
        assert services["web"].image == "nginx:latest"
        assert services["web"].ports == ["8080:80"]
        assert services["db"].environment["POSTGRES_PASSWORD"] == "secret"
        assert "pgdata:/var/lib/postgresql/data" in services["db"].volumes
        assert services["db"].healthcheck is not None

    def test_depends_on_list(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                depends_on:
                  - db
                  - redis
              db:
                image: postgres:16
              redis:
                image: redis:alpine
        """))
        services, _ = _parse_compose(compose, {})
        assert services["app"].depends_on == {"db": "service_started", "redis": "service_started"}

    def test_depends_on_dict(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                depends_on:
                  db:
                    condition: service_healthy
              db:
                image: postgres:16
        """))
        services, _ = _parse_compose(compose, {})
        assert "db" in services["app"].depends_on

    def test_variable_substitution(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              web:
                image: nginx:latest
                ports:
                  - "${WEB_PORT:-8080}:80"
                environment:
                  - API_URL=http://127.0.0.1:${API_PORT:-3000}
        """))
        services, _ = _parse_compose(compose, {"WEB_PORT": "9090"})
        assert services["web"].ports == ["9090:80"]
        assert services["web"].environment["API_URL"] == "http://127.0.0.1:3000"

    def test_build_string(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                build: ./app
        """))
        services, _ = _parse_compose(compose, {})
        assert services["app"].build == {"context": "./app"}

    def test_build_object(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                build:
                  context: ./app
                  dockerfile: Dockerfile.prod
                  target: production
        """))
        services, _ = _parse_compose(compose, {})
        assert services["app"].build["context"] == "./app"
        assert services["app"].build["dockerfile"] == "Dockerfile.prod"
        assert services["app"].build["target"] == "production"

    def test_devices_and_cap_add(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              vm:
                image: qemu-vm
                devices:
                  - /dev/kvm
                  - /dev/net/tun
                cap_add:
                  - NET_ADMIN
        """))
        services, _ = _parse_compose(compose, {})
        assert services["vm"].devices == ["/dev/kvm", "/dev/net/tun"]
        assert services["vm"].cap_add == ["NET_ADMIN"]

    def test_unsupported_field_raises(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                cgroup_parent: /custom
        """))
        with pytest.raises(ValueError, match="unsupported.*cgroup_parent"):
            _parse_compose(compose, {})

    def test_port_protocol_stripped(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                ports:
                  - "3389:3389/tcp"
                  - "3389:3389/udp"
        """))
        services, _ = _parse_compose(compose, {})
        assert services["app"].ports == ["3389:3389", "3389:3389"]

    def test_network_mode_host(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              web:
                image: nginx
                network_mode: host
        """))
        services, _ = _parse_compose(compose, {})
        assert services["web"].network_mode == "host"

    def test_dns(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              web:
                image: nginx
                dns:
                  - 8.8.8.8
                  - 8.8.4.4
        """))
        services, _ = _parse_compose(compose, {})
        assert services["web"].dns == ["8.8.8.8", "8.8.4.4"]

    def test_security_opt_and_privileged(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                security_opt:
                  - seccomp:unconfined
                privileged: true
        """))
        services, _ = _parse_compose(compose, {})
        assert "seccomp:unconfined" in services["app"].security_opt
        assert services["app"].privileged is True

    def test_command_string(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                command: "bash /workspace/init.sh"
        """))
        services, _ = _parse_compose(compose, {})
        assert services["app"].command == "bash /workspace/init.sh"

    def test_command_array(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                command: ["python", "main.py", "--port", "8080"]
        """))
        services, _ = _parse_compose(compose, {})
        assert services["app"].command == ["python", "main.py", "--port", "8080"]

    def test_working_dir(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                working_dir: /app/src
        """))
        services, _ = _parse_compose(compose, {})
        assert services["app"].working_dir == "/app/src"

    def test_restart_and_stop_grace_period(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              vm:
                image: qemu-vm
                restart: always
                stop_grace_period: 2m
        """))
        services, _ = _parse_compose(compose, {})
        assert services["vm"].restart == "always"
        assert services["vm"].stop_grace_period == "2m"

    def test_volume_ro_and_bind_mount(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                volumes:
                  - ./data:/app/data
                  - ./config.yml:/app/config.yml:ro
                  - /var/run/docker.sock:/var/run/docker.sock:ro
        """))
        services, _ = _parse_compose(compose, {})
        vols = services["app"].volumes
        assert len(vols) == 3
        assert "./data:/app/data" in vols
        assert "./config.yml:/app/config.yml:ro" in vols
        assert "/var/run/docker.sock:/var/run/docker.sock:ro" in vols

    def test_hostname(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                hostname: my-service
        """))
        services, _ = _parse_compose(compose, {})
        assert services["app"].hostname == "my-service"

    def test_healthcheck_cmd_shell(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              db:
                image: postgres:16
                healthcheck:
                  test: ["CMD-SHELL", "pg_isready -U user -d db"]
                  interval: 10s
                  timeout: 5s
                  retries: 5
                  start_period: 30s
        """))
        services, _ = _parse_compose(compose, {})
        hc = services["db"].healthcheck
        assert hc["test"] == ["CMD-SHELL", "pg_isready -U user -d db"]
        assert hc["interval"] == "10s"
        assert hc["start_period"] == "30s"

    def test_full_dt_style_service(self, tmp_path):
        """Parse a compose file mimicking DecodingTrust gmail env."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              mailpit:
                image: axllent/mailpit:latest
                restart: unless-stopped
                network_mode: host
                environment:
                  MP_UI_BIND_ADDR: "0.0.0.0:${GMAIL_UI_PORT:-8025}"
              user-service:
                build:
                  context: ./user_service
                  dockerfile: Dockerfile
                  network: host
                dns:
                  - 8.8.8.8
                restart: unless-stopped
                network_mode: host
                security_opt:
                  - seccomp:unconfined
                depends_on:
                  - mailpit
                healthcheck:
                  test: ["CMD", "python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8030/health')"]
                  interval: 5s
                  timeout: 5s
                  retries: 10
                  start_period: 10s
                volumes:
                  - gmail_data:/app/data
                  - ./init_examples:/app/init_examples
                environment:
                  - MAILPIT_BASE_URL=http://127.0.0.1:${GMAIL_UI_PORT:-8025}
                  - AUTH_PORT=${GMAIL_AUTH_PORT:-8030}
            volumes:
              gmail_data:
        """))
        services, vols = _parse_compose(compose, {"GMAIL_UI_PORT": "9025"})
        assert "gmail_data" in vols
        mp = services["mailpit"]
        assert mp.image == "axllent/mailpit:latest"
        assert mp.network_mode == "host"
        assert mp.environment["MP_UI_BIND_ADDR"] == "0.0.0.0:9025"

        us = services["user-service"]
        assert us.build is not None
        assert us.dns == ["8.8.8.8"]
        assert "seccomp:unconfined" in us.security_opt
        assert us.depends_on == {"mailpit": "service_started"}
        assert us.healthcheck is not None
        assert "gmail_data:/app/data" in us.volumes
        assert us.environment["MAILPIT_BASE_URL"] == "http://127.0.0.1:9025"
        assert us.environment["AUTH_PORT"] == "8030"  # default


# ------------------------------------------------------------------ #
#  New compose fields                                                  #
# ------------------------------------------------------------------ #


class TestNewComposeFields:
    """Parser tests for extra_hosts, sysctls, init, user, pid, ipc."""

    def test_extra_hosts(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                extra_hosts:
                  - "myhost:10.0.0.1"
                  - "other:192.168.1.1"
        """))
        services, _ = _parse_compose(compose, {})
        assert services["app"].extra_hosts == ["myhost:10.0.0.1", "other:192.168.1.1"]

    def test_sysctls_dict(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                sysctls:
                  net.ipv4.ip_forward: "1"
                  net.core.somaxconn: "1024"
        """))
        services, _ = _parse_compose(compose, {})
        assert services["app"].sysctls == {
            "net.ipv4.ip_forward": "1",
            "net.core.somaxconn": "1024",
        }

    def test_init_no_error(self, tmp_path):
        """init: true should not raise ValueError."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                init: true
        """))
        services, _ = _parse_compose(compose, {})
        assert "app" in services

    def test_user_no_error(self, tmp_path):
        """user field should not raise ValueError."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                user: "1000:1000"
        """))
        services, _ = _parse_compose(compose, {})
        assert "app" in services

    def test_pid_no_error(self, tmp_path):
        """pid field should not raise ValueError."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                pid: "host"
        """))
        services, _ = _parse_compose(compose, {})
        assert "app" in services

    def test_ipc_no_error(self, tmp_path):
        """ipc field should not raise ValueError."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                ipc: "host"
        """))
        services, _ = _parse_compose(compose, {})
        assert "app" in services


    def test_security_opt_whitespace(self, tmp_path):
        """security_opt with space after colon is still recognized."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                security_opt:
                  - "seccomp: unconfined"
        """))
        services, _ = _parse_compose(compose, {})
        assert "seccomp: unconfined" in services["app"].security_opt

    def test_env_file_single(self, tmp_path):
        """env_file loads variables from file."""
        env_file = tmp_path / "test.env"
        env_file.write_text("DB_HOST=localhost\nDB_PORT=5432\n# comment\n")
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent(f"""\
            services:
              db:
                image: postgres
                env_file:
                  - test.env
        """))
        services, _ = _parse_compose(compose, {})
        assert services["db"].environment["DB_HOST"] == "localhost"
        assert services["db"].environment["DB_PORT"] == "5432"

    def test_env_file_override(self, tmp_path):
        """environment: overrides env_file values."""
        env_file = tmp_path / "base.env"
        env_file.write_text("KEY=from_file\n")
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                env_file:
                  - base.env
                environment:
                  KEY: from_inline
        """))
        services, _ = _parse_compose(compose, {})
        assert services["app"].environment["KEY"] == "from_inline"

    def test_env_file_quoted_values(self, tmp_path):
        """env_file strips quotes around values."""
        env_file = tmp_path / "quoted.env"
        env_file.write_text('SINGLE=\'single\'\nDOUBLE="double"\n')
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                env_file:
                  - quoted.env
        """))
        services, _ = _parse_compose(compose, {})
        assert services["app"].environment["SINGLE"] == "single"
        assert services["app"].environment["DOUBLE"] == "double"

    def test_volume_single_path(self, tmp_path):
        """Single-path volume `/data` is treated as `/data:/data`."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: myapp
                volumes:
                  - /data
                  - /var/log:/var/log
        """))
        services, _ = _parse_compose(compose, {})
        assert "/data" in services["app"].volumes
        assert "/var/log:/var/log" in services["app"].volumes

    def test_tmpfs_string_and_list(self, tmp_path):
        """tmpfs as string and as list both work."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              str_form:
                image: myapp
                tmpfs: /run
              list_form:
                image: myapp
                tmpfs:
                  - /run
                  - /tmp
        """))
        services, _ = _parse_compose(compose, {})
        assert services["str_form"].tmpfs == ["/run"]
        assert services["list_form"].tmpfs == ["/run", "/tmp"]


# ------------------------------------------------------------------ #
#  Topological sort                                                    #
# ------------------------------------------------------------------ #


class TestTopoSort:
    def test_circular_deps_no_hang(self, tmp_path):
        """Circular depends_on should not cause infinite loop."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              a:
                image: a
                depends_on: [c]
              b:
                image: b
                depends_on: [a]
              c:
                image: c
                depends_on: [b]
        """))
        services, _ = _parse_compose(compose, {})
        # Should complete without hanging; order may vary but all included
        order = _topo_sort(services)
        assert set(order) == {"a", "b", "c"}

    def test_missing_dependency(self, tmp_path):
        """depends_on referencing a non-existent service should not crash."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: app
                depends_on: [missing_service]
        """))
        services, _ = _parse_compose(compose, {})
        order = _topo_sort(services)
        assert "app" in order

    def test_linear_deps(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              c:
                image: c
                depends_on: [b]
              b:
                image: b
                depends_on: [a]
              a:
                image: a
        """))
        services, _ = _parse_compose(compose, {})
        order = _topo_sort(services)
        assert order.index("a") < order.index("b") < order.index("c")

    def test_no_deps(self, tmp_path):
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              x:
                image: x
              y:
                image: y
        """))
        services, _ = _parse_compose(compose, {})
        order = _topo_sort(services)
        assert set(order) == {"x", "y"}


# ------------------------------------------------------------------ #
#  Complex compose (all features used in real projects)                 #
# ------------------------------------------------------------------ #

_FIXTURES_DIR = Path(__file__).parent / "fixtures"
_COMPLEX_COMPOSE = _FIXTURES_DIR / "complex-compose.yml"


class TestComplexCompose:
    """Parse a compose file exercising all features used in real projects."""

    @pytest.fixture
    def compose_file(self):
        return _COMPLEX_COMPOSE

    def test_all_services_parsed(self, compose_file):
        services, vols = _parse_compose(compose_file, {})
        assert set(services.keys()) == {
            "db", "mail", "api", "frontend", "vm", "healthcheck-sidecar",
        }
        assert set(vols) == {"pgdata", "appdata"}

    def test_image_and_build(self, compose_file):
        services, _ = _parse_compose(compose_file, {})
        assert services["db"].image == "postgres:16"
        assert services["mail"].image == "axllent/mailpit:latest"
        assert services["api"].image is None
        assert services["api"].build["target"] == "production"
        assert services["api"].build["network"] == "host"

    def test_network_mode(self, compose_file):
        services, _ = _parse_compose(compose_file, {})
        assert services["mail"].network_mode == "host"
        assert services["api"].network_mode == "host"
        assert services["db"].network_mode is None

    def test_depends_on_condition(self, compose_file):
        services, _ = _parse_compose(compose_file, {})
        # api depends on db (service_healthy) and mail (service_started)
        assert services["api"].depends_on == {
            "db": "service_healthy",
            "mail": "service_started",
        }
        # frontend uses list syntax → all default to service_started
        assert services["frontend"].depends_on == {
            "mail": "service_started",
            "api": "service_started",
        }

    def test_healthcheck_formats(self, compose_file):
        services, _ = _parse_compose(compose_file, {})
        # CMD-SHELL
        assert services["db"].healthcheck["test"][0] == "CMD-SHELL"
        # CMD with python
        assert services["api"].healthcheck["test"][0] == "CMD"
        assert services["api"].healthcheck["start_period"] == "10s"
        # CMD with curl
        assert services["healthcheck-sidecar"].healthcheck["retries"] == 60

    def test_volumes_named_bind_ro(self, compose_file):
        services, _ = _parse_compose(compose_file, {})
        assert "pgdata:/var/lib/postgresql/data" in services["db"].volumes
        assert "./init.sql:/docker-entrypoint-initdb.d/init.sql:ro" in services["db"].volumes
        assert "appdata:/app/data" in services["api"].volumes
        assert "./config:/app/config:ro" in services["api"].volumes

    def test_devices_and_cap_add(self, compose_file):
        services, _ = _parse_compose(compose_file, {})
        assert services["vm"].devices == ["/dev/kvm", "/dev/net/tun"]
        assert services["vm"].cap_add == ["NET_ADMIN"]

    def test_security_and_privileged(self, compose_file):
        services, _ = _parse_compose(compose_file, {})
        assert "seccomp:unconfined" in services["api"].security_opt
        assert services["api"].privileged is True

    def test_dns(self, compose_file):
        services, _ = _parse_compose(compose_file, {})
        assert services["api"].dns == ["8.8.8.8", "8.8.4.4"]
        assert services["frontend"].dns == ["8.8.8.8"]

    def test_command_array_and_string(self, compose_file):
        services, _ = _parse_compose(compose_file, {})
        assert services["api"].command == ["python", "main.py", "--port", "8030"]
        assert services["vm"].command == "bash /run/entry.sh"
        assert services["healthcheck-sidecar"].command == ["sleep", "infinity"]

    def test_working_dir(self, compose_file):
        services, _ = _parse_compose(compose_file, {})
        assert services["api"].working_dir == "/app/src"

    def test_restart_and_stop_grace(self, compose_file):
        services, _ = _parse_compose(compose_file, {})
        assert services["db"].restart == "unless-stopped"
        assert services["vm"].restart == "always"
        assert services["vm"].stop_grace_period == "2m"

    def test_port_protocol_stripped(self, compose_file):
        services, _ = _parse_compose(compose_file, {})
        # TCP/UDP suffix should be stripped
        assert "3389:3389" in services["vm"].ports

    def test_variable_substitution(self, compose_file):
        services, _ = _parse_compose(
            compose_file,
            {"API_PORT": "9090", "MAIL_UI_PORT": "9025"},
        )
        assert services["mail"].environment["MP_UI_BIND_ADDR"] == "0.0.0.0:9025"
        assert services["api"].environment["API_PORT"] == "9090"
        # Default value when var not provided
        assert services["api"].environment["MAIL_PORT"] == "1025"
        assert services["api"].environment["DB_URL"] == (
            "postgresql://postgres:secret@127.0.0.1:5432/appdb"
        )

    def test_ulimits(self, compose_file):
        services, _ = _parse_compose(compose_file, {})
        assert services["api"].ulimits["nproc"] == (65535, 65535)
        assert services["api"].ulimits["nofile"] == (65535, 65535)
        # Service without ulimits
        assert services["db"].ulimits == {}

    def test_networks_parsed(self, compose_file):
        """networks field should be parsed into service.networks list."""
        services, _ = _parse_compose(compose_file, {})
        assert services["healthcheck-sidecar"].networks == ["default"]
        # Services without explicit networks → empty (defaults to "default" at runtime)
        assert services["db"].networks == []

    def test_topo_sort(self, compose_file):
        services, _ = _parse_compose(compose_file, {})
        order = _topo_sort(services)
        assert order.index("db") < order.index("api")
        assert order.index("mail") < order.index("api")
        assert order.index("api") < order.index("frontend")
        assert order.index("vm") < order.index("healthcheck-sidecar")


# ------------------------------------------------------------------ #
#  Full lifecycle test                                                 #
# ------------------------------------------------------------------ #


class TestComposeProject:
    """Integration test: start/reset/stop with a minimal compose file."""

    def _skip_if_no_sandbox(self):
        if os.geteuid() == 0:
            pytest.skip("compose test must run as non-root")
        if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
            pytest.skip("requires Docker")

    def test_lifecycle(self, tmp_path, shared_cache_dir):
        """up → run → reset → run → down with a single-service compose."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                command: "sleep infinity"
        """))

        proj = ComposeProject(
            compose,
            project_name="test-lifecycle",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            assert "app" in proj.services

            sb = proj.services["app"]
            output, ec = sb.run("echo hello-compose")
            assert ec == 0
            assert "hello-compose" in output

            # Write a file, reset should clear it but service command restarts
            sb.run("echo ephemeral > /tmp/test.txt")
            proj.reset()

            # Service command should have restarted after reset
            output, ec = sb.run("echo post-reset-ok")
            assert ec == 0
            assert "post-reset-ok" in output
            _, ec = sb.run("cat /tmp/test.txt 2>/dev/null")
            assert ec != 0  # file gone after reset
        finally:
            proj.down()

    def test_multi_service(self, tmp_path, shared_cache_dir):
        """Two services with depends_on and /etc/hosts resolution."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              backend:
                image: ubuntu:22.04
                command: "sleep infinity"
              frontend:
                image: ubuntu:22.04
                command: "sleep infinity"
                depends_on:
                  - backend
        """))

        proj = ComposeProject(
            compose,
            project_name="test-multi",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            assert set(proj.services.keys()) == {"backend", "frontend"}

            # /etc/hosts should resolve service names
            output, ec = proj.services["frontend"].run("getent hosts backend")
            assert ec == 0
            assert "127.0.0.1" in output

            # After reset, /etc/hosts should still work
            proj.reset()
            output, ec = proj.services["frontend"].run("getent hosts backend")
            assert ec == 0, f"hosts resolution failed after reset: {output}"
            assert "127.0.0.1" in output
        finally:
            proj.down()

    def test_same_network_shared_netns(self, tmp_path, shared_cache_dir):
        """Services on same network share a network namespace."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              svc_a:
                image: ubuntu:22.04
                command: "sleep infinity"
              svc_b:
                image: ubuntu:22.04
                command: "sleep infinity"
                depends_on:
                  - svc_a
        """))

        proj = ComposeProject(
            compose,
            project_name="test-netns",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            # Both on default network → share netns via SharedNetwork sentinel
            ns_a, _ = proj.services["svc_a"].run("readlink /proc/1/ns/net")
            ns_b, _ = proj.services["svc_b"].run("readlink /proc/1/ns/net")
            assert ns_a.strip() == ns_b.strip(), (
                f"Expected same netns: {ns_a.strip()} vs {ns_b.strip()}"
            )

            # But they have different mount namespaces (filesystem isolation)
            mnt_a, _ = proj.services["svc_a"].run("readlink /proc/1/ns/mnt")
            mnt_b, _ = proj.services["svc_b"].run("readlink /proc/1/ns/mnt")
            assert mnt_a.strip() != mnt_b.strip(), "mount namespaces should differ"

            # After reset, shared netns should survive
            proj.reset()
            ns_a2, _ = proj.services["svc_a"].run("readlink /proc/1/ns/net")
            ns_b2, _ = proj.services["svc_b"].run("readlink /proc/1/ns/net")
            assert ns_a2.strip() == ns_b2.strip(), "shared netns lost after reset"
        finally:
            proj.down()

    def test_different_networks_isolated(self, tmp_path, shared_cache_dir):
        """Services on different networks have different netns."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              svc_x:
                image: ubuntu:22.04
                command: "sleep infinity"
                networks:
                  - net_a
              svc_y:
                image: ubuntu:22.04
                command: "sleep infinity"
                networks:
                  - net_b
            networks:
              net_a:
              net_b:
        """))

        proj = ComposeProject(
            compose,
            project_name="test-iso",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            ns_x, _ = proj.services["svc_x"].run("readlink /proc/1/ns/net")
            ns_y, _ = proj.services["svc_y"].run("readlink /proc/1/ns/net")
            assert ns_x.strip() != ns_y.strip(), (
                f"Expected different netns: {ns_x.strip()} vs {ns_y.strip()}"
            )
        finally:
            proj.down()

    def test_context_manager(self, tmp_path, shared_cache_dir):
        """ComposeProject as context manager."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                command: "sleep infinity"
        """))

        with ComposeProject(
            compose,
            project_name="test-ctx",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        ) as proj:
            output, ec = proj.services["app"].run("echo ctx-ok")
            assert ec == 0
            assert "ctx-ok" in output

    def test_named_volume(self, tmp_path, shared_cache_dir):
        """Named volumes should persist across service resets."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                command: "sleep infinity"
                volumes:
                  - appdata:/data
            volumes:
              appdata:
        """))

        proj = ComposeProject(
            compose,
            project_name="test-vol",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            proj.services["app"].run("echo persistent > /data/test.txt")

            # Named volume is a host bind mount — survives reset
            proj.reset()
            output, ec = proj.services["app"].run("cat /data/test.txt")
            assert ec == 0
            assert "persistent" in output
        finally:
            proj.down()

    def test_double_up_raises(self, tmp_path, shared_cache_dir):
        """Calling up() twice should raise RuntimeError."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                command: "sleep infinity"
        """))

        proj = ComposeProject(
            compose,
            project_name="test-double-up",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            with pytest.raises(RuntimeError, match="already running"):
                proj.up()
        finally:
            proj.down()

    def test_compose_file_not_found(self, tmp_path):
        """Non-existent compose file should raise FileNotFoundError."""
        with pytest.raises(FileNotFoundError):
            ComposeProject(tmp_path / "nonexistent.yml")

    def test_no_services(self, tmp_path, shared_cache_dir):
        """Compose file with no services should not crash."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text("volumes:\n  data:\n")

        proj = ComposeProject(
            compose,
            project_name="test-empty",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        proj.up()  # should be a no-op
        assert proj.services == {}
        proj.down()

    def test_network_mode_host(self, tmp_path, shared_cache_dir):
        """network_mode: host should use host network, not SharedNetwork."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              host_svc:
                image: ubuntu:22.04
                network_mode: host
                command: "sleep infinity"
              normal_svc:
                image: ubuntu:22.04
                command: "sleep infinity"
        """))

        proj = ComposeProject(
            compose,
            project_name="test-hostnet",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            # host_svc should see host network interfaces
            # normal_svc is on SharedNetwork (isolated netns)
            ns_host, _ = proj.services["host_svc"].run("readlink /proc/1/ns/net")
            ns_normal, _ = proj.services["normal_svc"].run("readlink /proc/1/ns/net")
            # They should be different — host_svc is on host netns
            assert ns_host.strip() != ns_normal.strip(), (
                "host mode and normal mode should have different netns"
            )
        finally:
            proj.down()

    def test_image_default_cmd_starts(self, tmp_path, shared_cache_dir):
        """Service with no compose command should auto-start image CMD."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        # python:3.12-slim has CMD ["python3"] — if it starts, we can
        # run commands that depend on python being alive.
        # Use a simpler test: ubuntu with no command. Image CMD is
        # ["bash"], so _cmd_string should return "bash" and start it.
        # We verify by checking the background process is running.
        compose.write_text(textwrap.dedent("""\
            services:
              worker:
                image: ubuntu:22.04
        """))

        proj = ComposeProject(
            compose,
            project_name="test-default-cmd",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            # The sandbox should be alive (image CMD started as background)
            output, ec = proj.services["worker"].run("echo cmd-ok")
            assert ec == 0
            assert "cmd-ok" in output
        finally:
            proj.down()

    def test_compose_command_overrides_image_cmd(self, tmp_path, shared_cache_dir):
        """Compose command: should override image CMD."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                command: "sleep infinity"
        """))

        proj = ComposeProject(
            compose,
            project_name="test-cmd-override",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            # sleep infinity should be running, not image's default CMD
            output, ec = proj.services["app"].run("pgrep -a sleep")
            assert ec == 0
            assert "infinity" in output
        finally:
            proj.down()

    def test_entrypoint_not_double_executed(self, tmp_path, shared_cache_dir):
        """Compose entrypoint should only run at sandbox startup, not as bg."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                entrypoint:
                  - /bin/sh
                  - -c
                  - 'echo ep-ran >> /tmp/ep.log; exec "$$@"'
                  - --
                command: "sleep infinity"
        """))

        proj = ComposeProject(
            compose,
            project_name="test-ep-once",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            import time
            time.sleep(0.5)
            # Entrypoint should have run exactly once (at sandbox startup)
            output, ec = proj.services["app"].run("wc -l < /tmp/ep.log")
            assert ec == 0
            assert output.strip() == "1", f"entrypoint ran {output.strip()} times, expected 1"
        finally:
            proj.down()

    def test_cap_add_passed(self, tmp_path, shared_cache_dir):
        """cap_add from compose should grant extra capabilities at runtime."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              net:
                image: ubuntu:22.04
                command: "sleep infinity"
                cap_add:
                  - NET_RAW
                  - NET_ADMIN
        """))

        proj = ComposeProject(
            compose,
            project_name="test-cap-add",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            sb = proj.services["net"]

            # Config should have cap_add
            assert sb._config.cap_add == ["NET_RAW", "NET_ADMIN"]

            # Runtime: check effective capabilities bitmask
            output, ec = sb.run("cat /proc/self/status | grep CapEff")
            assert ec == 0
            cap_hex = output.strip().split()[-1]
            cap_int = int(cap_hex, 16)
            NET_RAW_BIT = 1 << 13
            NET_ADMIN_BIT = 1 << 12
            assert cap_int & NET_RAW_BIT, f"NET_RAW not in caps: {cap_hex}"
            assert cap_int & NET_ADMIN_BIT, f"NET_ADMIN not in caps: {cap_hex}"
        finally:
            proj.down()

    def test_privileged_grants_all_caps(self, tmp_path, shared_cache_dir):
        """privileged: true should grant all capabilities."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              priv:
                image: ubuntu:22.04
                command: "sleep infinity"
                privileged: true
        """))

        proj = ComposeProject(
            compose,
            project_name="test-privileged",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            sb = proj.services["priv"]

            # privileged should disable seccomp
            assert sb._config.seccomp is False

            # Should have all capabilities (SYS_ADMIN=21, SYS_PTRACE=19, etc.)
            output, ec = sb.run("cat /proc/self/status | grep CapEff")
            assert ec == 0
            cap_hex = output.strip().split()[-1]
            cap_int = int(cap_hex, 16)
            SYS_ADMIN_BIT = 1 << 21
            SYS_PTRACE_BIT = 1 << 19
            NET_RAW_BIT = 1 << 13
            assert cap_int & SYS_ADMIN_BIT, f"SYS_ADMIN not in caps: {cap_hex}"
            assert cap_int & SYS_PTRACE_BIT, f"SYS_PTRACE not in caps: {cap_hex}"
            assert cap_int & NET_RAW_BIT, f"NET_RAW not in caps: {cap_hex}"
        finally:
            proj.down()

    def test_restart_on_failure(self, tmp_path, shared_cache_dir):
        """restart: on-failure should restart a crashing process."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              crasher:
                image: ubuntu:22.04
                command: "sh -c 'echo restarted >> /tmp/restarts; exit 1'"
                restart: on-failure
        """))

        proj = ComposeProject(
            compose,
            project_name="test-restart",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            import time
            time.sleep(5)  # let it crash and restart a few times
            output, ec = proj.services["crasher"].run("wc -l < /tmp/restarts")
            assert ec == 0
            count = int(output.strip())
            assert count >= 2, f"expected at least 2 restarts, got {count}"
        finally:
            proj.down()

    def test_restart_always_restarts_on_exit_0(self, tmp_path, shared_cache_dir):
        """restart: always should restart even on exit 0."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              exiter:
                image: ubuntu:22.04
                command: "sh -c 'echo ran >> /tmp/runs; exit 0'"
                restart: always
        """))

        proj = ComposeProject(
            compose,
            project_name="test-restart-always",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            import time
            time.sleep(5)
            output, ec = proj.services["exiter"].run("wc -l < /tmp/runs")
            assert ec == 0
            count = int(output.strip())
            assert count >= 2, f"expected at least 2 runs, got {count}"
        finally:
            proj.down()

    def test_restart_no_does_not_restart(self, tmp_path, shared_cache_dir):
        """restart: no should not restart after exit."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              oneshot:
                image: ubuntu:22.04
                command: "sh -c 'echo ran >> /tmp/runs; exit 1'"
        """))

        proj = ComposeProject(
            compose,
            project_name="test-no-restart",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            import time
            time.sleep(3)
            output, ec = proj.services["oneshot"].run("wc -l < /tmp/runs")
            assert ec == 0
            count = int(output.strip())
            assert count == 1, f"expected exactly 1 run, got {count}"
        finally:
            proj.down()

    def test_healthcheck_waits(self, tmp_path, shared_cache_dir):
        """Service with healthcheck should block up() until healthy."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        # Service that takes ~2s to become "healthy" (touch a file after delay)
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                command: "sh -c 'sleep 1 && touch /tmp/ready && sleep infinity'"
                healthcheck:
                  test: ["CMD-SHELL", "test -f /tmp/ready"]
                  interval: 30s
                  timeout: 5s
                  retries: 3
                  start_period: 15s
                  start_interval: 1s
        """))

        proj = ComposeProject(
            compose,
            project_name="test-hc-wait",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            t0 = time.monotonic()
            proj.up(timeout=30)
            elapsed = time.monotonic() - t0
            # Should NOT have waited the full start_period (15s).
            # Service becomes ready after ~1s, start_interval is 1s,
            # so health check passes within ~2-3s.  Sandbox creation
            # adds ~2-3s.  Total should be well under 15s.
            assert elapsed < 10.0, f"up() took {elapsed:.1f}s, should be <10s"
            # Verify the service is actually healthy
            _, ec = proj.services["app"].run("test -f /tmp/ready")
            assert ec == 0
        finally:
            proj.down()


# ------------------------------------------------------------------ #
#  Integration tests for extra_hosts and sysctls                       #
# ------------------------------------------------------------------ #


class TestDetachMode:
    """Tests for up(detach=True) and health_status()/wait_healthy()."""

    def _skip_if_no_sandbox(self):
        if os.geteuid() == 0:
            pytest.skip("compose test must run as non-root")
        if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
            pytest.skip("requires Docker")

    def test_detach_returns_immediately(self, tmp_path, shared_cache_dir):
        """up(detach=True) should return before health check passes."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                command: "sh -c 'sleep 3 && touch /tmp/ready && sleep infinity'"
                healthcheck:
                  test: ["CMD-SHELL", "test -f /tmp/ready"]
                  interval: 30s
                  timeout: 5s
                  retries: 3
                  start_period: 15s
                  start_interval: 1s
        """))

        proj = ComposeProject(
            compose,
            project_name="test-detach",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            t0 = time.monotonic()
            proj.up(detach=True)
            elapsed = time.monotonic() - t0
            # Should return in <2s (sandbox creation only, no health wait)
            assert elapsed < 3.0, f"detach took {elapsed:.1f}s, should be <3s"
            # health_status should show "starting" (not yet healthy)
            status = proj.health_status()
            assert "app" in status
            assert status["app"] in ("starting", "healthy")  # might be healthy already
        finally:
            proj.down()

    def test_health_status_transitions(self, tmp_path, shared_cache_dir):
        """health_status() should reflect monitor state changes."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                command: "sh -c 'sleep 1 && touch /tmp/ready && sleep infinity'"
                healthcheck:
                  test: ["CMD-SHELL", "test -f /tmp/ready"]
                  interval: 30s
                  timeout: 5s
                  retries: 3
                  start_period: 15s
                  start_interval: 1s
              worker:
                image: ubuntu:22.04
                command: "sleep infinity"
        """))

        proj = ComposeProject(
            compose,
            project_name="test-status",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up(detach=True)
            # worker has no healthcheck → "none"
            assert proj.health_status()["worker"] == "none"
            # Wait for app to become healthy
            proj.wait_healthy(timeout=15)
            assert proj.health_status()["app"] == "healthy"
        finally:
            proj.down()

    def test_wait_healthy_after_detach(self, tmp_path, shared_cache_dir):
        """wait_healthy() should block until all checks pass."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                command: "sh -c 'sleep 1 && touch /tmp/ready && sleep infinity'"
                healthcheck:
                  test: ["CMD-SHELL", "test -f /tmp/ready"]
                  interval: 30s
                  timeout: 5s
                  retries: 3
                  start_period: 15s
                  start_interval: 1s
        """))

        proj = ComposeProject(
            compose,
            project_name="test-wait-after-detach",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up(detach=True)
            proj.wait_healthy(timeout=15)
            # After wait_healthy, service should be healthy
            _, ec = proj.services["app"].run("test -f /tmp/ready")
            assert ec == 0
        finally:
            proj.down()


class TestExtraHostsAndSysctls:
    """Integration tests for extra_hosts and sysctls compose fields."""

    def _skip_if_no_sandbox(self):
        if os.geteuid() == 0:
            pytest.skip("compose test must run as non-root")
        if subprocess.run(["docker", "info"], capture_output=True).returncode != 0:
            pytest.skip("requires Docker")

    def test_extra_hosts_in_etc_hosts(self, tmp_path, shared_cache_dir):
        """extra_hosts entries should appear in /etc/hosts."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                command: "sleep infinity"
                extra_hosts:
                  - "myapi:10.0.0.99"
                  - "dbhost:192.168.1.50"
        """))

        proj = ComposeProject(
            compose,
            project_name="test-extra-hosts",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            output, ec = proj.services["app"].run("cat /etc/hosts")
            assert ec == 0
            assert "10.0.0.99" in output and "myapi" in output
            assert "192.168.1.50" in output and "dbhost" in output
            # getent should resolve them
            output2, ec2 = proj.services["app"].run("getent hosts myapi")
            assert ec2 == 0
            assert "10.0.0.99" in output2
        finally:
            proj.down()

    def test_extra_hosts_survive_reset(self, tmp_path, shared_cache_dir):
        """extra_hosts should persist after reset()."""
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                command: "sleep infinity"
                extra_hosts:
                  - "custom:10.10.10.10"
        """))

        proj = ComposeProject(
            compose,
            project_name="test-extra-hosts-reset",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            proj.reset()
            output, ec = proj.services["app"].run("getent hosts custom")
            assert ec == 0, f"extra_hosts lost after reset: {output}"
            assert "10.10.10.10" in output
        finally:
            proj.down()

    def test_sysctls_does_not_crash(self, tmp_path, shared_cache_dir):
        """Compose file with sysctls should not crash up().

        Actual sysctl writability depends on kernel namespace support
        and /proc mount options.  This test verifies the mechanism
        runs without error and the service starts successfully.
        """
        self._skip_if_no_sandbox()

        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                command: "sleep infinity"
                sysctls:
                  net.ipv4.ip_forward: "1"
                  kernel.hostname: "sysctl-test"
        """))

        proj = ComposeProject(
            compose,
            project_name="test-sysctls",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        try:
            proj.up()
            # Service should start successfully regardless of sysctl writability
            output, ec = proj.services["app"].run("echo ok")
            assert ec == 0
            assert "ok" in output
        finally:
            proj.down()


# ------------------------------------------------------------------ #
#  _HealthMonitor unit tests (mock-based, no sandbox needed)           #
# ------------------------------------------------------------------ #


class TestHealthMonitor:
    """Unit tests for _HealthMonitor using a mock sandbox."""

    @staticmethod
    def _mock_sb(results: list[tuple[str, int]]):
        """Create a mock sandbox that returns results in order."""
        sb = MagicMock()
        call_count = 0

        def run_side_effect(cmd, timeout=None):
            nonlocal call_count
            if call_count < len(results):
                result = results[call_count]
                call_count += 1
                return result
            return ("", 0)

        sb.run = MagicMock(side_effect=run_side_effect)
        return sb

    def test_immediate_healthy(self):
        """Monitor sets status to healthy on first successful check."""
        sb = self._mock_sb([("", 0)])
        mon = _HealthMonitor(sb, "true", interval=10, timeout=5)
        time.sleep(0.5)
        assert mon.status == "healthy"
        mon.stop()

    def test_healthy_after_failures(self):
        """Monitor becomes healthy after initial failures."""
        sb = self._mock_sb([("", 1), ("", 1), ("", 0)])
        mon = _HealthMonitor(
            sb, "check", interval=0.1, timeout=5,
            start_period=10, start_interval=0.1,
        )
        time.sleep(1.0)
        assert mon.status == "healthy"
        mon.stop()

    def test_unhealthy_after_retries(self):
        """Monitor marks unhealthy after retries consecutive failures."""
        sb = self._mock_sb([("", 1)] * 20)
        mon = _HealthMonitor(
            sb, "check", interval=0.1, timeout=5,
            start_period=0, retries=3,
        )
        time.sleep(1.0)
        assert mon.status == "unhealthy"
        mon.stop()

    def test_start_period_suppresses_unhealthy(self):
        """Failures during start_period don't mark unhealthy."""
        sb = self._mock_sb([("", 1)] * 50)
        mon = _HealthMonitor(
            sb, "check", interval=0.1, timeout=5,
            start_period=2.0, retries=3,
        )
        # During start_period, should stay "starting" not "unhealthy"
        time.sleep(0.5)
        assert mon.status == "starting"
        mon.stop()

    def test_stop_terminates_thread(self):
        """stop() should terminate the background thread promptly."""
        sb = self._mock_sb([("", 1)] * 100)
        mon = _HealthMonitor(
            sb, "check", interval=0.1, timeout=5, start_period=100,
        )
        mon.stop()
        assert not mon._thread.is_alive()

    def test_start_interval_used_during_start_period(self):
        """During start_period, checks use start_interval, not interval."""
        sb = self._mock_sb([("", 1)] * 100)
        mon = _HealthMonitor(
            sb, "check",
            interval=60.0,          # very long — would timeout test if used
            start_interval=0.1,     # fast — allows multiple checks
            start_period=5.0,
            timeout=5, retries=3,
        )
        time.sleep(1.0)
        # Should have made several calls (using start_interval=0.1s)
        call_count = sb.run.call_count
        assert call_count >= 3, f"expected >=3 calls, got {call_count}"
        mon.stop()

    def test_healthy_resets_failure_count(self):
        """A successful check resets consecutive failure counter."""
        # Fail twice, succeed once, fail twice more → should NOT be unhealthy
        # because the success reset the counter
        sb = self._mock_sb([("", 1), ("", 1), ("", 0), ("", 1), ("", 1)])
        mon = _HealthMonitor(
            sb, "check", interval=0.1, timeout=5,
            start_period=0, retries=3,
        )
        time.sleep(1.5)
        # Should be healthy (the success in the middle reset the counter)
        assert mon.status == "healthy"
        mon.stop()

    def test_exception_counts_as_failure(self):
        """If sb.run() raises, it should count as a failed check."""
        sb = MagicMock()
        sb.run = MagicMock(side_effect=RuntimeError("connection lost"))
        mon = _HealthMonitor(
            sb, "check", interval=0.1, timeout=5,
            start_period=0, retries=3,
        )
        time.sleep(1.0)
        assert mon.status == "unhealthy"
        mon.stop()

    def test_unhealthy_breaks_wait(self, tmp_path, shared_cache_dir):
        """_wait_healthy should return early when monitor reports unhealthy."""
        compose = tmp_path / "docker-compose.yml"
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                command: "sleep infinity"
                healthcheck:
                  test: ["CMD-SHELL", "false"]
                  interval: 0.5s
                  timeout: 1s
                  retries: 2
                  start_period: 0s
        """))

        proj = ComposeProject(
            compose,
            project_name="test-hc-unhealthy",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        # up() should raise because health check always fails
        t0 = time.monotonic()
        with pytest.raises(RuntimeError, match="Health check failed"):
            proj.up(timeout=30)
        elapsed = time.monotonic() - t0
        # Should fail fast (retries=2, interval=0.5s) — well before the
        # 30s timeout.  Allow some headroom for sandbox creation.
        assert elapsed < 15.0, f"took {elapsed:.1f}s, should fail fast"

    def test_timeout_raises(self, tmp_path, shared_cache_dir):
        """_wait_healthy should raise RuntimeError on timeout."""
        compose = tmp_path / "docker-compose.yml"
        # Health check that always fails (file never exists)
        compose.write_text(textwrap.dedent("""\
            services:
              app:
                image: ubuntu:22.04
                command: "sleep infinity"
                healthcheck:
                  test: ["CMD-SHELL", "test -f /nonexistent"]
                  interval: 30s
                  timeout: 1s
                  retries: 100
                  start_period: 30s
                  start_interval: 1s
        """))

        proj = ComposeProject(
            compose,
            project_name="test-hc-timeout",
            env_base_dir=str(tmp_path / "envs"),
            rootfs_cache_dir=shared_cache_dir,
        )
        # Short timeout — should hit deadline before retries exhaust
        with pytest.raises(RuntimeError, match="Health check"):
            proj.up(timeout=5)
