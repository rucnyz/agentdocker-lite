"""Tests for docker-compose compatibility layer."""

from __future__ import annotations

import os
import subprocess
import textwrap
from pathlib import Path

import pytest

from agentdocker_lite.compose import (
    ComposeProject,
    _parse_compose,
    _substitute,
    _topo_sort,
)


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
        assert services["app"].depends_on == ["db", "redis"]

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
                ulimits:
                  nofile:
                    soft: 65536
                    hard: 65536
                shm_size: "2g"
        """))
        with pytest.raises(ValueError, match="unsupported.*ulimits"):
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
        assert us.depends_on == ["mailpit"]
        assert us.healthcheck is not None
        assert "gmail_data:/app/data" in us.volumes
        assert us.environment["MAILPIT_BASE_URL"] == "http://127.0.0.1:9025"
        assert us.environment["AUTH_PORT"] == "8030"  # default


# ------------------------------------------------------------------ #
#  Topological sort                                                    #
# ------------------------------------------------------------------ #


class TestTopoSort:
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
        assert "db" in services["api"].depends_on
        assert "mail" in services["api"].depends_on
        assert services["frontend"].depends_on == ["mail", "api"]

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

            # Write a file, reset should clear it
            sb.run("echo ephemeral > /tmp/test.txt")
            proj.reset()
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
