"""Docker Engine REST API client over Unix socket.

Replaces all ``subprocess.run(["docker", ...])`` calls with direct
HTTP requests to the Docker daemon, matching how Docker Compose uses
the Go SDK.  Typical latency: ~5 ms per call vs ~300 ms for subprocess.

The socket is discovered automatically:

1. ``$DOCKER_HOST``  (``unix:///path/to/docker.sock``)
2. ``/var/run/docker.sock``  (rootful Docker)
3. ``$XDG_RUNTIME_DIR/docker.sock``  (rootless Docker)
4. ``$XDG_RUNTIME_DIR/podman/podman.sock``  (Podman compat)
"""

from __future__ import annotations

import http.client
import io
import json
import logging
import os
import socket
import tarfile
import threading
from pathlib import Path
from typing import IO, Any

logger = logging.getLogger(__name__)

# Docker Engine API version — 1.45 is compatible with Docker 25+ and Podman 5+.
_API_VERSION = "v1.45"


# ------------------------------------------------------------------
#  Exceptions
# ------------------------------------------------------------------

class DockerAPIError(Exception):
    """Non-200 response from the Docker Engine API."""

    def __init__(self, status: int, message: str) -> None:
        self.status = status
        self.message = message
        super().__init__(f"Docker API error {status}: {message}")


class ImageNotFoundError(DockerAPIError):
    """Image does not exist locally (HTTP 404)."""

    def __init__(self, image: str) -> None:
        super().__init__(404, f"No such image: {image}")
        self.image = image


class DockerSocketError(Exception):
    """Cannot find or connect to the Docker daemon socket."""


# ------------------------------------------------------------------
#  Unix-socket HTTP adapter
# ------------------------------------------------------------------

class _UnixHTTPConnection(http.client.HTTPConnection):
    """HTTPConnection subclass that connects via a Unix domain socket."""

    def __init__(self, socket_path: str, timeout: float = 30) -> None:
        # Host is required by HTTPConnection but unused for Unix sockets.
        super().__init__("localhost", timeout=timeout)
        self._socket_path = socket_path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self._socket_path)


# ------------------------------------------------------------------
#  Socket discovery
# ------------------------------------------------------------------

def _find_docker_socket() -> str:
    """Locate the Docker/Podman daemon socket.

    Raises :class:`DockerSocketError` if no socket is found.
    """
    # 1. Explicit DOCKER_HOST
    host = os.environ.get("DOCKER_HOST", "")
    if host.startswith("unix://"):
        path = host[len("unix://"):]
        if os.path.exists(path):
            return path

    uid = os.getuid()
    xdg = os.environ.get("XDG_RUNTIME_DIR", f"/run/user/{uid}")

    candidates = [
        "/var/run/docker.sock",
        f"{xdg}/docker.sock",
        f"{xdg}/podman/podman.sock",
        f"/run/user/{uid}/podman/podman.sock",
    ]
    for path in candidates:
        if os.path.exists(path):
            return path

    raise DockerSocketError(
        "Cannot find Docker daemon socket. Checked: "
        + ", ".join(candidates)
    )


# ------------------------------------------------------------------
#  DockerClient
# ------------------------------------------------------------------

def _resolve_registry_domain(image: str) -> str:
    """Extract the registry domain from an image reference.

    Uses ``container_image_dist_ref`` (Rust port of Go's
    ``distribution/reference``) for correct parsing.
    """
    try:
        from nitrobox._backend import py_parse_image_ref
        domain, _, _ = py_parse_image_ref(image)
        return domain
    except Exception:
        # Fallback: simple heuristic if Rust unavailable
        parts = image.split("/")
        if len(parts) == 1 or ("." not in parts[0] and ":" not in parts[0]):
            return "docker.io"
        return parts[0]


def _load_registry_auth(image: str) -> str:
    """Read registry auth from ``~/.docker/config.json`` for *image*.

    Matches Docker's auth resolution (and containers-image):
    1. Per-registry ``credHelpers`` (e.g. ``docker-credential-osxkeychain``)
    2. Default ``credsStore`` (e.g. ``docker-credential-pass``)
    3. Inline base64 ``auths`` entries

    Returns a base64-encoded JSON string suitable for the
    ``X-Registry-Auth`` header.
    """
    import base64

    domain = _resolve_registry_domain(image)

    # Docker Hub uses a special auth key.
    docker_hub_aliases = {"docker.io", "index.docker.io", "registry-1.docker.io"}
    if domain in docker_hub_aliases:
        auth_keys = ["https://index.docker.io/v1/", domain]
    else:
        auth_keys = [domain]

    config_path = Path.home() / ".docker" / "config.json"
    try:
        if config_path.exists():
            data = json.loads(config_path.read_text())

            # 1. Per-registry credential helpers (credHelpers)
            cred_helpers = data.get("credHelpers", {})
            for key in auth_keys:
                helper = cred_helpers.get(key)
                if helper:
                    cred = _call_cred_helper(helper, key)
                    if cred:
                        return base64.b64encode(
                            json.dumps(cred).encode()
                        ).decode()

            # 2. Default credential store (credsStore)
            creds_store = data.get("credsStore")
            if creds_store:
                for key in auth_keys:
                    cred = _call_cred_helper(creds_store, key)
                    if cred:
                        return base64.b64encode(
                            json.dumps(cred).encode()
                        ).decode()

            # 3. Inline base64 auth entries
            auths = data.get("auths", {})
            for key in auth_keys:
                entry = auths.get(key)
                if entry and "auth" in entry:
                    raw = base64.b64decode(entry["auth"]).decode()
                    user, _, passwd = raw.partition(":")
                    auth_json = json.dumps({
                        "username": user,
                        "password": passwd,
                    })
                    return base64.b64encode(auth_json.encode()).decode()
    except Exception:
        pass
    return base64.b64encode(b"{}").decode()


def _call_cred_helper(helper: str, server_url: str) -> dict | None:
    """Run ``docker-credential-<helper> get`` and return auth dict.

    Returns ``{"username": ..., "password": ...}`` or ``None``.
    """
    import subprocess

    try:
        result = subprocess.run(
            [f"docker-credential-{helper}", "get"],
            input=server_url.encode(),
            capture_output=True,
            timeout=10,
        )
        if result.returncode != 0:
            return None
        cred = json.loads(result.stdout)
        user = cred.get("Username", "")
        secret = cred.get("Secret", "")
        if user and secret:
            return {"username": user, "password": secret}
    except Exception:
        pass
    return None


class DockerClient:
    """Thin wrapper around the Docker Engine REST API.

    Each method creates a fresh HTTP connection (Unix socket
    connections cost ~0.1 ms, so pooling is unnecessary).
    """

    def __init__(self, socket_path: str | None = None) -> None:
        self._socket_path = socket_path or _find_docker_socket()

    def _conn(self, timeout: float = 30) -> _UnixHTTPConnection:
        return _UnixHTTPConnection(self._socket_path, timeout=timeout)

    def _request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | IO[bytes] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 30,
    ) -> http.client.HTTPResponse:
        conn = self._conn(timeout=timeout)
        hdrs = headers or {}
        if isinstance(body, bytes):
            hdrs.setdefault("Content-Length", str(len(body)))
        conn.request(method, f"/{_API_VERSION}{path}", body=body, headers=hdrs)
        return conn.getresponse()

    def _json_request(
        self,
        method: str,
        path: str,
        *,
        body: bytes | IO[bytes] | None = None,
        headers: dict[str, str] | None = None,
        timeout: float = 30,
    ) -> Any:
        resp = self._request(
            method, path, body=body, headers=headers, timeout=timeout,
        )
        data = resp.read()
        if resp.status >= 400:
            try:
                msg = json.loads(data).get("message", data.decode())
            except (json.JSONDecodeError, UnicodeDecodeError):
                msg = data.decode(errors="replace")
            raise DockerAPIError(resp.status, msg)
        return json.loads(data) if data else None

    # -- Image inspect ------------------------------------------------ #

    def image_inspect(self, name: str) -> dict:
        """``GET /images/{name}/json`` — full image inspect.

        Raises :class:`ImageNotFoundError` if the image does not exist.
        """
        resp = self._request("GET", f"/images/{name}/json")
        data = resp.read()
        if resp.status == 404:
            raise ImageNotFoundError(name)
        if resp.status >= 400:
            try:
                msg = json.loads(data).get("message", data.decode())
            except Exception:
                msg = data.decode(errors="replace")
            raise DockerAPIError(resp.status, msg)
        return json.loads(data)

    def image_exists(self, name: str) -> bool:
        """Return ``True`` if *name* exists in the local Docker store."""
        try:
            self.image_inspect(name)
            return True
        except ImageNotFoundError:
            return False

    # -- Image pull --------------------------------------------------- #

    def image_pull(
        self,
        image: str,
        tag: str = "latest",
        *,
        timeout: float = 600,
    ) -> None:
        """``POST /images/create`` — pull an image from a registry.

        Blocks until the pull is complete.  Sends registry credentials
        from ``~/.docker/config.json`` (same as ``docker pull``).
        """
        # Docker API requires fromImage and tag as separate params.
        if ":" in image and not image.startswith("sha256:"):
            image, tag = image.rsplit(":", 1)

        import urllib.parse
        params = urllib.parse.urlencode({"fromImage": image, "tag": tag})

        resp = self._request(
            "POST",
            f"/images/create?{params}",
            headers={"X-Registry-Auth": _load_registry_auth(image)},
            timeout=timeout,
        )
        # Response is a stream of newline-delimited JSON objects.
        # Must consume the entire stream — pull isn't done until EOF.
        last_error = None
        buf = b""
        while True:
            chunk = resp.read(8192)
            if not chunk:
                break
            buf += chunk
            while b"\n" in buf:
                line, buf = buf.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                    if "error" in event:
                        last_error = event["error"]
                except json.JSONDecodeError:
                    pass

        if last_error:
            raise DockerAPIError(500, f"Pull failed: {last_error}")
        if resp.status >= 400:
            raise DockerAPIError(resp.status, f"Failed to pull {image}:{tag}")

    # -- Image save (export as tar) ----------------------------------- #

    def image_save(self, name: str) -> http.client.HTTPResponse:
        """``GET /images/{name}/get`` — stream image layers as tar.

        Returns the raw :class:`HTTPResponse` (file-like) for streaming
        into ``tarfile.open(fileobj=..., mode='r|')``.
        """
        resp = self._request("GET", f"/images/{name}/get", timeout=300)
        if resp.status == 404:
            raise ImageNotFoundError(name)
        if resp.status >= 400:
            data = resp.read()
            raise DockerAPIError(resp.status, data.decode(errors="replace"))
        return resp

    # -- Image build -------------------------------------------------- #

    def image_build(
        self,
        context_dir: str | Path,
        *,
        dockerfile: str = "Dockerfile",
        tag: str | None = None,
        build_args: dict[str, str] | None = None,
        timeout: float = 600,
    ) -> str:
        """``POST /build`` — build an image from a Dockerfile.

        Returns the image ID (``sha256:...``).
        """
        context_dir = Path(context_dir)

        # Send the entire build context including .dockerignore.
        # BuildKit handles .dockerignore server-side.
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:gz") as tar:
            tar.add(str(context_dir), arcname=".")
        context_bytes = buf.getvalue()

        # Build query string.
        import urllib.parse
        params = urllib.parse.urlencode({"dockerfile": dockerfile})
        if tag:
            params += f"&t={urllib.parse.quote(tag)}"
        if build_args:
            ba = json.dumps(build_args)
            params += f"&buildargs={urllib.parse.quote(ba)}"

        headers = {
            "Content-Type": "application/x-tar",
            "Content-Length": str(len(context_bytes)),
        }
        resp = self._request(
            "POST",
            f"/build?{params}",
            body=context_bytes,
            headers=headers,
            timeout=timeout,
        )

        # Read streaming JSON response.
        image_id = ""
        buf_text = b""
        while True:
            chunk = resp.read(8192)
            if not chunk:
                break
            buf_text += chunk
            # Process complete JSON lines.
            while b"\n" in buf_text:
                line, buf_text = buf_text.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if "error" in event:
                    raise DockerAPIError(500, event["error"])
                if "stream" in event:
                    msg = event["stream"].rstrip("\n")
                    if msg:
                        logger.debug("build: %s", msg)
                # Capture image ID from the "aux" field.
                if "aux" in event and "ID" in event["aux"]:
                    image_id = event["aux"]["ID"]

        if not image_id:
            raise DockerAPIError(500, "Build completed but no image ID returned")
        return image_id

    # -- Image remove ------------------------------------------------- #

    def image_remove(self, name: str, *, force: bool = False) -> None:
        """``DELETE /images/{name}`` — remove a local image."""
        params = "?force=true" if force else ""
        self._json_request("DELETE", f"/images/{name}{params}")

    # -- Image import ------------------------------------------------- #

    def image_import(
        self,
        tar_stream: IO[bytes],
        repo: str,
        tag: str = "latest",
    ) -> str:
        """``POST /images/create?fromSrc=-`` — import a tar as an image.

        Returns the image ID.
        """
        resp = self._request(
            "POST",
            f"/images/create?fromSrc=-&repo={repo}&tag={tag}",
            body=tar_stream,
            headers={"Content-Type": "application/x-tar"},
            timeout=300,
        )
        data = resp.read()
        if resp.status >= 400:
            raise DockerAPIError(resp.status, data.decode(errors="replace"))
        result = json.loads(data)
        return result.get("Id", result.get("status", ""))

    # -- Container operations (for docker export flow) ---------------- #

    def container_create(
        self,
        image: str,
        command: list[str] | None = None,
        binds: list[str] | None = None,
    ) -> str:
        """``POST /containers/create`` — create a stopped container.

        Args:
            image: Image name or ID.
            command: Optional command (e.g. ``["sleep", "300"]``).
            binds: Optional bind-mount list (e.g. ``["/host:/container:ro"]``).

        Returns the container ID.
        """
        config: dict[str, Any] = {"Image": image}
        if command:
            config["Cmd"] = command
        if binds:
            config["HostConfig"] = {"Binds": binds}
        body = json.dumps(config).encode()
        result = self._json_request(
            "POST",
            "/containers/create",
            body=body,
            headers={"Content-Type": "application/json"},
        )
        return result["Id"]

    def container_start(self, container_id: str) -> None:
        """``POST /containers/{id}/start`` — start a created container."""
        resp = self._request("POST", f"/containers/{container_id}/start")
        data = resp.read()
        if resp.status >= 400 and resp.status != 304:  # 304 = already started
            raise DockerAPIError(resp.status, data.decode(errors="replace"))

    def container_stop(
        self, container_id: str, *, timeout: int = 5,
    ) -> None:
        """``POST /containers/{id}/stop`` — stop a running container."""
        resp = self._request(
            "POST", f"/containers/{container_id}/stop?t={timeout}",
            timeout=float(timeout + 10),
        )
        data = resp.read()
        if resp.status >= 400 and resp.status != 304:  # 304 = already stopped
            raise DockerAPIError(resp.status, data.decode(errors="replace"))

    def container_inspect(self, container_id: str) -> dict:
        """``GET /containers/{id}/json`` — full container inspect."""
        return self._json_request("GET", f"/containers/{container_id}/json")

    def container_export(self, container_id: str) -> http.client.HTTPResponse:
        """``GET /containers/{id}/export`` — stream container FS as tar.

        Returns the raw response for streaming into ``tarfile``.
        """
        resp = self._request(
            "GET", f"/containers/{container_id}/export", timeout=300,
        )
        if resp.status >= 400:
            data = resp.read()
            raise DockerAPIError(resp.status, data.decode(errors="replace"))
        return resp

    def container_remove(
        self, container_id: str, *, force: bool = False,
    ) -> None:
        """``DELETE /containers/{id}`` — remove a container."""
        params = "?force=true" if force else ""
        self._json_request(
            "DELETE", f"/containers/{container_id}{params}",
        )


# ------------------------------------------------------------------
#  Module-level singleton
# ------------------------------------------------------------------

_client: DockerClient | None = None
_client_lock = threading.Lock()


def get_client() -> DockerClient:
    """Return (or create) the module-level :class:`DockerClient`.

    Thread-safe: uses double-checked locking so that concurrent callers
    (e.g. health-check daemon threads) never create duplicate instances.
    """
    global _client
    if _client is not None:
        return _client
    with _client_lock:
        if _client is None:
            _client = DockerClient()
        return _client
