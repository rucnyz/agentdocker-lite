"""BuildKit-based image building with in-memory concurrent cache.

Manages an embedded buildkitd subprocess (via rootlesskit userns)
and communicates via a JSON-over-Unix-socket handler. All build,
pull, and layer resolution happens in-process on the server side.
"""

from __future__ import annotations

import json
import logging
import os
import signal
import socket
import subprocess
import threading
import time
from pathlib import Path

logger = logging.getLogger(__name__)

_manager: BuildKitManager | None = None
_lock = threading.Lock()

# Cache: image_name → list of layer fs/ paths
_buildkit_layer_cache: dict[str, list[str]] = {}
# Cache: image_name → OCI config dict
_buildkit_config_cache: dict[str, dict] = {}


def get_buildkit_layers(image_name: str) -> list[str] | None:
    """Look up cached BuildKit layer paths for an image."""
    return _buildkit_layer_cache.get(image_name)


def get_buildkit_config(image_name: str) -> dict | None:
    """Look up cached OCI config for a BuildKit-built image."""
    return _buildkit_config_cache.get(image_name)


class BuildKitManager:
    """Singleton manager for embedded buildkitd lifecycle."""

    def __init__(self):
        self._handler_path: str | None = None
        self._server_proc: subprocess.Popen | None = None
        self._root_dir = str(Path.home() / ".local/share/nitrobox/buildkit")

    @classmethod
    def get(cls) -> BuildKitManager:
        """Get or create the singleton BuildKitManager."""
        global _manager
        if _manager is None:
            with _lock:
                if _manager is None:
                    _manager = cls()
        return _manager

    def _gobin(self) -> str:
        """Find nitrobox-core binary."""
        from nitrobox._gobin import gobin
        return gobin()

    def ensure_running(self) -> str:
        """Start embedded buildkitd if not running, return handler socket path."""
        if self._handler_path and self._is_socket_alive():
            return self._handler_path

        # Check if server is already running (from a previous Python session)
        server_json = Path(self._root_dir) / "server.json"
        if server_json.exists():
            try:
                info = json.loads(server_json.read_text())
                hp = info.get("handler_path", "")
                if hp and os.path.exists(hp):
                    self._handler_path = hp
                    if self._is_socket_alive():
                        logger.info("Reusing existing buildkitd at %s", hp)
                        return self._handler_path
            except Exception:
                pass

        # Start the embedded server
        bin_path = self._gobin()
        ready_path = Path(self._root_dir) / "ready"
        ready_path.unlink(missing_ok=True)

        req = json.dumps({"root_dir": self._root_dir}).encode()

        self._server_proc = subprocess.Popen(
            [bin_path, "buildkit-serve"],
            stdin=subprocess.PIPE,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Send config via stdin (consumed by CLI before rootlesskit re-exec)
        self._server_proc.stdin.write(req + b"\n")
        self._server_proc.stdin.flush()
        # Don't close stdin — keep pipe open so server stays alive

        # Wait for ready
        for _ in range(60):
            if ready_path.exists():
                break
            time.sleep(0.5)
        else:
            raise RuntimeError(
                "buildkitd failed to start within 30s. "
                "Check server logs at " + self._root_dir
            )

        # Read server info
        info = json.loads(server_json.read_text())
        self._handler_path = info["handler_path"]
        logger.info("Embedded buildkitd started at %s", self._handler_path)
        return self._handler_path

    def _is_socket_alive(self) -> bool:
        """Check if the handler socket is connectable."""
        if not self._handler_path or not os.path.exists(self._handler_path):
            return False
        try:
            s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect(self._handler_path)
            s.close()
            return True
        except Exception:
            return False

    def _send_request(self, req: dict, timeout: int = 600) -> dict:
        """Send a JSON request to the handler socket and return response."""
        handler = self.ensure_running()
        docker_config = str(Path.home() / ".docker")
        req["docker_config"] = docker_config

        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect(handler)
        s.sendall(json.dumps(req).encode() + b"\n")
        s.shutdown(socket.SHUT_WR)

        resp = b""
        while True:
            try:
                chunk = s.recv(65536)
                if not chunk:
                    break
                resp += chunk
            except socket.timeout:
                break
        s.close()

        result = json.loads(resp)
        if result.get("error"):
            raise RuntimeError(result["error"])
        return result

    def build(self, context: str, dockerfile: str, tag: str) -> dict:
        """Build a Dockerfile via embedded BuildKit.

        Returns dict with keys: manifest_digest, layer_paths.
        """
        result = self._send_request({
            "action": "build",
            "dockerfile": dockerfile,
            "context": context,
            "tag": tag,
        })

        # Cache results
        if result.get("layer_paths"):
            _buildkit_layer_cache[tag] = result["layer_paths"]
        if result.get("manifest_digest"):
            self._cache_config(tag, result["manifest_digest"])

        return result

    def pull(self, image: str) -> dict:
        """Pull a pre-built image via BuildKit."""
        result = self._send_request({
            "action": "pull",
            "image_ref": image,
        })

        if result.get("layer_paths"):
            _buildkit_layer_cache[image] = result["layer_paths"]
        if result.get("manifest_digest"):
            self._cache_config(image, result["manifest_digest"])

        return result

    def read_image_config(self, manifest_digest: str) -> dict:
        """Read OCI image config via handler."""
        result = self._send_request({
            "action": "config",
            "digest": manifest_digest,
        }, timeout=10)
        if result.get("config"):
            return json.loads(result["config"]) if isinstance(result["config"], str) else result["config"]
        return {}

    def _cache_config(self, tag: str, manifest_digest: str):
        """Cache OCI config for an image tag."""
        try:
            cfg = self.read_image_config(manifest_digest)
            _buildkit_config_cache[tag] = cfg
        except Exception:
            pass

    def stop(self):
        """Stop the embedded buildkitd."""
        if self._server_proc and self._server_proc.poll() is None:
            self._server_proc.terminate()
            try:
                self._server_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self._server_proc.kill()
            self._server_proc = None

        # Also try killing by PID from rootlesskit state
        rk_pid = Path(self._root_dir) / "rootlesskit" / "child_pid"
        if rk_pid.exists():
            try:
                pid = int(rk_pid.read_text().strip())
                os.kill(pid, signal.SIGTERM)
            except (ValueError, ProcessLookupError, OSError):
                pass

        self._handler_path = None

    @property
    def available(self) -> bool:
        """Check if BuildKit backend is available (nitrobox-core exists)."""
        try:
            self._gobin()
            return True
        except Exception:
            return False
