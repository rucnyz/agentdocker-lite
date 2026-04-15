"""BuildKit-based image building with in-memory concurrent cache.

Manages a rootless buildkitd subprocess and provides build/layer APIs
for Dockerfile builds. BuildKit's in-memory content-addressable cache
enables true concurrent builds (~0.5s per cache-hit build, even with
16+ concurrent builds).
"""

from __future__ import annotations

import json
import logging
import os
import shutil
import subprocess
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

_manager: BuildKitManager | None = None
_lock = threading.Lock()

# Cache: image_name → list of layer fs/ paths (set during build)
_buildkit_layer_cache: dict[str, list[str]] = {}
# Cache: image_name → OCI config dict
_buildkit_config_cache: dict[str, dict] = {}


def get_buildkit_layers(image_name: str) -> list[str] | None:
    """Look up cached BuildKit layer paths for an image.

    Returns None if the image was not built via BuildKit.
    """
    return _buildkit_layer_cache.get(image_name)


def get_buildkit_config(image_name: str) -> dict | None:
    """Look up cached OCI config for a BuildKit-built image."""
    return _buildkit_config_cache.get(image_name)


class BuildKitManager:
    """Singleton manager for buildkitd lifecycle and build operations."""

    def __init__(self):
        self._socket_path: str | None = None
        self._snapshot_root: str | None = None
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

    def _buildkitd_bin(self) -> str:
        """Find buildkitd binary."""
        # Check vendored location first
        vendor = Path(__file__).parent.parent / "_vendor" / "buildkitd"
        if vendor.exists() and os.access(vendor, os.X_OK):
            return str(vendor)
        # Check PATH
        path = shutil.which("buildkitd")
        if path:
            return path
        raise FileNotFoundError(
            "buildkitd not found. Install BuildKit or place the binary "
            "at src/nitrobox/_vendor/buildkitd"
        )

    def ensure_running(self) -> str:
        """Start buildkitd if not running, return socket path."""
        if self._socket_path:
            return self._socket_path

        bin_path = self._gobin()
        buildkitd = self._buildkitd_bin()

        # Ensure rootlesskit is on PATH
        env = os.environ.copy()
        gopath = subprocess.run(
            ["go", "env", "GOPATH"], capture_output=True, text=True
        ).stdout.strip()
        if gopath:
            env["PATH"] = f"{gopath}/bin:{env.get('PATH', '')}"

        req = json.dumps({
            "buildkitd_bin": buildkitd,
            "root_dir": self._root_dir,
        }).encode()

        result = subprocess.run(
            [bin_path, "buildkit-start"],
            input=req, capture_output=True, env=env, timeout=60,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to start buildkitd: {result.stderr.decode()[:500]}"
            )

        resp = json.loads(result.stdout)
        self._socket_path = resp["socket_path"]
        self._snapshot_root = resp["snapshot_root"]
        logger.info("buildkitd running at %s", self._socket_path)
        return self._socket_path

    def build(self, context: str, dockerfile: str, tag: str) -> dict:
        """Build a Dockerfile via BuildKit.

        Returns dict with keys: manifest_digest, config_digest, layer_paths.
        """
        socket = self.ensure_running()
        bin_path = self._gobin()

        # Ensure rootlesskit is on PATH
        env = os.environ.copy()
        gopath = subprocess.run(
            ["go", "env", "GOPATH"], capture_output=True, text=True
        ).stdout.strip()
        if gopath:
            env["PATH"] = f"{gopath}/bin:{env.get('PATH', '')}"

        req = json.dumps({
            "socket_path": socket,
            "root_dir": self._root_dir,
            "dockerfile": dockerfile,
            "context": context,
            "tag": tag,
        }).encode()

        result = subprocess.run(
            [bin_path, "buildkit-build"],
            input=req, capture_output=True, env=env, timeout=600,
        )
        if result.returncode != 0:
            stderr = result.stderr.decode()
            if "invalid argument" in stderr and ("subuid" in stderr or "subgid" in stderr or "Lchown" in stderr):
                raise RuntimeError(
                    f"BuildKit build failed for {tag}: UID/GID mapping range too small.\n"
                    f"The image contains files with UIDs that exceed your "
                    f"/etc/subuid range.\n"
                    f"Fix: sudo sed -i 's/{os.getlogin()}:[0-9]*:[0-9]*/"
                    f"{os.getlogin()}:100000:1000000/' /etc/subuid /etc/subgid\n"
                    f"Then restart buildkitd: nitrobox buildkit-stop\n\n"
                    f"Original error: {stderr[-500:]}"
                )
            raise RuntimeError(
                f"BuildKit build failed for {tag}: {stderr[-1000:]}"
            )

        resp = json.loads(result.stdout)

        # Cache layer paths and config for later lookup
        if resp.get("layer_paths"):
            _buildkit_layer_cache[tag] = resp["layer_paths"]
        if resp.get("manifest_digest"):
            try:
                cfg = self.read_image_config(resp["manifest_digest"])
                _buildkit_config_cache[tag] = cfg
            except Exception:
                pass

        return resp

    def get_layer_paths(self, manifest_digest: str) -> list[str]:
        """Get layer fs/ paths from a previous build result."""
        bin_path = self._gobin()
        req = json.dumps({
            "root_dir": self._root_dir,
            "manifest_digest": manifest_digest,
        }).encode()

        result = subprocess.run(
            [bin_path, "buildkit-layers"],
            input=req, capture_output=True, timeout=30,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"Failed to get layers: {result.stderr.decode()[:300]}"
            )

        return json.loads(result.stdout)["layers"]

    def read_image_config(self, manifest_digest: str) -> dict:
        """Read OCI image config from BuildKit content store."""
        content_dir = Path(self._root_dir) / "root/runc-overlayfs/content/blobs/sha256"
        digest = manifest_digest.removeprefix("sha256:")

        # Read manifest
        manifest_path = content_dir / digest
        with open(manifest_path) as f:
            manifest = json.load(f)

        # Read config
        config_digest = manifest["config"]["digest"].removeprefix("sha256:")
        config_path = content_dir / config_digest
        with open(config_path) as f:
            return json.load(f)

    def stop(self):
        """Stop the managed buildkitd."""
        bin_path = self._gobin()
        subprocess.run(
            [bin_path, "buildkit-stop"],
            capture_output=True, timeout=10,
        )
        # Also kill any leftover rootlesskit/buildkitd processes
        import signal
        pid_path = Path(self._root_dir) / "buildkitd.pid"
        if pid_path.exists():
            try:
                pid = int(pid_path.read_text().strip())
                os.kill(pid, signal.SIGTERM)
            except (ValueError, ProcessLookupError, OSError):
                pass
            pid_path.unlink(missing_ok=True)
        self._socket_path = None

    @property
    def available(self) -> bool:
        """Check if BuildKit backend is available."""
        try:
            self._buildkitd_bin()
            return True
        except FileNotFoundError:
            return False
