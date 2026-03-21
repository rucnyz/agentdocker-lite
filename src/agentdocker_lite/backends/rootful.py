"""Namespace-based sandbox (root mode) with overlayfs or btrfs backend.

Provides near-zero-overhead environment isolation using Linux namespaces and
copy-on-write filesystems, designed for high-frequency workloads where
environments need to be created, reset, and destroyed thousands of times.

Supported filesystem backends:
- **overlayfs** (default): lowerdir (base) + upperdir (per-env changes).
  Reset clears upperdir -- O(n) in number of changed files.
- **btrfs**: Subvolume snapshots.  Reset = delete snapshot + re-snapshot
  from base -- O(1) regardless of changes.
"""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from agentdocker_lite.backends.base import SandboxBase, SandboxConfig
from agentdocker_lite._shell import _PersistentShell

logger = logging.getLogger(__name__)


class RootfulSandbox(SandboxBase):
    """Linux namespace sandbox with pluggable CoW filesystem backend.

    Each instance manages one isolated environment with:
    - ``unshare --pid --mount --fork`` for PID and mount namespace isolation
    - Persistent shell (chroot) for low-latency command execution
    - Copy-on-write filesystem (overlayfs or btrfs) for instant reset
    - Bind mounts for shared volumes
    - cgroup v2 for optional CPU / memory / PID limits

    Example::

        from agentdocker_lite import Sandbox, SandboxConfig

        config = SandboxConfig(image="ubuntu:22.04", working_dir="/workspace")
        sb = Sandbox(config, name="worker-0")
        output, ec = sb.run("echo hello world")
        sb.reset()        # instant filesystem reset
        sb.delete()       # full cleanup
    """

    SUPPORTED_FS_BACKENDS = ("overlayfs", "btrfs")

    def __init__(self, config: SandboxConfig, name: str = "default"):
        self._config = config
        self._name = name
        self._userns = False
        self._init_rootful(config, name)
        self._register(self)

    # ------------------------------------------------------------------ #
    #  Rootful init (full namespace / overlayfs / cgroup isolation)        #
    # ------------------------------------------------------------------ #

    def _init_rootful(self, config: SandboxConfig, name: str) -> None:
        """Initialize in rootful mode -- full isolation."""
        if not config.image:
            raise ValueError("SandboxConfig.image is required.")

        self._fs_backend = config.fs_backend

        if self._fs_backend not in self.SUPPORTED_FS_BACKENDS:
            raise ValueError(
                f"Unsupported fs_backend {self._fs_backend!r}. "
                f"Choose from: {self.SUPPORTED_FS_BACKENDS}"
            )

        self._check_prerequisites(self._fs_backend)

        # --- paths --------------------------------------------------------
        rootfs_cache_dir = Path(config.rootfs_cache_dir)
        self._base_rootfs, self._layer_dirs = self._resolve_base_rootfs(
            image=config.image,
            fs_backend=self._fs_backend,
            rootfs_cache_dir=rootfs_cache_dir,
        )
        if self._layer_dirs:
            # Multi-layer overlayfs: top layer last in _layer_dirs,
            # overlayfs lowerdir wants topmost first
            self._lowerdir_spec = ":".join(
                str(d) for d in reversed(self._layer_dirs)
            )
        else:
            self._lowerdir_spec = str(self._base_rootfs)

        env_base = Path(config.env_base_dir)
        self._env_dir = env_base / name
        self._rootfs = self._env_dir / "rootfs"

        # overlayfs-only paths
        self._upper_dir: Optional[Path] = None
        self._work_dir: Optional[Path] = None

        # --- state tracking -----------------------------------------------
        self._overlay_mounted = False
        self._btrfs_active = False
        self._bind_mounts: list[Path] = []
        self._cow_tmpdirs: list[str] = []
        self._cgroup_path: Optional[Path] = None
        self._cgroup_limits = {
            "cpu_max": config.cpu_max,
            "memory_max": config.memory_max,
            "pids_max": config.pids_max,
            "io_max": config.io_max,
            "cpuset_cpus": config.cpuset_cpus,
        }

        # --- setup --------------------------------------------------------
        t0 = time.monotonic()
        if self._fs_backend == "btrfs":
            self._setup_btrfs()
        else:
            self._upper_dir = self._env_dir / "upper"
            self._work_dir = self._env_dir / "work"
            self._setup_overlay()
        fs_ms = (time.monotonic() - t0) * 1000

        t1 = time.monotonic()
        self._setup_cgroup()
        cg_ms = (time.monotonic() - t1) * 1000

        t2 = time.monotonic()
        self._apply_config_volumes()
        vol_ms = (time.monotonic() - t2) * 1000

        if config.working_dir and config.working_dir != "/":
            wd = self._rootfs / config.working_dir.lstrip("/")
            wd.mkdir(parents=True, exist_ok=True)

        # Write custom DNS config
        if config.dns:
            self._write_dns(config.dns)

        # Write seccomp files BEFORE read-only remount (they go into
        # the overlayfs upper layer via the merged rootfs path).
        if config.seccomp:
            from agentdocker_lite.security import build_seccomp_bpf
            bpf_bytes = build_seccomp_bpf()
            if bpf_bytes:
                vendor_dir = Path(__file__).parent.parent / "_vendor"
                helper_src = vendor_dir / "adl-seccomp"
                if helper_src.exists():
                    tmp_dir = self._rootfs / "tmp"
                    tmp_dir.mkdir(parents=True, exist_ok=True)
                    (tmp_dir / ".adl_seccomp.bpf").write_bytes(bpf_bytes)
                    shutil.copy2(str(helper_src), str(tmp_dir / ".adl_seccomp"))
                    (tmp_dir / ".adl_seccomp").chmod(0o755)

        # Read-only rootfs: create marker file so adl-seccomp remounts
        # / ro after mounting /proc and /dev but before seccomp blocks
        # mount(). Cannot remount here — pivot_root needs writable rootfs.
        if config.read_only:
            marker = self._rootfs / "tmp" / ".adl_readonly"
            marker.parent.mkdir(parents=True, exist_ok=True)
            marker.touch()

        self._shell = self._detect_shell()
        self._cached_env = self._build_env()

        t3 = time.monotonic()
        self._persistent_shell = _PersistentShell(
            rootfs=self._rootfs,
            shell=self._shell,
            env=self._cached_env,
            working_dir=config.working_dir or "/",
            cgroup_path=self._cgroup_path,
            tty=config.tty,
            net_isolate=config.net_isolate,
            seccomp=config.seccomp,
            landlock_read=config.landlock_read,
            landlock_write=config.landlock_write,
            landlock_tcp_ports=config.landlock_tcp_ports,
            hostname=config.hostname,
            read_only=config.read_only,
        )
        shell_ms = (time.monotonic() - t3) * 1000

        self._bg_handles: dict[str, str] = {}  # handle -> pid
        self._pasta_process = None
        self._start_pasta()

        if config.oom_score_adj is not None:
            self._apply_oom_score_adj(config.oom_score_adj)

        # Write PID file for stale sandbox cleanup
        pid_file = self._env_dir / ".pid"
        pid_file.write_text(str(os.getpid()))

        self.features: dict[str, object] = {
            "pidfd": self._persistent_shell._pidfd is not None,
            "cgroup_v2": self._cgroup_path is not None,
            "seccomp": config.seccomp,
            "netns": config.net_isolate,
            "timens": getattr(self._persistent_shell, "_timens", False),
            "cpuset_cpus": config.cpuset_cpus,
            "oom_score_adj": config.oom_score_adj,
            "mask_paths": True,
            "cap_drop": True,
        }
        feat_str = ", ".join(
            k if v is True else f"{k}={v}"
            for k, v in self.features.items()
            if v
        )
        logger.info(
            "Sandbox ready: name=%s rootfs=%s fs=%s features=[%s] "
            "[setup: fs=%.1fms cgroup=%.1fms volumes=%.1fms shell=%.1fms]",
            name,
            self._rootfs,
            self._fs_backend,
            feat_str,
            fs_ms,
            cg_ms,
            vol_ms,
            shell_ms,
        )

    # ------------------------------------------------------------------ #
    #  Public API -- reset / delete                                        #
    # ------------------------------------------------------------------ #

    def reset(self) -> None:
        """Reset the sandbox filesystem to its initial state.

        This is the RL fast-path: ~27ms for overlayfs, ~28ms for btrfs.
        """
        self._bg_handles.clear()
        self._stop_pasta()
        t0 = time.monotonic()

        self._persistent_shell.kill()

        if self._userns:
            # Mount namespace died with shell -- mounts auto-cleaned.
            # Clear upper/work on host filesystem.
            # The kernel's overlayfs creates work/work with 000 perms;
            # fix permissions before rmtree.
            for d in (self._upper_dir, self._work_dir):
                if d and d.exists():
                    # Overlayfs kernel creates work/work with 000 perms.
                    # Fix permissions so rmtree can delete.
                    for child in d.iterdir():
                        try:
                            child.chmod(0o700)
                        except OSError:
                            pass
                    shutil.rmtree(d)
                if d:
                    d.mkdir(parents=True)

            # Re-create working dir in upper
            if self._config.working_dir and self._config.working_dir != "/":
                wd = self._upper_dir / self._config.working_dir.lstrip("/")
                wd.mkdir(parents=True, exist_ok=True)

            # Re-write seccomp helper to upper
            if self._config.seccomp:
                from agentdocker_lite.security import build_seccomp_bpf
                bpf_bytes = build_seccomp_bpf()
                if bpf_bytes:
                    tmp_dir = self._upper_dir / "tmp"
                    tmp_dir.mkdir(parents=True, exist_ok=True)
                    (tmp_dir / ".adl_seccomp.bpf").write_bytes(bpf_bytes)
                    vendor_dir = Path(__file__).parent.parent / "_vendor"
                    helper_src = vendor_dir / "adl-seccomp"
                    if helper_src.exists():
                        shutil.copy2(str(helper_src), str(tmp_dir / ".adl_seccomp"))
                        (tmp_dir / ".adl_seccomp").chmod(0o755)

            # Re-create read_only marker (cleared by upper dir wipe)
            if self._config.read_only and self._config.seccomp:
                marker = self._upper_dir / "tmp" / ".adl_readonly"
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.touch()
        else:
            self._unmount_binds()
            if self._fs_backend == "btrfs":
                self._reset_btrfs()
            else:
                self._reset_overlayfs()
            self._apply_config_volumes()
            if self._config.working_dir and self._config.working_dir != "/":
                wd = self._rootfs / self._config.working_dir.lstrip("/")
                wd.mkdir(parents=True, exist_ok=True)

            # Re-write seccomp + read_only marker after overlayfs reset
            if self._config.seccomp:
                from agentdocker_lite.security import build_seccomp_bpf
                bpf_bytes = build_seccomp_bpf()
                if bpf_bytes:
                    vendor_dir = Path(__file__).parent.parent / "_vendor"
                    helper_src = vendor_dir / "adl-seccomp"
                    if helper_src.exists():
                        tmp_dir = self._rootfs / "tmp"
                        tmp_dir.mkdir(parents=True, exist_ok=True)
                        (tmp_dir / ".adl_seccomp.bpf").write_bytes(bpf_bytes)
                        shutil.copy2(str(helper_src), str(tmp_dir / ".adl_seccomp"))
                        (tmp_dir / ".adl_seccomp").chmod(0o755)
            if self._config.read_only and self._config.seccomp:
                marker = self._rootfs / "tmp" / ".adl_readonly"
                marker.parent.mkdir(parents=True, exist_ok=True)
                marker.touch()

        self._persistent_shell.start()
        self._start_pasta()

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.debug("Environment reset (%.3fms): %s", elapsed_ms, self._env_dir)

    def delete(self) -> None:
        """Delete the sandbox and clean up all resources."""
        t0 = time.monotonic()

        # Kill all background processes before killing the shell
        # (stop_background uses self.run() which needs the shell alive)
        for handle in list(self._bg_handles):
            try:
                self.stop_background(handle)
            except Exception:
                pass

        self._stop_pasta()
        self._persistent_shell.kill()

        if not self._userns:
            self._unmount_all()
            if self._fs_backend == "btrfs" and self._btrfs_active:
                subprocess.run(
                    ["btrfs", "subvolume", "delete", str(self._rootfs)],
                    capture_output=True,
                )
                self._btrfs_active = False
            self._cleanup_cgroup()

        if self._env_dir.exists():
            # Fix 000-perm dirs left by overlayfs kernel in userns mode
            if self._userns and self._work_dir and self._work_dir.exists():
                for child in self._work_dir.iterdir():
                    try:
                        child.chmod(0o700)
                    except OSError:
                        pass
            shutil.rmtree(self._env_dir, ignore_errors=True)

        self._unregister(self)

        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.info("Deleted sandbox (%.1fms): %s", elapsed_ms, self._env_dir)

    # ------------------------------------------------------------------ #
    #  Auto rootfs preparation                                             #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _resolve_base_rootfs(
        image: str,
        fs_backend: str,
        rootfs_cache_dir: Path,
    ) -> tuple[Path, list[Path] | None]:
        """Resolve the base rootfs for a sandbox.

        For overlayfs (rootful): uses Docker layer-level caching.
        For btrfs: uses flat rootfs via docker export into a btrfs subvolume.
        For userns (rootless): uses flat rootfs via docker export
            (called separately from ``_resolve_flat_rootfs``).

        Returns:
            A tuple of (base_rootfs_path, layer_dirs).
            ``layer_dirs`` is an ordered list of layer directories
            (bottom to top) for multi-layer overlayfs stacking.
        """
        candidate = Path(image)
        if candidate.exists() and candidate.is_dir():
            return candidate, None

        if fs_backend == "btrfs":
            return RootfulSandbox._resolve_btrfs_rootfs(
                image, rootfs_cache_dir,
            ), None

        # --- overlayfs: layer-level caching ---
        from agentdocker_lite.rootfs import prepare_rootfs_layers_from_docker

        t0 = time.monotonic()
        layer_dirs = prepare_rootfs_layers_from_docker(
            image, rootfs_cache_dir, pull=True,
        )
        elapsed_ms = (time.monotonic() - t0) * 1000
        logger.info(
            "Layer cache ready (%.1fms): %s (%d layers)",
            elapsed_ms, image, len(layer_dirs),
        )
        return layer_dirs[0], layer_dirs

    @staticmethod
    def _resolve_btrfs_rootfs(
        image: str,
        rootfs_cache_dir: Path,
    ) -> Path:
        """Resolve flat rootfs for btrfs backend."""
        import fcntl

        from agentdocker_lite.rootfs import prepare_btrfs_rootfs_from_docker

        safe_name = image.replace("/", "_").replace(":", "_").replace(".", "_")
        cached_rootfs = rootfs_cache_dir / safe_name

        if cached_rootfs.exists() and cached_rootfs.is_dir():
            RootfulSandbox._verify_btrfs_subvolume(cached_rootfs)
            return cached_rootfs

        lock_path = rootfs_cache_dir / f".{safe_name}.lock"
        rootfs_cache_dir.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "w") as lock_fd:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                if cached_rootfs.exists() and cached_rootfs.is_dir():
                    RootfulSandbox._verify_btrfs_subvolume(cached_rootfs)
                    return cached_rootfs

                t0 = time.monotonic()
                prepare_btrfs_rootfs_from_docker(image, cached_rootfs)
                elapsed_ms = (time.monotonic() - t0) * 1000
                logger.info(
                    "Auto-prepared btrfs rootfs (%.1fms): %s -> %s",
                    elapsed_ms, image, cached_rootfs,
                )
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        return cached_rootfs

    @staticmethod
    def _resolve_flat_rootfs(
        image: str,
        rootfs_cache_dir: Path,
    ) -> Path:
        """Resolve flat rootfs via docker export (for userns/rootless)."""
        import fcntl

        candidate = Path(image)
        if candidate.exists() and candidate.is_dir():
            return candidate

        from agentdocker_lite.rootfs import prepare_rootfs_from_docker

        safe_name = image.replace("/", "_").replace(":", "_").replace(".", "_")
        cached_rootfs = rootfs_cache_dir / safe_name

        if cached_rootfs.exists() and cached_rootfs.is_dir():
            return cached_rootfs

        lock_path = rootfs_cache_dir / f".{safe_name}.lock"
        rootfs_cache_dir.mkdir(parents=True, exist_ok=True)
        with open(lock_path, "w") as lock_fd:
            fcntl.flock(lock_fd, fcntl.LOCK_EX)
            try:
                if cached_rootfs.exists() and cached_rootfs.is_dir():
                    return cached_rootfs

                t0 = time.monotonic()
                prepare_rootfs_from_docker(image, cached_rootfs)
                elapsed_ms = (time.monotonic() - t0) * 1000
                logger.info(
                    "Auto-prepared flat rootfs (%.1fms): %s -> %s",
                    elapsed_ms, image, cached_rootfs,
                )
            finally:
                fcntl.flock(lock_fd, fcntl.LOCK_UN)
        return cached_rootfs

    # ------------------------------------------------------------------ #
    #  Prerequisites                                                      #
    # ------------------------------------------------------------------ #

    @staticmethod
    def _check_prerequisites(fs_backend: str = "overlayfs"):
        if os.geteuid() != 0:
            raise PermissionError(
                "Sandbox requires root for mount / cgroup operations. "
                "Run as root or with CAP_SYS_ADMIN."
            )
        if shutil.which("unshare") is None:
            raise FileNotFoundError(
                "unshare not found. Install util-linux: apt-get install util-linux"
            )
        if fs_backend == "overlayfs":
            result = subprocess.run(
                ["grep", "-q", "overlay", "/proc/filesystems"],
                capture_output=True,
            )
            if result.returncode != 0:
                raise RuntimeError(
                    "Kernel does not support overlayfs. Load it: modprobe overlay"
                )
        elif fs_backend == "btrfs":
            if shutil.which("btrfs") is None:
                raise FileNotFoundError(
                    "btrfs-progs not found. Install: apt-get install btrfs-progs"
                )

    def _write_dns(self, dns_servers: list[str]) -> None:
        """Write custom /etc/resolv.conf into the sandbox rootfs."""
        resolv = self._host_path_write("/etc/resolv.conf")
        resolv.parent.mkdir(parents=True, exist_ok=True)
        content = "".join(f"nameserver {s}\n" for s in dns_servers)
        resolv.write_text(content)

    # ------------------------------------------------------------------ #
    #  Filesystem -- overlayfs                                             #
    # ------------------------------------------------------------------ #

    def _setup_overlay(self):
        from agentdocker_lite._mount import mount_overlay

        for d in (self._upper_dir, self._work_dir, self._rootfs):
            d.mkdir(parents=True, exist_ok=True)

        mount_overlay(
            lowerdir_spec=self._lowerdir_spec,
            upper_dir=str(self._upper_dir),
            work_dir=str(self._work_dir),
            target=str(self._rootfs),
        )

        # Make overlay mount private to prevent mount propagation.
        # On systemd systems, / is shared by default.  Mounts created
        # under a shared parent inherit shared propagation, which means
        # mount events inside a child namespace that still has shared
        # peers could propagate back to the host and corrupt /dev, etc.
        # Making the overlay mount itself private prevents this.
        # (See runc rootfsParentMountPrivate + bind-mount-self pattern.)
        subprocess.run(
            ["mount", "--make-private", str(self._rootfs)],
            capture_output=True,
        )

        self._overlay_mounted = True
        logger.debug("Mounted overlayfs at %s", self._rootfs)

    # ------------------------------------------------------------------ #
    #  Filesystem -- btrfs                                                 #
    # ------------------------------------------------------------------ #

    def _setup_btrfs(self):
        self._verify_btrfs_subvolume(self._base_rootfs)
        self._env_dir.mkdir(parents=True, exist_ok=True)

        if self._rootfs.exists():
            check = subprocess.run(
                ["btrfs", "subvolume", "show", str(self._rootfs)],
                capture_output=True,
                text=True,
            )
            if check.returncode == 0:
                subprocess.run(
                    ["btrfs", "subvolume", "delete", str(self._rootfs)],
                    capture_output=True,
                )
            else:
                shutil.rmtree(self._rootfs, ignore_errors=True)

        result = subprocess.run(
            [
                "btrfs",
                "subvolume",
                "snapshot",
                str(self._base_rootfs),
                str(self._rootfs),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"btrfs snapshot failed: {result.stderr.strip()}. "
                f"Ensure {self._base_rootfs} is a btrfs subvolume and "
                f"{self._env_dir} is on the same btrfs filesystem."
            )
        self._btrfs_active = True
        logger.debug(
            "Created btrfs snapshot: %s -> %s", self._base_rootfs, self._rootfs
        )

    @staticmethod
    def _verify_btrfs_subvolume(path: Path):
        result = subprocess.run(
            ["btrfs", "subvolume", "show", str(path)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise ValueError(
                f"Not a btrfs subvolume: {path}. "
                f"Create one via: btrfs subvolume create {path}"
            )

    # ------------------------------------------------------------------ #
    #  Volume management                                                   #
    # ------------------------------------------------------------------ #

    def _apply_config_volumes(self):
        for spec in self._config.volumes:
            if not isinstance(spec, str) or ":" not in spec:
                continue
            parts = spec.split(":")
            host_path = parts[0]
            container_path = parts[1] if len(parts) > 1 else "/"
            mode = parts[2] if len(parts) > 2 else "rw"
            if mode == "cow":
                self._overlay_mount(host_path, container_path)
            else:
                self._bind_mount(host_path, container_path, read_only=(mode == "ro"))

    def _bind_mount(
        self, host_path: str, container_path: str, read_only: bool = False
    ):
        target = self._rootfs / container_path.lstrip("/")
        target.mkdir(parents=True, exist_ok=True)

        result = subprocess.run(
            ["mount", "--bind", host_path, str(target)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.warning(
                "Failed to bind mount %s -> %s: %s",
                host_path,
                container_path,
                result.stderr.strip(),
            )
            return

        self._bind_mounts.append(target)

        if read_only:
            subprocess.run(
                ["mount", "-o", "remount,ro,bind", str(target)],
                capture_output=True,
            )
        logger.debug(
            "Bind mounted %s -> %s (%s)",
            host_path,
            container_path,
            "ro" if read_only else "rw",
        )

    def _overlay_mount(self, host_path: str, container_path: str):
        """Mount a host directory as copy-on-write via overlayfs.

        Writes inside the sandbox go to a temporary upperdir; the host
        directory is never modified.  Mode ``"cow"`` in volume specs.
        """
        import tempfile

        target = self._rootfs / container_path.lstrip("/")
        target.mkdir(parents=True, exist_ok=True)

        work_base = tempfile.mkdtemp(prefix="adl_cow_")
        upper = Path(work_base) / "upper"
        work = Path(work_base) / "work"
        upper.mkdir()
        work.mkdir()

        from agentdocker_lite._mount import mount_overlay

        try:
            mount_overlay(
                lowerdir_spec=str(host_path),
                upper_dir=str(upper),
                work_dir=str(work),
                target=str(target),
            )
        except OSError as e:
            logger.warning(
                "Failed to overlay mount %s -> %s: %s",
                host_path, container_path, e,
            )
            return

        # Track for cleanup (unmount overlay, then remove tmpdir)
        self._bind_mounts.append(target)
        self._cow_tmpdirs.append(work_base)
        logger.debug(
            "Overlay mounted %s -> %s (cow, upper=%s)", host_path, container_path, upper,
        )

    def _unmount_binds(self):
        import shutil as _shutil

        for mount_point in reversed(self._bind_mounts):
            subprocess.run(["umount", "-l", str(mount_point)], capture_output=True)
        self._bind_mounts.clear()
        for tmpdir in self._cow_tmpdirs:
            _shutil.rmtree(tmpdir, ignore_errors=True)
        self._cow_tmpdirs = []

    def _unmount_all(self):
        self._unmount_binds()
        if self._fs_backend == "overlayfs" and self._overlay_mounted:
            # Use -R (recursive) to handle stacked mounts (e.g. read_only
            # adds a ro remount on top of the overlay).
            subprocess.run(["umount", "-R", "-l", str(self._rootfs)], capture_output=True)
            self._overlay_mounted = False

    # ------------------------------------------------------------------ #
    #  cgroup v2 resource limits                                           #
    # ------------------------------------------------------------------ #

    def _setup_cgroup(self):
        if not any(self._cgroup_limits.values()):
            return

        if not Path("/sys/fs/cgroup/cgroup.controllers").exists():
            logger.warning(
                "cgroup v2 not available -- resource limits will not be enforced."
            )
            return

        cgroup_name = self._env_dir.name
        self._cgroup_path = Path(f"/sys/fs/cgroup/agentdocker_lite/{cgroup_name}")
        try:
            self._cgroup_path.mkdir(parents=True, exist_ok=True)
        except OSError as e:
            logger.warning("Failed to create cgroup %s: %s", self._cgroup_path, e)
            self._cgroup_path = None
            return

        parent = self._cgroup_path.parent
        try:
            subtree_ctl = parent / "cgroup.subtree_control"
            if subtree_ctl.exists():
                for key, ctrl in [
                    ("cpu_max", "cpu"),
                    ("memory_max", "memory"),
                    ("pids_max", "pids"),
                    ("io_max", "io"),
                    ("cpuset_cpus", "cpuset"),
                ]:
                    if self._cgroup_limits.get(key):
                        try:
                            subtree_ctl.write_text(f"+{ctrl}")
                        except OSError:
                            logger.debug(
                                "Could not enable cgroup controller %s", ctrl
                            )
        except OSError:
            pass

        limit_files = {
            "cpu_max": "cpu.max",
            "memory_max": "memory.max",
            "pids_max": "pids.max",
            "io_max": "io.max",
            "cpuset_cpus": "cpuset.cpus",
        }
        for key, filename in limit_files.items():
            value = self._cgroup_limits.get(key)
            if value:
                try:
                    (self._cgroup_path / filename).write_text(str(value))
                    logger.debug("cgroup %s = %s", filename, value)
                except OSError as e:
                    logger.warning("Failed to set cgroup %s: %s", filename, e)

    def _cleanup_cgroup(self):
        if not self._cgroup_path or not self._cgroup_path.exists():
            return
        try:
            procs_file = self._cgroup_path / "cgroup.procs"
            if procs_file.exists():
                for pid in procs_file.read_text().strip().split():
                    try:
                        os.kill(int(pid), 9)
                    except (ProcessLookupError, ValueError):
                        pass
            kill_file = self._cgroup_path / "cgroup.kill"
            if kill_file.exists():
                try:
                    kill_file.write_text("1")
                except OSError:
                    pass
            self._cgroup_path.rmdir()
        except OSError as e:
            logger.debug("cgroup cleanup (non-fatal): %s", e)

    # ------------------------------------------------------------------ #
    #  Reset helpers                                                       #
    # ------------------------------------------------------------------ #

    def _reset_overlayfs(self):
        if self._overlay_mounted:
            subprocess.run(["umount", "-l", str(self._rootfs)], capture_output=True)
            self._overlay_mounted = False

        if self._upper_dir and self._upper_dir.exists():
            shutil.rmtree(self._upper_dir)
        if self._upper_dir:
            self._upper_dir.mkdir(parents=True)

        if self._work_dir and self._work_dir.exists():
            shutil.rmtree(self._work_dir)
        if self._work_dir:
            self._work_dir.mkdir(parents=True)

        self._setup_overlay()

    def _reset_btrfs(self):
        result = subprocess.run(
            ["btrfs", "subvolume", "delete", str(self._rootfs)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            logger.warning(
                "btrfs subvolume delete failed (proceeding): %s",
                result.stderr.strip(),
            )
            if self._rootfs.exists():
                shutil.rmtree(self._rootfs, ignore_errors=True)

        result = subprocess.run(
            [
                "btrfs",
                "subvolume",
                "snapshot",
                str(self._base_rootfs),
                str(self._rootfs),
            ],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                f"btrfs snapshot failed on reset: {result.stderr.strip()}"
            )
        self._btrfs_active = True

    # ------------------------------------------------------------------ #
    #  OOM score                                                            #
    # ------------------------------------------------------------------ #

    def _apply_oom_score_adj(self, score: int) -> None:
        pid = self._persistent_shell._process.pid
        try:
            Path(f"/proc/{pid}/oom_score_adj").write_text(str(score))
        except OSError as e:
            logger.warning("Failed to set oom_score_adj=%d: %s", score, e)

    # ------------------------------------------------------------------ #
    #  Pasta networking                                                    #
    # ------------------------------------------------------------------ #

    def _start_pasta(self) -> None:
        """Start pasta for NAT'd networking with port mapping.

        Mirrors Podman's pasta invocation (containers/common
        ``libnetwork/pasta/pasta_linux.go``):

        1. Bind-mount sandbox netns to ``/run/netns/adl-<name>``
        2. Invoke pasta with ``--config-net``, explicit port mappings,
           and ``--netns <path>`` (never a raw PID)
        3. Disable all automatic port forwarding (``-t none`` etc.)
        4. Let pasta daemonize (no ``-f``)
        """
        port_map = self._config.port_map
        if not port_map:
            return
        if not self._config.net_isolate:
            logger.warning("port_map requires net_isolate=True; ignoring port_map")
            return

        # --- find pasta binary ------------------------------------------------
        vendored = Path(__file__).parent.parent / "_vendor" / "pasta"
        if vendored.exists() and vendored.is_file():
            pasta_bin = str(vendored)
        elif shutil.which("pasta"):
            pasta_bin = "pasta"
        else:
            raise FileNotFoundError(
                "port_map requires 'pasta' (from the passt package). "
                "Install: pacman -S passt / apt install passt"
            )

        # --- bind-mount netns -------------------------------------------------
        shell_pid = self._persistent_shell._process.pid
        netns_name = f"adl-{self._name}"
        netns_path = f"/run/netns/{netns_name}"
        os.makedirs("/run/netns", exist_ok=True)
        if os.path.exists(netns_path):
            subprocess.run(["umount", "-l", netns_path], capture_output=True)
            try:
                os.unlink(netns_path)
            except OSError:
                pass
        # Create file readable by nobody (pasta drops privileges)
        fd = os.open(netns_path, os.O_WRONLY | os.O_CREAT, 0o644)
        os.close(fd)
        subprocess.run(
            ["mount", "--bind", f"/proc/{shell_pid}/ns/net", netns_path],
            capture_output=True, check=True,
        )
        self._netns_path = netns_path

        # --- build pasta args (following Podman's createPastaArgs) ------------
        # Podman uses pasta in rootless mode where no privilege drop is needed.
        # We run as root, so pasta would drop to nobody and lose CAP_SYS_ADMIN
        # for setns().  --runas 0:0 keeps root (safe: pasta runs in our netns).
        cmd: list[str] = [pasta_bin, "--config-net", "--runas", "0:0"]

        # Explicit port mappings
        has_tcp = False
        for mapping in port_map:
            # "8080:80" → -t 8080:80 (TCP by default)
            cmd.extend(["-t", mapping])
            has_tcp = True

        # Disable all automatic port forwarding (Podman default)
        if not has_tcp:
            cmd.extend(["-t", "none"])
        cmd.extend(["-u", "none"])   # no auto UDP
        cmd.extend(["-T", "none"])   # no TCP from namespace to init
        cmd.extend(["-U", "none"])   # no UDP from namespace to init

        cmd.extend(["--dns-forward", "169.254.1.1"])
        cmd.append("--no-map-gw")
        cmd.append("--quiet")
        cmd.extend(["--netns", netns_path])
        cmd.extend(["--map-guest-addr", "169.254.1.2"])

        # --- run pasta (daemonizes by default) --------------------------------
        out = subprocess.run(cmd, capture_output=True, text=True)
        if out.returncode != 0:
            raise RuntimeError(
                f"pasta failed (exit={out.returncode}): {out.stderr.strip()}"
            )

        # Bring up loopback inside the sandbox (pasta --config-net
        # configures the pasta interface but doesn't touch lo)
        self._persistent_shell.execute(
            "ip link set lo up 2>/dev/null || "
            "python3 -c '"
            "import socket,struct,fcntl;"
            "s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM);"
            "fcntl.ioctl(s,0x8914,struct.pack(\"16sH\",b\"lo\","
            "struct.unpack(\"16sH\",fcntl.ioctl(s,0x8913,"
            "struct.pack(\"16sH\",b\"lo\",0)))[1]|1));"
            "s.close()' 2>/dev/null || true",
            timeout=5,
        )

        logger.debug("pasta ready: netns=%s, ports=%s", netns_name, port_map)

    def _stop_pasta(self) -> None:
        """Clean up pasta and the bind-mounted netns.

        pasta daemonizes and should exit when the netns is destroyed.
        We also kill any remaining pasta process bound to our netns.
        """
        netns_path = getattr(self, "_netns_path", None)
        if netns_path and os.path.exists(netns_path):
            subprocess.run(["umount", "-l", netns_path], capture_output=True)
            try:
                os.unlink(netns_path)
            except OSError:
                pass
            self._netns_path = None
        self._pasta_process = None

    # ------------------------------------------------------------------ #
    #  Internal helpers                                                    #
    # ------------------------------------------------------------------ #

    def _detect_shell(self) -> str:
        if self._host_path("/bin/bash").exists():
            return "/bin/bash"
        return "/bin/sh"

    # ------------------------------------------------------------------ #
    #  Userns file I/O: manual overlay (upper dir + base rootfs)           #
    # ------------------------------------------------------------------ #

    def _host_path(self, container_path: str) -> Path:
        """Resolve container_path for reads.

        In userns mode, check upper dir (modified files) first, then
        fall back to base rootfs (original image files).
        """
        if self._userns:
            stripped = container_path.lstrip("/")
            upper = self._upper_dir / stripped
            if upper.exists():
                return upper
            base = self._base_rootfs / stripped
            if base.exists():
                return base
            # Return upper as default (caller checks existence)
            return upper
        return self._rootfs / container_path.lstrip("/")

    def _host_path_write(self, container_path: str) -> Path:
        """Resolve container_path for writes.

        In userns mode, always write to the upper dir so the overlay
        picks up the change.
        """
        if self._userns:
            return self._upper_dir / container_path.lstrip("/")
        return self._rootfs / container_path.lstrip("/")
