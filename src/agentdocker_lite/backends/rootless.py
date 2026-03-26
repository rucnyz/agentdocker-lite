"""User-namespace-based sandbox (rootless mode).

Provides the same namespace + overlayfs + chroot isolation as
RootfulSandbox, but without requiring real root privileges.
Uses ``unshare --user --map-root-user`` to get fake root inside
a user namespace (requires kernel >= 5.11).

cgroup resource limits are applied via systemd delegation
(``systemd-run --user --scope``).
"""

from __future__ import annotations

import logging
import os
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Optional

from agentdocker_lite.backends.base import SandboxConfig
from agentdocker_lite.backends.rootful import RootfulSandbox
from agentdocker_lite._shell import _PersistentShell

logger = logging.getLogger(__name__)


class RootlessSandbox(RootfulSandbox):
    """Rootless sandbox using user namespaces.

    Inherits all functionality from RootfulSandbox but forces user
    namespace mode (``_userns = True``).  The Sandbox() factory
    creates this class when not running as root.

    Example::

        from agentdocker_lite import Sandbox, SandboxConfig

        config = SandboxConfig(image="ubuntu:22.04", working_dir="/workspace")
        sb = Sandbox(config, name="worker-0")   # RootlessSandbox if not root
        output, ec = sb.run("echo hello world")
        sb.reset()
        sb.delete()
    """

    def __init__(self, config: SandboxConfig, name: str = "default"):
        # Skip RootfulSandbox.__init__ — it would try rootful mode.
        # We directly initialize in userns mode.
        self._config = config
        self._name = name
        self._userns = True
        self._bg_handles: dict[str, str] = {}
        self._pasta_process = None
        try:
            self._init_userns(config, name)
        except Exception:
            # Clean up overlayfs work dirs (kernel creates d--------- entries)
            env_dir = getattr(self, "_env_dir", None)
            if env_dir and env_dir.exists():
                for child in env_dir.rglob("*"):
                    try:
                        child.chmod(0o700)
                    except OSError:
                        pass
                shutil.rmtree(env_dir, ignore_errors=True)
            raise
        self._register(self)

    # ------------------------------------------------------------------ #
    #  User namespace init (no real root required)                          #
    # ------------------------------------------------------------------ #

    def _init_userns(self, config: SandboxConfig, name: str) -> None:
        """Initialize in user namespace mode -- namespace+overlayfs without root."""
        if not config.image:
            raise ValueError("SandboxConfig.image is required.")

        if config.fs_backend != "overlayfs":
            raise ValueError(
                f"Rootless mode only supports overlayfs, got fs_backend={config.fs_backend!r}. "
                f"btrfs requires root."
            )
        self._fs_backend = "overlayfs"

        self._check_prerequisites_userns()

        # --- paths --------------------------------------------------------
        rootfs_cache_dir = Path(config.rootfs_cache_dir)
        from agentdocker_lite.rootfs import _detect_whiteout_strategy
        whiteout_strategy = _detect_whiteout_strategy()

        if whiteout_strategy == "none":
            logger.debug("Kernel too old for rootless layer cache, using flat rootfs")
            self._base_rootfs = self._resolve_flat_rootfs(
                image=config.image,
                rootfs_cache_dir=rootfs_cache_dir,
            )
            self._layer_dirs: list[Path] | None = None
            self._lowerdir_spec = str(self._base_rootfs)
        else:
            self._base_rootfs, self._layer_dirs = self._resolve_base_rootfs(
                image=config.image,
                rootfs_cache_dir=rootfs_cache_dir,
                fs_backend="overlayfs",
            )
            if self._layer_dirs:
                self._lowerdir_spec = ":".join(
                    str(d) for d in reversed(self._layer_dirs)
                )
            else:
                self._lowerdir_spec = str(self._base_rootfs)

        env_base = Path(config.env_base_dir)
        self._env_dir = env_base / name
        self._rootfs = self._env_dir / "rootfs"   # overlay merged (inside namespace only)
        self._upper_dir = self._env_dir / "upper"
        self._work_dir = self._env_dir / "work"

        for d in (self._upper_dir, self._work_dir, self._rootfs):
            d.mkdir(parents=True, exist_ok=True)

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
            "cpu_shares": config.cpu_shares,
            "memory_swap": config.memory_swap,
        }

        # --- cgroup via systemd delegation --------------------------------
        self._systemd_scope_properties: list[str] = []
        if any(self._cgroup_limits.values()):
            if shutil.which("systemd-run"):
                prop_map = {
                    "cpu_max": "CPUQuota",
                    "memory_max": "MemoryMax",
                    "pids_max": "TasksMax",
                    "io_max": "IOWriteBandwidthMax",
                    "cpu_shares": "CPUWeight",
                    "memory_swap": "MemorySwapMax",
                }
                for key, sd_prop in prop_map.items():
                    value = self._cgroup_limits.get(key)
                    if value:
                        if key == "cpu_max":
                            # Convert "50000 100000" → "50%"
                            parts = str(value).split()
                            if len(parts) == 2:
                                pct = int(int(parts[0]) / int(parts[1]) * 100)
                                self._systemd_scope_properties.append(f"{sd_prop}={pct}%")
                        elif key == "io_max":
                            # io_max is raw cgroup format "MAJ:MIN wbps=N"
                            # systemd uses "IOWriteBandwidthMax=/dev/X N"
                            # Pass as-is; user must use systemd format
                            self._systemd_scope_properties.append(f"{sd_prop}={value}")
                        elif key == "cpu_shares":
                            from agentdocker_lite.backends.base import _convert_cpu_shares
                            weight = _convert_cpu_shares(int(value))
                            self._systemd_scope_properties.append(f"{sd_prop}={weight}")
                        else:
                            self._systemd_scope_properties.append(f"{sd_prop}={value}")
                logger.debug(
                    "cgroup via systemd delegation: %s",
                    self._systemd_scope_properties,
                )
            else:
                logger.warning(
                    "cgroup resource limits requested but systemd-run not found. "
                    "Run as root for direct cgroup access."
                )
        # Device passthrough is handled in the setup script via bind mounts.
        # In user namespaces, bind-mounting from host devtmpfs preserves the
        # original superblock (no SB_I_NODEV), so device nodes work if the
        # user has the required group membership (e.g., kvm group for /dev/kvm).

        # --- seccomp helper in upper dir ----------------------------------
        if config.seccomp:
            from agentdocker_lite.security import build_seccomp_bpf
            bpf_bytes = build_seccomp_bpf()
            if bpf_bytes:
                tmp_dir = self._upper_dir / "tmp"
                tmp_dir.mkdir(parents=True, exist_ok=True)
                (tmp_dir / ".adl_seccomp.bpf").write_bytes(bpf_bytes)
                # Marker: skip /proc+/dev mount in adl-seccomp (setup script
                # already handles these with bind mounts instead of mknod)
                (tmp_dir / ".adl_skip_dev").touch()
                vendor_dir = Path(__file__).parent.parent / "_vendor"
                helper_src = vendor_dir / "adl-seccomp"
                if helper_src.exists():
                    shutil.copy2(str(helper_src), str(tmp_dir / ".adl_seccomp"))
                    (tmp_dir / ".adl_seccomp").chmod(0o755)

        # --- Landlock config in upper dir ---------------------------------
        ll_config = self._build_landlock_config(config)
        if ll_config:
            tmp_dir = self._upper_dir / "tmp"
            tmp_dir.mkdir(parents=True, exist_ok=True)
            (tmp_dir / ".adl_landlock").write_text(ll_config)

        # --- Hostname config (adl-seccomp calls sethostname before cap drop) ---
        if config.hostname:
            tmp_dir = self._upper_dir / "tmp"
            tmp_dir.mkdir(parents=True, exist_ok=True)
            (tmp_dir / ".adl_hostname").write_text(config.hostname + "\n")

        # --- DNS ----------------------------------------------------------
        if config.dns:
            self._write_dns(config.dns)

        # --- working dir in upper dir -------------------------------------
        if config.working_dir and config.working_dir != "/":
            wd = self._upper_dir / config.working_dir.lstrip("/")
            wd.mkdir(parents=True, exist_ok=True)

        # --- generate setup script ----------------------------------------
        self._shell = self._detect_shell()
        setup_script_path = self._generate_userns_setup_script()

        self._cached_env = self._build_env()

        # --- detect subordinate uid range for full mapping -----------------
        subuid_range = self._detect_subuid_range()

        # --- start persistent shell ---------------------------------------
        # In rootless mode with port_map, DON'T pass net_isolate to unshare.
        # The setup script handles network isolation + pasta internally
        # (pasta needs to run inside the userns for CAP_SYS_ADMIN).
        shell_net_isolate = config.net_isolate and not config.port_map and not config.net_ns
        t0 = time.monotonic()
        self._persistent_shell = _PersistentShell(
            rootfs=self._rootfs,
            shell=self._shell,
            env=self._cached_env,
            working_dir=config.working_dir or "/",
            tty=config.tty,
            net_isolate=shell_net_isolate,
            net_ns=config.net_ns,
            seccomp=config.seccomp,
            userns_setup_script=str(setup_script_path),
            systemd_scope_properties=self._systemd_scope_properties or None,
            hostname=config.hostname,
            subuid_range=subuid_range,
            shared_userns=config.shared_userns,
            ulimits=config.ulimits or None,
            entrypoint=config.entrypoint,
        )
        shell_ms = (time.monotonic() - t0) * 1000

        self._bg_handles: dict[str, str] = {}
        self._pasta_process = None
        # Rootless pasta is started from inside the setup script (not here)

        if config.oom_score_adj is not None:
            self._apply_oom_score_adj(config.oom_score_adj)

        # Write PID file for stale sandbox cleanup.
        # Store the shell process PID (not the creator's PID) so that
        # adl kill can terminate the sandbox without killing the owner.
        pid_file = self._env_dir / ".pid"
        pid_file.write_text(str(self._persistent_shell._process.pid))

        self.features: dict[str, object] = {
            "userns": True,
            "layer_cache": self._layer_dirs is not None,
            "whiteout": whiteout_strategy,
            "pidfd": self._persistent_shell._pidfd is not None,
            "seccomp": config.seccomp,
            "landlock": ll_config is not None,
            "netns": config.net_isolate,
            "devices": bool(config.devices),
            "mask_paths": True,
            "cap_drop": True,
        }
        feat_str = ", ".join(
            k if v is True else f"{k}={v}"
            for k, v in self.features.items()
            if v
        )
        logger.info(
            "Sandbox ready (userns): name=%s rootfs=%s features=[%s] [shell=%.1fms]",
            name, self._rootfs, feat_str, shell_ms,
        )

    def _generate_userns_setup_script(self) -> Path:
        """Generate bash setup script for user namespace mode.

        This script runs inside the user namespace (before chroot) and:
        1. Mounts overlayfs
        2. Mounts /proc and /dev (with bind-mounted devices, no mknod)
        3. Bind-mounts volumes
        4. Execs into chroot -- after this, stdin commands go to the inner bash
        """
        merged = self._rootfs
        upper = self._upper_dir
        work = self._work_dir
        shell = self._shell
        norc = " --norc --noprofile" if "bash" in shell else ""

        lines = [
            "#!/bin/bash",
            "set -e",
            "",
            "# Fix 000-perm dirs left by previous overlayfs (shell restart)",
            f"chmod -R 700 {work} 2>/dev/null || true",
            f"rm -rf {work}/work 2>/dev/null || true",
            "",
            "# Mount overlayfs (LIBMOUNT_FORCE_MOUNT2 forces legacy mount(2) syscall,",
            "# bypassing fsconfig 256-byte limit in util-linux >= 2.39)",
            f"LIBMOUNT_FORCE_MOUNT2=always mount -t overlay overlay "
            f"-o lowerdir={self._lowerdir_spec},upperdir={upper},workdir={work},userxattr {merged}",
        ]

        # Pre-create volume mount points BEFORE read-only remount.
        for spec in self._config.volumes:
            if not isinstance(spec, str) or ":" not in spec:
                continue
            parts = spec.split(":")
            container_path = parts[1] if len(parts) > 1 else "/"
            target = f"{merged}/{container_path.lstrip('/')}"
            lines.append(f"mkdir -p {target}")

        # Read-only rootfs: bind + remount ro BEFORE other mounts.
        # Mounts added afterwards (/proc, /dev, volumes) are on top and stay rw.
        if self._config.read_only:
            lines.append(f"mount --bind {merged} {merged}")
            lines.append(f"mount -o remount,ro,bind {merged}")

        lines.extend([
            "",
            "# Mount /proc",
            f"mount -t proc proc {merged}/proc",
            # sysfs only works in userns when network namespace is also new
            f"mount -t sysfs sysfs {merged}/sys 2>/dev/null || true"
            if self._config.net_isolate else
            "# /sys: skipped (requires net_isolate=True in userns)",
            "",
            "# Setup /dev (bind mount from host -- mknod not available in userns)",
            f"mount -t tmpfs -o nosuid,mode=0755 tmpfs {merged}/dev",
        ])

        for dev in ["null", "zero", "full", "random", "urandom", "tty"]:
            lines.append(f"touch {merged}/dev/{dev} 2>/dev/null || true")
            lines.append(
                f"mount --bind /dev/{dev} {merged}/dev/{dev} 2>/dev/null || true"
            )

        lines.extend([
            f"ln -sf /proc/self/fd {merged}/dev/fd 2>/dev/null || true",
            f"ln -sf /proc/self/fd/0 {merged}/dev/stdin 2>/dev/null || true",
            f"ln -sf /proc/self/fd/1 {merged}/dev/stdout 2>/dev/null || true",
            f"ln -sf /proc/self/fd/2 {merged}/dev/stderr 2>/dev/null || true",
            f"mkdir -p {merged}/dev/pts {merged}/dev/shm 2>/dev/null || true",
            f"mount -t devpts devpts {merged}/dev/pts -o nosuid,newinstance,ptmxmode=0666 2>/dev/null || true",
            f"ln -sf pts/ptmx {merged}/dev/ptmx 2>/dev/null || true",
        ])

        # /dev/shm as tmpfs (256MB default — generous enough for QEMU/PyTorch,
        # tmpfs is demand-paged so unused space costs nothing)
        shm_size = self._config.shm_size or str(256 * 1024 * 1024)
        lines.append(
            f"mount -t tmpfs -o nosuid,nodev,noexec,size={shm_size} "
            f"tmpfs {merged}/dev/shm"
        )

        # Custom device passthrough (e.g., /dev/kvm, /dev/fuse)
        # Bind-mount from host devtmpfs preserves the original superblock
        # (no SB_I_NODEV), so the device is usable if the user has the
        # required group membership (e.g., kvm group for /dev/kvm).
        if self._config.devices:
            lines.append("")
            lines.append("# Device passthrough (bind mount from host)")
            for dev_path in self._config.devices:
                dev_name = dev_path.lstrip("/")
                target = f"{merged}/{dev_name}"
                parent = str(Path(dev_name).parent)
                if parent and parent != ".":
                    lines.append(f"mkdir -p {merged}/{parent} 2>/dev/null || true")
                lines.append(f"touch {target} 2>/dev/null || true")
                lines.append(f"mount --bind {dev_path} {target} 2>/dev/null || true")

        lines.extend([
            "",
            "# Propagate DNS: copy host resolv.conf if sandbox one is empty/missing",
            f"if [ ! -s {merged}/etc/resolv.conf ] && [ -s /etc/resolv.conf ]; then",
            f"  cp /etc/resolv.conf {merged}/etc/resolv.conf 2>/dev/null || true",
            "fi",
            "",
            "# Ensure /tmp has standard permissions (Docker exports may lose them)",
            f"chmod 1777 {merged}/tmp 2>/dev/null || true",
            "",
        ])

        # Volume mounts (mount points already created above, before ro remount)
        for spec in self._config.volumes:
            if not isinstance(spec, str) or ":" not in spec:
                continue
            parts = spec.split(":")
            host_path = parts[0]
            container_path = parts[1] if len(parts) > 1 else "/"
            mode = parts[2] if len(parts) > 2 else "rw"
            target = f"{merged}/{container_path.lstrip('/')}"
            if mode == "cow":
                safe = container_path.replace("/", "_").strip("_")
                cow_upper = self._env_dir / f"cow_{safe}_upper"
                cow_work = self._env_dir / f"cow_{safe}_work"
                cow_upper.mkdir(parents=True, exist_ok=True)
                cow_work.mkdir(parents=True, exist_ok=True)
                lines.append(
                    f"mount -t overlay overlay "
                    f"-o lowerdir={host_path},upperdir={cow_upper},"
                    f"workdir={cow_work} {target}"
                )
            else:
                lines.append(f"mount --bind {host_path} {target}")
                if mode == "ro":
                    lines.append(f"mount -o remount,ro,bind {target}")

        # --- Tmpfs mounts ---
        if self._config.tmpfs:
            lines.append("")
            lines.append("# Tmpfs mounts")
            for spec in self._config.tmpfs:
                parts = spec.split(":", 1)
                path = parts[0]
                opts = parts[1] if len(parts) > 1 else ""
                target = f"{merged}/{path.lstrip('/')}"
                lines.append(f"mkdir -p {target}")
                mount_opts = f"-o {opts}" if opts else ""
                lines.append(f"mount -t tmpfs {mount_opts} tmpfs {target}")

        # --- Network isolation + pasta (rootless) ---
        # When port_map is set, unshare did NOT create a net namespace.
        # We handle it here (inside userns where we have CAP_SYS_ADMIN):
        # 1. Create a new netns via unshare --net, bind-mount it
        # 2. Run pasta (still in host netns, can bind host ports)
        # 3. nsenter --net into the new netns for chroot
        # Hostname is set by adl-seccomp via sethostname() syscall
        # (reads /tmp/.adl_hostname, written to upper dir above).

        port_map = self._config.port_map
        # Use adl-seccomp for cap drop + mask + readonly + seccomp BPF.
        # It skips /proc+/dev mount when .adl_skip_dev marker exists.
        seccomp_wrap = "/tmp/.adl_seccomp " if self._config.seccomp else ""
        # OCI ENTRYPOINT: prepend to shell exec so entrypoint runs
        # initialization, then `exec "$@"` hands off to the shell.
        ep_prefix = ""
        if self._config.entrypoint:
            ep_prefix = " ".join(shlex.quote(a) for a in self._config.entrypoint) + " "
        chroot_cmd = f"exec chroot {merged} {seccomp_wrap}{ep_prefix}{shell}{norc}"

        if port_map:
            vendored = Path(__file__).parent.parent / "_vendor" / "pasta"
            pasta_bin = str(vendored) if vendored.exists() else shutil.which("pasta") or ""

            if pasta_bin:
                netns_file = self._env_dir / ".netns"
                pasta_args = f"{pasta_bin} --config-net"
                if not self._config.ipv6:
                    pasta_args += " --ipv4-only"
                for mapping in port_map:
                    pasta_args += f" -t {mapping}"
                pasta_args += (
                    " -u none -T none -U none"
                    " --dns-forward 169.254.1.1 --no-map-gw --quiet"
                    f" --netns {netns_file}"
                    " --map-guest-addr 169.254.1.2"
                )
                lines.extend([
                    "",
                    "# Create network namespace (inside userns for CAP_SYS_ADMIN)",
                    f"touch {netns_file}",
                    f"unshare --net mount --bind /proc/self/ns/net {netns_file}",
                    "",
                    "# Start pasta (in host netns, can bind host ports)",
                    pasta_args,
                    "",
                    "# Enter netns, bring up lo, then chroot",
                    f"exec nsenter --net={netns_file} bash -c "
                    f"'ip link set lo up 2>/dev/null; {chroot_cmd}'",
                ])
            else:
                lines.extend(["", chroot_cmd])
        else:
            lines.extend(["", chroot_cmd])

        script_path = self._env_dir / "setup.sh"
        script_path.write_text("\n".join(lines) + "\n")
        script_path.chmod(0o755)
        return script_path

    @staticmethod
    def _check_prerequisites_userns() -> None:
        """Check user namespace prerequisites."""
        if shutil.which("unshare") is None:
            raise FileNotFoundError(
                "unshare not found. Install util-linux: apt-get install util-linux"
            )
        # Test if user namespaces actually work
        result = subprocess.run(
            ["unshare", "--user", "--map-root-user", "true"],
            capture_output=True,
        )
        if result.returncode != 0:
            raise RuntimeError(
                "User namespaces are not available. Possible fixes:\n"
                "  sysctl -w kernel.unprivileged_userns_clone=1\n"
                "  sysctl -w kernel.apparmor_restrict_unprivileged_userns=0\n"
                f"Error: {result.stderr.decode().strip()}"
            )

    @staticmethod
    def _detect_subuid_range() -> Optional[tuple[int, int, int]]:
        """Detect subordinate UID range for full uid mapping in user namespaces.

        Checks for newuidmap/newgidmap and /etc/subuid entry for the current user.
        Returns (outer_uid, sub_start, sub_count) if available, None otherwise.
        When None, the sandbox falls back to --map-root-user (only uid 0 mapped).
        """
        if shutil.which("newuidmap") is None or shutil.which("newgidmap") is None:
            logger.debug(
                "newuidmap/newgidmap not found. Install uidmap package for full "
                "uid mapping (enables apt-get, useradd, etc. inside sandbox). "
                "Falling back to root-only mapping."
            )
            return None

        import getpass
        try:
            username = getpass.getuser()
        except Exception:
            return None

        uid = os.getuid()

        # Parse /etc/subuid for the current user
        try:
            with open("/etc/subuid") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    parts = line.split(":")
                    if len(parts) != 3:
                        continue
                    # Match by username or UID
                    if parts[0] == username or parts[0] == str(uid):
                        sub_start = int(parts[1])
                        sub_count = int(parts[2])
                        logger.debug(
                            "Full uid mapping available: %s:%d:%d",
                            username, sub_start, sub_count,
                        )
                        return (uid, sub_start, sub_count)
        except FileNotFoundError:
            pass

        logger.debug(
            "No /etc/subuid entry for %s. For full uid mapping, run:\n"
            "  echo '%s:%d:65536' | sudo tee -a /etc/subuid\n"
            "  echo '%s:%d:65536' | sudo tee -a /etc/subgid\n"
            "Falling back to root-only mapping.",
            username, username, 200000, username, 200000,
        )
        return None
