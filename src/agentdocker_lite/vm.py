"""QEMU/KVM virtual machine manager for agentdocker-lite sandboxes.

Manages a QEMU process inside a sandbox and provides QMP (QEMU Monitor
Protocol) communication for VM state management.  Designed for
OSWorld-style GUI agent training where fast VM reset is critical.

Usage::

    from agentdocker_lite import Sandbox, SandboxConfig
    from agentdocker_lite.vm import QemuVM

    sb = Sandbox(SandboxConfig(image="ubuntu:22.04", devices=["/dev/kvm"]))
    vm = QemuVM(sb, disk="/path/to/vm.qcow2", memory="4G")
    vm.start()          # boot VM + QMP handshake
    vm.savevm("ready")  # snapshot VM state

    # Episode loop (1-5s per reset):
    vm.loadvm("ready")
    # ... agent actions ...

    vm.stop()
    sb.delete()
"""

from __future__ import annotations

import json
import logging
import os
import shlex
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any, Optional

if TYPE_CHECKING:
    from agentdocker_lite.backends.base import SandboxBase

logger = logging.getLogger(__name__)

_QMP_SOCKET = "/tmp/.adl_qmp.sock"
_QMP_HELPER = "/tmp/.adl_qmp"  # static binary copied into sandbox


class QemuVM:
    """QEMU/KVM VM running inside a sandbox.

    Args:
        sandbox: The sandbox to run QEMU in.  Must have
            ``devices=["/dev/kvm"]`` in its config.
        disk: Path to the QCOW2 disk image **inside the sandbox**
            (mount the host file via ``volumes``).
        memory: VM memory (e.g. ``"4G"``, ``"2048M"``).
        cpus: Number of virtual CPUs.
        display: Display backend (e.g. ``"vnc=:0"``, ``"none"``).
            Default ``"none"`` (headless — use :meth:`screenshot`).
        extra_args: Additional QEMU command-line arguments.
        qmp_socket: QMP Unix socket path inside the sandbox.

    Example::

        sb = Sandbox(SandboxConfig(
            image="ubuntu:22.04",
            devices=["/dev/kvm"],
            volumes=["/host/vms:/vms:rw"],
        ))
        vm = QemuVM(sb, disk="/vms/osworld.qcow2", memory="4G", cpus=4)
        vm.start()
        vm.savevm("ready")

        for episode in range(1000):
            vm.loadvm("ready")   # 1-5s
            # ... agent loop ...

        vm.stop()
        sb.delete()
    """

    def __init__(
        self,
        sandbox: SandboxBase,
        disk: str,
        memory: str = "2G",
        cpus: int = 2,
        display: str = "none",
        extra_args: Optional[list[str]] = None,
        qmp_socket: str = _QMP_SOCKET,
    ):
        self._sb = sandbox
        self._disk = disk
        self._memory = memory
        self._cpus = cpus
        self._display = display
        self._extra_args = extra_args or []
        self._qmp_path = qmp_socket
        self._handle: Optional[str] = None

    # ------------------------------------------------------------------ #
    #  Lifecycle                                                           #
    # ------------------------------------------------------------------ #

    def start(self, timeout: int = 120) -> None:
        """Start the QEMU VM and wait for QMP to be ready.

        Blocks until the QMP socket is ready (VM BIOS/firmware started).
        Does NOT wait for the guest OS to boot — use a custom readiness
        check for that (e.g. polling an agent server port).

        Args:
            timeout: Max seconds to wait for QMP socket.

        Raises:
            TimeoutError: QMP socket not ready within *timeout*.
            FileNotFoundError: ``qemu-system-x86_64`` not found.
        """
        self._install_qmp_helper()
        cmd = self._build_cmd()
        self._handle = self._sb.run_background(cmd)
        self._wait_qmp(timeout)
        logger.info(
            "VM started: disk=%s memory=%s cpus=%d display=%s",
            self._disk, self._memory, self._cpus, self._display,
        )

    def stop(self) -> None:
        """Stop the VM gracefully via QMP quit, then clean up."""
        if self._handle:
            try:
                self._qmp_exec("quit")
            except (RuntimeError, OSError):
                pass
            try:
                self._sb.stop_background(self._handle)
            except Exception:
                pass
            self._handle = None
        logger.info("VM stopped")

    @property
    def running(self) -> bool:
        """Check if the VM process is still running."""
        if not self._handle:
            return False
        _, is_running = self._sb.check_background(self._handle)
        return is_running

    # ------------------------------------------------------------------ #
    #  VM state (savevm / loadvm)                                          #
    # ------------------------------------------------------------------ #

    def savevm(self, tag: str) -> str:
        """Save VM state snapshot (RAM + CPU + device state).

        The snapshot is stored inside the QCOW2 disk image.

        Args:
            tag: Snapshot name (e.g. ``"ready"``).

        Returns:
            HMP command output (empty on success).
        """
        t0 = time.monotonic()
        result = self.hmp(f"savevm {tag}")
        elapsed = (time.monotonic() - t0) * 1000
        logger.info("savevm %r: %.0fms", tag, elapsed)
        return result

    def loadvm(self, tag: str) -> str:
        """Load VM state from a snapshot (typically 1-5s).

        Restores RAM, CPU registers, and device state to the exact
        point when :meth:`savevm` was called.

        Args:
            tag: Snapshot name to restore.

        Returns:
            HMP command output (empty on success).
        """
        t0 = time.monotonic()
        result = self.hmp(f"loadvm {tag}")
        elapsed = (time.monotonic() - t0) * 1000
        logger.info("loadvm %r: %.0fms", tag, elapsed)
        return result

    def delvm(self, tag: str) -> str:
        """Delete a VM state snapshot from the disk image."""
        return self.hmp(f"delvm {tag}")

    def info_snapshots(self) -> str:
        """List all VM state snapshots."""
        return self.hmp("info snapshots")

    # ------------------------------------------------------------------ #
    #  VM interaction                                                      #
    # ------------------------------------------------------------------ #

    def screenshot(self, path: str = "/tmp/.adl_screenshot.ppm") -> bytes:
        """Take a screenshot of the VM display.

        Args:
            path: Temporary file path inside the sandbox for the screenshot.

        Returns:
            Raw PPM image data as bytes.
        """
        self.hmp(f"screendump {path}")
        time.sleep(0.1)
        content = self._sb.read_file(path)
        return content.encode("latin-1")

    # ------------------------------------------------------------------ #
    #  QMP (QEMU Monitor Protocol)                                         #
    # ------------------------------------------------------------------ #

    def qmp(self, command: str, **arguments: Any) -> dict:
        """Send a QMP command and return the response.

        Args:
            command: QMP command name (e.g. ``"query-status"``).
            **arguments: Command arguments.

        Returns:
            Response dict with ``"return"`` key.

        Raises:
            RuntimeError: Command error or not connected.
        """
        msg: dict[str, Any] = {"execute": command}
        if arguments:
            msg["arguments"] = arguments
        return self._qmp_exec(command, arguments or None)

    def hmp(self, command: str) -> str:
        """Execute an HMP command via QMP.

        Useful for ``savevm``, ``loadvm``, ``info snapshots`` etc.

        Args:
            command: HMP command string.

        Returns:
            Command output string.
        """
        resp = self._qmp_exec(
            "human-monitor-command",
            {"command-line": command},
        )
        if "error" in resp:
            raise RuntimeError(f"HMP command failed: {resp['error']}")
        return resp.get("return", "")

    # ------------------------------------------------------------------ #
    #  Availability check                                                  #
    # ------------------------------------------------------------------ #

    @staticmethod
    def check_available(sandbox: Optional[SandboxBase] = None) -> bool:
        """Check if QEMU/KVM is available.

        Args:
            sandbox: If provided, also checks that ``qemu-system-x86_64``
                is installed inside the sandbox.

        Returns:
            ``True`` if KVM device exists and is accessible.
        """
        if not Path("/dev/kvm").exists():
            return False
        if not os.access("/dev/kvm", os.R_OK | os.W_OK):
            return False
        if sandbox is not None:
            _, ec = sandbox.run("which qemu-system-x86_64 >/dev/null 2>&1")
            return ec == 0
        return True

    # ------------------------------------------------------------------ #
    #  Internal                                                            #
    # ------------------------------------------------------------------ #

    def _build_cmd(self) -> str:
        """Build the QEMU command line."""
        args = [
            "qemu-system-x86_64",
            "-enable-kvm",
            "-m", self._memory,
            "-smp", str(self._cpus),
            "-drive", f"file={self._disk},format=qcow2,if=virtio",
            "-qmp", f"unix:{self._qmp_path},server,nowait",
            "-display", self._display,
            "-no-shutdown",
        ]
        args.extend(self._extra_args)
        return " ".join(shlex.quote(a) for a in args)

    def _wait_qmp(self, timeout: int) -> None:
        """Wait for the QMP socket to appear inside the sandbox."""
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            _, ec = self._sb.run(
                f"test -S {shlex.quote(self._qmp_path)}", timeout=5,
            )
            if ec == 0:
                logger.debug("QMP socket ready")
                return
            time.sleep(0.5)
        # Check if QEMU is still running
        if self._handle:
            out, running = self._sb.check_background(self._handle)
            if not running:
                raise RuntimeError(f"QEMU exited before QMP ready: {out}")
        raise TimeoutError(
            f"QMP socket not ready after {timeout}s at {self._qmp_path}"
        )

    def _install_qmp_helper(self) -> None:
        """Copy the adl-qmp static binary into the sandbox."""
        vendor_dir = Path(__file__).parent / "_vendor"
        helper_src = vendor_dir / "adl-qmp"
        if not helper_src.exists():
            raise FileNotFoundError(
                f"adl-qmp binary not found at {helper_src}. "
                "Rebuild: gcc -static -nostdlib -Os -fno-builtin "
                "-march=x86-64 -fno-stack-protector "
                "-o adl-qmp adl-qmp.c && strip adl-qmp"
            )
        self._sb.write_file(_QMP_HELPER, helper_src.read_bytes())
        self._sb.run(f"chmod +x {_QMP_HELPER}")

    def _qmp_exec(
        self, command: str, arguments: Optional[dict] = None
    ) -> dict:
        """Send a QMP command via the adl-qmp static binary.

        Each call opens a new QMP connection, negotiates capabilities,
        sends the command, reads the response, and disconnects.
        """
        msg: dict[str, Any] = {"execute": command}
        if arguments:
            msg["arguments"] = arguments
        msg_json = json.dumps(msg)

        output, ec = self._sb.run(
            f"{_QMP_HELPER} "
            f"{shlex.quote(self._qmp_path)} "
            f"{shlex.quote(msg_json)}",
            timeout=30,
        )
        if ec != 0:
            raise RuntimeError(f"QMP command failed (ec={ec}): {output}")
        try:
            return json.loads(output.strip())
        except json.JSONDecodeError:
            raise RuntimeError(f"QMP invalid response: {output}")

    def __del__(self):
        try:
            if self._handle:
                self.stop()
        except Exception:
            pass

    def __repr__(self) -> str:
        status = "running" if self.running else "stopped"
        return (
            f"QemuVM(disk={self._disk!r}, memory={self._memory}, "
            f"cpus={self._cpus}, {status})"
        )
