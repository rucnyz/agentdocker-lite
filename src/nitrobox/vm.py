"""QEMU/KVM virtual machine manager for nitrobox sandboxes.

Manages a QEMU process inside a sandbox and provides QMP (QEMU Monitor
Protocol) communication for VM state management, plus QEMU Guest Agent
(QGA) for executing commands inside the VM guest.

Designed for OSWorld-style GUI agent training where fast VM reset is
critical.

Usage::

    from nitrobox import Sandbox, SandboxConfig
    from nitrobox.vm import QemuVM

    sb = Sandbox(SandboxConfig(image="ubuntu:22.04", devices=["/dev/kvm"]))
    vm = QemuVM(sb, disk="/path/to/vm.qcow2", memory="4G")
    vm.start()
    vm.wait_guest_ready()       # wait for guest OS + qemu-ga
    vm.savevm("ready")

    # Episode loop:
    vm.loadvm("ready")
    out, ec = vm.guest_exec("echo hello")  # run command in guest
    # ... agent actions ...

    vm.stop()
    sb.delete()
"""

from __future__ import annotations

import base64
import json
import logging
import os
import random
import shlex
import socket as _socket
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from nitrobox.sandbox import Sandbox

logger = logging.getLogger(__name__)

# Default socket / binary paths inside the sandbox.
# /tmp is world-writable and overlayfs-friendly; custom paths via __init__.
_QMP_SOCKET = "/tmp/.nbx_qmp.sock"
_QMP_HELPER = "/tmp/.nbx_qmp"  # static Rust binary copied into sandbox
_QGA_SOCKET = "/tmp/.nbx_qga.sock"
_QGA_CHUNK_SIZE = 65536  # 64 KB — virtio-serial file I/O chunk size


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
        qga_socket: QGA (Guest Agent) Unix socket path inside the
            sandbox.  The guest must have ``qemu-ga`` running for
            :meth:`guest_exec` and related methods to work.
        cmd_override: Complete QEMU command line string.  When set,
            ``disk``/``memory``/``cpus``/``display``/``extra_args`` are
            ignored and only ``-qmp`` and QGA arguments are appended.
            Use this for complex VM setups (e.g. Windows/macOS with
            pflash, TPM, custom networking).

    Example::

        sb = Sandbox(SandboxConfig(
            image="ubuntu:22.04",
            devices=["/dev/kvm"],
            volumes=["/host/vms:/vms:rw"],
        ))
        vm = QemuVM(sb, disk="/vms/osworld.qcow2", memory="4G", cpus=4)
        vm.start()
        vm.wait_guest_ready()   # wait for qemu-ga
        vm.savevm("ready")

        for episode in range(1000):
            vm.loadvm("ready")   # 1-5s
            out, ec = vm.guest_exec("whoami")
            # ... agent loop ...

        vm.stop()
        sb.delete()
    """

    def __init__(
        self,
        sandbox: Sandbox,
        disk: str = "",
        memory: str = "2G",
        cpus: int = 2,
        display: str = "none",
        extra_args: list[str] | None = None,
        qmp_socket: str = _QMP_SOCKET,
        qga_socket: str = _QGA_SOCKET,
        cmd_override: str | None = None,
    ):
        self._sb = sandbox
        self._disk = disk
        self._memory = memory
        self._cpus = cpus
        self._display = display
        self._extra_args = extra_args or []
        self._qmp_path = qmp_socket
        self._qga_path = qga_socket
        self._cmd_override = cmd_override
        self._handle: str | None = None

    # ================================================================== #
    #  Public API — Lifecycle                                              #
    # ================================================================== #

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

        if self._cmd_override:
            # Complex commands with special shell chars (e.g. parentheses
            # in Apple SMC key) break when double-shell-wrapped.  Write
            # to a script file to avoid quoting issues.
            #
            # Use sb.run() to write the script — write_file() goes to the
            # overlayfs upper layer which is hidden by bind mounts, so
            # scripts on volume paths would be invisible to the shell.
            script_path = str(Path(self._qmp_path).parent / ".nbx_qemu_launch.sh")
            escaped_cmd = cmd.replace("'", "'\\''")
            self._sb.run(
                f"printf '#!/bin/sh\\nexec %s\\n' '{escaped_cmd}' "
                f"> {shlex.quote(script_path)} && "
                f"chmod +x {shlex.quote(script_path)}",
            )
            self._handle = self._sb.run_background(script_path)
        else:
            self._handle = self._sb.run_background(cmd)

        self._wait_qmp(timeout)
        logger.info(
            "VM started: disk=%s memory=%s cpus=%d display=%s",
            self._disk, self._memory, self._cpus, self._display,
        )

    def stop(self) -> None:
        """Stop the VM gracefully via QMP quit, then clean up.

        Removes QMP and QGA socket files after stopping QEMU.
        """
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
        # Clean up socket files from the host side.  QEMU doesn't always
        # remove them, and volume-mount sockets survive sandbox deletion.
        # Resolve host paths first, then unlink — no dependency on the
        # sandbox shell being alive.
        for sock_path in (self._qmp_path, self._qga_path):
            try:
                host = self._resolve_host_socket(sock_path)
                Path(host).unlink(missing_ok=True)
            except (FileNotFoundError, OSError, AttributeError):
                pass
        logger.info("VM stopped")

    @property
    def running(self) -> bool:
        """Check if the VM process is still running."""
        if not self._handle:
            return False
        _, is_running = self._sb.check_background(self._handle)
        return is_running

    # ================================================================== #
    #  Public API — VM state (savevm / loadvm)                             #
    # ================================================================== #

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

    # ================================================================== #
    #  Public API — QMP / HMP                                              #
    # ================================================================== #

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
        return self._qmp_exec(command, arguments or None)

    def hmp(self, command: str, timeout: int = 120) -> str:
        """Execute an HMP command via QMP.

        Useful for ``savevm``, ``loadvm``, ``info snapshots`` etc.

        Args:
            command: HMP command string.
            timeout: Timeout in seconds (loadvm/savevm can take 30-60s).

        Returns:
            Command output string.
        """
        resp = self._qmp_exec(
            "human-monitor-command",
            {"command-line": command},
            timeout=timeout,
        )
        if "error" in resp:
            raise RuntimeError(f"HMP command failed: {resp['error']}")
        return resp.get("return", "")

    def screenshot(self, path: str = "/tmp/.nbx_screenshot.ppm") -> bytes:
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

    # ================================================================== #
    #  Public API — QGA (QEMU Guest Agent)                                 #
    # ================================================================== #

    def guest_ping(self, timeout: int = 5) -> bool:
        """Check if the QEMU Guest Agent is responsive.

        Returns ``True`` if ``qemu-ga`` responds, ``False`` on timeout
        or connection error.
        """
        try:
            self._qga_send("guest-ping", timeout=timeout)
            return True
        except (OSError, RuntimeError, FileNotFoundError, AttributeError):
            return False

    def wait_guest_ready(self, timeout: int = 300) -> None:
        """Wait for the guest OS and ``qemu-ga`` to become responsive.

        Call this after :meth:`start` (first boot) or when the guest
        needs time to initialize.  After :meth:`loadvm` this is usually
        not needed — the agent resumes immediately.

        Args:
            timeout: Max seconds to wait.

        Raises:
            TimeoutError: Guest agent not responsive within *timeout*.
        """
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            if self.guest_ping(timeout=3):
                logger.info("Guest agent ready")
                return
            time.sleep(1)
        raise TimeoutError(
            f"Guest agent not ready after {timeout}s "
            f"(is qemu-ga running in the guest?)"
        )

    def guest_exec(
        self, command: str, timeout: int = 30,
    ) -> tuple[str, int]:
        """Execute a shell command inside the VM guest.

        Requires ``qemu-ga`` running in the guest.

        Args:
            command: Shell command string (run via ``/bin/bash -c``).
            timeout: Max seconds to wait for the command to finish.

        Returns:
            ``(output, exit_code)`` — stdout + stderr combined,
            and the process exit code.

        Raises:
            RuntimeError: QGA communication error.
            TimeoutError: Command did not finish within *timeout*.
        """
        sock, reader = self._qga_connect(timeout)
        try:
            resp = self._qga_cmd(sock, reader, "guest-exec", {
                "path": "/bin/bash",
                "arg": ["-c", command],
                "capture-output": True,
            })
            pid = resp["return"]["pid"]

            deadline = time.monotonic() + timeout
            while time.monotonic() < deadline:
                status = self._qga_cmd(sock, reader, "guest-exec-status",
                                       {"pid": pid})
                ret = status["return"]
                if ret["exited"]:
                    stdout = base64.b64decode(
                        ret.get("out-data", "")
                    ).decode("utf-8", errors="replace")
                    stderr = base64.b64decode(
                        ret.get("err-data", "")
                    ).decode("utf-8", errors="replace")
                    output = stdout + stderr if stderr else stdout
                    return output, ret.get("exitcode", -1)
                time.sleep(0.1)

            raise TimeoutError(f"guest-exec timed out after {timeout}s")
        finally:
            reader.close()
            sock.close()

    def guest_file_read(self, path: str) -> bytes:
        """Read a file from the VM guest filesystem.

        Args:
            path: Absolute path inside the guest.

        Returns:
            File contents as bytes.
        """
        sock, reader = self._qga_connect()
        try:
            resp = self._qga_cmd(sock, reader, "guest-file-open", {
                "path": path, "mode": "r",
            })
            handle = resp["return"]
            try:
                chunks: list[bytes] = []
                while True:
                    resp = self._qga_cmd(sock, reader, "guest-file-read", {
                        "handle": handle, "count": _QGA_CHUNK_SIZE,
                    })
                    ret = resp["return"]
                    data = base64.b64decode(ret.get("buf-b64", ""))
                    if data:
                        chunks.append(data)
                    if ret.get("eof", False):
                        break
                return b"".join(chunks)
            finally:
                self._qga_cmd(sock, reader, "guest-file-close",
                              {"handle": handle})
        finally:
            reader.close()
            sock.close()

    def guest_file_write(self, path: str, data: bytes) -> None:
        """Write data to a file in the VM guest filesystem.

        Args:
            path: Absolute path inside the guest.
            data: File contents to write.
        """
        sock, reader = self._qga_connect()
        try:
            resp = self._qga_cmd(sock, reader, "guest-file-open", {
                "path": path, "mode": "w",
            })
            handle = resp["return"]
            try:
                offset = 0
                while offset < len(data):
                    chunk = data[offset:offset + _QGA_CHUNK_SIZE]
                    resp = self._qga_cmd(sock, reader, "guest-file-write", {
                        "handle": handle,
                        "buf-b64": base64.b64encode(chunk).decode("ascii"),
                    })
                    written = resp.get("return", {}).get("count", 0)
                    if written != len(chunk):
                        raise RuntimeError(
                            f"QGA short write: sent {len(chunk)} bytes, "
                            f"wrote {written}"
                        )
                    offset += len(chunk)
            finally:
                self._qga_cmd(sock, reader, "guest-file-close",
                              {"handle": handle})
        finally:
            reader.close()
            sock.close()

    # ================================================================== #
    #  Public API — Availability                                           #
    # ================================================================== #

    @staticmethod
    def check_available(sandbox: Sandbox | None = None) -> bool:
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

    # ================================================================== #
    #  Internal — QEMU command line & startup                              #
    # ================================================================== #

    def _build_cmd(self) -> str:
        """Build the QEMU command line.

        If *cmd_override* was provided at construction, use it verbatim
        (only ``-qmp`` and QGA arguments are appended).  Otherwise build
        a standard command from the disk/memory/cpus/display parameters.

        QGA (Guest Agent) is always enabled via a virtio-serial channel.
        The guest must have ``qemu-ga`` running to use :meth:`guest_exec`.
        """
        qmp_spec = f"unix:{self._qmp_path},server,nowait"
        qga_chardev = f"socket,id=nbxqga,path={self._qga_path},server=on,wait=off"
        qga_suffix = (
            f" -chardev {qga_chardev}"
            f" -device virtio-serial-pci,id=nbx-vser"
            f" -device virtserialport,bus=nbx-vser.0,chardev=nbxqga,"
            f"name=org.qemu.guest_agent.0"
        )

        if self._cmd_override:
            return f"{self._cmd_override} -qmp {qmp_spec}{qga_suffix}"

        args = [
            "qemu-system-x86_64",
            "-enable-kvm",
            "-m", self._memory,
            "-smp", str(self._cpus),
            "-drive", f"file={self._disk},format=qcow2,if=virtio",
            "-qmp", qmp_spec,
            "-chardev", qga_chardev,
            "-device", "virtio-serial-pci,id=nbx-vser",
            "-device", "virtserialport,bus=nbx-vser.0,chardev=nbxqga,"
                       "name=org.qemu.guest_agent.0",
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
        """Copy the nbx-qmp static binary into the sandbox.

        Used as fallback when the QMP socket is not host-accessible
        (e.g. on overlayfs without a volume mount).
        """
        vendor_dir = Path(__file__).parent / "_vendor"
        helper_src = vendor_dir / "nbx-qmp"
        if not helper_src.exists():
            raise FileNotFoundError(
                f"nbx-qmp binary not found at {helper_src}. "
                "Rebuild: rustc --edition 2024 -C opt-level=2 -C panic=abort "
                "-C link-arg=-nostdlib -C link-arg=-static -C strip=symbols "
                "-o nbx-qmp rust/src/bin/nbx_qmp.rs"
            )
        self._sb.write_file(_QMP_HELPER, helper_src.read_bytes())
        self._sb.run(f"chmod +x {_QMP_HELPER}")

    # ================================================================== #
    #  Internal — QMP execution                                            #
    # ================================================================== #

    def _qmp_exec(
        self, command: str, arguments: dict | None = None,
        timeout: int = 30,
    ) -> dict:
        """Send a QMP command.

        Tries the Rust native QMP client first (host-side, no subprocess
        overhead).  Falls back to the nbx-qmp static binary inside the
        sandbox if the host-side socket is not reachable.
        """
        msg: dict[str, Any] = {"execute": command}
        if arguments:
            msg["arguments"] = arguments
        msg_json = json.dumps(msg)

        # Try host-side Rust binding first.
        try:
            host_sock = self._resolve_host_socket(self._qmp_path)
            from nitrobox._core import py_qmp_send
            output = py_qmp_send(host_sock, msg_json, timeout)
            return json.loads(output)
        except (OSError, ImportError, FileNotFoundError):
            pass  # fall through to sandbox-side helper

        # Fallback: nbx-qmp static binary inside sandbox.
        output, ec = self._sb.run(
            f"{_QMP_HELPER} "
            f"{shlex.quote(self._qmp_path)} "
            f"{shlex.quote(msg_json)}",
            timeout=timeout,
        )
        if ec != 0:
            raise RuntimeError(f"QMP command failed (ec={ec}): {output}")
        try:
            return json.loads(output.strip())
        except json.JSONDecodeError:
            raise RuntimeError(f"QMP invalid response: {output}")

    # ================================================================== #
    #  Internal — Host socket resolution                                   #
    # ================================================================== #

    def _resolve_host_socket(self, sandbox_path: str) -> str:
        """Resolve a sandbox socket path to its host-accessible path.

        Checks (in order): explicit override attrs, volume mounts,
        then overlayfs host path.
        """
        # 1. Explicit host path override (set by caller).
        for attr in ("_host_qmp_path", "_host_qga_path"):
            host = getattr(self, attr, None)
            if host and sandbox_path in host and Path(host).exists():
                return host

        # 2. Volume mounts — socket on a bind-mounted path is
        #    directly accessible from the host.
        for vol in self._sb._config.volumes:
            parts = vol.split(":")
            if len(parts) >= 2:
                host_part, container_part = parts[0], parts[1]
                if sandbox_path.startswith(container_part + "/") or sandbox_path == container_part:
                    rel = sandbox_path[len(container_part):].lstrip("/")
                    resolved = Path(host_part) / rel
                    if resolved.exists():
                        return str(resolved)

        # 3. Overlayfs host path (upper dir / layer search).
        host = self._sb._host_path(sandbox_path)
        if host.exists():
            return str(host)

        raise FileNotFoundError(
            f"Socket not accessible from host: {sandbox_path}. "
            f"Place it on a volume mount for host-side access."
        )

    # ================================================================== #
    #  Internal — QGA protocol                                             #
    # ================================================================== #

    def _qga_connect(self, timeout: int = 30) -> tuple[_socket.socket, Any]:
        """Open a QGA connection and perform the sync handshake.

        Returns ``(sock, reader)``.  Caller is responsible for closing
        both when done.

        QEMU's chardev socket only supports one concurrent connection.
        Multi-step operations (exec + poll, file open/read/close) MUST
        use a single connection — reconnecting drops the virtio-serial
        channel and loses buffered data.

        Retries with backoff because QEMU's chardev needs time to
        transition back to listening state after a client disconnects.
        """
        host_sock = self._resolve_host_socket(self._qga_path)
        deadline = time.monotonic() + timeout
        last_err: Exception | None = None

        while time.monotonic() < deadline:
            reader = None
            sock = _socket.socket(_socket.AF_UNIX, _socket.SOCK_STREAM)
            sock.settimeout(min(5, max(1, deadline - time.monotonic())))
            try:
                sock.connect(host_sock)
                reader = sock.makefile("rb")

                # Sync handshake (QGA protocol):
                # Send a random ID with 0xFF delimiter; QGA flushes any
                # stale buffered data from previous connections, then
                # echoes back the same ID.  We skip lines until we see
                # our ID, discarding leftover messages and malformed JSON.
                sync_id = random.randint(1, 2**31)
                sock.sendall(
                    b"\xff"
                    + json.dumps({
                        "execute": "guest-sync-delimited",
                        "arguments": {"id": sync_id},
                    }).encode()
                    + b"\n"
                )
                while True:
                    line = reader.readline()
                    if not line:
                        raise RuntimeError("QGA closed during sync")
                    line = line.lstrip(b"\xff").strip()
                    if not line:
                        continue
                    try:
                        resp = json.loads(line)
                        if resp.get("return") == sync_id:
                            remaining = max(1, deadline - time.monotonic())
                            sock.settimeout(remaining)
                            return sock, reader
                    except (json.JSONDecodeError, UnicodeDecodeError):
                        continue
            except (OSError, RuntimeError, TimeoutError) as e:
                last_err = e
                # makefile() dups the fd — must close both to fully
                # release the connection so QEMU can accept a new one.
                if reader is not None:
                    try:
                        reader.close()
                    except OSError:
                        pass
                try:
                    sock.close()
                except OSError:
                    pass
                time.sleep(0.5)

        raise OSError(
            f"QGA connect failed after {timeout}s: {last_err}"
        )

    @staticmethod
    def _qga_cmd(
        sock: _socket.socket, reader: Any,
        command: str, arguments: dict | None = None,
    ) -> dict:
        """Send a QGA command on an existing connection and read response."""
        msg: dict[str, Any] = {"execute": command}
        if arguments:
            msg["arguments"] = arguments
        sock.sendall(json.dumps(msg).encode() + b"\n")

        while True:
            line = reader.readline()
            if not line:
                raise RuntimeError("QGA closed before response")
            line = line.strip()
            if not line:
                continue
            try:
                resp = json.loads(line)
            except (json.JSONDecodeError, UnicodeDecodeError):
                raise RuntimeError(
                    f"QGA {command}: malformed response: {line!r}"
                )
            if "error" in resp:
                raise RuntimeError(
                    f"QGA {command}: {resp['error'].get('desc', resp['error'])}"
                )
            return resp

    def _qga_send(
        self, command: str, arguments: dict | None = None, timeout: int = 30,
    ) -> dict:
        """Send a single QGA command (connect → sync → send → read → close).

        For multi-step operations, use :meth:`_qga_connect` +
        :meth:`_qga_cmd` to reuse a single connection.
        """
        sock, reader = self._qga_connect(timeout)
        try:
            return self._qga_cmd(sock, reader, command, arguments)
        finally:
            reader.close()
            sock.close()

    # ================================================================== #
    #  Dunder                                                              #
    # ================================================================== #

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
