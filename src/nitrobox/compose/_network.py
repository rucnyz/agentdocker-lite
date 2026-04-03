"""Shared network namespace (Podman-style pod networking) and health-check helpers."""

from __future__ import annotations

import logging
import os
import re
import shlex
import shutil
import subprocess
import time
from pathlib import Path
from typing import Any, List

from nitrobox.sandbox import Sandbox

logger = logging.getLogger(__name__)


def _find_pasta_bin() -> str | None:
    """Find the pasta binary (vendored or system)."""
    vendored = Path(__file__).resolve().parent.parent / "_vendor" / "pasta"
    if vendored.exists() and vendored.is_file():
        return str(vendored)
    if shutil.which("pasta"):
        return "pasta"
    return None


class SharedNetwork:
    """Shared userns + netns for compose network isolation.

    Creates a sentinel process that holds a user namespace (with full
    uid mapping) and a network namespace.  Other sandboxes join the
    sentinel's namespaces via ``nsenter``.

    By default, pasta is attached to the shared netns to provide NAT
    and DNS forwarding, giving containers internet access (matching
    Docker Compose's default behaviour).  Pass ``internet=False`` to
    disable this.

    This mirrors Podman's pod infra container: one shared userns+netns
    per pod, individual mount/pid namespaces per container.
    """

    def __init__(
        self,
        name: str = "default",
        *,
        internet: bool = True,
        port_map: list[str] | None = None,
    ) -> None:
        self.name = name
        self.has_pasta: bool = False
        self.dns_forward_ips: list[str] = []
        self.guest_ip: str | None = None
        # Detect subuid range (reuse rootless sandbox logic)
        self._subuid_range = Sandbox._detect_subuid_range()

        # Create sentinel with userns + netns
        unshare_cmd = ["unshare", "--user", "--net", "--fork"]
        if not self._subuid_range:
            unshare_cmd.insert(2, "--map-root-user")
        unshare_cmd.extend(["--", "sleep", "infinity"])

        self._sentinel = subprocess.Popen(
            unshare_cmd,
            start_new_session=True,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        try:
            # Wait for child to enter new userns
            if self._subuid_range:
                my_userns = os.readlink("/proc/self/ns/user")
                for _ in range(1000):
                    try:
                        child_userns = os.readlink(
                            f"/proc/{self._sentinel.pid}/ns/user"
                        )
                        if child_userns != my_userns:
                            break
                    except (FileNotFoundError, PermissionError):
                        pass
                    time.sleep(0.001)
                else:
                    raise RuntimeError("Timeout waiting for sentinel userns")

                # Set up full uid/gid mapping
                outer_uid, sub_start, sub_count = self._subuid_range
                outer_gid = os.getgid()
                pid = self._sentinel.pid
                subprocess.run(
                    ["newuidmap", str(pid),
                     "0", str(outer_uid), "1",
                     "1", str(sub_start), str(sub_count)],
                    check=True, capture_output=True, timeout=10,
                )
                subprocess.run(
                    ["newgidmap", str(pid),
                     "0", str(outer_gid), "1",
                     "1", str(sub_start), str(sub_count)],
                    check=True, capture_output=True, timeout=10,
                )

            # Attach pasta for NAT + DNS (like Docker Compose default networking)
            if internet:
                self._start_pasta(port_map or [])

        except Exception:
            self.destroy()
            raise

    def _start_pasta(self, port_map: list[str]) -> None:
        """Attach pasta to the sentinel's netns for NAT and DNS forwarding.

        Uses pasta's PID mode (``pasta PID``) which attaches to the
        network namespace of the given process — no bind-mount needed.
        """
        pasta_bin = _find_pasta_bin()
        if not pasta_bin:
            logger.warning(
                "pasta not found — shared network will have no internet access. "
                "Install 'passt' package or ensure vendored pasta is available."
            )
            return

        pid = self._sentinel.pid

        cmd: list[str] = [
            pasta_bin, "--config-net",
            "--ipv4-only",
        ]
        for mapping in port_map:
            cmd.extend(["-t", mapping])
        cmd.extend([
            "-u", "none", "-T", "none", "-U", "none",
            "--dns-forward", "169.254.1.1",
            "--no-map-gw", "--quiet",
            "--map-guest-addr", "169.254.1.2",
            str(pid),
        ])

        out = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if out.returncode != 0:
            logger.warning(
                "pasta failed (exit=%d): %s — shared network will have no internet",
                out.returncode, out.stderr.strip(),
            )
            return

        # Parse pasta output to get actual DNS and guest IP
        # (matching Podman's pastaResult.DNSForwardIPs / IPAddresses)
        self.dns_forward_ips = _parse_pasta_dns(out.stderr)
        self.guest_ip = _parse_pasta_guest_ip(out.stderr)
        self.has_pasta = True

        # Verify DNS forwarding is actually working before declaring
        # the network ready.  Pasta forks to background on success, but
        # the DNS forwarder may not be fully initialised yet.
        self._verify_dns(pid)

        logger.debug(
            "pasta ready for shared network %r (pid=%d, dns=%s, guest_ip=%s)",
            self.name, pid, self.dns_forward_ips, self.guest_ip,
        )

    def _verify_dns(self, sentinel_pid: int) -> None:
        """Probe pasta's DNS forwarder inside the shared netns.

        Sends a tiny UDP packet to 169.254.1.1:53 and waits for a
        response.  Retries a few times with short sleeps — pasta's
        internal DNS proxy occasionally needs a moment after fork.
        """
        import socket as _socket
        import struct

        dns_ip = self.dns_forward_ips[0] if self.dns_forward_ips else "169.254.1.1"

        # Minimal DNS query for "localhost" (just needs a response, any RCODE is fine)
        query = (
            b"\x12\x34"  # ID
            b"\x01\x00"  # flags: standard query, recursion desired
            b"\x00\x01\x00\x00\x00\x00\x00\x00"  # 1 question
            b"\x09localhost\x00"  # QNAME
            b"\x00\x01\x00\x01"  # QTYPE=A, QCLASS=IN
        )

        for attempt in range(5):
            try:
                # Open a UDP socket inside the sentinel's netns via nsenter
                result = subprocess.run(
                    ["nsenter", f"--net=/proc/{sentinel_pid}/ns/net",
                     "python3", "-c",
                     f"import socket; s=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); "
                     f"s.settimeout(1); s.sendto({query!r},('{dns_ip}',53)); "
                     f"d,_=s.recvfrom(512); print(len(d))"],
                    capture_output=True, text=True, timeout=5,
                )
                if result.returncode == 0 and result.stdout.strip():
                    logger.debug("DNS probe OK on attempt %d", attempt + 1)
                    return
            except (subprocess.TimeoutExpired, OSError):
                pass
            time.sleep(0.1 * (attempt + 1))

        logger.warning(
            "DNS probe failed after 5 attempts for shared network %r — "
            "pasta DNS forwarder at %s may be unreliable",
            self.name, dns_ip,
        )

    @property
    def userns_path(self) -> str:
        """Path to the sentinel's user namespace."""
        return f"/proc/{self._sentinel.pid}/ns/user"

    @property
    def netns_path(self) -> str:
        """Path to the sentinel's network namespace."""
        return f"/proc/{self._sentinel.pid}/ns/net"

    @property
    def alive(self) -> bool:
        return self._sentinel.poll() is None

    def destroy(self) -> None:
        """Kill the sentinel, releasing the shared namespaces."""
        if self._sentinel.poll() is None:
            import signal as _signal
            try:
                os.killpg(self._sentinel.pid, _signal.SIGKILL)
            except (ProcessLookupError, PermissionError):
                try:
                    self._sentinel.kill()
                except Exception:
                    pass
            try:
                self._sentinel.wait(timeout=5)
            except Exception:
                pass

    def __repr__(self) -> str:
        state = "alive" if self.alive else "dead"
        return f"SharedNetwork({self.name!r}, {state})"


def _parse_pasta_dns(output: str) -> list[str]:
    """Extract DNS forward IPs from pasta's stderr output.

    Pasta prints lines like::

        DNS:
            169.254.1.1
    """
    ips: list[str] = []
    in_dns = False
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("DNS:"):
            in_dns = True
            continue
        if in_dns:
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", stripped):
                ips.append(stripped)
            else:
                in_dns = False
    return ips or ["169.254.1.1"]  # fallback


def _parse_pasta_guest_ip(output: str) -> str | None:
    """Extract DHCP-assigned guest IP from pasta's stderr output.

    Pasta prints lines like::

        DHCP:
            assign: 10.0.2.15
    """
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("assign:"):
            ip = stripped.split(":", 1)[1].strip()
            if re.match(r"^\d+\.\d+\.\d+\.\d+$", ip):
                return ip
    return None


# ------------------------------------------------------------------ #
#  Duration parsing                                                    #
# ------------------------------------------------------------------ #


def _parse_duration(s: str | int | float) -> float:
    """Parse compose duration string (e.g. ``"30s"``, ``"2m"``) to seconds."""
    if isinstance(s, (int, float)):
        return float(s)
    s = str(s).strip()
    m = re.match(r"^(\d+(?:\.\d+)?)\s*(s|ms|m|h)?$", s)
    if not m:
        return 30.0
    val = float(m.group(1))
    unit = m.group(2) or "s"
    return val * {"ms": 0.001, "s": 1, "m": 60, "h": 3600}[unit]


# ------------------------------------------------------------------ #
#  Health check                                                        #
# ------------------------------------------------------------------ #


def _healthcheck_cmd(test: Any) -> str:
    """Convert healthcheck test to a shell command string."""
    if isinstance(test, str):
        return test
    if isinstance(test, list) and test:
        if test[0] == "CMD":
            return shlex.join(test[1:])
        if test[0] == "CMD-SHELL":
            return " ".join(test[1:])
        # NONE disables
        if test[0] == "NONE":
            return ""
        return shlex.join(test)
    return ""
