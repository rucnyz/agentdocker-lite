#!/usr/bin/env python3
"""QGA integration tests -- real Ubuntu VM inside nitrobox sandbox.

Boots a real VM with qemu-guest-agent, then exercises the full QGA API:
guest_ping, guest_exec, guest_file_read/write, and state management
(savevm/loadvm + QGA reconnect).

Prerequisites:
    1. python scripts/build_test_vm.py            # download image + create seed
    2. python scripts/test_qga_integration.py    # run tests (needs KVM + Docker)

First run: ~2-3 min (cloud-init installs qemu-guest-agent).
Subsequent runs: ~30s (restores from snapshot).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from pathlib import Path

# Ensure project root is importable
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from nitrobox import Sandbox, SandboxConfig
from nitrobox.vm import QemuVM

VM_DIR_DEFAULT = "scripts/vm"
SANDBOX_IMAGE = os.environ.get("LITE_SANDBOX_TEST_IMAGE", "ubuntu:22.04")

# ------------------------------------------------------------------ #
#  Helpers                                                             #
# ------------------------------------------------------------------ #

_passed = 0
_failed = 0


def section(title: str) -> None:
    print(f"\n{'=' * 60}\n  {title}\n{'=' * 60}")


def check(name: str, condition: bool, detail: str = "") -> None:
    global _passed, _failed
    if condition:
        _passed += 1
        print(f"  PASS  {name}" + (f"  ({detail})" if detail else ""))
    else:
        _failed += 1
        print(f"  FAIL  {name}" + (f"  ({detail})" if detail else ""))


def _has_snapshot(image_path: Path, tag: str) -> bool:
    info = subprocess.run(
        ["qemu-img", "snapshot", "-l", str(image_path)],
        capture_output=True, text=True,
    )
    return tag in info.stdout


# ------------------------------------------------------------------ #
#  Main                                                                #
# ------------------------------------------------------------------ #

def main() -> None:
    parser = argparse.ArgumentParser(
        description="QGA integration tests with real Ubuntu VM",
    )
    parser.add_argument("--vm-dir", default=VM_DIR_DEFAULT,
                        help="VM files directory (default: scripts/vm)")
    parser.add_argument("--fresh", action="store_true",
                        help="Ignore existing 'ready' snapshot, redo first boot")
    args = parser.parse_args()

    vm_dir = Path(args.vm_dir).resolve()
    test_image = vm_dir / "ubuntu-test.qcow2"
    seed_iso = vm_dir / "seed.iso"

    # ---- Prerequisites ----
    if not test_image.exists():
        print(f"ERROR: VM image not found: {test_image}")
        print(f"  Run:  python scripts/build_test_vm.py --vm-dir {args.vm_dir}")
        sys.exit(1)
    if not seed_iso.exists():
        print(f"ERROR: Seed ISO not found: {seed_iso}")
        print(f"  Run:  python scripts/build_test_vm.py --vm-dir {args.vm_dir}")
        sys.exit(1)
    if not Path("/dev/kvm").exists():
        print("ERROR: /dev/kvm not available")
        sys.exit(1)
    if not os.access("/dev/kvm", os.R_OK | os.W_OK):
        print("ERROR: no read/write access to /dev/kvm")
        sys.exit(1)
    if os.geteuid() == 0:
        print("ERROR: do not run as root (sandbox uses Docker backend in rootless mode)")
        sys.exit(1)

    has_ready = _has_snapshot(test_image, "ready") and not args.fresh

    # If image is dirty (no snapshot but not fresh), recreate it.
    # This happens when a previous first-boot failed mid-cloud-init,
    # leaving a qcow2 where cloud-init already recorded its instance-id
    # but qemu-ga was never installed.
    if not has_ready and test_image.stat().st_size > 1_000_000:
        base_image = vm_dir / "ubuntu-base.img"
        if base_image.exists():
            print(f"  Recreating dirty working copy (no snapshot, {test_image.stat().st_size / 1e6:.0f}MB)...")
            test_image.unlink()
            subprocess.run(
                ["qemu-img", "create", "-f", "qcow2",
                 "-b", base_image.name, "-F", "qcow2",
                 str(test_image), "4G"],
                check=True, capture_output=True,
            )

    # ---- Setup sandbox ----
    section("Setup: sandbox + QEMU")

    config = SandboxConfig(
        image=SANDBOX_IMAGE,
        devices=["/dev/kvm"],
        volumes=[f"{vm_dir}:/vm:rw"],
    )
    sb = Sandbox(config, name="qga-integ")

    # Install QEMU in sandbox if needed
    _, ec = sb.run("which qemu-system-x86_64 >/dev/null 2>&1")
    if ec != 0:
        print("  Installing QEMU in sandbox (~1 min)...")
        _, ec = sb.run(
            "apt-get update -qq 2>/dev/null && "
            "DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
            "--no-install-recommends qemu-system-x86 qemu-utils 2>/dev/null "
            "| tail -1",
            timeout=300,
        )
        if ec != 0:
            sb.delete()
            print("ERROR: failed to install QEMU in sandbox")
            sys.exit(1)

    out, _ = sb.run("qemu-system-x86_64 --version 2>&1 | head -1")
    print(f"  {out.strip()}")

    # Clean up leftover sockets from previous runs
    sb.run("rm -f /vm/.qmp.sock /vm/.qga.sock")

    # ---- Build VM ----
    # Use extra_args (not cmd_override) so QEMU launches directly
    # without a launch script (write_file doesn't work on volume mounts).
    # Always include cdrom + network so the device config matches the
    # snapshot state (QEMU requires consistent devices for loadvm).
    qmp_sock = "/vm/.qmp.sock"
    qga_sock = "/vm/.qga.sock"

    vm = QemuVM(
        sb, disk="/vm/ubuntu-test.qcow2", memory="1G", cpus=2,
        extra_args=[
            "-cdrom", "/vm/seed.iso",
            "-netdev", "user,id=net0",
            "-device", "virtio-net-pci,netdev=net0",
        ],
        qmp_socket=qmp_sock, qga_socket=qga_sock,
    )

    # ---- Boot VM ----
    section("Boot VM")
    t0 = time.monotonic()
    vm.start(timeout=60)
    print(f"  QEMU started in {time.monotonic() - t0:.1f}s")

    try:
        if has_ready:
            print("  Loading 'ready' snapshot...")
            vm.loadvm("ready")
            time.sleep(0.5)
            print("  Waiting for QGA...")
            vm.wait_guest_ready(timeout=30)
        else:
            print("  First boot: cloud-init installing qemu-guest-agent...")
            print("  (this takes ~1-2 min, please wait)")
            vm.wait_guest_ready(timeout=300)
            print("  Saving 'ready' snapshot for future runs...")
            vm.savevm("ready")
            print("  Snapshot saved!")

        boot_time = time.monotonic() - t0
        print(f"  VM ready in {boot_time:.1f}s")

        # ============================================================ #
        #  Test 1: guest_ping                                           #
        # ============================================================ #
        section("Test 1: guest_ping")
        check("guest_ping", vm.guest_ping(timeout=5))

        # ============================================================ #
        #  Test 2: guest_exec -- basic commands                         #
        # ============================================================ #
        section("Test 2: guest_exec basics")

        out, ec = vm.guest_exec("echo hello-from-qga")
        check("echo", ec == 0 and "hello-from-qga" in out,
              f"out={out.strip()!r} ec={ec}")

        out, ec = vm.guest_exec("whoami")
        check("whoami", ec == 0 and out.strip() != "",
              f"user={out.strip()!r}")

        out, ec = vm.guest_exec("uname -r")
        check("uname -r", ec == 0 and out.strip() != "",
              f"kernel={out.strip()!r}")

        out, ec = vm.guest_exec("cat /etc/os-release | grep PRETTY_NAME")
        check("os-release", ec == 0 and "Ubuntu" in out,
              f"os={out.strip()!r}")

        # ============================================================ #
        #  Test 3: guest_exec -- exit codes                             #
        # ============================================================ #
        section("Test 3: guest_exec exit codes")

        _, ec = vm.guest_exec("true")
        check("true -> 0", ec == 0, f"ec={ec}")

        _, ec = vm.guest_exec("false")
        check("false -> 1", ec == 1, f"ec={ec}")

        _, ec = vm.guest_exec("exit 42")
        check("exit 42 -> 42", ec == 42, f"ec={ec}")

        _, ec = vm.guest_exec("exit 0")
        check("exit 0 -> 0", ec == 0, f"ec={ec}")

        # ============================================================ #
        #  Test 4: guest_exec -- complex commands                       #
        # ============================================================ #
        section("Test 4: guest_exec complex commands")

        out, ec = vm.guest_exec("echo -n foo; echo bar")
        check("semicolon", ec == 0 and "foobar" in out,
              f"out={out.strip()!r}")

        out, ec = vm.guest_exec("for i in 1 2 3; do echo $i; done")
        lines = out.strip().split("\n")
        check("for loop", lines == ["1", "2", "3"],
              f"lines={lines}")

        out, ec = vm.guest_exec("echo hello | tr a-z A-Z")
        check("pipe", "HELLO" in out, f"out={out.strip()!r}")

        out, ec = vm.guest_exec("ls /nonexistent 2>&1")
        check("stderr redirect", ec != 0)

        # ============================================================ #
        #  Test 5: guest_file_write + guest_file_read                   #
        # ============================================================ #
        section("Test 5: guest_file_read / guest_file_write")

        # Text roundtrip
        test_text = b"Hello from nitrobox QGA test!\nLine 2.\nLine 3.\n"
        vm.guest_file_write("/tmp/qga_test.txt", test_text)
        read_back = vm.guest_file_read("/tmp/qga_test.txt")
        check("text roundtrip", read_back == test_text,
              f"wrote={len(test_text)}B read={len(read_back)}B")

        # Verify via guest_exec
        out, ec = vm.guest_exec("cat /tmp/qga_test.txt")
        check("cat written file", "Hello from nitrobox" in out)

        # Binary data roundtrip
        binary_data = bytes(range(256)) * 4  # 1KB
        vm.guest_file_write("/tmp/qga_binary.bin", binary_data)
        read_binary = vm.guest_file_read("/tmp/qga_binary.bin")
        check("binary roundtrip", read_binary == binary_data,
              f"wrote={len(binary_data)}B read={len(read_binary)}B")

        # Large file (64KB)
        large_data = os.urandom(65536)
        vm.guest_file_write("/tmp/qga_large.bin", large_data)
        read_large = vm.guest_file_read("/tmp/qga_large.bin")
        check("64KB roundtrip", read_large == large_data,
              f"wrote={len(large_data)}B read={len(read_large)}B")

        # ============================================================ #
        #  Test 6: savevm / loadvm + QGA reconnect                      #
        # ============================================================ #
        section("Test 6: savevm/loadvm + QGA")

        # Write marker, save state
        vm.guest_file_write("/tmp/snap_marker.txt", b"before-loadvm\n")
        vm.savevm("qga_test")

        # Modify after save
        vm.guest_exec("echo after-save > /tmp/snap_marker.txt")
        out, _ = vm.guest_exec("cat /tmp/snap_marker.txt")
        check("modified after savevm", "after-save" in out)

        # Restore
        vm.loadvm("qga_test")
        time.sleep(0.5)
        check("ping after loadvm", vm.guest_ping(timeout=10))

        out, _ = vm.guest_exec("cat /tmp/snap_marker.txt")
        check("state restored", "before-loadvm" in out,
              f"out={out.strip()!r}")

        # ============================================================ #
        #  Test 7: multiple loadvm cycles                               #
        # ============================================================ #
        section("Test 7: multiple loadvm cycles")

        for i in range(5):
            vm.loadvm("qga_test")
            time.sleep(0.3)
            ok = vm.guest_ping(timeout=10)
            if ok:
                out, ec = vm.guest_exec("cat /tmp/snap_marker.txt")
                ok = ok and "before-loadvm" in out and ec == 0
            check(f"cycle {i + 1}/5", ok)

        # Clean up test snapshot
        vm.delvm("qga_test")

        # ============================================================ #
        #  Test 8: QMP still works alongside QGA                        #
        # ============================================================ #
        section("Test 8: QMP alongside QGA")

        status = vm.qmp("query-status")
        check("query-status", status["return"]["status"] == "running",
              f"status={status['return']['status']}")

        version = vm.hmp("info version")
        check("info version", len(version.strip()) > 0,
              f"ver={version.strip()[:40]}")

        snapshots = vm.info_snapshots()
        check("info snapshots", "ready" in snapshots)

    finally:
        # ---- Cleanup ----
        section("Cleanup")
        vm.stop()
        sb.delete()
        print("  VM stopped, sandbox deleted")

    # ---- Verify no garbage left on host ----
    section("Cleanup verification")
    leftover = []
    for name in [".qmp.sock", ".qga.sock", ".nbx_qemu_launch.sh"]:
        p = vm_dir / name
        if p.exists():
            leftover.append(str(p))
    check("no leftover sockets in vm_dir", len(leftover) == 0,
          f"leftover: {leftover}" if leftover else "")

    # Sandbox env dir should be gone
    env_dir = Path("/tmp") / "qga-integ"
    env_dir_envs = Path("/tmp") / "qga-integ_envs"
    for d in [env_dir, env_dir_envs]:
        if d.exists():
            leftover.append(str(d))
    check("no leftover sandbox dirs in /tmp", len(leftover) == 0,
          f"leftover: {leftover}" if leftover else "")

    # ---- Summary ----
    section("Summary")
    total = _passed + _failed
    print(f"  {_passed}/{total} passed, {_failed} failed")
    if _failed:
        sys.exit(1)
    print("\n  All QGA integration tests passed!")


if __name__ == "__main__":
    main()
