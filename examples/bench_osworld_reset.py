#!/usr/bin/env python3
"""Benchmark: VM reset for OSWorld-style GUI agent workloads.

Compares the episode reset strategy used by OSWorld's Docker provider
(destroy container + recreate) vs QEMU's native loadvm (in-place memory
restore).  Both use the same OSWorld Ubuntu Desktop qcow2 image.

The speedup comes from the reset strategy (loadvm vs restart), not from
the sandbox layer.  OSWorld's Docker provider cannot use loadvm because
it destroys the QEMU process on every reset.  adl's QemuVM keeps QEMU
alive and uses QMP to restore state in-place.

Requires:
    - /dev/kvm with read/write access
    - Docker with ``happysixd/osworld-docker`` image pulled
    - OSWorld Ubuntu.qcow2 (download from HuggingFace, ~13GB zip → 23GB)
    - ``pip install docker requests``

Usage:
    python examples/bench_osworld_reset.py
    python examples/bench_osworld_reset.py --qcow2 /path/to/Ubuntu.qcow2
    python examples/bench_osworld_reset.py --rounds 5
"""

import argparse
import json
import os
import socket
import statistics
import subprocess
import time

# ---------------------------------------------------------------------------
# QMP helpers (same protocol as agentdocker_lite.vm.QemuVM)
# ---------------------------------------------------------------------------

def _qmp_send(sock_path: str, command: str, arguments: dict = None) -> dict:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(120)
    s.connect(sock_path)
    s.recv(4096)  # greeting
    s.sendall(b'{"execute": "qmp_capabilities"}\n')
    s.recv(4096)

    msg = {"execute": command}
    if arguments:
        msg["arguments"] = arguments
    s.sendall(json.dumps(msg).encode() + b"\n")

    data = b""
    while True:
        chunk = s.recv(4096)
        if not chunk:
            break
        data += chunk
        text = data.decode(errors="ignore")
        if '"return"' in text or '"error"' in text:
            break
    s.close()

    for line in data.decode(errors="ignore").strip().split("\n"):
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
            if "return" in obj or "error" in obj:
                return obj
        except json.JSONDecodeError:
            continue
    return {"return": {}}


def _hmp(sock_path: str, command: str) -> str:
    resp = _qmp_send(sock_path, "human-monitor-command",
                     {"command-line": command})
    if "error" in resp:
        raise RuntimeError(f"HMP failed: {resp['error']}")
    return resp.get("return", "")


# ---------------------------------------------------------------------------
# OSWorld Docker provider reset benchmark
# ---------------------------------------------------------------------------

def bench_osworld_docker_reset(qcow2: str, rounds: int, memory: str,
                               cpus: int) -> dict:
    """Benchmark OSWorld Docker provider reset.

    Replicates the exact flow from
    desktop_env/providers/docker/provider.py:
      revert_to_snapshot() → stop_emulator() (stop + remove + sleep(3))
      then start_emulator() → _wait_for_vm_ready() (poll /screenshot)
    """
    import docker
    import requests

    print("=== OSWorld Docker provider reset ===")
    print(f"  Image: happysixd/osworld-docker")
    print(f"  VM: {memory} RAM, {cpus} CPUs")

    client = docker.from_env()
    env = {"DISK_SIZE": "32G", "RAM_SIZE": memory, "CPU_CORES": str(cpus)}
    devices = ["/dev/kvm"] if os.path.exists("/dev/kvm") else []
    if not devices:
        env["KVM"] = "N"
    server_port = 15000

    def start():
        return client.containers.run(
            "happysixd/osworld-docker",
            environment=env,
            cap_add=["NET_ADMIN"],
            devices=devices,
            volumes={os.path.abspath(qcow2): {"bind": "/System.qcow2",
                                               "mode": "ro"}},
            ports={5000: server_port},
            detach=True,
        )

    def wait_ready(timeout=300):
        t0 = time.time()
        while time.time() - t0 < timeout:
            try:
                r = requests.get(f"http://localhost:{server_port}/screenshot",
                                 timeout=(10, 10))
                if r.status_code == 200:
                    return
            except Exception:
                pass
            time.sleep(1)
        raise TimeoutError("VM not ready")

    # Initial boot
    print("  Booting VM for the first time...")
    container = start()
    wait_ready()
    print("  VM ready.\n")

    # Reset loop: stop + remove + sleep(3) + start + wait_ready
    reset_times = []
    for i in range(rounds):
        t0 = time.monotonic()
        container.stop()
        container.remove()
        time.sleep(3)  # WAIT_TIME from OSWorld provider.py
        container = start()
        wait_ready()
        elapsed = (time.monotonic() - t0) * 1000
        reset_times.append(elapsed)
        print(f"  Reset {i+1}/{rounds}: {elapsed/1000:.1f}s")

    container.stop()
    container.remove()

    med = statistics.median(reset_times)
    print(f"  Median: {med/1000:.1f}s")
    return {"median_ms": med, "all_ms": reset_times}


# ---------------------------------------------------------------------------
# adl QemuVM (loadvm) reset benchmark
# ---------------------------------------------------------------------------

def bench_adl_loadvm_reset(qcow2: str, rounds: int, memory: str,
                           cpus: int) -> dict:
    """Benchmark QEMU loadvm reset (same operation as QemuVM.loadvm).

    Uses raw QMP commands — same protocol as agentdocker_lite.vm.QemuVM.
    The QemuVM wrapper adds ~12ms overhead per call.
    """
    qmp_sock = "/tmp/adl_bench_osworld_qmp.sock"

    print(f"\n=== adl QemuVM reset (loadvm) ===")
    print(f"  VM: {memory} RAM, {cpus} CPUs")

    try:
        os.unlink(qmp_sock)
    except FileNotFoundError:
        pass

    cmd = [
        "qemu-system-x86_64", "-enable-kvm",
        "-m", memory, "-smp", str(cpus),
        "-drive", f"file={qcow2},format=qcow2,if=virtio,snapshot=on",
        "-qmp", f"unix:{qmp_sock},server,nowait",
        "-display", "none", "-serial", "null",
        "-no-shutdown", "-nographic",
        "-device", "virtio-vga",
    ]

    proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)

    # Wait for QMP
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        if os.path.exists(qmp_sock):
            try:
                _qmp_send(qmp_sock, "query-status")
                break
            except Exception:
                pass
        time.sleep(0.2)
    else:
        proc.kill()
        raise TimeoutError("QMP not ready")

    # Wait for OS to boot so savevm captures a fully-booted state
    print("  Waiting 30s for Ubuntu Desktop to boot...")
    time.sleep(30)

    # Save state (one-time cost)
    print("  Saving VM state (savevm)...")
    t0 = time.monotonic()
    _hmp(qmp_sock, "savevm episode_base")
    savevm_ms = (time.monotonic() - t0) * 1000
    print(f"  savevm: {savevm_ms/1000:.1f}s (one-time cost)\n")

    # loadvm reset loop
    reset_times = []
    for i in range(rounds):
        t0 = time.monotonic()
        _hmp(qmp_sock, "loadvm episode_base")
        elapsed = (time.monotonic() - t0) * 1000
        reset_times.append(elapsed)
        print(f"  Reset {i+1}/{rounds}: {elapsed:.0f}ms")

    _hmp(qmp_sock, "delvm episode_base")
    try:
        _qmp_send(qmp_sock, "quit")
    except Exception:
        pass
    proc.wait(timeout=30)

    med = statistics.median(reset_times)
    print(f"  Median: {med:.0f}ms")
    return {"median_ms": med, "savevm_ms": savevm_ms, "all_ms": reset_times}


# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(
        description="Benchmark VM reset: OSWorld Docker vs adl QemuVM (loadvm)")
    parser.add_argument("--qcow2", default=None,
                        help="Path to OSWorld Ubuntu.qcow2")
    parser.add_argument("--rounds", type=int, default=5,
                        help="Number of reset cycles (default: 5)")
    parser.add_argument("--memory", default="4G", help="VM memory")
    parser.add_argument("--cpus", type=int, default=4, help="VM CPUs")
    args = parser.parse_args()

    # Find qcow2
    qcow2 = args.qcow2
    if not qcow2:
        for candidate in [
            "docker_vm_data/Ubuntu.qcow2",
            "../osworld/docker_vm_data/Ubuntu.qcow2",
            os.path.expanduser("~/.cache/osworld/Ubuntu.qcow2"),
        ]:
            if os.path.exists(candidate):
                qcow2 = candidate
                break
    if not qcow2 or not os.path.exists(qcow2):
        print("ERROR: OSWorld Ubuntu.qcow2 not found.")
        print("Download from: https://huggingface.co/datasets/xlangai/ubuntu_osworld")
        print("Or specify with: --qcow2 /path/to/Ubuntu.qcow2")
        return

    # Preflight
    if not os.path.exists("/dev/kvm") or not os.access("/dev/kvm", os.R_OK | os.W_OK):
        print("ERROR: /dev/kvm not accessible (need kvm group)")
        return

    print("VM Reset Benchmark: OSWorld Docker vs adl QemuVM (loadvm)")
    print(f"Image: {qcow2} ({os.path.getsize(qcow2) // 1024**3}GB)")
    print(f"VM: {args.memory} RAM, {args.cpus} CPUs, {args.rounds} rounds")
    print()
    print("Both use the same OSWorld Ubuntu Desktop qcow2 and QEMU/KVM.")
    print("The difference is reset strategy:")
    print("  OSWorld: destroy container → new container → reboot OS")
    print("  adl:     QMP loadvm → in-place memory restore (no reboot)")
    print()

    osworld = bench_osworld_docker_reset(
        qcow2, args.rounds, args.memory, args.cpus)
    adl = bench_adl_loadvm_reset(
        qcow2, args.rounds, args.memory, args.cpus)

    speedup = osworld["median_ms"] / adl["median_ms"]

    print()
    print("=" * 60)
    print(f"  {'':22} {'OSWorld Docker':>16} {'adl loadvm':>12} {'Speedup':>10}")
    print(f"  {'-'*22} {'-'*16} {'-'*12} {'-'*10}")
    print(f"  {'Reset (median)':22} "
          f"{osworld['median_ms']/1000:>14.1f}s "
          f"{adl['median_ms']/1000:>10.1f}s "
          f"{speedup:>8.1f}x")
    print()
    print(f"  savevm (one-time):  {adl['savevm_ms']/1000:.1f}s")
    print()

    episodes = 1000
    os_h = osworld["median_ms"] * episodes / 3600000
    adl_h = adl["median_ms"] * episodes / 3600000
    print(f"  RL training impact ({episodes} episodes):")
    print(f"    OSWorld Docker: {os_h:.1f}h on resets")
    print(f"    adl loadvm:     {adl_h:.1f}h on resets")
    print(f"    Saved:          {os_h - adl_h:.1f}h ({speedup:.0f}x)")
    print()
    print("  Note: Speedup comes from the reset strategy (loadvm vs")
    print("  container restart), not from the sandbox layer itself.")


if __name__ == "__main__":
    main()
