#!/usr/bin/env python3
"""Basic usage example for agentdocker-lite.

Must be run as root (requires mount/cgroup operations).
Requires Docker to auto-prepare rootfs from image names.
"""

import os
import shutil
import subprocess
import tempfile

from agentdocker_lite import Sandbox, SandboxConfig, CheckpointManager


def main():
    # ---- Create sandbox with resource limits + security hardening ----
    host_dir = tempfile.mkdtemp(prefix="adl_demo_vol_")
    with open(os.path.join(host_dir, "host_file.txt"), "w") as f:
        f.write("from host\n")

    config = SandboxConfig(
        image="ubuntu:22.04",
        working_dir="/workspace",
        cpu_max="50000 100000",  # 50% of one core
        memory_max="512m",       # 512 MB
        pids_max="256",
        cpuset_cpus="0-1",       # pin to CPU 0-1
        oom_score_adj=500,       # prefer killing sandbox over host
        volumes=[
            f"{host_dir}:/mnt/shared:ro",   # read-only bind mount
        ],
        # Security: seccomp, masked paths, readonly paths, cap drop
        # are all ON by default — no config needed.
    )

    sb = Sandbox(config, name="demo")

    # ---- Feature detection ----
    print(f"Active features: {sb.features}")

    # ---- Run commands ----
    output, ec = sb.run("echo hello from sandbox")
    print(f"[exit={ec}] {output.strip()}")

    output, ec = sb.run("cat /etc/os-release | head -2")
    print(f"[exit={ec}] {output.strip()}")

    # ---- File I/O ----
    sb.write_file("/workspace/test.txt", "hello world\n")
    content = sb.read_file("/workspace/test.txt")
    print(f"File content: {content.strip()}")

    # ---- Volumes ----
    output, ec = sb.run("cat /mnt/shared/host_file.txt")
    print(f"Volume (ro): {output.strip()}")
    output, ec = sb.run("touch /mnt/shared/test 2>&1")
    print(f"Volume write (should fail): exit={ec}")

    # ---- Background processes ----
    handle = sb.run_background("sleep 100")
    output, running = sb.check_background(handle)
    print(f"Background: running={running}")
    all_procs = sb.list_background()
    print(f"All background: {all_procs}")
    sb.stop_background(handle)
    print("Background process stopped")

    # ---- Interactive processes (popen) ----
    proc = sb.popen("bash")
    proc.stdin.write(b"echo popen_works\n")
    proc.stdin.flush()
    line = proc.stdout.readline()
    print(f"popen: {line.decode().strip()}")
    proc.terminate()

    # ---- Filesystem snapshot/restore (no root required) ----
    sb.run("echo snapshot_v1 > /workspace/data.txt")
    sb.fs_snapshot("/tmp/adl_demo_snapshot")

    sb.run("echo snapshot_v2 > /workspace/data.txt")
    sb.fs_restore("/tmp/adl_demo_snapshot")

    output, _ = sb.run("cat /workspace/data.txt")
    print(f"After fs_restore: {output.strip()}")  # snapshot_v1
    shutil.rmtree("/tmp/adl_demo_snapshot", ignore_errors=True)

    # ---- Save as Docker image ----
    sb.run("echo image_data > /workspace/exported.txt")
    sb.save_as_image("adl-demo:cached")
    print("Saved sandbox state as Docker image: adl-demo:cached")

    sb2 = Sandbox(SandboxConfig(image="adl-demo:cached", working_dir="/workspace"), name="from-cache")
    out, _ = sb2.run("cat /workspace/exported.txt")
    print(f"From cached image: {out.strip()}")  # image_data
    sb2.delete()
    subprocess.run(["docker", "rmi", "-f", "adl-demo:cached"], capture_output=True)

    # ---- CRIU process checkpoint/restore ----
    if CheckpointManager.check_available():
        mgr = CheckpointManager(sb)

        sb.run("echo criu_v1 > /workspace/state.txt")
        shutil.rmtree("/tmp/adl_demo_ckpt", ignore_errors=True)
        mgr.save("/tmp/adl_demo_ckpt")
        print("CRIU checkpoint saved")

        sb.run("rm -rf /workspace/*")  # destructive action
        mgr.restore("/tmp/adl_demo_ckpt")

        output, _ = sb.run("cat /workspace/state.txt")
        print(f"After CRIU restore: {output.strip()}")  # criu_v1
        shutil.rmtree("/tmp/adl_demo_ckpt", ignore_errors=True)
    else:
        print("CRIU not available, skipping checkpoint demo")

    # ---- Reset to clean image ----
    sb.reset()
    output, ec = sb.run("cat /workspace/test.txt 2>&1")
    print(f"After reset [exit={ec}]: {output.strip()}")

    # ---- Security: masked paths ----
    output, _ = sb.run("cat /proc/kcore 2>&1 | wc -c")
    print(f"/proc/kcore bytes (masked → 0): {output.strip()}")

    # ---- Pressure monitoring (PSI) ----
    psi = sb.pressure()
    if psi:
        print(f"PSI: cpu={psi.get('cpu', {}).get('avg10', 0):.1f}% "
              f"mem={psi.get('memory', {}).get('avg10', 0):.1f}% "
              f"io={psi.get('io', {}).get('avg10', 0):.1f}%")

    # ---- Memory reclamation ----
    reclaimed = sb.reclaim_memory()
    print(f"reclaim_memory: {'ok' if reclaimed else 'not supported'}")

    # ---- Clean up ----
    sb.delete()
    shutil.rmtree(host_dir, ignore_errors=True)
    print("Done.")


def demo_layer_cache():
    """Demonstrate Docker layer-level caching.

    Images sharing base layers (e.g. python:3.11-slim and python:3.12-slim
    both use Debian bookworm) only extract the unique layers on the second
    pull — shared layers are cached and reused via overlayfs multi-layer
    stacking.
    """
    import time
    from pathlib import Path

    images = ["python:3.11-slim", "python:3.12-slim"]
    sandboxes = []

    for img in images:
        t0 = time.monotonic()
        sb = Sandbox(SandboxConfig(image=img), name=f"layer-demo-{img.replace(':', '-')}")
        elapsed = (time.monotonic() - t0) * 1000
        sandboxes.append(sb)

        layers = getattr(sb, "_layer_dirs", None)
        n_layers = len(layers) if layers else 0
        out, _ = sb.run("python3 --version")
        print(f"  {img}: {elapsed:.0f}ms, {n_layers} layers, {out.strip()}")

    # Show layer deduplication
    all_layers = []
    for sb in sandboxes:
        layers = getattr(sb, "_layer_dirs", None) or []
        all_layers.append({l.name for l in layers})

    if len(all_layers) == 2:
        shared = all_layers[0] & all_layers[1]
        total = all_layers[0] | all_layers[1]
        print(f"  Shared layers: {len(shared)}/{len(total)} "
              f"({len(shared)/len(total)*100:.0f}% deduplication)")

    # Show cache disk usage
    cache_dir = Path(sandboxes[0]._config.rootfs_cache_dir) / "layers"
    if cache_dir.exists():
        total_bytes = sum(f.stat().st_size for f in cache_dir.rglob("*") if f.is_file())
        print(f"  Layer cache: {total_bytes / 1024 / 1024:.0f}MB on disk")

    for sb in sandboxes:
        sb.delete()


if __name__ == "__main__":
    main()
    print()
    print("=== Layer Cache Demo ===")
    demo_layer_cache()
