#!/usr/bin/env python3
"""Basic usage example for agentdocker-lite.

Must be run as root (requires mount/cgroup operations).
Requires Docker to auto-prepare rootfs from image names.
"""

import shutil

from agentdocker_lite import Sandbox, SandboxConfig, CheckpointManager


def main():
    # ---- Create sandbox with resource limits + security hardening ----
    config = SandboxConfig(
        image="ubuntu:22.04",
        working_dir="/workspace",
        cpu_max="50000 100000",  # 50% of one core
        memory_max="512m",       # 512 MB
        pids_max="256",
        cpuset_cpus="0-1",       # pin to CPU 0-1
        oom_score_adj=500,       # prefer killing sandbox over host
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

    # ---- Filesystem snapshot/restore (no root required) ----
    sb.run("echo snapshot_v1 > /workspace/data.txt")
    sb.fs_snapshot("/tmp/adl_demo_snapshot")

    sb.run("echo snapshot_v2 > /workspace/data.txt")
    sb.fs_restore("/tmp/adl_demo_snapshot")

    output, _ = sb.run("cat /workspace/data.txt")
    print(f"After fs_restore: {output.strip()}")  # snapshot_v1
    shutil.rmtree("/tmp/adl_demo_snapshot", ignore_errors=True)

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

    # ---- Clean up ----
    sb.delete()
    print("Done.")


if __name__ == "__main__":
    main()
