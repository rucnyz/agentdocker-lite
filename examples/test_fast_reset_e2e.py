#!/usr/bin/env python3
"""End-to-end test + benchmark: fast_reset vs default reset.

Tests the FULL sandbox reset lifecycle (not just filesystem ops):
  create sandbox → run commands → populate files → reset → verify → repeat

Validates correctness AND measures performance for both paths.

Works in rootful (sudo) and rootless (no sudo) modes.

Usage:
    python3 examples/test_fast_reset_e2e.py
    python3 examples/test_fast_reset_e2e.py --rounds 20 --files 500
"""

import argparse
import os
import statistics
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "src"))

from agentdocker_lite import Sandbox, SandboxConfig

IMAGE = os.environ.get("LITE_SANDBOX_TEST_IMAGE", "ubuntu:22.04")


# ====================================================================== #
#  Correctness tests                                                      #
# ====================================================================== #

def test_basic_reset(sb: Sandbox, label: str) -> None:
    """Test that reset clears files and preserves base image."""
    print(f"  [{label}] test_basic_reset...", end=" ")

    # Create a file
    sb.run("echo 'hello' > /workspace/test.txt")
    out, ec = sb.run("cat /workspace/test.txt")
    assert ec == 0 and "hello" in out, f"write failed: ec={ec}, out={out!r}"

    # Reset should clear it
    sb.reset()
    _, ec = sb.run("cat /workspace/test.txt 2>/dev/null")
    assert ec != 0, "file survived reset"

    # Base image should be intact
    _, ec = sb.run("ls /bin/sh")
    assert ec == 0, "base image broken after reset"

    print("PASS")


def test_multiple_resets(sb: Sandbox, label: str) -> None:
    """Test 5 consecutive resets."""
    print(f"  [{label}] test_multiple_resets...", end=" ")

    for i in range(5):
        sb.run(f"echo round-{i} > /workspace/marker_{i}.txt")
        sb.reset()
        _, ec = sb.run(f"test -f /workspace/marker_{i}.txt")
        assert ec != 0, f"file survived reset #{i}"
        # Verify commands still work
        out, ec = sb.run(f"echo alive-{i}")
        assert ec == 0 and f"alive-{i}" in out, f"command failed after reset #{i}"

    print("PASS")


def test_many_files_reset(sb: Sandbox, n_files: int, label: str) -> None:
    """Test reset with many files (the actual RL scenario)."""
    print(f"  [{label}] test_many_files_reset ({n_files} files)...", end=" ")

    # Create many files simulating agent code generation
    sb.run(f"mkdir -p /workspace/src && seq 1 {n_files} | xargs -I{{}} "
           f"sh -c 'echo \"print({{}})\"> /workspace/src/gen_{{}}.py'")

    # Verify they exist
    out, ec = sb.run(f"ls /workspace/src/ | wc -l")
    assert ec == 0
    count = int(out.strip())
    assert count == n_files, f"expected {n_files} files, got {count}"

    # Reset
    sb.reset()

    # All files should be gone
    _, ec = sb.run("ls /workspace/src/ 2>/dev/null")
    assert ec != 0, "directory survived reset"

    # Commands still work
    out, ec = sb.run("echo post-reset-ok")
    assert ec == 0 and "post-reset-ok" in out

    print("PASS")


def test_modified_base_file(sb: Sandbox, label: str) -> None:
    """Test that modifying a base image file is reverted on reset."""
    print(f"  [{label}] test_modified_base_file...", end=" ")

    # Read original
    original, ec = sb.run("cat /etc/hostname 2>/dev/null || echo __none__")
    assert ec == 0

    # Modify it
    sb.run("echo 'TAMPERED' > /etc/hostname")
    modified, _ = sb.run("cat /etc/hostname")
    assert "TAMPERED" in modified

    # Reset should revert
    sb.reset()
    restored, _ = sb.run("cat /etc/hostname 2>/dev/null || echo __none__")
    assert restored.strip() == original.strip(), (
        f"base file not restored: {restored.strip()!r} != {original.strip()!r}"
    )

    print("PASS")


def test_deleted_base_file(sb: Sandbox, label: str) -> None:
    """Test that deleting a base image file is reverted on reset."""
    print(f"  [{label}] test_deleted_base_file...", end=" ")

    _, ec = sb.run("ls /bin/ls")
    assert ec == 0

    sb.run("rm -f /bin/ls")
    _, ec = sb.run("ls /bin/ls 2>/dev/null")
    assert ec != 0, "rm didn't work"

    sb.reset()
    _, ec = sb.run("ls /bin/ls")
    assert ec == 0, "/bin/ls not restored after reset"

    print("PASS")


def test_nested_dirs_and_symlinks(sb: Sandbox, label: str) -> None:
    """Test reset handles nested dirs, symlinks, special names."""
    print(f"  [{label}] test_nested_dirs_and_symlinks...", end=" ")

    sb.run("mkdir -p /workspace/a/b/c/d/e")
    sb.run("echo deep > /workspace/a/b/c/d/e/file.txt")
    sb.run("ln -s /workspace/a/b/c /workspace/shortcut")
    sb.run("touch '/workspace/file with spaces.txt'")
    sb.run("touch '/workspace/special!@#.txt'")

    sb.reset()

    _, ec = sb.run("test -e /workspace/a")
    assert ec != 0, "nested dir survived"
    _, ec = sb.run("test -e /workspace/shortcut")
    assert ec != 0, "symlink survived"
    _, ec = sb.run("test -e '/workspace/file with spaces.txt'")
    assert ec != 0, "file with spaces survived"

    print("PASS")


# ====================================================================== #
#  Performance benchmark                                                  #
# ====================================================================== #

def bench_reset_e2e(
    sb: Sandbox, n_rounds: int, n_files: int
) -> dict:
    """Full end-to-end reset benchmark."""
    # Warmup
    sb.run("echo warmup")
    sb.reset()

    times_ms = []
    for i in range(n_rounds):
        # Populate (simulating agent episode)
        sb.run(f"mkdir -p /workspace/data && seq 1 {n_files} | "
               f"xargs -I{{}} touch /workspace/data/f_{{}}")

        t0 = time.monotonic()
        sb.reset()
        elapsed = (time.monotonic() - t0) * 1000
        times_ms.append(elapsed)

        # Quick sanity check
        _, ec = sb.run("echo ok")
        assert ec == 0, f"shell broken after reset round {i}"

    return {
        "median": statistics.median(times_ms),
        "mean": statistics.mean(times_ms),
        "stdev": statistics.stdev(times_ms) if len(times_ms) > 1 else 0,
        "min": min(times_ms),
        "max": max(times_ms),
        "raw": times_ms,
    }


# ====================================================================== #
#  Main                                                                   #
# ====================================================================== #

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--files", type=int, default=200)
    parser.add_argument("--image", type=str, default=IMAGE)
    parser.add_argument("--skip-bench", action="store_true",
                        help="Run correctness tests only, skip benchmark")
    args = parser.parse_args()

    mode = "rootful" if os.geteuid() == 0 else "rootless"
    print(f"=== End-to-end fast_reset test ({mode} mode) ===")
    print(f"    Image: {args.image}")
    print()

    # ---- Phase 1: Correctness tests ----
    for fast_reset in (False, True):
        label = "FAST" if fast_reset else "DEFAULT"
        print(f"--- Correctness: {label} reset ---")
        config = SandboxConfig(
            image=args.image,
            working_dir="/workspace",
            fast_reset=fast_reset,
        )
        sb = Sandbox(config, name=f"test-{label.lower()}")

        try:
            test_basic_reset(sb, label)
            test_multiple_resets(sb, label)
            test_many_files_reset(sb, args.files, label)
            test_modified_base_file(sb, label)
            test_deleted_base_file(sb, label)
            test_nested_dirs_and_symlinks(sb, label)
        finally:
            sb.delete()

        print()

    print("All correctness tests PASSED.\n")

    if args.skip_bench:
        return

    # ---- Phase 2: Performance benchmark ----
    print(f"--- Performance benchmark ({args.rounds} rounds, {args.files} files) ---")

    results = {}
    for fast_reset in (False, True):
        label = "FAST" if fast_reset else "DEFAULT"
        config = SandboxConfig(
            image=args.image,
            working_dir="/workspace",
            fast_reset=fast_reset,
        )
        sb = Sandbox(config, name=f"bench-{label.lower()}")
        print(f"  Benchmarking {label}...")
        results[label] = bench_reset_e2e(sb, args.rounds, args.files)
        sb.delete()

    # Print results
    d = results["DEFAULT"]
    f = results["FAST"]

    print()
    print(f"{'':20s} {'Default':>12s} {'Fast':>12s} {'Speedup':>10s}")
    print("-" * 56)
    for metric in ("median", "mean", "min", "max"):
        dv, fv = d[metric], f[metric]
        sp = dv / fv if fv > 0 else float("inf")
        print(f"  {metric:18s} {dv:10.2f}ms {fv:10.2f}ms {sp:8.2f}x")
    print(f"  {'stdev':18s} {d['stdev']:10.2f}ms {f['stdev']:10.2f}ms")

    print()
    print(f"Raw default: {[f'{t:.1f}' for t in d['raw']]}")
    print(f"Raw fast:    {[f'{t:.1f}' for t in f['raw']]}")

    saved = d["median"] - f["median"]
    speedup = d["median"] / f["median"] if f["median"] > 0 else 0
    print(f"\nFull reset median: {d['median']:.1f}ms → {f['median']:.1f}ms "
          f"({speedup:.2f}x, {saved:.1f}ms saved)")


if __name__ == "__main__":
    main()
