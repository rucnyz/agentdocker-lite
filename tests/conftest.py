"""Shared fixtures for nitrobox tests."""

from __future__ import annotations

import os
import shutil
import subprocess

import pytest


@pytest.fixture(scope="session")
def shared_cache_dir(tmp_path_factory):
    """Session-scoped rootfs cache shared by all tests.

    Avoids re-extracting Docker image layers per-test (~80 MB each),
    which quickly fills tmpfs on repeated runs.
    """
    cache = tmp_path_factory.mktemp("rootfs_cache")
    yield str(cache)
    # Layers are read-only dirs; shutil handles them fine.
    shutil.rmtree(str(cache), ignore_errors=True)


def _find_stale_mounts(path: str) -> list[str]:
    """Return list of active bind mounts under *path*."""
    result = subprocess.run(["mount"], capture_output=True, text=True)
    return [
        line for line in result.stdout.splitlines()
        if path in line
    ]


def _find_stale_processes(env_dir: str) -> list[int]:
    """Return PIDs that still reference *env_dir* (via /proc/*/root)."""
    stale: list[int] = []
    pid_file = os.path.join(env_dir, ".pid")
    if not os.path.exists(pid_file):
        return stale
    try:
        pid = int(open(pid_file).read().strip())
        # Check if process is alive
        os.kill(pid, 0)
        stale.append(pid)
    except (ValueError, OSError, ProcessLookupError):
        pass
    return stale


@pytest.fixture(autouse=True)
def _assert_clean_after_test(request, tmp_path):
    """After every test, assert that no sandbox resources leaked.

    Checks:
    - No bind mounts left under tmp_path (e.g. .netns, overlayfs)
    - No sandbox env directories left with stale .pid files
    - tmp_path can be fully removed (no "Directory not empty")
    """
    yield

    # Only check tests that used tmp_path for sandbox env_dirs
    envs_dir = tmp_path / "envs"
    if not envs_dir.exists():
        return

    errors: list[str] = []

    # 1. Check for stale bind mounts
    stale_mounts = _find_stale_mounts(str(tmp_path))
    if stale_mounts:
        # Try to clean up, then report
        for mount_line in stale_mounts:
            mount_point = mount_line.split(" on ")[1].split(" type ")[0] if " on " in mount_line else ""
            if mount_point:
                subprocess.run(["umount", "-l", mount_point], capture_output=True)
        errors.append(
            f"Stale bind mounts after test: {stale_mounts}"
        )

    # 2. Check for leftover env directories with .pid files (zombie sandboxes)
    for entry in envs_dir.iterdir():
        if not entry.is_dir():
            continue
        stale_pids = _find_stale_processes(str(entry))
        if stale_pids:
            errors.append(
                f"Stale sandbox process(es) in {entry.name}: pids={stale_pids}"
            )

    # 3. Verify tmp_path is cleanly removable (no stuck files)
    try:
        shutil.rmtree(str(envs_dir))
    except OSError as e:
        errors.append(f"Cannot clean env dir: {e}")

    if errors:
        pytest.fail(
            "Resource leak detected after test:\n" + "\n".join(f"  - {e}" for e in errors)
        )
