"""Shared fixtures for agentdocker-lite tests."""

from __future__ import annotations

import shutil

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
