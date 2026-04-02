"""Tests for Rust whiteout conversion (OCI → overlayfs)."""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

from nitrobox._core import py_convert_whiteouts


def _can_set_user_xattr(tmp_path: Path) -> bool:
    """Check if user.* xattrs are supported and setfattr is available."""
    test_file = tmp_path / ".xattr_test"
    test_file.touch()
    try:
        result = subprocess.run(
            ["setfattr", "-n", "user.test", "-v", "1", str(test_file)],
            capture_output=True,
        )
        return result.returncode == 0
    except FileNotFoundError:
        return False  # setfattr not installed
    finally:
        test_file.unlink(missing_ok=True)


class TestWhiteoutXattr:
    """Whiteout conversion using user.overlay.* xattrs (rootless)."""

    def test_regular_whiteout(self, tmp_path):
        """`.wh.foo` → create `foo` with user.overlay.whiteout xattr."""
        if not _can_set_user_xattr(tmp_path):
            pytest.skip("user.* xattrs not supported on this filesystem")

        layer = tmp_path / "layer"
        layer.mkdir()
        (layer / ".wh.deleted_file").touch()

        count = py_convert_whiteouts(str(layer), True)
        assert count == 1
        assert not (layer / ".wh.deleted_file").exists()

        target = layer / "deleted_file"
        assert target.exists()
        # Verify xattr
        result = subprocess.run(
            ["getfattr", "-n", "user.overlay.whiteout", str(target)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "user.overlay.whiteout" in result.stdout

    def test_opaque_dir(self, tmp_path):
        """`.wh..wh..opq` → set user.overlay.opaque on parent dir."""
        if not _can_set_user_xattr(tmp_path):
            pytest.skip("user.* xattrs not supported on this filesystem")

        layer = tmp_path / "layer"
        subdir = layer / "somedir"
        subdir.mkdir(parents=True)
        (subdir / ".wh..wh..opq").touch()

        count = py_convert_whiteouts(str(layer), True)
        assert count == 1
        assert not (subdir / ".wh..wh..opq").exists()

        result = subprocess.run(
            ["getfattr", "-n", "user.overlay.opaque", str(subdir)],
            capture_output=True, text=True,
        )
        assert result.returncode == 0
        assert "user.overlay.opaque" in result.stdout

    def test_multiple_whiteouts(self, tmp_path):
        """Multiple whiteouts in different directories."""
        if not _can_set_user_xattr(tmp_path):
            pytest.skip("user.* xattrs not supported on this filesystem")

        layer = tmp_path / "layer"
        layer.mkdir()
        (layer / ".wh.a").touch()
        (layer / ".wh.b").touch()
        sub = layer / "sub"
        sub.mkdir()
        (sub / ".wh.c").touch()
        (sub / ".wh..wh..opq").touch()

        count = py_convert_whiteouts(str(layer), True)
        assert count == 4
        assert (layer / "a").exists()
        assert (layer / "b").exists()
        assert (sub / "c").exists()
        assert not (sub / ".wh..wh..opq").exists()

    def test_no_whiteouts(self, tmp_path):
        """Layer with no whiteouts returns count=0."""
        layer = tmp_path / "layer"
        layer.mkdir()
        (layer / "normal_file.txt").write_text("content")

        count = py_convert_whiteouts(str(layer), True)
        assert count == 0
        assert (layer / "normal_file.txt").read_text() == "content"

    def test_nonexistent_dir_raises(self):
        """Nonexistent directory raises OSError."""
        with pytest.raises(OSError):
            py_convert_whiteouts("/tmp/nonexistent_whiteout_test_dir", True)

    def test_preserves_non_whiteout_files(self, tmp_path):
        """Non-whiteout files are untouched."""
        if not _can_set_user_xattr(tmp_path):
            pytest.skip("user.* xattrs not supported on this filesystem")

        layer = tmp_path / "layer"
        layer.mkdir()
        (layer / "keep_me.txt").write_text("preserved")
        (layer / ".wh.delete_me").touch()

        py_convert_whiteouts(str(layer), True)
        assert (layer / "keep_me.txt").read_text() == "preserved"
        assert not (layer / ".wh.delete_me").exists()
        assert (layer / "delete_me").exists()


class TestWhiteoutMknod:
    """Whiteout conversion using mknod(0,0) (requires root)."""

    def test_mknod_whiteout(self, tmp_path):
        """`.wh.foo` → create char device (0,0) at `foo`."""
        if os.geteuid() != 0:
            pytest.skip("mknod requires root")

        layer = tmp_path / "layer"
        layer.mkdir()
        (layer / ".wh.gone").touch()

        count = py_convert_whiteouts(str(layer), False)
        assert count == 1
        assert not (layer / ".wh.gone").exists()

        target = layer / "gone"
        assert target.exists()
        stat = target.stat()
        # Check it's a char device with major=0, minor=0
        import stat as stat_mod
        assert stat_mod.S_ISCHR(stat.st_mode)
        assert os.major(stat.st_rdev) == 0
        assert os.minor(stat.st_rdev) == 0
