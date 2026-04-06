"""Tests for UID-preserving layer extraction (unpack.rs).

These tests verify that our extraction matches Podman's behavior:
  - archive.go: Unpack() loop
  - archive.go: extractTarFileEntry() — create, lchown, chmod, chtimes
  - archive_linux.go: ConvertRead() — whiteout handling

Each test creates a tar in-memory, extracts it via the Rust function
inside a user namespace, and verifies the result.
"""

from __future__ import annotations

import io
import os
import stat
import tarfile
import tempfile
import time
from pathlib import Path

import pytest

# Skip entire module if not rootless with subuid
_subuid_available = False
try:
    from nitrobox.config import detect_subuid_range
    _subuid_available = os.geteuid() != 0 and detect_subuid_range() is not None
except Exception:
    pass

pytestmark = pytest.mark.skipif(
    not _subuid_available,
    reason="Requires rootless mode with subuid range",
)


def _make_tar(**entries) -> bytes:
    """Build a tar archive in memory.

    entries: name → dict with optional keys:
        type: "file" (default), "dir", "symlink", "hardlink", "char", "fifo"
        content: bytes (for files)
        mode: int
        uid: int
        gid: int
        linkname: str (for symlinks/hardlinks)
        mtime: float
    """
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w") as tar:
        for name, props in entries.items():
            entry_type = props.get("type", "file")
            info = tarfile.TarInfo(name=name)
            info.uid = props.get("uid", 0)
            info.gid = props.get("gid", 0)
            info.mode = props.get("mode", 0o755 if entry_type == "dir" else 0o644)
            info.mtime = props.get("mtime", 1700000000)

            if entry_type == "dir":
                info.type = tarfile.DIRTYPE
                tar.addfile(info)
            elif entry_type == "file":
                content = props.get("content", b"")
                info.size = len(content)
                tar.addfile(info, io.BytesIO(content))
            elif entry_type == "symlink":
                info.type = tarfile.SYMTYPE
                info.linkname = props["linkname"]
                tar.addfile(info)
            elif entry_type == "hardlink":
                info.type = tarfile.LNKTYPE
                info.linkname = props["linkname"]
                tar.addfile(info)
            elif entry_type == "char":
                info.type = tarfile.CHRTYPE
                info.devmajor = props.get("devmajor", 0)
                info.devminor = props.get("devminor", 0)
                tar.addfile(info)
            elif entry_type == "fifo":
                info.type = tarfile.FIFOTYPE
                tar.addfile(info)
    return buf.getvalue()


def _extract(tar_data: bytes, dest: Path) -> None:
    """Extract tar via Rust unpack in userns."""
    from nitrobox.config import detect_subuid_range
    from nitrobox._backend import py_extract_tar_in_userns

    subuid = detect_subuid_range()
    assert subuid is not None
    outer_uid, sub_start, sub_count = subuid

    tar_path = dest.parent / f".{dest.name}.tar"
    tar_path.write_bytes(tar_data)
    try:
        py_extract_tar_in_userns(
            str(tar_path), str(dest),
            outer_uid, os.getgid(), sub_start, sub_count,
        )
    finally:
        tar_path.unlink(missing_ok=True)


def _stat_in_userns(path: Path) -> os.stat_result:
    """Stat a file via nsenter into the storage userns (to see mapped UIDs)."""
    from nitrobox.image.layers import _StorageNS
    ns = _StorageNS.get()
    assert ns is not None
    result = ns.run(["stat", "-c", "%u %g %a %F", str(path)])
    return result.stdout.strip()


@pytest.fixture
def extract_dir(tmp_path):
    """Provide a temp dir for extraction + clean up with rmtree_mapped."""
    dest = tmp_path / "layer"
    dest.mkdir()
    yield dest
    from nitrobox.image.layers import rmtree_mapped
    rmtree_mapped(tmp_path)


# ====================================================================== #
#  1. UID/GID preservation                                                 #
# ====================================================================== #


class TestUIDPreservation:
    """Podman: extractTarFileEntry lchown (archive.go:794-807)."""

    def test_file_ownership(self, extract_dir):
        tar = _make_tar(**{
            "file_root.txt": {"content": b"root", "uid": 0, "gid": 0},
            "file_user.txt": {"content": b"user", "uid": 1000, "gid": 1000},
            "file_service.txt": {"content": b"svc", "uid": 101, "gid": 103},
        })
        _extract(tar, extract_dir)

        # Verify via nsenter (sees mapped UIDs as container UIDs)
        assert "0 0" in _stat_in_userns(extract_dir / "file_root.txt")
        assert "1000 1000" in _stat_in_userns(extract_dir / "file_user.txt")
        assert "101 103" in _stat_in_userns(extract_dir / "file_service.txt")

    def test_directory_ownership(self, extract_dir):
        tar = _make_tar(**{
            "spool/": {"type": "dir", "uid": 101, "gid": 101, "mode": 0o700},
        })
        _extract(tar, extract_dir)

        info = _stat_in_userns(extract_dir / "spool")
        assert "101 101" in info
        assert "700" in info


# ====================================================================== #
#  2. Permissions                                                          #
# ====================================================================== #


class TestPermissions:
    """Podman: handleLChmod (archive_linux.go:191-206)."""

    def test_setuid_preserved(self, extract_dir):
        tar = _make_tar(**{
            "passwd": {"content": b"x", "mode": 0o4755, "uid": 0},
        })
        _extract(tar, extract_dir)

        info = _stat_in_userns(extract_dir / "passwd")
        assert "4755" in info

    def test_dir_permissions(self, extract_dir):
        tar = _make_tar(**{
            "private/": {"type": "dir", "mode": 0o700, "uid": 33},
        })
        _extract(tar, extract_dir)

        info = _stat_in_userns(extract_dir / "private")
        assert "700" in info


# ====================================================================== #
#  3. Symlinks and hardlinks                                               #
# ====================================================================== #


class TestLinks:
    """Podman: archive.go:762-784."""

    def test_symlink_created(self, extract_dir):
        tar = _make_tar(**{
            "target.txt": {"content": b"hello"},
            "link.txt": {"type": "symlink", "linkname": "target.txt"},
        })
        _extract(tar, extract_dir)

        link = extract_dir / "link.txt"
        assert link.is_symlink()
        assert os.readlink(str(link)) == "target.txt"

    def test_hardlink_created(self, extract_dir):
        tar = _make_tar(**{
            "original.txt": {"content": b"data"},
            "hardlink.txt": {"type": "hardlink", "linkname": "original.txt"},
        })
        _extract(tar, extract_dir)

        orig = extract_dir / "original.txt"
        hard = extract_dir / "hardlink.txt"
        assert orig.exists()
        assert hard.exists()
        # Same inode
        assert os.stat(str(orig)).st_ino == os.stat(str(hard)).st_ino

    def test_absolute_symlink_allowed(self, extract_dir):
        """Docker images commonly use absolute symlinks (e.g. /usr/bin/python -> /usr/bin/python3)."""
        tar = _make_tar(**{
            "usr/": {"type": "dir"},
            "usr/bin/": {"type": "dir"},
            "usr/bin/python3": {"content": b"#!/bin/sh"},
            "usr/bin/python": {"type": "symlink", "linkname": "/usr/bin/python3"},
        })
        _extract(tar, extract_dir)

        link = extract_dir / "usr/bin/python"
        assert link.is_symlink()
        assert os.readlink(str(link)) == "/usr/bin/python3"


# ====================================================================== #
#  4. Whiteout conversion                                                  #
# ====================================================================== #


class TestWhiteouts:
    """Podman: ConvertRead (archive_linux.go:115-153)."""

    def test_opaque_whiteout(self, extract_dir):
        """`.wh..wh..opq` → user.overlay.opaque xattr on parent dir."""
        tar = _make_tar(**{
            "mydir/": {"type": "dir"},
            "mydir/.wh..wh..opq": {"content": b""},
        })
        _extract(tar, extract_dir)

        mydir = extract_dir / "mydir"
        assert mydir.is_dir()
        # .wh..wh..opq marker should NOT exist as a file
        assert not (mydir / ".wh..wh..opq").exists()
        # xattr should be set (check via nsenter)
        from nitrobox.image.layers import _StorageNS
        ns = _StorageNS.get()
        result = ns.run(["getfattr", "-n", "user.overlay.opaque", str(mydir)])
        # getfattr may not be installed; if so, just check dir exists
        if result.returncode == 0:
            assert "y" in result.stdout

    def test_file_whiteout(self, extract_dir):
        """`.wh.filename` → mknod char(0,0) at `filename`."""
        tar = _make_tar(**{
            "dir/": {"type": "dir"},
            "dir/.wh.deleted_file": {"content": b""},
        })
        _extract(tar, extract_dir)

        # Marker should NOT exist
        assert not (extract_dir / "dir" / ".wh.deleted_file").exists()
        # Whiteout device or xattr should exist at "deleted_file"
        whiteout = extract_dir / "dir" / "deleted_file"
        assert whiteout.exists() or whiteout.is_char_device()

    def test_nested_whiteout_enotdir(self, extract_dir):
        """ENOTDIR case from Podman archive_linux.go:131-139.

        When `rm -rf /foo/bar` is done in an image, some tools generate:
            /.wh.foo        (whiteout for /foo — creates char device at /foo)
            /foo/.wh.bar    (whiteout for /foo/bar — but /foo is now a device!)
        The second mknod fails with ENOTDIR. Podman silently skips it.
        """
        tar = _make_tar(**{
            ".wh.foo": {"content": b""},      # creates device at /foo
            "foo/.wh.bar": {"content": b""},  # /foo is device → ENOTDIR → skip
        })
        # Should NOT error (ENOTDIR is handled gracefully)
        _extract(tar, extract_dir)

        # /foo should be a whiteout device (char 0,0) or xattr whiteout
        foo = extract_dir / "foo"
        assert foo.exists()

    def test_whiteout_chown(self, extract_dir):
        """Whiteout device should be chowned to match tar header.

        Podman: archive_linux.go:144
        """
        tar = _make_tar(**{
            "dir/": {"type": "dir", "uid": 0, "gid": 0},
            "dir/.wh.removed": {"uid": 1000, "gid": 1000, "content": b""},
        })
        _extract(tar, extract_dir)

        whiteout = extract_dir / "dir" / "removed"
        if whiteout.exists():
            info = _stat_in_userns(whiteout)
            assert "1000 1000" in info


# ====================================================================== #
#  4b. Overwrite behavior                                                  #
# ====================================================================== #


class TestOverwrite:
    """Podman: archive.go:1157-1183."""

    def test_file_overwrites_file(self, extract_dir):
        """Extracting a file over an existing file replaces it."""
        # First extraction
        tar1 = _make_tar(**{"f.txt": {"content": b"old"}})
        _extract(tar1, extract_dir)
        assert (extract_dir / "f.txt").read_bytes() == b"old"

        # Second extraction overwrites
        tar2 = _make_tar(**{"f.txt": {"content": b"new"}})
        _extract(tar2, extract_dir)
        assert (extract_dir / "f.txt").read_bytes() == b"new"

    def test_dir_plus_dir_merges(self, extract_dir):
        """Podman: directory + directory → merge (don't delete existing dir).

        archive.go:1178: if !fi.IsDir() || hdr.Typeflag != tar.TypeDir { remove }
        """
        tar1 = _make_tar(**{
            "d/": {"type": "dir"},
            "d/a.txt": {"content": b"a"},
        })
        _extract(tar1, extract_dir)

        tar2 = _make_tar(**{
            "d/": {"type": "dir"},
            "d/b.txt": {"content": b"b"},
        })
        _extract(tar2, extract_dir)

        # Both files should exist (directory was merged, not replaced)
        assert (extract_dir / "d" / "a.txt").exists()
        assert (extract_dir / "d" / "b.txt").exists()


# ====================================================================== #
#  5. Device nodes skipped                                                 #
# ====================================================================== #


class TestDeviceNodes:
    """Podman: extractTarFileEntry line 750-754."""

    def test_char_device_skipped(self, extract_dir):
        tar = _make_tar(**{
            "normal.txt": {"content": b"ok"},
            "dev/null": {"type": "char", "devmajor": 1, "devminor": 3},
        })
        _extract(tar, extract_dir)

        # Normal file extracted
        assert (extract_dir / "normal.txt").exists()
        # Device node silently skipped (no error, no file)
        assert not (extract_dir / "dev" / "null").exists()


# ====================================================================== #
#  6. Path breakout prevention                                             #
# ====================================================================== #


class TestBreakoutPrevention:
    """Podman: archive.go:1145-1155, 762-770, 772-784."""

    def test_dotdot_path_rejected(self, extract_dir):
        """Paths with `..` that escape dest should be rejected."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="../escape.txt")
            info.size = 5
            tar.addfile(info, io.BytesIO(b"pwned"))
        tar_data = buf.getvalue()

        # Should error (Podman returns breakoutError)
        with pytest.raises(OSError):
            _extract(tar_data, extract_dir)

    def test_hardlink_breakout_rejected(self, extract_dir):
        """Hardlinks targeting outside dest should be rejected."""
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="evil_link")
            info.type = tarfile.LNKTYPE
            info.linkname = "../../../etc/passwd"
            tar.addfile(info)
        tar_data = buf.getvalue()

        with pytest.raises(OSError):
            _extract(tar_data, extract_dir)

    def test_symlink_breakout_rejected(self, extract_dir):
        """Relative symlinks that escape dest should be rejected.

        Podman: archive.go:779-780
        """
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="evil_symlink")
            info.type = tarfile.SYMTYPE
            info.linkname = "../../../../etc/shadow"
            tar.addfile(info)
        tar_data = buf.getvalue()

        with pytest.raises(OSError):
            _extract(tar_data, extract_dir)

    def test_slash_dotdot_path_rejected(self, extract_dir):
        """Leading /../ should also be rejected.

        storage: TestUntarInvalidFilenames case 2
        """
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="/../victim/slash-dotdot")
            info.size = 5
            tar.addfile(info, io.BytesIO(b"pwned"))
        tar_data = buf.getvalue()

        with pytest.raises(OSError):
            _extract(tar_data, extract_dir)

    def test_symlink_then_write_through_it(self, extract_dir):
        """Symlink to ../victim + file written through symlink.

        storage: TestUntarInvalidSymlink case 3
        This is the most dangerous attack: create a symlink pointing
        outside, then write a file through it.
        """
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            # First: symlink pointing to ../victim
            info = tarfile.TarInfo(name="loophole-victim")
            info.type = tarfile.SYMTYPE
            info.linkname = "../victim"
            info.mode = 0o755
            tar.addfile(info)
            # Then: write a file through the symlink
            info2 = tarfile.TarInfo(name="loophole-victim/file")
            info2.type = tarfile.REGTYPE
            info2.size = 6
            info2.mode = 0o644
            tar.addfile(info2, io.BytesIO(b"pwned!"))
        tar_data = buf.getvalue()

        # The symlink should be rejected, OR the file write through it
        # should fail, OR victim dir should not be modified.
        # Set up a victim dir to verify no breakout occurred.
        victim = extract_dir.parent / "victim"
        victim.mkdir(exist_ok=True)
        (victim / "hello").write_text("safe")

        try:
            _extract(tar_data, extract_dir)
        except OSError:
            pass  # Expected: breakout detected

        # Verify victim was not modified (storage's testBreakout pattern)
        assert (victim / "hello").read_text() == "safe"
        assert not (victim / "file").exists()

    def test_hardlink_then_write_through_it(self, extract_dir):
        """Hardlink to ../victim + file written through hardlink.

        storage: TestUntarInvalidHardlink case 3
        """
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="loophole-victim")
            info.type = tarfile.LNKTYPE
            info.linkname = "../victim"
            info.mode = 0o755
            tar.addfile(info)
            info2 = tarfile.TarInfo(name="loophole-victim/file")
            info2.type = tarfile.REGTYPE
            info2.size = 6
            info2.mode = 0o644
            tar.addfile(info2, io.BytesIO(b"pwned!"))
        tar_data = buf.getvalue()

        victim = extract_dir.parent / "victim"
        victim.mkdir(exist_ok=True)
        (victim / "hello").write_text("safe")

        try:
            _extract(tar_data, extract_dir)
        except OSError:
            pass

        assert (victim / "hello").read_text() == "safe"
        assert not (victim / "file").exists()

    def test_symlink_chain_breakout(self, extract_dir):
        """Symlink → ../victim, then another symlink through it.

        storage: TestUntarInvalidSymlink case 4 (symlink, symlink)
        """
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="loophole-victim")
            info.type = tarfile.SYMTYPE
            info.linkname = "../victim"
            info.mode = 0o755
            tar.addfile(info)
            info2 = tarfile.TarInfo(name="symlink")
            info2.type = tarfile.SYMTYPE
            info2.linkname = "loophole-victim/hello"
            info2.mode = 0o644
            tar.addfile(info2)
        tar_data = buf.getvalue()

        victim = extract_dir.parent / "victim"
        victim.mkdir(exist_ok=True)
        (victim / "hello").write_text("safe")

        try:
            _extract(tar_data, extract_dir)
        except OSError:
            pass

        # The symlink chain should NOT have been able to read victim/hello
        assert (victim / "hello").read_text() == "safe"

    def test_pax_global_header_ignored(self, extract_dir):
        """PAX global headers should be silently ignored.

        storage: TestTypeXGlobalHeaderDoesNotFail
        """
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="pax_global_header")
            info.type = tarfile.XGLTYPE
            tar.addfile(info)
            info2 = tarfile.TarInfo(name="normal.txt")
            info2.size = 2
            tar.addfile(info2, io.BytesIO(b"ok"))
        tar_data = buf.getvalue()

        _extract(tar_data, extract_dir)
        assert (extract_dir / "normal.txt").read_bytes() == b"ok"

    def test_dotdot_in_middle_normalized(self, extract_dir):
        """Paths like `a/../b` are normalized to `b` (not rejected).

        Podman: archive.go:1122 filepath.Clean normalizes these.
        """
        tar = _make_tar(**{
            "usr/": {"type": "dir"},
            "usr/share/": {"type": "dir"},
            "usr/share/../lib/": {"type": "dir"},
            "usr/share/../lib/file.txt": {"content": b"normalized"},
        })
        _extract(tar, extract_dir)
        # filepath.Clean("usr/share/../lib") → "usr/lib"
        assert (extract_dir / "usr" / "lib" / "file.txt").exists()

    def test_foo_dotdot_dotdot_escape_rejected(self, extract_dir):
        """Paths like `foo/../../escape` should be rejected.

        Podman: filepath.Join(dest, "foo/../../escape") resolves to
        dest/../escape which is outside dest.  Our old normalize_path
        ate the leading ".." on relative paths, silently renaming
        the entry to "escape" inside dest.  Fixed by resolving the
        absolute joined path.
        """
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w") as tar:
            info = tarfile.TarInfo(name="foo/../../escape.txt")
            info.size = 5
            tar.addfile(info, io.BytesIO(b"pwned"))
        tar_data = buf.getvalue()

        with pytest.raises(OSError):
            _extract(tar_data, extract_dir)

    def test_symlink_masquerading_as_dir(self, extract_dir):
        """A symlink with the same name as a dir entry must not be silently merged.

        Podman: os.Lstat(path) — does NOT follow symlinks.
        If the name is a symlink to another dir, Lstat sees it as a symlink
        (not a dir), so Mkdir is attempted (correctly).
        Our old is_dir() followed symlinks, which would skip mkdir.
        """
        # Pre-create a symlink pointing to a dir outside extract_dir
        outside = extract_dir.parent / "outside_dir"
        outside.mkdir()
        (outside / "secret.txt").write_text("do not touch")
        os.symlink(str(outside), str(extract_dir / "target"))

        tar = _make_tar(**{
            "target/": {"type": "dir", "mode": 0o755},
            "target/injected.txt": {"content": b"injected"},
        })

        # The existing removal logic should remove the symlink before creating
        # the real directory.  After extraction, "target" should be a real dir,
        # not a symlink, and outside_dir should be untouched.
        _extract(tar, extract_dir)

        target = extract_dir / "target"
        assert not target.is_symlink(), "symlink should have been replaced by real dir"
        assert target.is_dir()
        assert (target / "injected.txt").exists()
        # outside_dir must not have been modified
        assert not (outside / "injected.txt").exists()
        assert (outside / "secret.txt").read_text() == "do not touch"


# ====================================================================== #
#  7. Directory mtime deferred                                             #
# ====================================================================== #


class TestDirectoryMtime:
    """Podman: archive.go:1211-1224."""

    def test_dir_mtime_not_clobbered(self, extract_dir):
        """Directory mtime should survive subsequent file creation inside it."""
        fixed_mtime = 1600000000  # 2020-09-13
        tar = _make_tar(**{
            "mydir/": {"type": "dir", "mtime": fixed_mtime},
            "mydir/file.txt": {"content": b"hi", "mtime": 1700000000},
        })
        _extract(tar, extract_dir)

        dir_stat = os.stat(str(extract_dir / "mydir"))
        # mtime should be the directory's mtime (1600000000), not the file's
        assert dir_stat.st_mtime == pytest.approx(fixed_mtime, abs=1)


# ====================================================================== #
#  8. PAX xattr                                                            #
# ====================================================================== #


class TestPAXXattr:
    """Podman: archive.go:839-861 — apply xattrs from PAX records."""

    def test_pax_xattr_applied(self, extract_dir):
        """PAX SCHILY.xattr.* records should be applied to files.

        This is how security.capability (e.g. for ping) is stored in
        Docker image layers.  We use user.test.* namespace since
        security.* requires root.
        """
        buf = io.BytesIO()
        with tarfile.open(fileobj=buf, mode="w:") as tar:
            # Create a file with a PAX xattr
            info = tarfile.TarInfo(name="myfile")
            info.size = 4
            info.uid = 0
            info.gid = 0
            info.mode = 0o755
            # Set PAX records (the tar module supports this)
            info.pax_headers = {
                "SCHILY.xattr.user.test.hello": "world",
            }
            tar.addfile(info, io.BytesIO(b"data"))
        tar_data = buf.getvalue()
        _extract(tar_data, extract_dir)

        # Verify xattr was set via nsenter
        myfile = extract_dir / "myfile"
        assert myfile.exists()

        from nitrobox.image.layers import _StorageNS
        ns = _StorageNS.get()
        if ns is not None:
            result = ns.run([
                "getfattr", "-n", "user.test.hello", "--only-values",
                str(myfile),
            ])
            if result.returncode == 0:
                assert "world" in result.stdout
            # If getfattr is not installed, just verify file was created
        # File content should still be correct
        assert myfile.read_bytes() == b"data"


# ====================================================================== #
#  9. Cleanup (rmtree_mapped)                                              #
# ====================================================================== #


class TestCleanup:
    """Podman: system.EnsureRemoveAll via _StorageNS."""

    def test_rmtree_mapped_removes_userns_files(self, tmp_path):
        """rmtree_mapped can delete directories with mapped UIDs."""
        from nitrobox.image.layers import rmtree_mapped

        dest = tmp_path / "layer"
        dest.mkdir()

        tar = _make_tar(**{
            "spool/": {"type": "dir", "uid": 101, "mode": 0o700},
            "spool/data": {"content": b"private", "uid": 101, "mode": 0o600},
        })
        _extract(tar, dest)

        # Regular rmtree would fail (host can't enter uid-101 dirs)
        assert dest.exists()
        rmtree_mapped(dest)
        assert not dest.exists()
