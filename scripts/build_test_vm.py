#!/usr/bin/env python3
"""Download Ubuntu cloud image and create cloud-init seed for QGA testing.

Creates a test VM directory with:
  - ubuntu-base.img:     Downloaded Ubuntu 22.04 cloud image (cached)
  - ubuntu-test.qcow2:   Working copy backed by base (4GB virtual size)
  - seed.iso:            cloud-init NoCloud seed (installs qemu-guest-agent)

Usage:
    python scripts/build_test_vm.py [--vm-dir scripts/vm]

The base image is ~300MB. First VM boot with cloud-init takes ~1-2 min
to install qemu-guest-agent via apt.  After that, the test script saves
a snapshot so subsequent runs boot instantly.
"""

from __future__ import annotations

import argparse
import struct
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

CLOUD_IMAGE_URL = (
    "https://cloud-images.ubuntu.com/minimal/releases/jammy/release/"
    "ubuntu-22.04-minimal-cloudimg-amd64.img"
)

USERDATA = """\
#cloud-config
package_update: true
packages:
  - qemu-guest-agent
runcmd:
  - systemctl enable qemu-guest-agent
  - systemctl start qemu-guest-agent
ssh_pwauth: true
chpasswd:
  list: |
    root:test
  expire: false
"""

METADATA = """\
instance-id: nbx-test-vm
local-hostname: nbx-test
"""


def _download(url: str, dest: Path) -> None:
    """Download file with wget or curl."""
    if shutil.which("wget"):
        subprocess.run(
            ["wget", "-q", "--show-progress", "-O", str(dest), url],
            check=True,
        )
    elif shutil.which("curl"):
        subprocess.run(
            ["curl", "-fL", "--progress-bar", "-o", str(dest), url],
            check=True,
        )
    else:
        print("ERROR: need wget or curl")
        sys.exit(1)


def _make_seed_iso_python(files: dict[str, bytes], volume_id: str, output: Path) -> None:
    """Create a minimal ISO 9660 image using pure Python.

    Supports only a flat directory with small files.  Good enough for
    cloud-init NoCloud seeds (user-data + meta-data).
    """
    SECTOR = 2048

    def _pad(data: bytes, size: int) -> bytes:
        return data + b"\x00" * (size - len(data))

    def _both_endian_16(v: int) -> bytes:
        return struct.pack("<H", v) + struct.pack(">H", v)

    def _both_endian_32(v: int) -> bytes:
        return struct.pack("<I", v) + struct.pack(">I", v)

    def _strA(s: str, length: int) -> bytes:
        return s.upper().encode("ascii").ljust(length, b" ")

    def _strD(s: str, length: int) -> bytes:
        return s.upper().encode("ascii").ljust(length, b" ")

    def _dir_record(name: bytes, loc: int, size: int, flags: int = 0) -> bytes:
        """Build a single ISO 9660 directory record."""
        name_len = len(name)
        rec_len = 33 + name_len + (1 if name_len % 2 == 0 else 0)  # pad to even
        rec = struct.pack("B", rec_len)             # length of record
        rec += struct.pack("B", 0)                  # extended attr length
        rec += _both_endian_32(loc)                  # location of extent
        rec += _both_endian_32(size)                 # data length
        rec += bytes([0] * 7)                        # recording date (zeros = ok)
        rec += struct.pack("B", flags)               # file flags (2=directory)
        rec += struct.pack("B", 0)                   # file unit size
        rec += struct.pack("B", 0)                   # interleave gap
        rec += _both_endian_16(1)                    # volume sequence number
        rec += struct.pack("B", name_len)            # length of file identifier
        rec += name                                  # file identifier
        if name_len % 2 == 0:
            rec += b"\x00"                           # padding to even
        return rec

    # Layout:
    #   0-15:   system area (zeros)
    #   16:     Primary Volume Descriptor
    #   17:     Volume Descriptor Set Terminator
    #   18:     Little-endian path table
    #   19:     Big-endian path table
    #   20:     Root directory
    #   21+:    File data (each file starts at a new sector)

    file_list = sorted(files.items())  # deterministic order
    root_dir_sector = 20
    data_start = 21

    # Pre-calculate file sectors
    file_sectors: list[tuple[str, bytes, int, int]] = []
    cur_sector = data_start
    for fname, fdata in file_list:
        n_sectors = (len(fdata) + SECTOR - 1) // SECTOR
        if n_sectors == 0:
            n_sectors = 1
        file_sectors.append((fname, fdata, cur_sector, n_sectors))
        cur_sector += n_sectors

    total_sectors = cur_sector

    # Build root directory
    root_dir = b""
    root_dir += _dir_record(b"\x00", root_dir_sector, SECTOR, flags=2)  # . (self)
    root_dir += _dir_record(b"\x01", root_dir_sector, SECTOR, flags=2)  # .. (parent)
    for fname, fdata, sector, _ in file_sectors:
        # ISO 9660: uppercase name + ;1 version suffix.
        # Keep hyphens as-is (technically non-standard but Linux handles it).
        iso_name = fname.upper() + ";1"
        root_dir += _dir_record(iso_name.encode("ascii"), sector, len(fdata))
    root_dir = _pad(root_dir, SECTOR)

    # Path table (just root directory)
    path_table_le = struct.pack("<BBIH", 1, 0, root_dir_sector, 1) + b"\x00\x00"
    path_table_be = struct.pack(">BBIH", 1, 0, root_dir_sector, 1) + b"\x00\x00"

    # Primary Volume Descriptor
    pvd = b"\x01"                                   # type: primary
    pvd += b"CD001"                                  # standard identifier
    pvd += b"\x01"                                   # version
    pvd += b"\x00"                                   # unused
    pvd += _strA("", 32)                             # system identifier
    pvd += _strD(volume_id, 32)                      # volume identifier
    pvd += b"\x00" * 8                               # unused
    pvd += _both_endian_32(total_sectors)             # volume space size
    pvd += b"\x00" * 32                              # unused
    pvd += _both_endian_16(1)                        # volume set size
    pvd += _both_endian_16(1)                        # volume sequence number
    pvd += _both_endian_16(SECTOR)                   # logical block size
    pvd += _both_endian_32(len(path_table_le))       # path table size
    pvd += struct.pack("<I", 18)                     # L path table location
    pvd += struct.pack("<I", 0)                      # optional L path table
    pvd += struct.pack(">I", 19)                     # M path table location
    pvd += struct.pack(">I", 0)                      # optional M path table
    pvd += _dir_record(b"\x00", root_dir_sector, SECTOR, flags=2)  # root dir record (34 bytes)
    pvd += _strD(volume_id, 128)                     # volume set identifier
    pvd += _strA("", 128)                            # publisher identifier
    pvd += _strA("", 128)                            # data preparer
    pvd += _strA("", 128)                            # application identifier
    pvd += _strA("", 37)                             # copyright file
    pvd += _strA("", 37)                             # abstract file
    pvd += _strA("", 37)                             # bibliographic file
    pvd += _strA("", 17)                             # volume creation date
    pvd += _strA("", 17)                             # volume modification date
    pvd += _strA("", 17)                             # volume expiration date
    pvd += _strA("", 17)                             # volume effective date
    pvd += b"\x01"                                   # file structure version
    pvd += b"\x00"                                   # reserved
    pvd = _pad(pvd, SECTOR)

    # Volume Descriptor Set Terminator
    vdst = b"\xff" + b"CD001" + b"\x01"
    vdst = _pad(vdst, SECTOR)

    # Write ISO
    with open(output, "wb") as f:
        # System area (16 sectors of zeros)
        f.write(b"\x00" * 16 * SECTOR)
        # PVD
        f.write(pvd)
        # VDST
        f.write(vdst)
        # Path tables
        f.write(_pad(path_table_le, SECTOR))
        f.write(_pad(path_table_be, SECTOR))
        # Root directory
        f.write(root_dir)
        # File data
        for _, fdata, _, n_sectors in file_sectors:
            f.write(_pad(fdata, n_sectors * SECTOR))


def _make_seed_iso(userdata: str, metadata: str, output: Path) -> None:
    """Create a NoCloud seed ISO from user-data and meta-data.

    Tries system tools first (faster, produces standard-compliant Joliet/RR),
    falls back to a pure Python ISO 9660 creator.
    """
    with tempfile.TemporaryDirectory() as tmpdir:
        ud = Path(tmpdir) / "user-data"
        md = Path(tmpdir) / "meta-data"
        ud.write_text(userdata)
        md.write_text(metadata)

        for tool, args in [
            ("cloud-localds", ["cloud-localds", str(output), str(ud), str(md)]),
            ("genisoimage", ["genisoimage", "-output", str(output), "-volid", "cidata",
                             "-joliet", "-rock", str(ud), str(md)]),
            ("mkisofs", ["mkisofs", "-output", str(output), "-volid", "cidata",
                         "-joliet", "-rock", str(ud), str(md)]),
        ]:
            if shutil.which(tool):
                subprocess.run(args, check=True, capture_output=True)
                return

    # Pure Python fallback — no external tools needed
    print("  (using built-in ISO creator)")
    _make_seed_iso_python(
        {"user-data": userdata.encode(), "meta-data": metadata.encode()},
        "cidata",
        output,
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Build test VM for QGA integration testing",
    )
    parser.add_argument("--vm-dir", default="scripts/vm",
                        help="Output directory (default: scripts/vm)")
    parser.add_argument("--force", action="store_true",
                        help="Re-download base image even if cached")
    args = parser.parse_args()

    vm_dir = Path(args.vm_dir)
    vm_dir.mkdir(parents=True, exist_ok=True)

    base_image = vm_dir / "ubuntu-base.img"
    test_image = vm_dir / "ubuntu-test.qcow2"
    seed_iso = vm_dir / "seed.iso"

    # 1. Download cloud image
    if base_image.exists() and not args.force:
        sz = base_image.stat().st_size / 1e6
        print(f"Using cached base image: {base_image} ({sz:.0f} MB)")
    else:
        print(f"Downloading Ubuntu cloud image...")
        print(f"  {CLOUD_IMAGE_URL}")
        _download(CLOUD_IMAGE_URL, base_image)
        sz = base_image.stat().st_size / 1e6
        print(f"  Saved: {base_image} ({sz:.0f} MB)")

    # 2. Create working copy (qcow2 backed by base, 4GB virtual)
    if test_image.exists():
        # Check for existing snapshots
        info = subprocess.run(
            ["qemu-img", "snapshot", "-l", str(test_image)],
            capture_output=True, text=True,
        )
        if "ready" in info.stdout:
            print(f"Working copy with 'ready' snapshot exists: {test_image}")
            print("  (use --force to recreate)")
            if not args.force:
                # Still regenerate seed.iso in case it was deleted
                pass
            else:
                test_image.unlink()
                subprocess.run(
                    ["qemu-img", "create", "-f", "qcow2",
                     "-b", base_image.name, "-F", "qcow2",
                     str(test_image), "4G"],
                    check=True, capture_output=True,
                )
                print("  Recreated working copy (snapshots cleared)")
        else:
            print(f"Working copy exists (no snapshot): {test_image}")
    else:
        print("Creating working copy (4GB virtual)...")
        subprocess.run(
            ["qemu-img", "create", "-f", "qcow2",
             "-b", base_image.name, "-F", "qcow2",
             str(test_image), "4G"],
            check=True, capture_output=True,
        )

    # 3. Create cloud-init seed ISO
    print("Creating cloud-init seed ISO...")
    _make_seed_iso(USERDATA, METADATA, seed_iso)

    # Summary
    print(f"\nVM files in {vm_dir}/:")
    for f in [base_image, test_image, seed_iso]:
        if f.exists():
            sz = f.stat().st_size / 1e6
            print(f"  {f.name:<25s} {sz:>7.1f} MB")

    print(f"\nRun integration tests:")
    print(f"  python scripts/test_qga_integration.py --vm-dir {vm_dir}")


if __name__ == "__main__":
    main()
