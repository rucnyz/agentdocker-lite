//! UID-preserving layer extraction with inline whiteout conversion.
//!
//! Faithfully ports Podman's rootless extraction pipeline:
//!
//!   `Unpack()` (archive.go:1089)
//!     → `remapIDs()` (archive.go:1441)        — kernel does this via userns
//!     → `ConvertRead()` (`archive_linux.go:115`) — whiteout handling
//!     → `extractTarFileEntry()` (archive.go:705)
//!         create → lchown → chmod → chtimes → xattrs
//!
//! The `tar` crate is used only for **parsing** (reading headers + content).
//! File creation, ownership, permissions, and timestamps are all set
//! manually in the same order as Podman's `extractTarFileEntry`.

use std::ffi::CString;
use std::io;
use std::os::fd::IntoRawFd;
use std::os::unix::fs::{OpenOptionsExt, symlink};
use std::path::{Path, PathBuf};

// Kernel overflow UID/GID — used when a tar entry's UID/GID falls outside
// the user namespace idmap.  Matches /proc/sys/kernel/overflowuid (65534)
// and Podman's ToHostOverflow() fallback (containers/storage PR #1220).
const OVERFLOW_ID: u32 = 65534;

// ======================================================================
// Public API
// ======================================================================

/// Extract a tar into `dest` inside a fresh user namespace, converting
/// OCI whiteouts to overlayfs format in the same pass.
pub fn extract_tar_in_userns(
    tar_path: &str,
    dest: &str,
    outer_uid: u32,
    outer_gid: u32,
    sub_start: u32,
    sub_count: u32,
) -> io::Result<()> {
    let (userns_r, userns_w) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(io::Error::from)?;
    let (go_r, go_w) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(io::Error::from)?;

    let userns_r = userns_r.into_raw_fd();
    let userns_w = userns_w.into_raw_fd();
    let go_r = go_r.into_raw_fd();
    let go_w = go_w.into_raw_fd();

    let tar_data = std::fs::read(tar_path)?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }

    if pid == 0 {
        // ---- Child ----
        unsafe { libc::close(userns_r) };
        unsafe { libc::close(go_w) };

        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } < 0 {
            unsafe { libc::_exit(1) };
        }

        let _ = nix::unistd::write(
            unsafe { std::os::fd::BorrowedFd::borrow_raw(userns_w) },
            b"R",
        );
        unsafe { libc::close(userns_w) };

        let mut buf = [0u8; 1];
        let _ = nix::unistd::read(
            unsafe { std::os::fd::BorrowedFd::borrow_raw(go_r) },
            &mut buf,
        );
        unsafe { libc::close(go_r) };

        // sub_count + 1 = highest usable UID inside the namespace
        // (0 is mapped to outer_uid, 1..sub_count mapped to sub_start..)
        let max_id = sub_count;
        let code = match do_extract(&tar_data, dest, max_id) {
            Ok(()) => 0,
            Err(e) => {
                eprintln!("nitrobox: layer extraction failed: {e}");
                2
            }
        };
        unsafe { libc::_exit(code) };
    }

    // ---- Parent ----
    unsafe { libc::close(userns_w) };
    unsafe { libc::close(go_r) };

    let mut buf = [0u8; 1];
    let _ = nix::unistd::read(
        unsafe { std::os::fd::BorrowedFd::borrow_raw(userns_r) },
        &mut buf,
    );
    unsafe { libc::close(userns_r) };

    let mapping_result = setup_id_mapping(pid, outer_uid, outer_gid, sub_start, sub_count);

    let _ = nix::unistd::write(unsafe { std::os::fd::BorrowedFd::borrow_raw(go_w) }, b"G");
    unsafe { libc::close(go_w) };

    if let Err(e) = mapping_result {
        unsafe { libc::kill(pid, libc::SIGKILL) };
        let mut status: libc::c_int = 0;
        unsafe { libc::waitpid(pid, &raw mut status, 0) };
        return Err(e);
    }

    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    if libc::WIFEXITED(status) {
        let code = libc::WEXITSTATUS(status);
        if code == 0 {
            Ok(())
        } else {
            Err(io::Error::other(format!(
                "layer extraction in userns failed (exit code {code})"
            )))
        }
    } else {
        Err(io::Error::other(format!(
            "layer extraction in userns terminated by signal (status {status})"
        )))
    }
}

// ======================================================================
// Child-side: Unpack() port  (archive.go:1089-1240)
// ======================================================================

fn do_extract(tar_data: &[u8], dest: &str, max_id: u32) -> io::Result<()> {
    let cursor = io::Cursor::new(tar_data);
    let gz = flate2::read::GzDecoder::new(cursor);
    let is_gz = gz.header().is_some();

    if is_gz {
        let gz = flate2::read::GzDecoder::new(io::Cursor::new(tar_data));
        unpack(gz, dest, max_id)
    } else {
        unpack(io::Cursor::new(tar_data), dest, max_id)
    }
}

/// Port of Podman `archive.Unpack()` (archive.go:1089-1240).
///
/// Key differences from the old `extract_archive` that used `entry.unpack_in()`:
///   - Manual file creation (not delegated to tar crate)
///   - Explicit lchown → chmod → chtimes ordering (Podman lines 794-837)
///   - Hardlink/symlink breakout validation (Podman lines 762-784)
///   - Parent directory creation with chown (Podman lines 1133-1143)
///   - Directory mtime deferred to end (Podman lines 1211-1224)
///   - Existing file removal before overwrite (Podman lines 1157-1183)
fn unpack<R: io::Read>(reader: R, dest: &str, max_id: u32) -> io::Result<()> {
    let dest = Path::new(dest);
    let mut archive = tar::Archive::new(reader);

    // Podman: deferred directory mtime/atime (archive.go:1094, 1211-1224)
    let mut dir_headers: Vec<(PathBuf, i64, i64)> = Vec::new();

    for entry_result in archive.entries()? {
        let mut entry = entry_result?;
        let raw_path = entry.path()?.into_owned();

        // -- Path normalization (Podman: archive.go:1122) --
        // Go's filepath.Clean normalizes "a/../b" → "b".
        let cleaned = normalize_path(&raw_path);

        // -- Breakout check (Podman: archive.go:1145-1155) --
        // Podman: path := filepath.Join(dest, hdr.Name)
        //         rel, _ := filepath.Rel(dest, path)
        //         if strings.HasPrefix(rel, "../") { return breakoutError }
        //
        // We replicate this by joining the RAW path to dest (preserving
        // ".." components), then normalizing the ABSOLUTE result.
        // This correctly resolves "foo/../../escape" → parent/escape
        // which falls outside dest.  Our normalize_path on relative
        // paths eats leading ".." (unlike Go's filepath.Clean), so we
        // MUST normalize the absolute joined path instead.
        let resolved = normalize_path(&dest.join(&raw_path));
        if !resolved.starts_with(dest) {
            return Err(io::Error::other(format!(
                "path breakout: {} is outside {}",
                raw_path.display(),
                dest.display()
            )));
        }

        // Actual extraction path uses the cleaned relative path
        let full_path = dest.join(&cleaned);

        // -- Parent directory creation (Podman: archive.go:1133-1143) --
        if let Some(parent_rel) = cleaned.parent() {
            let parent_abs = dest.join(parent_rel);
            if !parent_abs.exists() {
                std::fs::create_dir_all(&parent_abs)?;
                // Podman: MkdirAllAndChownNew(parentPath, 0o777, rootIDs)
                lchown(&parent_abs, 0, 0)?;
            }
        }

        let entry_type = entry.header().entry_type();
        let raw_uid: u32 = entry.header().uid()?.try_into().unwrap_or(0);
        let raw_gid: u32 = entry.header().gid()?.try_into().unwrap_or(0);
        // Podman: ToHostOverflow() falls back to the kernel overflow ID
        // (65534 = nobody) for UIDs outside the userns idmap.  Without
        // this, lchown returns EINVAL for unmapped UIDs (e.g. UID 197609
        // from Windows-built tarballs in SWE-bench images).
        // Ref: containers/storage pkg/idtools/idtools.go, PR #1220.
        let uid = if raw_uid > max_id {
            OVERFLOW_ID
        } else {
            raw_uid
        };
        let gid = if raw_gid > max_id {
            OVERFLOW_ID
        } else {
            raw_gid
        };
        let mode = entry.header().mode()?;
        let mtime = entry.header().mtime()? as i64;

        let file_name = cleaned.file_name().and_then(|n| n.to_str()).unwrap_or("");

        // -- Skip device nodes (Podman: extractTarFileEntry line 750-754) --
        if entry_type == tar::EntryType::Block || entry_type == tar::EntryType::Char {
            continue;
        }

        // -- Whiteout handling (Podman: ConvertRead, archive_linux.go:115-153) --
        if let Some(original_name) = file_name.strip_prefix(".wh.") {
            let parent = full_path.parent().unwrap_or(dest);

            if file_name == ".wh..wh..opq" {
                // Podman: handler.Setxattr(dir, "user.overlay.opaque", "y")
                set_xattr(parent, "user.overlay.opaque", b"y")?;
            } else {
                // strip ".wh."
                let original_path = parent.join(original_name);

                // Podman: handler.Mknod(originalPath, S_IFCHR, 0)
                if try_mknod_whiteout(&original_path) {
                    // Podman: handler.Chown(originalPath, hdr.Uid, hdr.Gid)
                    lchown(&original_path, uid, gid)?;
                } else {
                    let errno = io::Error::last_os_error().raw_os_error().unwrap_or(0);
                    // Podman: if isENOTDIR(err) { return false, nil }
                    if errno == libc::ENOTDIR {
                        continue;
                    }
                    // Fallback: xattr whiteout (kernel >= 6.7)
                    set_xattr(&original_path, "user.overlay.whiteout", b"y")?;
                }
            }
            continue; // Don't extract the .wh.* marker file
        }

        // -- Remove existing file before overwrite (Podman: archive.go:1157-1183) --
        if let Ok(meta) = std::fs::symlink_metadata(&full_path) {
            // Podman: if fi.IsDir() && hdr.Name == "." { continue }
            if meta.is_dir() && cleaned.as_os_str() == "." {
                continue;
            }
            // Podman: directory + directory → merge (don't remove)
            if !(meta.is_dir() && entry_type == tar::EntryType::Directory) {
                std::fs::remove_file(&full_path)
                    .or_else(|_| std::fs::remove_dir_all(&full_path))?;
            }
        }

        // =============================================================
        // extractTarFileEntry port  (archive.go:705-891)
        //   Step 1: create file/dir/symlink/hardlink/fifo
        //   Step 2: lchown  (line 794-807)
        //   Step 3: chmod   (line 809-813) — skip symlinks
        //   Step 4: chtimes (line 815-837) — different for symlinks
        //   Step 5: xattrs  (line 839-861)
        // =============================================================

        // -- Step 1: Create --
        match entry_type {
            tar::EntryType::Directory => {
                // Podman: if fi, err := os.Lstat(path); err != nil || !fi.IsDir()
                // Use symlink_metadata (Lstat) — do NOT follow symlinks.
                // A symlink named like the dir must not be silently skipped.
                match std::fs::symlink_metadata(&full_path) {
                    Ok(meta) if meta.is_dir() => {} // already a real dir, merge
                    _ => {
                        std::fs::create_dir(&full_path)?;
                    }
                }
            }

            tar::EntryType::Regular | tar::EntryType::Continuous => {
                // Podman: os.OpenFile(path, O_CREATE|O_WRONLY, mask)
                let mut file = std::fs::OpenOptions::new()
                    .create(true)
                    .write(true)
                    .truncate(true)
                    .mode(mode)
                    .open(&full_path)?;
                io::copy(&mut entry, &mut file)?;
            }

            tar::EntryType::Symlink => {
                // Podman: archive.go:772-784
                let link_target = entry
                    .link_name()?
                    .ok_or_else(|| io::Error::other("symlink without target"))?
                    .into_owned();

                // Podman: breakout check
                // targetPath := filepath.Join(filepath.Dir(path), hdr.Linkname)
                // if !strings.HasPrefix(targetPath, extractDir) { return breakoutError }
                let resolved = full_path.parent().unwrap_or(dest).join(&link_target);
                let resolved = normalize_path(&resolved);
                // Only check relative symlinks for breakout.
                // Absolute symlinks resolve inside the sandbox chroot at runtime,
                // so they're safe in layer cache context.
                if !link_target.is_absolute() && !resolved.starts_with(dest) {
                    return Err(io::Error::other(format!(
                        "symlink breakout: {} -> {}",
                        full_path.display(),
                        link_target.display()
                    )));
                }

                symlink(&link_target, &full_path)?;
            }

            tar::EntryType::Link => {
                // Podman: archive.go:762-770
                let link_target = entry
                    .link_name()?
                    .ok_or_else(|| io::Error::other("hardlink without target"))?
                    .into_owned();

                // Podman: breakout check
                // targetPath := filepath.Join(extractDir, hdr.Linkname)
                // if !strings.HasPrefix(targetPath, extractDir) { return breakoutError }
                let target_abs = dest.join(&link_target);
                if !target_abs.starts_with(dest) {
                    return Err(io::Error::other(format!(
                        "hardlink breakout: {} -> {}",
                        full_path.display(),
                        link_target.display()
                    )));
                }
                // Podman: handleLLink uses linkat(AT_FDCWD, target, AT_FDCWD, path, 0)
                // (non-following, same as std::fs::hard_link on Linux)
                std::fs::hard_link(&target_abs, &full_path)?;
            }

            tar::EntryType::Fifo => {
                // Podman: handleTarTypeBlockCharFifo — mknod with S_IFIFO
                let c_path = CString::new(full_path.as_os_str().as_encoded_bytes())
                    .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
                let ret =
                    unsafe { libc::mknod(c_path.as_ptr(), libc::S_IFIFO | (mode & 0o7777), 0) };
                if ret < 0 {
                    return Err(io::Error::last_os_error());
                }
            }

            tar::EntryType::XGlobalHeader | tar::EntryType::XHeader => {
                // Podman: "PAX Global Extended Headers found and ignored"
                continue;
            }

            other => {
                log::debug!("Skipping unsupported tar entry type: {other:?}");
                continue;
            }
        }

        // -- Step 2: lchown (Podman: archive.go:794-807) --
        lchown(&full_path, uid, gid)?;

        // -- Step 3: chmod (Podman: handleLChmod, archive_linux.go:191-206) --
        // "There is no LChmod, so ignore mode for symlink.
        //  Also, this must happen after chown, as that can modify the file mode"
        if entry_type == tar::EntryType::Link {
            // Podman: only chmod hardlink if target is not a symlink
            if let Ok(meta) = std::fs::symlink_metadata(&full_path) {
                if !meta.file_type().is_symlink() {
                    chmod(&full_path, mode)?;
                }
            }
        } else if entry_type != tar::EntryType::Symlink {
            chmod(&full_path, mode)?;
        }
        // symlinks: skip chmod (no lchmod on Linux)

        // -- Step 4: chtimes (Podman: archive.go:815-837) --
        // Use mtime for both atime and mtime (Podman: "aTime should never be before mTime")
        if entry_type == tar::EntryType::Symlink {
            // Podman: LUtimesNano for symlinks (non-following)
            lutimes(&full_path, mtime)?;
        } else if entry_type == tar::EntryType::Link {
            // Podman: only set times if target is not a symlink
            if let Ok(meta) = std::fs::symlink_metadata(&full_path) {
                if !meta.file_type().is_symlink() {
                    utimes(&full_path, mtime)?;
                }
            }
        } else if entry_type == tar::EntryType::Directory {
            // Podman: defer directory mtime to end of loop
            dir_headers.push((full_path.clone(), mtime, mtime));
        } else {
            utimes(&full_path, mtime)?;
        }

        // -- Step 5: xattrs from PAX records (Podman: archive.go:839-861) --
        // Apply xattrs stored in PAX headers (e.g. security.capability).
        // The tar crate provides pax_extensions() which returns PAX records
        // from the preceding PAX header.
        if let Ok(Some(pax)) = entry.pax_extensions() {
            for ext in pax.flatten() {
                if let Ok(key) = ext.key() {
                    if let Some(xattr_key) = key.strip_prefix("SCHILY.xattr.") {
                        // Podman: system.Lsetxattr(path, xattrKey, []byte(value), 0)
                        // Ignore ENOTSUP/EPERM (same as set_xattr helper)
                        let _ = lsetxattr(&full_path, xattr_key, ext.value_bytes());
                    }
                }
            }
        }
    }

    // -- Deferred directory mtime (Podman: archive.go:1216-1224) --
    for (dir_path, _atime, mtime) in &dir_headers {
        utimes(dir_path, *mtime)?;
    }

    Ok(())
}

// ======================================================================
// Path normalization (equivalent to Go's filepath.Clean)
// ======================================================================

fn normalize_path(path: &Path) -> PathBuf {
    let mut result = PathBuf::new();
    for component in path.components() {
        match component {
            std::path::Component::ParentDir => {
                result.pop();
            }
            std::path::Component::CurDir => {} // skip "."
            _ => result.push(component),
        }
    }
    if result.as_os_str().is_empty() {
        result.push(".");
    }
    result
}

// ======================================================================
// Syscall helpers (matching Podman's SafeLchown, handleLChmod, Chtimes)
// ======================================================================

fn try_mknod_whiteout(path: &Path) -> bool {
    let Ok(c_path) = CString::new(path.as_os_str().as_encoded_bytes()) else {
        return false;
    };
    unsafe { libc::mknod(c_path.as_ptr(), libc::S_IFCHR, 0) == 0 }
}

/// `lchown(path, uid, gid)` — Podman: `idtools.SafeLchown`
fn lchown(path: &Path, uid: u32, gid: u32) -> io::Result<()> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if unsafe { libc::lchown(c.as_ptr(), uid, gid) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `chmod(path, mode)` — Podman: `os.Chmod(path, permissionsMask)`
fn chmod(path: &Path, mode: u32) -> io::Result<()> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if unsafe { libc::chmod(c.as_ptr(), mode) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `utimensat(path, mtime)` — following version for regular files
fn utimes(path: &Path, mtime: i64) -> io::Result<()> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let times = [
        libc::timespec {
            tv_sec: mtime,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: mtime,
            tv_nsec: 0,
        },
    ];
    if unsafe { libc::utimensat(libc::AT_FDCWD, c.as_ptr(), times.as_ptr(), 0) } < 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// `utimensat(path, mtime, AT_SYMLINK_NOFOLLOW)` — Podman: `LUtimesNano`
fn lutimes(path: &Path, mtime: i64) -> io::Result<()> {
    let c = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let times = [
        libc::timespec {
            tv_sec: mtime,
            tv_nsec: 0,
        },
        libc::timespec {
            tv_sec: mtime,
            tv_nsec: 0,
        },
    ];
    if unsafe {
        libc::utimensat(
            libc::AT_FDCWD,
            c.as_ptr(),
            times.as_ptr(),
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } < 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Set xattr — Podman: `system.Lsetxattr`. Ignores ENOTSUP/EPERM.
fn set_xattr(path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let c_name = CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let ret = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if ret == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    let errno = err.raw_os_error().unwrap_or(0);
    // Podman: ignore ENOTSUP and EPERM in userns (archive.go:849-853)
    if errno == libc::ENOTSUP || errno == libc::EPERM || errno == libc::EOPNOTSUPP {
        return Ok(());
    }
    Err(err)
}

/// `lsetxattr(path, name, value)` — non-following version for PAX xattrs.
/// Podman: `system.Lsetxattr(path, key, value, 0)`.
/// Ignores ENOTSUP/EPERM/EOPNOTSUPP (same policy as Podman archive.go:849-853).
fn lsetxattr(path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let c_name = CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let ret = unsafe {
        libc::lsetxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            value.as_ptr().cast(),
            value.len(),
            0,
        )
    };
    if ret == 0 {
        return Ok(());
    }
    let err = io::Error::last_os_error();
    let errno = err.raw_os_error().unwrap_or(0);
    if errno == libc::ENOTSUP || errno == libc::EPERM || errno == libc::EOPNOTSUPP {
        return Ok(());
    }
    Err(err)
}

// ======================================================================
// Cleanup helper
// ======================================================================

/// Remove a directory tree containing files with mapped UIDs.
pub fn rmtree_in_userns(
    path: &str,
    outer_uid: u32,
    outer_gid: u32,
    sub_start: u32,
    sub_count: u32,
) -> io::Result<()> {
    let (userns_r, userns_w) =
        nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(io::Error::from)?;
    let (go_r, go_w) = nix::unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(io::Error::from)?;

    let userns_r = userns_r.into_raw_fd();
    let userns_w = userns_w.into_raw_fd();
    let go_r = go_r.into_raw_fd();
    let go_w = go_w.into_raw_fd();

    let c_rm = CString::new("rm").unwrap();
    let c_rf = CString::new("-rf").unwrap();
    let c_path = CString::new(path).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let pid = unsafe { libc::fork() };
    if pid < 0 {
        return Err(io::Error::last_os_error());
    }

    if pid == 0 {
        unsafe { libc::close(userns_r) };
        unsafe { libc::close(go_w) };
        if unsafe { libc::unshare(libc::CLONE_NEWUSER) } < 0 {
            unsafe { libc::_exit(1) };
        }
        let _ = nix::unistd::write(
            unsafe { std::os::fd::BorrowedFd::borrow_raw(userns_w) },
            b"R",
        );
        unsafe { libc::close(userns_w) };
        let mut buf = [0u8; 1];
        let _ = nix::unistd::read(
            unsafe { std::os::fd::BorrowedFd::borrow_raw(go_r) },
            &mut buf,
        );
        unsafe { libc::close(go_r) };

        let args: [*mut libc::c_char; 4] = [
            c_rm.as_ptr().cast_mut(),
            c_rf.as_ptr().cast_mut(),
            c_path.as_ptr().cast_mut(),
            std::ptr::null_mut(),
        ];
        unsafe { libc::execvp(c_rm.as_ptr(), args.as_ptr()) };
        unsafe { libc::_exit(127) };
    }

    unsafe { libc::close(userns_w) };
    unsafe { libc::close(go_r) };
    let mut buf = [0u8; 1];
    let _ = nix::unistd::read(
        unsafe { std::os::fd::BorrowedFd::borrow_raw(userns_r) },
        &mut buf,
    );
    unsafe { libc::close(userns_r) };
    let _ = setup_id_mapping(pid, outer_uid, outer_gid, sub_start, sub_count);
    let _ = nix::unistd::write(unsafe { std::os::fd::BorrowedFd::borrow_raw(go_w) }, b"G");
    unsafe { libc::close(go_w) };

    let mut status: libc::c_int = 0;
    unsafe { libc::waitpid(pid, &raw mut status, 0) };
    Ok(())
}

// ======================================================================
// UID/GID mapping
// ======================================================================

fn setup_id_mapping(
    child_pid: i32,
    outer_uid: u32,
    outer_gid: u32,
    sub_start: u32,
    sub_count: u32,
) -> io::Result<()> {
    let pid_s = child_pid.to_string();
    let uid_s = outer_uid.to_string();
    let gid_s = outer_gid.to_string();
    let sub_s = sub_start.to_string();
    let cnt_s = sub_count.to_string();

    let uid_out = std::process::Command::new("newuidmap")
        .args([&pid_s, "0", &uid_s, "1", "1", &sub_s, &cnt_s])
        .output()?;
    if !uid_out.status.success() {
        return Err(io::Error::other(format!(
            "newuidmap failed: {}",
            String::from_utf8_lossy(&uid_out.stderr)
        )));
    }

    let gid_out = std::process::Command::new("newgidmap")
        .args([&pid_s, "0", &gid_s, "1", "1", &sub_s, &cnt_s])
        .output()?;
    if !gid_out.status.success() {
        return Err(io::Error::other(format!(
            "newgidmap failed: {}",
            String::from_utf8_lossy(&gid_out.stderr)
        )));
    }

    Ok(())
}
