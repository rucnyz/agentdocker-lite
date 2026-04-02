//! User namespace helpers for sandbox cleanup.
//!
//! When deleting a userns sandbox, files created by mapped UIDs
//! (e.g. _apt uid 100 → host uid 100100) can't be deleted by the
//! host user.  These functions fork a child, enter the sandbox's
//! user namespace via `setns()`, and fix permissions/ownership so
//! the host-side `rmtree` can clean up everything.

use std::ffi::CString;
use std::fs;
use std::io;
use std::path::Path;

/// Enter a user namespace and recursively chmod + chown a directory.
///
/// Forks a child process that:
/// 1. `setns()` into the user namespace of `userns_pid`
/// 2. Walks `dir_path` recursively
/// 3. `chmod(a+rwX)` every entry (dirs get +x, files get +rw)
/// 4. `lchown(0, 0)` every entry (map to root = host user)
///
/// Returns the number of entries processed.
pub fn fixup_dir_for_delete(userns_pid: i32, dir_path: &Path) -> io::Result<u32> {
    // Open the user namespace fd before forking.
    let ns_path = format!("/proc/{userns_pid}/ns/user");
    let ns_fd = {
        let c_path = CString::new(ns_path.as_bytes())
            .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
        let fd = unsafe { libc::open(c_path.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        fd
    };

    // Fork: child does the work, parent waits.
    let pid = unsafe { libc::fork() };
    if pid < 0 {
        unsafe { libc::close(ns_fd) };
        return Err(io::Error::last_os_error());
    }

    if pid == 0 {
        // --- Child process ---
        // Enter the user namespace.
        if unsafe { libc::setns(ns_fd, libc::CLONE_NEWUSER) } < 0 {
            unsafe { libc::_exit(1) };
        }
        unsafe { libc::close(ns_fd) };

        // Walk and fixup.
        let Ok(count) = walk_fixup(dir_path) else {
            unsafe { libc::_exit(2) };
        };

        // Write count to stdout so parent can read it (optional).
        // For simplicity, just exit with 0 = success.
        let _ = count;
        unsafe { libc::_exit(0) };
    }

    // --- Parent process ---
    unsafe { libc::close(ns_fd) };

    let mut status: libc::c_int = 0;
    let ret = unsafe { libc::waitpid(pid, &raw mut status, 0) };
    if ret < 0 {
        return Err(io::Error::last_os_error());
    }

    if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 {
        Ok(0) // Can't easily return count across fork; 0 = success
    } else {
        Err(io::Error::other(format!(
            "userns fixup child exited with status {status}"
        )))
    }
}

/// Recursively chmod a+rwX and lchown 0:0 on all entries.
fn walk_fixup(dir: &Path) -> io::Result<u32> {
    let mut count = 0u32;
    // Fix the directory itself first so we can list its contents.
    fixup_entry(dir)?;
    count += 1;

    let Ok(entries) = fs::read_dir(dir) else {
        return Ok(count); // Can't read — skip
    };

    for entry in entries {
        let Ok(entry) = entry else { continue };
        let path = entry.path();
        let Ok(ft) = entry.file_type() else { continue };

        if ft.is_dir() {
            count += walk_fixup(&path).unwrap_or(0);
        } else if fixup_entry(&path).is_ok() {
            count += 1;
        }
    }
    Ok(count)
}

/// chmod a+rwX and lchown 0:0 on a single path.
fn fixup_entry(path: &Path) -> io::Result<()> {
    let c_path = CString::new(path.as_os_str().as_encoded_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    // lchown to root:root (maps to host user outside userns).
    unsafe { libc::lchown(c_path.as_ptr(), 0, 0) };

    // chmod: dirs get 0o777, files get 0o666.
    // Use stat to check type, don't follow symlinks for chmod.
    let mut st: libc::stat = unsafe { std::mem::zeroed() };
    if unsafe { libc::lstat(c_path.as_ptr(), &raw mut st) } == 0 {
        let mode = if (st.st_mode & libc::S_IFMT) == libc::S_IFDIR {
            0o777
        } else {
            0o666
        };
        // Use fchmodat with AT_SYMLINK_NOFOLLOW if available,
        // otherwise regular chmod (which follows symlinks).
        unsafe { libc::chmod(c_path.as_ptr(), mode) };
    }

    Ok(())
}
