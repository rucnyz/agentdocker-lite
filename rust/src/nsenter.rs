//! Namespace enter helpers for rootful sandbox `popen()`.
//!
//! Replaces the `nsenter` subprocess with direct `setns()` + `chroot()`
//! syscalls, called from a Python `preexec_fn`.
//!
//! Note: PID namespace is **not** entered because `setns(CLONE_NEWPID)`
//! only affects future children, not the calling process or its exec.
//! This matches the userns `preexec_fn` behavior.

use std::ffi::CString;
use std::io;

/// Enter the mount namespace of `target_pid`, chroot to its root,
/// and chdir to "/".
///
/// Intended to be called from a `preexec_fn` (after fork, before exec).
/// The calling process must have `CAP_SYS_ADMIN` (i.e. running as root).
///
/// Like real `nsenter`, we open `/proc/{pid}/root` as an fd **before**
/// entering the mount namespace, then `fchdir` + `chroot(".")` after.
/// This avoids the problem of /proc becoming inaccessible after setns.
pub fn nsenter_preexec(target_pid: i32) -> io::Result<()> {
    // 1. Open the target's root fd BEFORE entering mount namespace.
    //    After setns, the host's /proc may not be visible.
    let root_path = format!("/proc/{target_pid}/root");
    let c_root = CString::new(root_path.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let root_fd = unsafe { libc::open(c_root.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if root_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    // 2. Open mount namespace fd.
    let mnt_ns = format!("/proc/{target_pid}/ns/mnt");
    let c_mnt = CString::new(mnt_ns.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mnt_fd = unsafe { libc::open(c_mnt.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if mnt_fd < 0 {
        unsafe { libc::close(root_fd) };
        return Err(io::Error::last_os_error());
    }

    // 3. Enter mount namespace.
    let rc = unsafe { libc::setns(mnt_fd, libc::CLONE_NEWNS) };
    unsafe { libc::close(mnt_fd) };
    if rc < 0 {
        unsafe { libc::close(root_fd) };
        return Err(io::Error::last_os_error());
    }

    // 4. fchdir to the pre-opened root fd, then chroot(".").
    if unsafe { libc::fchdir(root_fd) } < 0 {
        unsafe { libc::close(root_fd) };
        return Err(io::Error::last_os_error());
    }
    unsafe { libc::close(root_fd) };

    let c_dot = CString::new(".").unwrap();
    if unsafe { libc::chroot(c_dot.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // 5. chdir to /.
    let c_slash = CString::new("/").unwrap();
    if unsafe { libc::chdir(c_slash.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}

/// Enter user + mount namespace of `target_pid`, chroot to `rootfs`,
/// and chdir to `working_dir`.
///
/// Used by userns `popen()`.  The difference from [`nsenter_preexec`] is
/// that we also join the user namespace (needed for rootless sandboxes)
/// and chroot to an explicit rootfs path instead of /proc/{pid}/root.
///
/// For userns sandboxes, the rootfs path is on the host filesystem
/// (not inside the target's mount namespace), so we open namespace fds
/// first, then enter both namespaces, then chroot to the host-side path.
pub fn userns_preexec(target_pid: i32, rootfs: &str, working_dir: &str) -> io::Result<()> {
    // 1. Open namespace fds BEFORE entering any namespace.
    let user_ns = format!("/proc/{target_pid}/ns/user");
    let c_user = CString::new(user_ns.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let user_fd = unsafe { libc::open(c_user.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if user_fd < 0 {
        return Err(io::Error::last_os_error());
    }

    let mnt_ns = format!("/proc/{target_pid}/ns/mnt");
    let c_mnt = CString::new(mnt_ns.as_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    let mnt_fd = unsafe { libc::open(c_mnt.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC) };
    if mnt_fd < 0 {
        unsafe { libc::close(user_fd) };
        return Err(io::Error::last_os_error());
    }

    // 2. Enter user namespace.
    let rc = unsafe { libc::setns(user_fd, libc::CLONE_NEWUSER) };
    unsafe { libc::close(user_fd) };
    if rc < 0 {
        unsafe { libc::close(mnt_fd) };
        return Err(io::Error::last_os_error());
    }

    // 3. Enter mount namespace.
    let rc = unsafe { libc::setns(mnt_fd, libc::CLONE_NEWNS) };
    unsafe { libc::close(mnt_fd) };
    if rc < 0 {
        return Err(io::Error::last_os_error());
    }

    // 4. chroot to the rootfs.
    let c_root =
        CString::new(rootfs).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if unsafe { libc::chroot(c_root.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }

    // 5. chdir to working_dir.
    let c_wd =
        CString::new(working_dir).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;
    if unsafe { libc::chdir(c_wd.as_ptr()) } < 0 {
        return Err(io::Error::last_os_error());
    }

    Ok(())
}
