//! pidfd wrappers — race-free process management via file descriptors.
//!
//! `pidfd_open` via rustix (type-safe `OwnedFd`), `send_signal` via libc (signal 0 support),
//! `process_madvise` via libc (no crate wraps it).

use std::io;
use std::os::fd::{AsRawFd, RawFd};

/// Create a pidfd for the given PID. Returns the raw fd or an error.
pub fn pidfd_open(pid: i32) -> io::Result<RawFd> {
    let pid = rustix::process::Pid::from_raw(pid)
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid pid"))?;
    let owned = rustix::process::pidfd_open(pid, rustix::process::PidfdFlags::empty())?;
    let raw = owned.as_raw_fd();
    std::mem::forget(owned); // Python manages the fd lifetime
    Ok(raw)
}

/// Send a signal to the process identified by pidfd.
/// Uses libc because `rustix::Signal` doesn't support signal 0 (check alive).
pub fn pidfd_send_signal(pidfd: RawFd, sig: i32) -> io::Result<()> {
    let ret = unsafe {
        libc::syscall(
            libc::SYS_pidfd_send_signal,
            pidfd,
            sig,
            std::ptr::null::<libc::c_void>(),
            0,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

/// Check if the process behind the pidfd is still alive (signal 0).
#[must_use]
pub fn pidfd_is_alive(pidfd: RawFd) -> bool {
    pidfd_send_signal(pidfd, 0).is_ok()
}

/// Hint kernel to mark process memory as cold (`MADV_COLD`) via `process_madvise`.
/// No crate wraps this syscall.
pub fn process_madvise_cold(pidfd: RawFd) -> io::Result<()> {
    let iov = libc::iovec {
        iov_base: std::ptr::null_mut(),
        iov_len: 0,
    };
    let ret = unsafe {
        libc::syscall(
            libc::SYS_process_madvise,
            pidfd,
            &raw const iov,
            1 as libc::c_ulong,
            libc::MADV_COLD,
            0 as libc::c_uint,
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
