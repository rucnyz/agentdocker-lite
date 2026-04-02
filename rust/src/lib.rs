//! nitrobox-core: Rust core for nitrobox.
//!
//! Provides direct syscall interfaces for Linux namespace sandboxing,
//! replacing Python ctypes/subprocess string concatenation.

// Clippy pedantic: enable all, suppress lints that don't apply to internal syscall code.
#![warn(clippy::pedantic)]
#![allow(
    clippy::missing_errors_doc,    // internal library, not public API docs
    clippy::missing_panics_doc,    // same
    clippy::cast_possible_truncation, // syscall args have known ranges
    clippy::cast_sign_loss,        // pid_t → usize in /proc walks
    clippy::cast_possible_wrap,    // u8 → i8 for BPF insns
    clippy::similar_names,         // outer_uid/outer_gid is clear
    clippy::too_many_lines,        // spawn_sandbox is complex by nature
    clippy::struct_excessive_bools, // SandboxSpawnConfig mirrors Python config
    clippy::implicit_hasher,       // PyO3 dictates HashMap type
    clippy::cast_ptr_alignment,    // BPF bytecode pointer cast is intentional
)]

pub mod cgroup;
pub mod init;
pub mod mount;
pub mod nsenter;
pub mod pidfd;
pub mod proc;
pub mod qmp;
pub mod security;
pub mod userns;
pub mod whiteout;

use pyo3::prelude::*;
use pyo3::types::{PyBytes, PyDict};
use pyo3_stub_gen::derive::{gen_stub_pyclass, gen_stub_pyfunction};
use std::collections::HashMap;

// ======================================================================
// PyO3 types
// ======================================================================

/// Result of spawning a sandbox process.
#[gen_stub_pyclass]
#[pyclass(get_all, frozen, skip_from_py_object)]
#[derive(Clone)]
pub struct PySpawnResult {
    /// PID of the sandbox shell process.
    pub pid: i32,
    /// File descriptor for writing to the shell's stdin.
    pub stdin_fd: i32,
    /// File descriptor for reading the shell's stdout.
    pub stdout_fd: i32,
    /// File descriptor for reading the signal pipe (exit codes).
    pub signal_r_fd: i32,
    /// The fd number of the signal write end *inside* the child process.
    pub signal_w_fd_num: i32,
    /// PTY master fd (only set when tty=True).
    pub master_fd: Option<i32>,
    /// pidfd for the shell process (None if kernel doesn't support it).
    pub pidfd: Option<i32>,
    /// Read end of the error/warning pipe from child init.
    /// After startup, Python reads this for non-fatal warnings.
    pub err_r_fd: i32,
}

// ======================================================================
// PyO3 bindings
// ======================================================================

/// Check if kernel supports new mount API with lowerdir+ (>= 6.8).
#[gen_stub_pyfunction]
#[pyfunction]
fn py_check_new_mount_api() -> bool {
    mount::check_new_mount_api()
}

/// Mount overlayfs, auto-selecting new mount API or legacy mount(2).
#[gen_stub_pyfunction]
#[pyfunction]
#[pyo3(signature = (lowerdir_spec, upper_dir, work_dir, target))]
fn py_mount_overlay(
    lowerdir_spec: &str,
    upper_dir: &str,
    work_dir: &str,
    target: &str,
) -> PyResult<()> {
    mount::mount_overlay(lowerdir_spec, upper_dir, work_dir, target)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Bind mount ``source`` onto ``target``.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_bind_mount(source: &str, target: &str) -> PyResult<()> {
    mount::bind_mount(source, target)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Recursive bind mount (``mount --rbind``).
#[gen_stub_pyfunction]
#[pyfunction]
fn py_rbind_mount(source: &str, target: &str) -> PyResult<()> {
    mount::rbind_mount(source, target)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Make a mount point private.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_make_private(target: &str) -> PyResult<()> {
    mount::make_private(target).map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Remount a bind mount as read-only.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_remount_ro_bind(target: &str) -> PyResult<()> {
    mount::remount_ro_bind(target).map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Lazy unmount (``umount -l``).
#[gen_stub_pyfunction]
#[pyfunction]
fn py_umount_lazy(target: &str) -> PyResult<()> {
    mount::umount_lazy(target).map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Regular unmount.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_umount(target: &str) -> PyResult<()> {
    mount::umount(target).map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Recursive lazy unmount (``umount -R -l``).
#[gen_stub_pyfunction]
#[pyfunction]
fn py_umount_recursive_lazy(target: &str) -> PyResult<()> {
    mount::umount_recursive_lazy(target)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Build seccomp BPF bytecode as raw bytes.
#[gen_stub_pyfunction]
#[pyfunction]
#[allow(clippy::unnecessary_wraps)] // PyO3 requires PyResult
fn py_build_seccomp_bpf(py: Python<'_>) -> PyResult<Py<PyBytes>> {
    let bpf = security::build_seccomp_bpf();
    Ok(PyBytes::new(py, &bpf).into())
}

/// Apply seccomp-bpf filter. Raises `OSError` on failure.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_apply_seccomp_filter() -> PyResult<()> {
    security::apply_seccomp_filter()
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Drop capabilities except Docker defaults + `extra_keep`.
#[gen_stub_pyfunction]
#[pyfunction]
#[pyo3(signature = (extra_keep = None))]
fn py_drop_capabilities(extra_keep: Option<Vec<u32>>) -> PyResult<u32> {
    security::drop_capabilities(&extra_keep.unwrap_or_default())
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Apply Landlock filesystem + network restrictions.
#[gen_stub_pyfunction]
#[pyfunction]
#[pyo3(signature = (read_paths = None, write_paths = None, allowed_tcp_ports = None, strict = false))]
fn py_apply_landlock(
    read_paths: Option<Vec<String>>,
    write_paths: Option<Vec<String>>,
    allowed_tcp_ports: Option<Vec<u16>>,
    strict: bool,
) -> PyResult<bool> {
    security::apply_landlock(
        &read_paths.unwrap_or_default(),
        &write_paths.unwrap_or_default(),
        &allowed_tcp_ports.unwrap_or_default(),
        strict,
    )
    .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Query kernel Landlock ABI version (0 if unavailable).
#[gen_stub_pyfunction]
#[pyfunction]
fn py_landlock_abi_version() -> u32 {
    security::landlock_abi_version()
}

/// Create a pidfd for the given PID. Returns fd or None.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_pidfd_open(pid: i32) -> Option<i32> {
    pidfd::pidfd_open(pid).ok()
}

/// Send signal to process via pidfd. Returns True on success.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_pidfd_send_signal(pidfd: i32, sig: i32) -> bool {
    pidfd::pidfd_send_signal(pidfd, sig).is_ok()
}

/// Check if process behind pidfd is alive.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_pidfd_is_alive(pidfd: i32) -> bool {
    pidfd::pidfd_is_alive(pidfd)
}

/// Hint kernel to reclaim (swap out) sandbox process memory via `MADV_COLD`.
#[gen_stub_pyfunction]
#[pyfunction]
#[allow(clippy::unnecessary_wraps)] // PyO3 requires PyResult
fn py_process_madvise_cold(pidfd: i32) -> PyResult<bool> {
    match pidfd::process_madvise_cold(pidfd) {
        Ok(()) => Ok(true),
        Err(e) => {
            log::debug!("process_madvise failed: {e}");
            Ok(false)
        }
    }
}

// --- cgroup bindings ---

/// Check if cgroup v2 is available.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_cgroup_v2_available() -> bool {
    cgroup::cgroup_v2_available()
}

/// Create a cgroup for the sandbox. Returns the cgroup path.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_create_cgroup(name: &str) -> PyResult<String> {
    cgroup::create_cgroup(name)
        .map(|p| p.to_string_lossy().into_owned())
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Apply resource limits to a cgroup.
#[gen_stub_pyfunction]
#[pyfunction]
#[allow(clippy::needless_pass_by_value)] // PyO3 extracts HashMap by value
fn py_apply_cgroup_limits(cgroup_path: &str, limits: HashMap<String, String>) -> PyResult<()> {
    let path = std::path::Path::new(cgroup_path);
    cgroup::enable_controllers(path, &limits)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))?;
    cgroup::apply_limits(path, &limits)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Move a process into a cgroup.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_cgroup_add_process(cgroup_path: &str, pid: u32) -> PyResult<()> {
    cgroup::add_process(std::path::Path::new(cgroup_path), pid)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Kill all processes in a cgroup and remove it.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_cleanup_cgroup(cgroup_path: &str) -> PyResult<()> {
    cgroup::cleanup_cgroup(std::path::Path::new(cgroup_path))
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Convert Docker CPU shares to cgroup v2 weight.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_convert_cpu_shares(shares: u64) -> u64 {
    cgroup::convert_cpu_shares(shares)
}

// --- spawn_sandbox binding ---

/// Helper: extract optional string from `PyDict`.
fn get_opt_str(d: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<String>> {
    match d.get_item(key)? {
        Some(v) if !v.is_none() => Ok(Some(v.extract()?)),
        _ => Ok(None),
    }
}

fn get_str(d: &Bound<'_, PyDict>, key: &str, default: &str) -> PyResult<String> {
    get_opt_str(d, key).map(|v| v.unwrap_or_else(|| default.to_string()))
}

fn get_bool(d: &Bound<'_, PyDict>, key: &str, default: bool) -> PyResult<bool> {
    match d.get_item(key)? {
        Some(v) if !v.is_none() => Ok(v.extract()?),
        _ => Ok(default),
    }
}

fn get_vec_str(d: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<String>> {
    match d.get_item(key)? {
        Some(v) if !v.is_none() => Ok(v.extract()?),
        _ => Ok(Vec::new()),
    }
}

fn get_vec_u32(d: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<u32>> {
    match d.get_item(key)? {
        Some(v) if !v.is_none() => Ok(v.extract()?),
        _ => Ok(Vec::new()),
    }
}

fn get_vec_u16(d: &Bound<'_, PyDict>, key: &str) -> PyResult<Vec<u16>> {
    match d.get_item(key)? {
        Some(v) if !v.is_none() => Ok(v.extract()?),
        _ => Ok(Vec::new()),
    }
}

fn get_opt_u64(d: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<u64>> {
    match d.get_item(key)? {
        Some(v) if !v.is_none() => Ok(Some(v.extract()?)),
        _ => Ok(None),
    }
}

fn get_opt_subuid(d: &Bound<'_, PyDict>, key: &str) -> PyResult<Option<(u32, u32, u32)>> {
    match d.get_item(key)? {
        Some(v) if !v.is_none() => {
            let tuple: (u32, u32, u32) = v.extract()?;
            Ok(Some(tuple))
        }
        _ => Ok(None),
    }
}

fn get_env(d: &Bound<'_, PyDict>, key: &str) -> PyResult<HashMap<String, String>> {
    match d.get_item(key)? {
        Some(v) if !v.is_none() => Ok(v.extract()?),
        _ => Ok(HashMap::new()),
    }
}

/// Spawn a sandbox process. Takes a config dict, returns a `PySpawnResult`.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_spawn_sandbox(config: &Bound<'_, PyDict>) -> PyResult<PySpawnResult> {
    let cfg = init::SandboxSpawnConfig {
        rootfs: get_str(config, "rootfs", "/")?,
        shell: get_str(config, "shell", "/bin/sh")?,
        working_dir: get_str(config, "working_dir", "/")?,
        env: get_env(config, "env")?,
        rootful: get_bool(config, "rootful", false)?,
        lowerdir_spec: get_opt_str(config, "lowerdir_spec")?,
        upper_dir: get_opt_str(config, "upper_dir")?,
        work_dir: get_opt_str(config, "work_dir")?,
        userns: get_bool(config, "userns", false)?,
        net_isolate: get_bool(config, "net_isolate", false)?,
        net_ns: get_opt_str(config, "net_ns")?,
        shared_userns: get_opt_str(config, "shared_userns")?,
        subuid_range: get_opt_subuid(config, "subuid_range")?,
        seccomp: get_bool(config, "seccomp", true)?,
        cap_add: get_vec_u32(config, "cap_add")?,
        hostname: get_opt_str(config, "hostname")?,
        read_only: get_bool(config, "read_only", false)?,
        landlock_read_paths: get_vec_str(config, "landlock_read_paths")?,
        landlock_write_paths: get_vec_str(config, "landlock_write_paths")?,
        landlock_ports: get_vec_u16(config, "landlock_ports")?,
        landlock_strict: get_bool(config, "landlock_strict", false)?,
        volumes: get_vec_str(config, "volumes")?,
        devices: get_vec_str(config, "devices")?,
        shm_size: get_opt_u64(config, "shm_size")?,
        tmpfs_mounts: get_vec_str(config, "tmpfs_mounts")?,
        cgroup_path: get_opt_str(config, "cgroup_path")?,
        entrypoint: get_vec_str(config, "entrypoint")?,
        tty: get_bool(config, "tty", false)?,
        port_map: get_vec_str(config, "port_map")?,
        pasta_bin: get_opt_str(config, "pasta_bin")?,
        ipv6: get_bool(config, "ipv6", false)?,
        env_dir: get_opt_str(config, "env_dir")?,
        vm_mode: get_bool(config, "vm_mode", false)?,
    };

    let r = init::spawn_sandbox(&cfg)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))?;

    Ok(PySpawnResult {
        pid: r.pid,
        stdin_fd: r.stdin_fd,
        stdout_fd: r.stdout_fd,
        signal_r_fd: r.signal_r_fd,
        signal_w_fd_num: r.signal_w_fd_num,
        master_fd: r.master_fd,
        pidfd: r.pidfd,
        err_r_fd: r.err_r_fd,
    })
}

// ======================================================================
// QMP
// ======================================================================

/// Send a QMP command to a QEMU monitor Unix socket.
///
/// Connects, negotiates capabilities, sends *`command_json`*, and returns
/// the JSON response string (containing ``"return"`` or ``"error"``).
///
/// The socket must be accessible from the calling process (i.e. on a
/// bind-mounted volume path, not inside an overlayfs mount namespace).
#[gen_stub_pyfunction]
#[pyfunction]
#[pyo3(signature = (socket_path, command_json, timeout_secs=30))]
fn py_qmp_send(socket_path: &str, command_json: &str, timeout_secs: u64) -> PyResult<String> {
    qmp::qmp_send(socket_path, command_json, timeout_secs)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

// ======================================================================
// User namespace cleanup
// ======================================================================

/// Enter a user namespace and recursively fix permissions + ownership.
///
/// Forks, ``setns()`` into the user namespace of *`userns_pid`*, then
/// walks *`dir_path`* doing ``chmod(a+rwX)`` + ``lchown(0,0)`` so that
/// the host user can ``rmtree`` the directory after sandbox deletion.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_userns_fixup_for_delete(userns_pid: i32, dir_path: &str) -> PyResult<u32> {
    userns::fixup_dir_for_delete(userns_pid, std::path::Path::new(dir_path))
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

// ======================================================================
// Namespace enter (popen preexec)
// ======================================================================

/// Enter mount namespace + chroot + chdir for rootful ``popen()``.
///
/// Called from ``preexec_fn`` (after fork, before exec).  Replaces the
/// ``nsenter`` subprocess with direct ``setns()`` + ``chroot()`` syscalls.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_nsenter_preexec(target_pid: i32) -> PyResult<()> {
    nsenter::nsenter_preexec(target_pid)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

/// Enter user + mount namespace + chroot + chdir for userns ``popen()``.
///
/// Like :func:`py_nsenter_preexec` but also joins the user namespace
/// and chroots to an explicit *rootfs* path (needed for rootless).
#[gen_stub_pyfunction]
#[pyfunction]
fn py_userns_preexec(target_pid: i32, rootfs: &str, working_dir: &str) -> PyResult<()> {
    nsenter::userns_preexec(target_pid, rootfs, working_dir)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

// ======================================================================
// Process helpers (fuser)
// ======================================================================

/// Kill all processes with open fds to *`target_path`* (replaces ``fuser -k``).
///
/// Walks ``/proc/*/fd/`` and sends ``SIGKILL`` to matching PIDs.
/// Returns the number of processes killed.
#[gen_stub_pyfunction]
#[pyfunction]
fn py_fuser_kill(target_path: &str) -> PyResult<u32> {
    r#proc::fuser_kill(target_path).map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

// ======================================================================
// Whiteout conversion
// ======================================================================

/// Convert OCI `.wh.*` whiteout files to overlayfs-native format.
///
/// Walks *`layer_dir`* and replaces sentinel files with xattrs (rootless)
/// or char-device (0,0) nodes (root).  Returns the number of files
/// converted.  ~100x faster than the subprocess-per-file Python version.
#[gen_stub_pyfunction]
#[pyfunction]
#[pyo3(signature = (layer_dir, use_user_xattr = true))]
fn py_convert_whiteouts(layer_dir: &str, use_user_xattr: bool) -> PyResult<u32> {
    whiteout::convert_whiteouts(std::path::Path::new(layer_dir), use_user_xattr)
        .map_err(|e| pyo3::exceptions::PyOSError::new_err(e.to_string()))
}

// ======================================================================
// Module definition
// ======================================================================

/// nitrobox Rust core: direct syscall interface for namespace sandboxing.
#[pymodule]
fn _core(m: &Bound<'_, PyModule>) -> PyResult<()> {
    // types
    m.add_class::<PySpawnResult>()?;

    // mount
    m.add_function(wrap_pyfunction!(py_check_new_mount_api, m)?)?;
    m.add_function(wrap_pyfunction!(py_mount_overlay, m)?)?;
    m.add_function(wrap_pyfunction!(py_bind_mount, m)?)?;
    m.add_function(wrap_pyfunction!(py_rbind_mount, m)?)?;
    m.add_function(wrap_pyfunction!(py_make_private, m)?)?;
    m.add_function(wrap_pyfunction!(py_remount_ro_bind, m)?)?;
    m.add_function(wrap_pyfunction!(py_umount, m)?)?;
    m.add_function(wrap_pyfunction!(py_umount_lazy, m)?)?;
    m.add_function(wrap_pyfunction!(py_umount_recursive_lazy, m)?)?;

    // security
    m.add_function(wrap_pyfunction!(py_build_seccomp_bpf, m)?)?;
    m.add_function(wrap_pyfunction!(py_apply_seccomp_filter, m)?)?;
    m.add_function(wrap_pyfunction!(py_drop_capabilities, m)?)?;
    m.add_function(wrap_pyfunction!(py_apply_landlock, m)?)?;
    m.add_function(wrap_pyfunction!(py_landlock_abi_version, m)?)?;

    // pidfd
    m.add_function(wrap_pyfunction!(py_pidfd_open, m)?)?;
    m.add_function(wrap_pyfunction!(py_pidfd_send_signal, m)?)?;
    m.add_function(wrap_pyfunction!(py_pidfd_is_alive, m)?)?;
    m.add_function(wrap_pyfunction!(py_process_madvise_cold, m)?)?;

    // cgroup
    m.add_function(wrap_pyfunction!(py_cgroup_v2_available, m)?)?;
    m.add_function(wrap_pyfunction!(py_create_cgroup, m)?)?;
    m.add_function(wrap_pyfunction!(py_apply_cgroup_limits, m)?)?;
    m.add_function(wrap_pyfunction!(py_cgroup_add_process, m)?)?;
    m.add_function(wrap_pyfunction!(py_cleanup_cgroup, m)?)?;
    m.add_function(wrap_pyfunction!(py_convert_cpu_shares, m)?)?;

    // spawn
    m.add_function(wrap_pyfunction!(py_spawn_sandbox, m)?)?;

    // qmp
    m.add_function(wrap_pyfunction!(py_qmp_send, m)?)?;

    // whiteout
    m.add_function(wrap_pyfunction!(py_convert_whiteouts, m)?)?;

    // userns cleanup
    m.add_function(wrap_pyfunction!(py_userns_fixup_for_delete, m)?)?;

    // nsenter (popen preexec)
    m.add_function(wrap_pyfunction!(py_nsenter_preexec, m)?)?;
    m.add_function(wrap_pyfunction!(py_userns_preexec, m)?)?;

    // proc (fuser)
    m.add_function(wrap_pyfunction!(py_fuser_kill, m)?)?;

    Ok(())
}

// Generates stub_info() for the stub_gen binary.
pyo3_stub_gen::define_stub_info_gatherer!(stub_info);
