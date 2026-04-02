//! cgroup v2 operations: create, set limits, kill, cleanup.

use std::collections::HashMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

const CGROUP_BASE: &str = "/sys/fs/cgroup/nitrobox";

/// Check if cgroup v2 is available on this system.
#[must_use]
pub fn cgroup_v2_available() -> bool {
    Path::new("/sys/fs/cgroup/cgroup.controllers").exists()
}

/// Create a cgroup for the given sandbox name. Returns the cgroup path.
pub fn create_cgroup(name: &str) -> io::Result<PathBuf> {
    let path = PathBuf::from(CGROUP_BASE).join(name);
    fs::create_dir_all(&path)?;
    Ok(path)
}

/// Enable required controllers on the parent cgroup.
pub fn enable_controllers(cgroup_path: &Path, limits: &HashMap<String, String>) -> io::Result<()> {
    let Some(parent) = cgroup_path.parent() else {
        return Ok(());
    };
    let subtree_ctl = parent.join("cgroup.subtree_control");
    if !subtree_ctl.exists() {
        return Ok(());
    }

    let controller_map = [
        ("cpu_max", "cpu"),
        ("cpu_shares", "cpu"),
        ("memory_max", "memory"),
        ("memory_swap", "memory"),
        ("pids_max", "pids"),
        ("io_max", "io"),
        ("cpuset_cpus", "cpuset"),
    ];

    for (key, ctrl) in &controller_map {
        if limits.contains_key(*key) {
            let _ = fs::write(&subtree_ctl, format!("+{ctrl}"));
        }
    }
    Ok(())
}

/// Convert Docker CPU shares (2-262144) to cgroup v2 weight (1-10000).
#[must_use]
pub fn convert_cpu_shares(shares: u64) -> u64 {
    if shares == 0 {
        return 100; // default
    }
    // Docker shares range: 2-262144, default 1024
    // cgroup v2 weight range: 1-10000, default 100
    ((shares.saturating_sub(2)) * 9999 / 262_142 + 1).clamp(1, 10000)
}

/// Apply resource limits to a cgroup.
pub fn apply_limits(cgroup_path: &Path, limits: &HashMap<String, String>) -> io::Result<()> {
    let limit_files = [
        ("cpu_max", "cpu.max"),
        ("memory_max", "memory.max"),
        ("pids_max", "pids.max"),
        ("io_max", "io.max"),
        ("cpuset_cpus", "cpuset.cpus"),
        ("cpu_shares", "cpu.weight"),
        ("memory_swap", "memory.swap.max"),
    ];

    for (key, filename) in &limit_files {
        if let Some(value) = limits.get(*key) {
            let write_value = if *key == "cpu_shares" {
                match value.parse::<u64>() {
                    Ok(shares) => convert_cpu_shares(shares).to_string(),
                    Err(_) => continue,
                }
            } else {
                value.clone()
            };

            let file_path = cgroup_path.join(filename);
            match fs::write(&file_path, &write_value) {
                Ok(()) => log::debug!("cgroup {filename} = {write_value}"),
                Err(e) => log::warn!("Failed to set cgroup {filename}: {e}"),
            }
        }
    }
    Ok(())
}

/// Move a process into a cgroup.
pub fn add_process(cgroup_path: &Path, pid: u32) -> io::Result<()> {
    fs::write(cgroup_path.join("cgroup.procs"), pid.to_string())
}

/// Kill all processes in a cgroup and remove it.
pub fn cleanup_cgroup(cgroup_path: &Path) -> io::Result<()> {
    if !cgroup_path.exists() {
        return Ok(());
    }

    // Kill via cgroup.kill (kernel 5.14+)
    let kill_file = cgroup_path.join("cgroup.kill");
    if kill_file.exists() {
        let _ = fs::write(&kill_file, "1");
    }

    // SIGKILL any remaining processes
    let procs_file = cgroup_path.join("cgroup.procs");
    if procs_file.exists() {
        if let Ok(contents) = fs::read_to_string(&procs_file) {
            for pid_str in contents.split_whitespace() {
                if let Ok(pid) = pid_str.parse::<i32>() {
                    let _ = nix::sys::signal::kill(
                        nix::unistd::Pid::from_raw(pid),
                        nix::sys::signal::Signal::SIGKILL,
                    );
                }
            }
        }
    }

    // Remove the cgroup directory
    match fs::remove_dir(cgroup_path) {
        Ok(()) => {}
        Err(e) => log::debug!("cgroup cleanup (non-fatal): {e}"),
    }
    Ok(())
}
