//! Process inspection helpers.
//!
//! Replaces `fuser -k <path>` with a direct `/proc` walk + kill.

use std::fs;
use std::io;
use std::path::Path;

/// Kill all processes that have open file descriptors to `target_path`.
///
/// Walks `/proc/*/fd/` and checks each symlink.  Sends SIGKILL to
/// every PID whose fd links to the target.  Returns the number of
/// processes killed.
pub fn fuser_kill(target_path: &str) -> io::Result<u32> {
    let target =
        fs::canonicalize(target_path).unwrap_or_else(|_| Path::new(target_path).to_path_buf());

    let my_pid = unsafe { libc::getpid() };
    let mut killed = 0u32;

    let proc_dir = fs::read_dir("/proc")?;

    for entry in proc_dir {
        let Ok(entry) = entry else { continue };

        // Only numeric directories (PIDs).
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let Ok(pid) = pid_str.parse::<i32>() else {
            continue;
        };

        // Skip self.
        if pid == my_pid {
            continue;
        }

        let fd_dir = format!("/proc/{pid}/fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };

        let mut should_kill = false;
        for fd_entry in fds {
            let Ok(fd_entry) = fd_entry else { continue };
            if let Ok(link_target) = fs::read_link(fd_entry.path()) {
                if link_target == target {
                    should_kill = true;
                    break;
                }
            }
        }

        if should_kill && unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
            killed += 1;
        }
    }

    Ok(killed)
}
