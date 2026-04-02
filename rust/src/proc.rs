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
    let target = match fs::canonicalize(target_path) {
        Ok(p) => p,
        Err(_) => Path::new(target_path).to_path_buf(),
    };

    let my_pid = unsafe { libc::getpid() };
    let mut killed = 0u32;

    let proc_dir = match fs::read_dir("/proc") {
        Ok(d) => d,
        Err(e) => return Err(e),
    };

    for entry in proc_dir {
        let entry = match entry {
            Ok(e) => e,
            Err(_) => continue,
        };

        // Only numeric directories (PIDs).
        let name = entry.file_name();
        let pid_str = name.to_string_lossy();
        let pid: i32 = match pid_str.parse() {
            Ok(p) => p,
            Err(_) => continue,
        };

        // Skip self.
        if pid == my_pid {
            continue;
        }

        let fd_dir = format!("/proc/{}/fd", pid);
        let fds = match fs::read_dir(&fd_dir) {
            Ok(d) => d,
            Err(_) => continue, // permission denied or gone
        };

        let mut should_kill = false;
        for fd_entry in fds {
            let fd_entry = match fd_entry {
                Ok(e) => e,
                Err(_) => continue,
            };
            match fs::read_link(fd_entry.path()) {
                Ok(link_target) if link_target == target => {
                    should_kill = true;
                    break;
                }
                _ => continue,
            }
        }

        if should_kill {
            if unsafe { libc::kill(pid, libc::SIGKILL) } == 0 {
                killed += 1;
            }
        }
    }

    Ok(killed)
}
