//! nitrobox-checkpoint-helper: setuid binary for rootful CRIU checkpoint/restore.
//!
//! Installed via `nitrobox setup` with setuid root.  For both dump and
//! restore, the helper enters the sandbox's namespaces (as root) and
//! runs CRIU from inside — giving it the same view as runc/Docker.
//!
//! Security: validates that the caller (real UID) owns the sandbox.

use std::env;
use std::ffi::CString;
use std::fs;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::os::unix::process::CommandExt;
use std::process::{Command, exit};

fn die(msg: &str) -> ! {
    eprintln!("nitrobox-checkpoint-helper: {msg}");
    exit(1);
}

fn find_criu() -> PathBuf {
    let self_exe = env::current_exe().unwrap_or_else(|e| die(&format!("can't find self: {e}")));
    let dir = self_exe.parent().unwrap_or_else(|| die("no parent dir"));
    for candidate in [dir.join("criu"), dir.join("../lib/nitrobox/criu")] {
        if candidate.is_file() {
            return candidate;
        }
    }
    die("CRIU binary not found (expected next to helper)");
}

fn verify_ownership(path: &Path, caller_uid: u32) {
    let meta = fs::metadata(path)
        .unwrap_or_else(|e| die(&format!("can't stat {}: {e}", path.display())));
    if meta.uid() != caller_uid {
        die(&format!(
            "permission denied: {} owned by uid {}, caller is uid {}",
            path.display(), meta.uid(), caller_uid
        ));
    }
}

fn enter_ns(pid: u32, ns_type: &str, clone_flag: i32) {
    let path = format!("/proc/{pid}/ns/{ns_type}");
    let fd = unsafe {
        libc::open(CString::new(path.as_str()).unwrap().as_ptr(), libc::O_RDONLY)
    };
    if fd < 0 {
        die(&format!("can't open {path}: {}", std::io::Error::last_os_error()));
    }
    if unsafe { libc::setns(fd, clone_flag) } != 0 {
        die(&format!("setns {ns_type} failed: {}", std::io::Error::last_os_error()));
    }
    unsafe { libc::close(fd) };
}

fn chown_recursive(path: &Path, uid: u32, gid: u32) {
    if let Ok(entries) = fs::read_dir(path) {
        for entry in entries.flatten() {
            let p = entry.path();
            if let Ok(cs) = CString::new(p.to_string_lossy().as_bytes()) {
                unsafe { libc::chown(cs.as_ptr(), uid, gid) };
            }
            if p.is_dir() {
                chown_recursive(&p, uid, gid);
            }
        }
    }
    if let Ok(cs) = CString::new(path.to_string_lossy().as_bytes()) {
        unsafe { libc::chown(cs.as_ptr(), uid, gid) };
    }
}

fn usage() -> ! {
    eprintln!(
        "Usage:\n\
         \n\
         nitrobox-checkpoint-helper dump \\\n\
         \x20   --ns-pid PID --tree PID --images-dir DIR \\\n\
         \x20   [--leave-running] [--shell-job] [other CRIU opts...]\n\
         \n\
         nitrobox-checkpoint-helper restore \\\n\
         \x20   --ns-pid PID --images-dir DIR --pidfile FILE \\\n\
         \x20   [--shell-job] [--restore-sibling] [--restore-detached] \\\n\
         \x20   [--inherit-fd fd[N]:KEY ...] [other CRIU opts...]\n\
         \n\
         nitrobox-checkpoint-helper mount-overlay \\\n\
         \x20   --lowerdir DIR --upper DIR --work DIR --target DIR\n\
         \n\
         --ns-pid: PID of sandbox process whose namespaces to enter"
    );
    exit(1);
}

fn main() {
    let args: Vec<String> = env::args().collect();
    if args.len() < 2 {
        usage();
    }

    let caller_uid = unsafe { libc::getuid() };
    let caller_gid = unsafe { libc::getgid() };
    let subcommand = &args[1];
    let criu_args = &args[2..];

    match subcommand.as_str() {
        "dump" | "restore" | "mount-overlay" | "umount" => {}
        "--help" | "-h" | "help" => usage(),
        _ => die(&format!("unknown subcommand: {subcommand}")),
    }

    // ---- umount subcommand ------------------------------------------------
    if subcommand == "umount" {
        let target = criu_args.first().unwrap_or_else(|| die("umount: PATH required"));
        verify_ownership(Path::new(target), caller_uid);
        unsafe {
            let dst = CString::new(target.as_str()).unwrap();
            if libc::umount2(dst.as_ptr(), libc::MNT_DETACH) != 0 {
                die(&format!("umount {target}: {}", std::io::Error::last_os_error()));
            }
        }
        exit(0);
    }

    // ---- mount-overlay subcommand ----------------------------------------
    if subcommand == "mount-overlay" {
        let mut lowerdir: Option<&str> = None;
        let mut upper: Option<&str> = None;
        let mut work: Option<&str> = None;
        let mut target: Option<&str> = None;
        let mut j = 0;
        while j < criu_args.len() {
            match criu_args[j].as_str() {
                "--lowerdir" if j + 1 < criu_args.len() => { lowerdir = Some(&criu_args[j+1]); j += 2; }
                "--upper" if j + 1 < criu_args.len() => { upper = Some(&criu_args[j+1]); j += 2; }
                "--work" if j + 1 < criu_args.len() => { work = Some(&criu_args[j+1]); j += 2; }
                "--target" if j + 1 < criu_args.len() => { target = Some(&criu_args[j+1]); j += 2; }
                _ => j += 1,
            }
        }
        let (l, u, w, t) = (
            lowerdir.unwrap_or_else(|| die("--lowerdir required")),
            upper.unwrap_or_else(|| die("--upper required")),
            work.unwrap_or_else(|| die("--work required")),
            target.unwrap_or_else(|| die("--target required")),
        );
        verify_ownership(Path::new(u), caller_uid);
        let opts = format!("lowerdir={l},upperdir={u},workdir={w}");
        unsafe {
            let src = CString::new("overlay").unwrap();
            let dst = CString::new(t).unwrap();
            let fstype = CString::new("overlay").unwrap();
            let data = CString::new(opts.as_str()).unwrap();
            if libc::mount(src.as_ptr(), dst.as_ptr(), fstype.as_ptr(), 0,
                           data.as_ptr() as *const _) != 0 {
                die(&format!("mount overlay: {}", std::io::Error::last_os_error()));
            }
        }
        exit(0);
    }

    // ---- dump / restore --------------------------------------------------
    let mut ns_pid: Option<u32> = None;
    let mut images_dir: Option<String> = None;
    let mut root_path: Option<String> = None;
    let mut i = 0;
    while i < criu_args.len() {
        match criu_args[i].as_str() {
            "--ns-pid" if i + 1 < criu_args.len() => {
                ns_pid = criu_args[i + 1].parse().ok(); i += 2;
            }
            "--images-dir" if i + 1 < criu_args.len() => {
                images_dir = Some(criu_args[i + 1].clone()); i += 2;
            }
            "--root" if i + 1 < criu_args.len() => {
                root_path = Some(criu_args[i + 1].clone()); i += 2;
            }
            _ => i += 1,
        }
    }

    let ns_pid = ns_pid.unwrap_or_else(|| die("--ns-pid PID required"));
    verify_ownership(&PathBuf::from(format!("/proc/{ns_pid}")), caller_uid);

    // Resolve paths to absolute before entering namespace
    let images_abs = images_dir.as_ref().map(|d| {
        fs::canonicalize(d).unwrap_or_else(|_| PathBuf::from(d))
    });
    if let Some(ref abs) = images_abs {
        verify_ownership(
            if abs.exists() { abs } else { abs.parent().unwrap_or(abs) },
            caller_uid,
        );
    }

    // For restore: bind-mount rootfs (runc's criu-root trick).
    // CRIU requires --root to be a mount point whose parent isn't overmounted.
    let mut criu_root: Option<String> = None;
    if subcommand == "restore" {
        if let Some(ref root) = root_path {
            verify_ownership(Path::new(root), caller_uid);
            let cr = format!("{root}-criu-root");
            let _ = fs::create_dir_all(&cr);
            unsafe {
                let src = CString::new(root.as_str()).unwrap();
                let dst = CString::new(cr.as_str()).unwrap();
                if libc::mount(src.as_ptr(), dst.as_ptr(), std::ptr::null(),
                               libc::MS_BIND | libc::MS_REC, std::ptr::null()) != 0 {
                    die(&format!("bind mount: {}", std::io::Error::last_os_error()));
                }
            }
            criu_root = Some(cr);
        }
    }

    // Resolve CRIU path and open fd BEFORE entering any namespace —
    // after setns(mnt) the host filesystem is invisible.  We exec CRIU
    // via /proc/self/fd/N so the kernel reads the binary from the
    // already-open fd, not from a path in the new mount namespace.
    let criu = find_criu();
    let criu_fd = unsafe {
        let p = CString::new(criu.to_string_lossy().as_bytes().to_vec()).unwrap();
        libc::open(p.as_ptr(), libc::O_RDONLY | libc::O_CLOEXEC)
    };
    if criu_fd < 0 {
        die(&format!("can't open CRIU binary {}: {}", criu.display(),
                     std::io::Error::last_os_error()));
    }
    unsafe {
        let flags = libc::fcntl(criu_fd, libc::F_GETFD);
        libc::fcntl(criu_fd, libc::F_SETFD, flags & !libc::FD_CLOEXEC);
    }
    let criu_exec_path = format!("/proc/self/fd/{criu_fd}");

    let images_host_fd: Option<i32>;
    let images_mount: Option<String> = if subcommand == "dump" {
        if let Some(ref abs) = images_abs {
            let dir_fd = unsafe {
                let p = CString::new(abs.to_string_lossy().as_bytes().to_vec()).unwrap();
                libc::open(p.as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY)
            };
            if dir_fd < 0 {
                die(&format!("can't open images dir {}: {}", abs.display(),
                             std::io::Error::last_os_error()));
            }
            images_host_fd = Some(dir_fd);

            enter_ns(ns_pid, "mnt", libc::CLONE_NEWNS);

            let target = "/tmp/.nitrobox-criu-images";
            let _ = fs::create_dir_all(target);
            let src = CString::new("tmpfs").unwrap();
            let dst = CString::new(target).unwrap();
            let fstype = CString::new("tmpfs").unwrap();
            let opts = CString::new("size=1G").unwrap();
            if unsafe {
                libc::mount(src.as_ptr(), dst.as_ptr(), fstype.as_ptr(),
                            0, opts.as_ptr() as *const _)
            } != 0 {
                die(&format!("mount tmpfs for images: {}", std::io::Error::last_os_error()));
            }
            Some(target.to_string())
        } else {
            images_host_fd = None;
            enter_ns(ns_pid, "mnt", libc::CLONE_NEWNS);
            None
        }
    } else {
        images_host_fd = None;
        None
    };

    let exec_path = if images_mount.is_some() {
        criu_exec_path.clone()
    } else {
        criu.to_string_lossy().into_owned()
    };
    let mut cmd = Command::new(&exec_path);

    unsafe {
        cmd.pre_exec(move || {
            if libc::setresgid(0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::setresuid(0, 0, 0) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            Ok(())
        });
    }
    cmd.arg(subcommand);

    let mut skip_next = false;
    let mut skip_key = "";
    for arg in criu_args {
        if skip_next {
            skip_next = false;
            match skip_key {
                "--images-dir" => {
                    if let Some(ref mnt) = images_mount {
                        cmd.arg(mnt);
                    } else if let Some(ref abs) = images_abs {
                        cmd.arg(abs);
                    }
                }
                "--root" => {
                    if let Some(ref cr) = criu_root {
                        cmd.arg("--root");
                        cmd.arg(cr);
                    }
                }
                _ => {}
            }
            continue;
        }
        match arg.as_str() {
            "--ns-pid" => { skip_next = true; skip_key = "--ns-pid"; }
            "--root" => { skip_next = true; skip_key = "--root"; }
            "--images-dir" => {
                cmd.arg(arg);
                skip_next = true; skip_key = "--images-dir";
            }
            _ => { cmd.arg(arg); }
        }
    }

    cmd.arg("--log-file").arg(format!("{subcommand}.log"));
    cmd.arg("-v4");

    let status = cmd.status()
        .unwrap_or_else(|e| die(&format!("exec criu failed: {e}")));

    if let Some(ref mnt) = images_mount {
        if let Some(host_fd) = images_host_fd {
            let saved = unsafe { libc::open(c".".as_ptr(), libc::O_RDONLY | libc::O_DIRECTORY) };
            if unsafe { libc::fchdir(host_fd) } == 0 {
                if let Ok(entries) = fs::read_dir(mnt) {
                    for entry in entries.flatten() {
                        let name = entry.file_name();
                        let src = entry.path();
                        let _ = fs::copy(&src, &name);
                        if let Ok(cs) = CString::new(name.to_string_lossy().as_bytes().to_vec()) {
                            unsafe { libc::chown(cs.as_ptr(), caller_uid, caller_gid) };
                        }
                    }
                }
            }
            if saved >= 0 {
                unsafe { libc::fchdir(saved); libc::close(saved); }
            }
            unsafe { libc::close(host_fd) };
        }
        unsafe {
            let dst = CString::new(mnt.as_str()).unwrap();
            libc::umount2(dst.as_ptr(), libc::MNT_DETACH);
        }
        let _ = fs::remove_dir(mnt);
    }

    if let Some(ref abs) = images_abs {
        chown_recursive(abs, caller_uid, caller_gid);
    }

    if let Some(ref cr) = criu_root {
        unsafe {
            let dst = CString::new(cr.as_str()).unwrap();
            libc::umount2(dst.as_ptr(), libc::MNT_DETACH);
        }
        let _ = fs::remove_dir(cr);
    }

    exit(status.code().unwrap_or(1));
}
