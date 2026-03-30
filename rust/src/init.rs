//! Sandbox init chain: fork → unshare → mount → pivot_root/chroot → security → exec.
//!
//! Uses nix for process lifecycle (fork/exec/mount/dup2/pipe/pty/ioctl),
//! rustix for namespace ops (pivot_root/chroot/chdir/setsid/waitpid/prctl),
//! libc only for _exit (required after fork) and fcntl (clear CLOEXEC).

use std::collections::HashMap;
use std::ffi::CString;
use std::io;
use std::os::fd::{AsRawFd, BorrowedFd, IntoRawFd, RawFd};
use std::path::Path;

use nix::mount::{MntFlags, MsFlags};
use nix::sched::CloneFlags;
use nix::sys::stat::{mknod, Mode, SFlag};
use nix::unistd::{self, ForkResult, Pid};

use crate::{mount, security};

// ======================================================================
// Config + Result structs
// ======================================================================

pub struct SandboxSpawnConfig {
    pub rootfs: String,
    pub shell: String,
    pub working_dir: String,
    pub env: HashMap<String, String>,
    pub rootful: bool,
    pub lowerdir_spec: Option<String>,
    pub upper_dir: Option<String>,
    pub work_dir: Option<String>,
    pub userns: bool,
    pub net_isolate: bool,
    pub net_ns: Option<String>,
    pub shared_userns: Option<String>,
    pub subuid_range: Option<(u32, u32, u32)>,
    pub seccomp: bool,
    pub cap_add: Vec<u32>,
    pub hostname: Option<String>,
    pub read_only: bool,
    pub landlock_read_paths: Vec<String>,
    pub landlock_write_paths: Vec<String>,
    pub landlock_ports: Vec<u16>,
    pub landlock_strict: bool,
    pub volumes: Vec<String>,
    pub devices: Vec<String>,
    pub shm_size: Option<u64>,
    pub tmpfs_mounts: Vec<String>,
    pub cgroup_path: Option<String>,
    pub entrypoint: Vec<String>,
    pub tty: bool,
    pub port_map: Vec<String>,
    pub pasta_bin: Option<String>,
    pub ipv6: bool,
    pub env_dir: Option<String>,
}

pub struct SpawnResult {
    pub pid: i32,
    pub stdin_fd: RawFd,
    pub stdout_fd: RawFd,
    pub signal_r_fd: RawFd,
    pub signal_w_fd_num: RawFd,
    pub master_fd: Option<RawFd>,
    pub pidfd: Option<RawFd>,
    /// Read end of the error/warning pipe.  Python reads this after the
    /// shell init signal to collect non-fatal warnings from child init.
    pub err_r_fd: RawFd,
}

// ======================================================================
// Docker-default masked/readonly paths
// ======================================================================

const MASKED_PATHS: &[&str] = &[
    "/proc/kcore", "/proc/keys", "/proc/timer_list",
    "/proc/sched_debug", "/sys/firmware", "/proc/scsi",
];

const RO_PATHS: &[&str] = &[
    "/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
];

// ======================================================================
// nix ioctl definitions for loopback
// ======================================================================

nix::ioctl_read_bad!(siocgifflags, libc::SIOCGIFFLAGS, libc::ifreq);
nix::ioctl_write_ptr_bad!(siocsifflags, libc::SIOCSIFFLAGS, libc::ifreq);

// ======================================================================
// Helper: write error/warning to pipe (used in child after fork)
// ======================================================================

// Thread-local fd for the child error pipe.  Set once in the child
// process right after fork; helpers use `init_warn_tl()` to write
// non-fatal warnings without needing `err_w` threaded through every
// function signature.
std::thread_local! {
    static ERR_W_FD: std::cell::Cell<RawFd> = const { std::cell::Cell::new(-1) };
}

fn init_fatal(err_w: RawFd, msg: &str) -> ! {
    let tagged = format!("F:{}", msg);
    let _ = nix::unistd::write(borrow(err_w), tagged.as_bytes());
    unsafe { libc::_exit(1) };
}

/// Write a non-fatal warning to the error pipe (newline-terminated so
/// the reader can split on `\n`).
fn init_warn(err_w: RawFd, msg: &str) {
    let tagged = format!("W:{}\n", msg);
    let _ = nix::unistd::write(borrow(err_w), tagged.as_bytes());
}

/// Convenience: write a warning using the thread-local `ERR_W_FD`.
/// Falls back to `log::warn!` if the fd hasn't been set (parent process).
fn init_warn_tl(msg: &str) {
    let fd = ERR_W_FD.with(|c| c.get());
    if fd >= 0 {
        init_warn(fd, msg);
    } else {
        log::warn!("{}", msg);
    }
}

fn c(s: &str) -> CString {
    CString::new(s).unwrap_or_else(|_| CString::new("").unwrap())
}

// ======================================================================
// Mount helpers (using nix::mount)
// ======================================================================

/// Convenience wrapper — nix::mount::mount with io::Result.
fn mnt(
    source: Option<&str>,
    target: &str,
    fstype: Option<&str>,
    flags: MsFlags,
    data: Option<&str>,
) -> io::Result<()> {
    nix::mount::mount(source, target, fstype, flags, data).map_err(io::Error::from)
}

fn umnt(target: &str, flags: MntFlags) -> io::Result<()> {
    nix::mount::umount2(target, flags).map_err(io::Error::from)
}

// ======================================================================
// Filesystem setup functions
// ======================================================================

fn mount_overlay_fs(config: &SandboxSpawnConfig) -> io::Result<()> {
    if let (Some(lowerdir), Some(upper), Some(work)) =
        (&config.lowerdir_spec, &config.upper_dir, &config.work_dir)
    {
        // Fix 000-perm dirs left by previous overlayfs
        if let Err(e) = std::process::Command::new("chmod")
            .args(["-R", "700", work])
            .output()
        {
            log::debug!("chmod work dir failed: {}", e);
        }
        let work_inner = format!("{}/work", work);
        if let Err(e) = std::fs::remove_dir_all(&work_inner) {
            log::debug!("remove work/work failed: {}", e);
        }

        if config.userns {
            // User namespace: must add userxattr option.
            // xino=on: generate unique inode numbers across layers to prevent
            // EOVERFLOW (Value too large for defined data type) when creating
            // temp files on overlayfs.  This is the Docker default.
            let opts = format!(
                "lowerdir={},upperdir={},workdir={},userxattr,xino=on",
                lowerdir, upper, work
            );
            mnt(
                Some("overlay"),
                &config.rootfs,
                Some("overlay"),
                MsFlags::empty(),
                Some(&opts),
            )?;
        } else {
            mount::mount_overlay(lowerdir, upper, work, &config.rootfs)?;
        }
    }
    Ok(())
}

fn mount_proc(rootfs: &str, net_isolate: bool) {
    let proc_path = format!("{}/proc", rootfs);
    let _ = std::fs::create_dir_all(&proc_path);
    if let Err(e) = mnt(Some("proc"), &proc_path, Some("proc"), MsFlags::empty(), None) {
        init_warn_tl(&format!("mount /proc failed: {}", e));
    }

    // Mount /sys: fresh sysfs when we own the netns, bind-mount otherwise.
    // Docker always provides /sys; QEMU/KVM and system tools rely on it.
    let sys_path = format!("{}/sys", rootfs);
    let _ = std::fs::create_dir_all(&sys_path);
    if net_isolate {
        if let Err(e) = mnt(Some("sysfs"), &sys_path, Some("sysfs"), MsFlags::empty(), None)
        {
            log::debug!("mount fresh sysfs failed: {}", e);
        }
    } else {
        // Shared netns: can't mount fresh sysfs, bind-mount host's /sys read-only.
        if let Err(e) = mnt(
            Some("/sys"), &sys_path, None::<&str>,
            MsFlags::MS_BIND | MsFlags::MS_REC, None,
        ) {
            log::debug!("bind-mount /sys failed: {}", e);
        } else {
            // Remount read-only
            let _ = mnt(
                None::<&str>, &sys_path, None::<&str>,
                MsFlags::MS_BIND | MsFlags::MS_REC | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                None,
            );
        }
    }
}

fn setup_dev_rootful(rootfs: &str) {
    let dev = format!("{}/dev", rootfs);
    let _ = std::fs::create_dir_all(&dev);
    if let Err(e) = mnt(
        Some("tmpfs"), &dev, Some("tmpfs"), MsFlags::MS_NOSUID, Some("mode=0755"),
    ) {
        init_warn_tl(&format!("mount tmpfs on /dev failed: {}", e));
    }

    let devices: &[(u32, u32, &str, u32)] = &[
        (1, 3, "null", 0o666), (1, 5, "zero", 0o666), (1, 7, "full", 0o666),
        (1, 8, "random", 0o444), (1, 9, "urandom", 0o444), (5, 0, "tty", 0o666),
    ];
    for &(major, minor, name, mode) in devices {
        let path = format!("{}/{}", dev, name);
        let _ = mknod(
            path.as_str(),
            SFlag::S_IFCHR,
            Mode::from_bits_truncate(mode),
            nix::sys::stat::makedev(major.into(), minor.into()),
        );
    }
    setup_dev_links(rootfs);
}

fn setup_dev_rootless(rootfs: &str) {
    let dev = format!("{}/dev", rootfs);
    let _ = std::fs::create_dir_all(&dev);
    if let Err(e) = mnt(
        Some("tmpfs"), &dev, Some("tmpfs"), MsFlags::MS_NOSUID, Some("mode=0755"),
    ) {
        init_warn_tl(&format!("mount tmpfs on /dev failed: {}", e));
    }

    for name in &["null", "zero", "full", "random", "urandom", "tty"] {
        let target = format!("{}/{}", dev, name);
        let _ = std::fs::File::create(&target);
        let source = format!("/dev/{}", name);
        if let Err(e) = mnt(Some(&source), &target, None::<&str>, MsFlags::MS_BIND, None) {
            init_warn_tl(&format!("bind mount /dev/{} failed: {}", name, e));
        }
    }
    setup_dev_links(rootfs);
}

fn setup_dev_links(rootfs: &str) {
    let dev = format!("{}/dev", rootfs);
    let _ = std::os::unix::fs::symlink("/proc/self/fd", format!("{}/fd", dev));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/0", format!("{}/stdin", dev));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/1", format!("{}/stdout", dev));
    let _ = std::os::unix::fs::symlink("/proc/self/fd/2", format!("{}/stderr", dev));

    let pts = format!("{}/pts", dev);
    let _ = std::fs::create_dir_all(&pts);
    if let Err(e) = mnt(
        Some("devpts"), &pts, Some("devpts"),
        MsFlags::MS_NOSUID, Some("newinstance,ptmxmode=0666"),
    ) {
        init_warn_tl(&format!("mount devpts failed: {}", e));
    }
    let _ = std::os::unix::fs::symlink("pts/ptmx", format!("{}/ptmx", dev));

    let shm = format!("{}/shm", dev);
    let _ = std::fs::create_dir_all(&shm);
}

fn mount_shm(rootfs: &str, shm_size: Option<u64>) {
    let size = shm_size.unwrap_or(256 * 1024 * 1024);
    let shm = format!("{}/dev/shm", rootfs);
    let _ = std::fs::create_dir_all(&shm);
    let opts = format!("size={}", size);
    if let Err(e) = mnt(Some("tmpfs"), &shm, Some("tmpfs"), MsFlags::MS_NOSUID, Some(&opts))
    {
        init_warn_tl(&format!("mount /dev/shm failed: {}", e));
    }
}

fn mount_devices(rootfs: &str, devices: &[String]) {
    for dev_path in devices {
        let dev_name = dev_path.trim_start_matches('/');
        let target = format!("{}/{}", rootfs, dev_name);
        if let Some(parent) = Path::new(dev_name).parent() {
            let ps = parent.to_string_lossy();
            if !ps.is_empty() && ps != "." {
                let _ = std::fs::create_dir_all(format!("{}/{}", rootfs, ps));
            }
        }
        let _ = std::fs::File::create(&target);
        if let Err(e) = mnt(Some(dev_path), &target, None::<&str>, MsFlags::MS_BIND, None) {
            init_warn_tl(&format!("device bind mount {} failed: {}", dev_path, e));
        }
    }
}

fn mount_volumes(config: &SandboxSpawnConfig) {
    for spec in &config.volumes {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() < 2 { continue; }
        let host_path = parts[0];
        let container_path = parts[1];
        let mode = if parts.len() > 2 { parts[2] } else { "rw" };
        let target = format!("{}/{}", config.rootfs, container_path.trim_start_matches('/'));
        let _ = std::fs::create_dir_all(&target);

        match mode {
            "cow" => {
                if let Some(ref env_dir) = config.env_dir {
                    let safe = container_path.replace('/', "_").trim_matches('_').to_string();
                    let cow_upper = format!("{}/cow_{}_upper", env_dir, safe);
                    let cow_work = format!("{}/cow_{}_work", env_dir, safe);
                    let _ = std::fs::create_dir_all(&cow_upper);
                    let _ = std::fs::create_dir_all(&cow_work);
                    let opts = format!("lowerdir={},upperdir={},workdir={}", host_path, cow_upper, cow_work);
                    if let Err(e) = mnt(Some("overlay"), &target, Some("overlay"), MsFlags::empty(), Some(&opts)) {
                        init_warn_tl(&format!("cow volume mount {} failed: {}", container_path, e));
                    }
                }
            }
            "ro" => {
                if let Err(e) = mnt(Some(host_path), &target, None::<&str>, MsFlags::MS_BIND, None) {
                    init_warn_tl(&format!("ro volume bind {} failed: {}", container_path, e));
                } else if let Err(e) = mnt(
                    None::<&str>, &target, None::<&str>,
                    // In user namespaces the kernel locks MS_NOSUID|MS_NODEV on
                    // bind mounts; a remount that drops them is rejected with EPERM.
                    MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY
                        | MsFlags::MS_NOSUID | MsFlags::MS_NODEV,
                    None,
                ) {
                    init_warn_tl(&format!("ro volume remount {} failed: {}", container_path, e));
                }
            }
            _ => {
                if let Err(e) = mnt(Some(host_path), &target, None::<&str>, MsFlags::MS_BIND, None) {
                    init_warn_tl(&format!("volume bind {} failed: {}", container_path, e));
                }
            }
        }
    }
}

fn mount_tmpfs(config: &SandboxSpawnConfig) {
    for spec in &config.tmpfs_mounts {
        let parts: Vec<&str> = spec.splitn(2, ':').collect();
        let path = parts[0];
        let opts = if parts.len() > 1 { parts[1] } else { "" };
        let target = format!("{}/{}", config.rootfs, path.trim_start_matches('/'));
        let _ = std::fs::create_dir_all(&target);
        if let Err(e) = mnt(
            Some("tmpfs"), &target, Some("tmpfs"), MsFlags::empty(),
            if opts.is_empty() { None } else { Some(opts) },
        ) {
            init_warn_tl(&format!("tmpfs mount {} failed: {}", path, e));
        }
    }
}

fn propagate_dns(rootfs: &str) {
    let sandbox_resolv = format!("{}/etc/resolv.conf", rootfs);
    if Path::new("/etc/resolv.conf").exists() {
        let needs_copy = if Path::new(&sandbox_resolv).exists() {
            std::fs::metadata(&sandbox_resolv).map(|m| m.len() == 0).unwrap_or(true)
        } else { true };
        if needs_copy {
            if let Err(e) = std::fs::copy("/etc/resolv.conf", &sandbox_resolv) {
                log::debug!("copy resolv.conf failed: {}", e);
            }
        }
    }
}

fn fix_tmp_perms(rootfs: &str) {
    let tmp = format!("{}/tmp", rootfs);
    let _ = nix::sys::stat::fchmodat(
        rustix::fs::CWD,
        tmp.as_str(),
        Mode::from_bits_truncate(0o1777),
        nix::sys::stat::FchmodatFlags::FollowSymlink,
    );
}

fn make_rootfs_readonly(rootfs: &str) {
    if let Err(e) = mnt(Some(rootfs), rootfs, None::<&str>, MsFlags::MS_BIND, None) {
        init_warn_tl(&format!("rootfs bind for readonly failed: {}", e));
    }
    if let Err(e) = mnt(None::<&str>, rootfs, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY, None) {
        init_warn_tl(&format!("rootfs readonly remount failed: {}", e));
    }
}

fn precreate_volume_mountpoints(config: &SandboxSpawnConfig) {
    for spec in &config.volumes {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() < 2 { continue; }
        let target = format!("{}/{}", config.rootfs, parts[1].trim_start_matches('/'));
        let _ = std::fs::create_dir_all(&target);
    }
}

// ======================================================================
// Security (post pivot_root / chroot)
// ======================================================================

fn apply_security(config: &SandboxSpawnConfig) {
    if let Some(ref hostname) = config.hostname {
        if let Err(e) = unistd::sethostname(hostname) {
            init_warn_tl(&format!("sethostname failed: {}", e));
        }
    }

    match security::drop_capabilities(&config.cap_add) {
        Ok(n) => log::debug!("dropped {} capabilities", n),
        Err(e) => init_warn_tl(&format!("cap_drop failed: {}", e)),
    }

    // Mask paths
    for path in MASKED_PATHS {
        if !Path::new(path).exists() { continue; }
        let result = if Path::new(path).is_dir() {
            mnt(Some("tmpfs"), path, Some("tmpfs"), MsFlags::empty(), None)
        } else {
            mnt(Some("/dev/null"), path, None::<&str>, MsFlags::MS_BIND, None)
        };
        if let Err(e) = result {
            init_warn_tl(&format!("mask_path {} failed: {}", path, e));
        }
    }

    // Read-only paths
    for path in RO_PATHS {
        if mnt(Some(path), path, None::<&str>, MsFlags::MS_BIND, None).is_ok() {
            if let Err(e) = mnt(None::<&str>, path, None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY, None) {
                init_warn_tl(&format!("readonly_path {} remount failed: {}", path, e));
            }
        }
    }

    if config.read_only {
        if let Err(e) = mnt(None::<&str>, "/", None::<&str>, MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY, None) {
            init_warn_tl(&format!("read-only rootfs remount failed: {}", e));
        }
    }

    // Landlock
    for path in config.landlock_write_paths.iter().chain(config.landlock_read_paths.iter()) {
        let _ = std::fs::create_dir_all(path);
    }
    if !config.landlock_read_paths.is_empty()
        || !config.landlock_write_paths.is_empty()
        || !config.landlock_ports.is_empty()
    {
        match security::apply_landlock(
            &config.landlock_read_paths, &config.landlock_write_paths,
            &config.landlock_ports, config.landlock_strict,
        ) {
            Ok(true) => log::debug!("landlock applied"),
            Ok(false) => init_warn_tl("landlock not available"),
            Err(e) => init_warn_tl(&format!("landlock failed: {}", e)),
        }
    }

    if config.seccomp {
        if let Err(e) = security::apply_seccomp_filter() {
            init_warn_tl(&format!("seccomp failed: {}", e));
        }
    }
}

// ======================================================================
// Pasta networking
// ======================================================================

/// Set up pasta networking: create a new network namespace, start pasta, enter it.
///
/// `pasta_bin`: path to pasta binary (may need `host_prefix` prepended in rootful mode)
/// `env_dir`: sandbox env directory for the `.netns` file
/// `host_prefix`: prepended to `pasta_bin` and `env_dir` paths to reach host filesystem
///   (e.g. `"/.pivot_old"` in rootful mode after pivot_root, `""` in userns mode)
fn setup_pasta_networking(
    pasta_bin: &str, env_dir: &str, port_map: &[String], ipv6: bool, host_prefix: &str,
) {
    let actual_pasta = if host_prefix.is_empty() {
        pasta_bin.to_string()
    } else {
        format!("{}{}", host_prefix, pasta_bin)
    };
    let actual_env_dir = if host_prefix.is_empty() {
        env_dir.to_string()
    } else {
        format!("{}{}", host_prefix, env_dir)
    };
    let netns_file = format!("{}/.netns", actual_env_dir);
    let _ = std::fs::File::create(&netns_file);

    // 1. Create new netns via fork + unshare(CLONE_NEWNET) + bind mount
    match unsafe { unistd::fork() } {
        Ok(ForkResult::Child) => {
            let _ = nix::sched::unshare(CloneFlags::CLONE_NEWNET);
            let _ = mnt(
                Some("/proc/self/ns/net"), &netns_file, None::<&str>, MsFlags::MS_BIND, None,
            );
            unsafe { libc::_exit(0) };
        }
        Ok(ForkResult::Parent { child }) => {
            let _ = nix::sys::wait::waitpid(child, None);
        }
        Err(_) => {}
    }

    // 2. Start pasta
    let mut args: Vec<String> = vec!["--config-net".into()];
    // When running as root, pasta drops to 'nobody' by default — which then
    // can't setns. Tell it to stay as root.
    if rustix::process::geteuid().is_root() {
        args.extend(["--runas".into(), "0:0".into()]);
    }
    if !ipv6 { args.push("--ipv4-only".into()); }
    for m in port_map { args.extend(["-t".into(), m.clone()]); }
    args.extend(["-u", "none", "-T", "none", "-U", "none",
        "--dns-forward", "169.254.1.1", "--no-map-gw", "--quiet",
        "--netns"].iter().map(|s| s.to_string()));
    args.push(netns_file.clone());
    args.extend(["--map-guest-addr", "169.254.1.2"].iter().map(|s| s.to_string()));

    match std::process::Command::new(&actual_pasta).args(&args).output() {
        Ok(out) if !out.status.success() => {
            init_warn_tl(&format!("pasta exited with {}: {}", out.status, String::from_utf8_lossy(&out.stderr)));
        }
        Err(e) => init_warn_tl(&format!("pasta spawn failed: {}", e)),
        _ => {}
    }

    // 3. Enter the new netns
    if let Ok(ns_file) = std::fs::File::open(&netns_file) {
        let fd = unsafe { BorrowedFd::borrow_raw(ns_file.as_raw_fd()) };
        if let Err(e) = nix::sched::setns(fd, CloneFlags::CLONE_NEWNET) {
            init_warn_tl(&format!("setns into netns failed: {}", e));
        }
    } else {
        init_warn_tl(&format!("open netns file {} failed", netns_file));
    }

    // 4. Bring up loopback via nix ioctl
    if let Ok(sock) = nix::sys::socket::socket(
        nix::sys::socket::AddressFamily::Inet,
        nix::sys::socket::SockType::Datagram,
        nix::sys::socket::SockFlag::empty(),
        None,
    ) {
        unsafe {
            let mut ifr: libc::ifreq = std::mem::zeroed();
            ifr.ifr_name[0] = b'l' as libc::c_char;
            ifr.ifr_name[1] = b'o' as libc::c_char;
            let _ = siocgifflags(sock.as_raw_fd(), &mut ifr);
            ifr.ifr_ifru.ifru_flags |= libc::IFF_UP as libc::c_short;
            let _ = siocsifflags(sock.as_raw_fd(), &ifr);
        }
        // sock (OwnedFd) drops here → auto-close
    }
}

// ======================================================================
// Pivot root (rootful mode)
// ======================================================================

/// Phase 1: pivot_root into `rootfs`, leaving `/.pivot_old` mounted.
/// Call `cleanup_pivot_old()` once device/volume mounts that need the old
/// root are done.
fn do_pivot_root_phase1(rootfs: &str) -> io::Result<()> {
    mnt(None::<&str>, "/", None::<&str>, MsFlags::MS_SLAVE | MsFlags::MS_REC, None)?;
    mnt(Some(rootfs), rootfs, None::<&str>, MsFlags::MS_BIND, None)?;

    rustix::process::chdir(rootfs)?;

    let pivot_old = format!("{}/.pivot_old", rootfs);
    let _ = std::fs::create_dir_all(&pivot_old);

    rustix::process::pivot_root(".", ".pivot_old")?;
    rustix::process::chdir("/")?;

    if let Err(e) = mnt(None::<&str>, "/.pivot_old", None::<&str>, MsFlags::MS_SLAVE | MsFlags::MS_REC, None) {
        init_warn_tl(&format!("pivot_old rslave failed: {}", e));
    }

    Ok(())
}

/// Phase 2: detach and remove `/.pivot_old`.
fn cleanup_pivot_old() {
    if let Err(e) = umnt("/.pivot_old", MntFlags::MNT_DETACH) {
        init_warn_tl(&format!("pivot_old umount failed: {}", e));
    }
    if let Err(e) = std::fs::remove_dir("/.pivot_old") {
        log::debug!("pivot_old rmdir failed: {}", e);
    }
}

/// Bind-mount host devices (e.g. `/dev/fuse`) into `rootfs/dev/`.
/// `old_root` is the path to the old root mount (e.g. `/.pivot_old`).
/// Must be called BEFORE `cleanup_pivot_old()`.
fn mount_devices_from_old_root(rootfs: &str, old_root: &str, devices: &[String]) {
    for dev_path in devices {
        let dev_name = dev_path.trim_start_matches('/');
        let target = format!("{}/{}", rootfs, dev_name);
        // Ensure parent directory exists (e.g. /dev)
        if let Some(parent) = Path::new(dev_name).parent() {
            let ps = parent.to_string_lossy();
            if !ps.is_empty() && ps != "." {
                let _ = std::fs::create_dir_all(format!("{}/{}", rootfs, ps));
            }
        }
        let _ = std::fs::File::create(&target);
        // Use the host device path relative to old_root
        let source = format!("{}/{}", old_root, dev_name);
        if let Err(e) = mnt(Some(&source), &target, None::<&str>, MsFlags::MS_BIND, None) {
            init_warn_tl(&format!("device bind mount {} from old root failed: {}", dev_path, e));
        }
    }
}

/// Mount volumes at an explicit rootfs path (used after pivot_root in
/// rootful mode where the new rootfs is `/`).
///
/// `host_prefix`: if non-empty, prepend to host paths. In rootful mode
/// after pivot_root, the old host root lives at `/.pivot_old`, so pass
/// `"/.pivot_old"` here and this function will resolve host paths like
/// `/tmp/foo` to `/.pivot_old/tmp/foo`.
fn mount_volumes_at(volumes: &[String], rootfs: &str, env_dir: Option<&str>, host_prefix: &str) {
    for spec in volumes {
        let parts: Vec<&str> = spec.split(':').collect();
        if parts.len() < 2 { continue; }
        let raw_host_path = parts[0];
        let container_path = parts[1];
        let mode = if parts.len() > 2 { parts[2] } else { "rw" };
        let target = format!("{}/{}", rootfs, container_path.trim_start_matches('/'));
        let _ = std::fs::create_dir_all(&target);

        // Resolve host path through the old root if a prefix is given.
        let host_path_owned;
        let host_path = if !host_prefix.is_empty() {
            host_path_owned = format!("{}/{}", host_prefix, raw_host_path.trim_start_matches('/'));
            host_path_owned.as_str()
        } else {
            raw_host_path
        };

        match mode {
            "cow" => {
                if let Some(ed) = env_dir {
                    let safe = container_path.replace('/', "_").trim_matches('_').to_string();
                    let cow_upper = format!("{}/cow_{}_upper", ed, safe);
                    let cow_work = format!("{}/cow_{}_work", ed, safe);
                    let _ = std::fs::create_dir_all(&cow_upper);
                    let _ = std::fs::create_dir_all(&cow_work);
                    let opts = format!("lowerdir={},upperdir={},workdir={}", host_path, cow_upper, cow_work);
                    if let Err(e) = mnt(Some("overlay"), &target, Some("overlay"), MsFlags::empty(), Some(&opts)) {
                        init_warn_tl(&format!("cow volume mount {} failed: {}", container_path, e));
                    }
                }
            }
            "ro" => {
                if let Err(e) = mnt(Some(host_path), &target, None::<&str>, MsFlags::MS_BIND, None) {
                    init_warn_tl(&format!("ro volume bind {} failed: {}", container_path, e));
                } else if let Err(e) = mnt(
                    None::<&str>, &target, None::<&str>,
                    MsFlags::MS_BIND | MsFlags::MS_REMOUNT | MsFlags::MS_RDONLY,
                    None,
                ) {
                    init_warn_tl(&format!("ro volume remount {} failed: {}", container_path, e));
                }
            }
            _ => {
                if let Err(e) = mnt(Some(host_path), &target, None::<&str>, MsFlags::MS_BIND, None) {
                    init_warn_tl(&format!("volume bind {} failed: {}", container_path, e));
                }
            }
        }
    }
}

/// Mount tmpfs mounts at an explicit rootfs path (used after pivot_root in
/// rootful mode).
fn mount_tmpfs_at(tmpfs_mounts: &[String], rootfs: &str) {
    for spec in tmpfs_mounts {
        let parts: Vec<&str> = spec.splitn(2, ':').collect();
        let path = parts[0];
        let opts = if parts.len() > 1 { parts[1] } else { "" };
        let target = format!("{}/{}", rootfs, path.trim_start_matches('/'));
        let _ = std::fs::create_dir_all(&target);
        if let Err(e) = mnt(
            Some("tmpfs"), &target, Some("tmpfs"), MsFlags::empty(),
            if opts.is_empty() { None } else { Some(opts) },
        ) {
            init_warn_tl(&format!("tmpfs mount {} failed: {}", path, e));
        }
    }
}

// ======================================================================
// Main spawn function
// ======================================================================

/// Borrow a raw fd for passing to nix APIs. Safe when fd is known-valid.
fn borrow(fd: RawFd) -> BorrowedFd<'static> {
    unsafe { BorrowedFd::borrow_raw(fd) }
}

pub fn spawn_sandbox(config: &SandboxSpawnConfig) -> io::Result<SpawnResult> {
    // Create pipes. We extract raw fds immediately — Python manages lifetimes.
    // nix pipe2 returns (OwnedFd, OwnedFd); we convert to raw via into_raw_fd().
    let (err_r, err_w) = {
        let (r, w) = unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(io::Error::from)?;
        (r.into_raw_fd(), w.into_raw_fd())
    };
    let (signal_r, signal_w) = {
        let (r, w) = unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(io::Error::from)?;
        (r.into_raw_fd(), w.into_raw_fd())
    };

    let (stdin_r, stdin_w, stdout_r, stdout_w, master_fd) = if config.tty {
        let pty = nix::pty::openpty(None, None).map_err(io::Error::from)?;
        let master = pty.master.into_raw_fd();
        let slave = pty.slave.into_raw_fd();
        // Disable echo
        if let Ok(mut attrs) = nix::sys::termios::tcgetattr(borrow(master)) {
            attrs.local_flags.remove(nix::sys::termios::LocalFlags::ECHO);
            let _ = nix::sys::termios::tcsetattr(borrow(master), nix::sys::termios::SetArg::TCSANOW, &attrs);
        }
        (slave, master, master, slave, Some(master))
    } else {
        let (in_r, in_w) = unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(io::Error::from)?;
        let (out_r, out_w) = unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(io::Error::from)?;
        (in_r.into_raw_fd(), in_w.into_raw_fd(), out_r.into_raw_fd(), out_w.into_raw_fd(), None)
    };

    let needs_userns_sync = config.userns && config.shared_userns.is_none();
    // userns_ready pipe: child writes after unshare, parent reads before uid_map write.
    // Replaces polling /proc/pid/ns/user (which held GIL in a sleep loop).
    let (userns_ready_r, userns_ready_w) = if needs_userns_sync {
        let (r, w) = unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(io::Error::from)?;
        (Some(r.into_raw_fd()), Some(w.into_raw_fd()))
    } else {
        (None, None)
    };
    let (sync_r, sync_w) = if needs_userns_sync {
        let (r, w) = unistd::pipe2(nix::fcntl::OFlag::O_CLOEXEC).map_err(io::Error::from)?;
        (Some(r.into_raw_fd()), Some(w.into_raw_fd()))
    } else {
        (None, None)
    };

    // Fork
    match unsafe { unistd::fork() } {
        Err(e) => return Err(io::Error::from(e)),
        Ok(ForkResult::Child) => {
            // === CHILD A ===
            // NOTE: setsid() is now called in child_init (PID 1 of the new
            // PID namespace) so that CRIU can dump it without the
            // "session leader outside pid namespace" error.

            // Redirect stdin/stdout via nix typed API (borrow raw fds)
            let _ = unistd::dup2_stdin(borrow(stdin_r));
            if config.tty {
                let _ = unistd::dup2_stdout(borrow(stdin_r));
                let _ = unistd::dup2_stderr(borrow(stdin_r));
                if stdin_r > 2 { let _ = nix::unistd::close(stdin_r); }
            } else {
                let _ = unistd::dup2_stdout(borrow(stdout_w));
                let _ = unistd::dup2_stderr(borrow(stdout_w));
                let _ = nix::unistd::close(stdin_r);
                let _ = nix::unistd::close(stdin_w);
                let _ = nix::unistd::close(stdout_r);
                let _ = nix::unistd::close(stdout_w);
            }
            let _ = nix::unistd::close(signal_r);
            let _ = nix::unistd::close(err_r);
            if let Some(sw) = sync_w { let _ = nix::unistd::close(sw); }
            if let Some(urr) = userns_ready_r { let _ = nix::unistd::close(urr); }

            // Join cgroup
            if let Some(ref cg) = config.cgroup_path {
                let procs = format!("{}/cgroup.procs", cg);
                let pid = rustix::process::getpid();
                let _ = std::fs::write(&procs, format!("{}", pid.as_raw_nonzero()));
            }

            // Shared userns: enter existing namespaces
            if let Some(ref shared_userns) = config.shared_userns {
                if let Ok(f) = std::fs::File::open(shared_userns) {
                    let fd = unsafe { BorrowedFd::borrow_raw(f.as_raw_fd()) };
                    if let Err(e) = nix::sched::setns(fd, CloneFlags::CLONE_NEWUSER) {
                        init_fatal(err_w, &format!("setns shared userns failed: {}", e));
                    }
                }
                if let Some(ref net_ns) = config.net_ns {
                    if let Ok(f) = std::fs::File::open(net_ns) {
                        let fd = unsafe { BorrowedFd::borrow_raw(f.as_raw_fd()) };
                        if let Err(e) = nix::sched::setns(fd, CloneFlags::CLONE_NEWNET) {
                            init_fatal(err_w, &format!("setns shared netns failed: {}", e));
                        }
                    }
                }
            }

            // Build unshare flags
            let mut ns_flags = CloneFlags::CLONE_NEWPID | CloneFlags::CLONE_NEWNS
                | CloneFlags::CLONE_NEWUTS | CloneFlags::CLONE_NEWIPC;
            if config.userns && config.shared_userns.is_none() {
                ns_flags |= CloneFlags::CLONE_NEWUSER;
            }
            if config.net_isolate && config.net_ns.is_none() && config.shared_userns.is_none() {
                ns_flags |= CloneFlags::CLONE_NEWNET;
            }

            if let Err(e) = nix::sched::unshare(ns_flags) {
                init_fatal(err_w, &format!("unshare failed: {}", e));
            }

            // Signal parent that userns is ready (parent is blocked on read)
            if let Some(urw) = userns_ready_w {
                let _ = nix::unistd::write(borrow(urw), b"R");
                let _ = nix::unistd::close(urw);
            }

            // Wait for UID mapping from parent
            if let Some(sr) = sync_r {
                let mut buf = [0u8; 1];
                let _ = unistd::read(borrow(sr), &mut buf);
                let _ = nix::unistd::close(sr);
            }

            // Mount propagation slave
            if let Err(e) = mnt(None::<&str>, "/", None::<&str>, MsFlags::MS_SLAVE | MsFlags::MS_REC, None) {
                init_fatal(err_w, &format!("mount propagation slave failed: {}", e));
            }

            // Join net namespace if specified
            if config.shared_userns.is_none() {
                if let Some(ref net_ns) = config.net_ns {
                    if let Ok(f) = std::fs::File::open(net_ns) {
                        let fd = unsafe { BorrowedFd::borrow_raw(f.as_raw_fd()) };
                        if let Err(e) = nix::sched::setns(fd, CloneFlags::CLONE_NEWNET) {
                            init_fatal(err_w, &format!("setns netns failed: {}", e));
                        }
                    }
                }
            }

            // Fork for PID namespace
            match unsafe { unistd::fork() } {
                Err(_) => init_fatal(err_w, "fork for PID namespace failed"),
                Ok(ForkResult::Child) => {
                    child_init(config, signal_w, err_w);
                }
                Ok(ForkResult::Parent { child }) => {
                    let _ = nix::unistd::close(err_w);
                    let status = nix::sys::wait::waitpid(child, None);
                    let code = match status {
                        Ok(nix::sys::wait::WaitStatus::Exited(_, c)) => c,
                        _ => 1,
                    };
                    unsafe { libc::_exit(code) };
                }
            }
            // All child branches diverge (child_init→exec or _exit), never returns.
        }
        Ok(ForkResult::Parent { child }) => {
            // === PARENT: Phase 1 complete (fork done) ===
            let child_pid = child.as_raw();

            // Close child-side fds
            if config.tty {
                let _ = nix::unistd::close(stdin_r);
            } else {
                let _ = nix::unistd::close(stdin_r);
                let _ = nix::unistd::close(stdout_w);
            }
            let _ = nix::unistd::close(signal_w);
            let _ = nix::unistd::close(err_w);
            if let Some(urw) = userns_ready_w { let _ = nix::unistd::close(urw); }

            // UID/GID mapping
            if let Some(sw) = sync_w {
                // Wait for child to signal userns ready (via userns_ready pipe).
                // This blocks until child writes 1 byte after unshare — typically < 0.1ms.
                if let Some(urr) = userns_ready_r {
                    let mut buf = [0u8; 1];
                    let _ = unistd::read(borrow(urr), &mut buf);
                    let _ = nix::unistd::close(urr);
                }

                let outer_uid = rustix::process::getuid().as_raw();
                let outer_gid = rustix::process::getgid().as_raw();
                let pid_s = child_pid.to_string();

                if let Some((_, sub_start, sub_count)) = config.subuid_range {
                    let pid_s = child_pid.to_string();
                    let uid_s = outer_uid.to_string();
                    let gid_s = outer_gid.to_string();
                    let sub_s = sub_start.to_string();
                    let cnt_s = sub_count.to_string();
                    match std::process::Command::new("newuidmap")
                        .args([&pid_s, "0", &uid_s, "1", "1", &sub_s, &cnt_s]).output()
                    {
                        Ok(o) if !o.status.success() => log::warn!("newuidmap failed: {}", String::from_utf8_lossy(&o.stderr)),
                        Err(e) => log::warn!("newuidmap spawn failed: {}", e),
                        _ => {}
                    }
                    match std::process::Command::new("newgidmap")
                        .args([&pid_s, "0", &gid_s, "1", "1", &sub_s, &cnt_s]).output()
                    {
                        Ok(o) if !o.status.success() => log::warn!("newgidmap failed: {}", String::from_utf8_lossy(&o.stderr)),
                        Err(e) => log::warn!("newgidmap spawn failed: {}", e),
                        _ => {}
                    }
                } else {
                    if let Err(e) = std::fs::write(format!("/proc/{}/setgroups", pid_s), "deny\n") {
                        log::warn!("write setgroups failed: {}", e);
                    }
                    if let Err(e) = std::fs::write(format!("/proc/{}/uid_map", pid_s), format!("0 {} 1\n", outer_uid)) {
                        log::warn!("write uid_map failed: {}", e);
                    }
                    if let Err(e) = std::fs::write(format!("/proc/{}/gid_map", pid_s), format!("0 {} 1\n", outer_gid)) {
                        log::warn!("write gid_map failed: {}", e);
                    }
                }
                let _ = nix::unistd::close(sw);
            }

            // Non-blocking error pipe check.
            // Fatal messages are prefixed with "F:", warnings with "W:".
            // If child already exec'd → EOF (CLOEXEC closed err_w) → n=0.
            // If child still initializing → EAGAIN → treat as success (init_script will catch failures).
            // If child wrote a fatal error → kill child and report.
            // Otherwise, keep err_r open and return it so Python can read warnings later.
            {
                // Set non-blocking
                let _ = nix::fcntl::fcntl(
                    borrow(err_r),
                    nix::fcntl::FcntlArg::F_SETFL(nix::fcntl::OFlag::O_NONBLOCK),
                );
                let mut err_buf = [0u8; 4096];
                let n = match unistd::read(borrow(err_r), &mut err_buf) {
                    Ok(n) => n,
                    Err(nix::Error::EAGAIN) => 0, // child still running, not an error
                    Err(_) => 0,
                };
                if n > 0 {
                    let msg = String::from_utf8_lossy(&err_buf[..n]);
                    // Check if any line is a fatal error (F: prefix).
                    // The buffer may contain W: warnings before the fatal.
                    let has_fatal = msg.lines().any(|l| l.starts_with("F:"));
                    if has_fatal {
                        let _ = nix::unistd::close(err_r);
                        // Extract the fatal message and any preceding warnings
                        let detail: String = msg.lines()
                            .filter_map(|l| {
                                if l.starts_with("F:") { Some(l.trim_start_matches("F:").to_string()) }
                                else if l.starts_with("W:") { Some(format!("[warn] {}", l.trim_start_matches("W:"))) }
                                else if !l.is_empty() { Some(l.to_string()) }
                                else { None }
                            })
                            .collect::<Vec<_>>()
                            .join("; ");
                        let _ = nix::sys::signal::kill(Pid::from_raw(child_pid), nix::sys::signal::Signal::SIGKILL);
                        let _ = nix::sys::wait::waitpid(Pid::from_raw(child_pid), None);
                        let _ = nix::unistd::close(stdin_w);
                        let _ = nix::unistd::close(stdout_r);
                        let _ = nix::unistd::close(signal_r);
                        if let Some(mfd) = master_fd { let _ = nix::unistd::close(mfd); }
                        return Err(io::Error::new(io::ErrorKind::Other, format!("sandbox init failed: {}", detail)));
                    }
                    // Non-fatal data read — warnings are still in the pipe.
                    // We consumed some data; that's fine, Python will read the rest.
                    // But we can't un-read, so we accept loss of early warnings that
                    // were already buffered at this point.  In practice the parent
                    // reaches here before the child has written anything (EAGAIN).
                }
            }

            let pidfd_val = crate::pidfd::pidfd_open(child_pid).ok();

            Ok(SpawnResult {
                pid: child_pid,
                stdin_fd: stdin_w,
                stdout_fd: stdout_r,
                signal_r_fd: signal_r,
                signal_w_fd_num: signal_w,
                master_fd,
                pidfd: pidfd_val,
                err_r_fd: err_r,
            })
        }
    }
}

// ======================================================================
// Child init (PID 1): mount + security + exec
// ======================================================================

fn child_init(config: &SandboxSpawnConfig, signal_w: RawFd, err_w: RawFd) -> ! {
    // Store err_w in thread-local so helper functions can write warnings
    // without needing the fd threaded through every signature.
    ERR_W_FD.with(|c| c.set(err_w));

    // Create a new session inside the sandbox so that the shell (PID 1 in
    // its namespace) becomes its own session leader.  This is required for
    // CRIU: if the session leader lives outside the PID namespace that CRIU
    // is asked to dump, criu dump aborts with "session leader outside pid
    // namespace".  Moving setsid() here (into PID 1 of the namespace, not
    // the outer helper process) avoids that.
    rustix::process::setsid().ok();

    if config.rootful {
        if let Err(e) = do_pivot_root_phase1(&config.rootfs) {
            init_fatal(err_w, &format!("pivot_root failed: {}", e));
        }
        mount_proc("/", config.net_isolate);
        setup_dev_rootful("/");
        mount_shm("/", config.shm_size);
        // Mount host devices from /.pivot_old BEFORE we detach it.
        mount_devices_from_old_root("/", "/.pivot_old", &config.devices);
        // Mount volumes BEFORE detaching the old root: host paths in volume
        // specs (e.g. "/tmp/mydata") are accessible as
        // "/.pivot_old/tmp/mydata" while /.pivot_old is still attached.
        // env_dir also lives in the old root, needed for COW upper/work dirs.
        let env_dir_str = config.env_dir.as_deref();
        let env_dir_in_old_root = env_dir_str.map(|ed| {
            format!("/.pivot_old/{}", ed.trim_start_matches('/'))
        });
        mount_volumes_at(
            &config.volumes, "/",
            env_dir_in_old_root.as_deref(),
            "/.pivot_old",
        );
        // Now detach old root.
        cleanup_pivot_old();
        // Mount tmpfs inside the new root (no host paths, can be after cleanup).
        mount_tmpfs_at(&config.tmpfs_mounts, "/");
        apply_security(config);
    } else {
        if let Err(e) = mount_overlay_fs(config) {
            init_fatal(err_w, &format!("overlay mount failed: {}", e));
        }
        precreate_volume_mountpoints(config);
        if config.read_only { make_rootfs_readonly(&config.rootfs); }
        mount_proc(&config.rootfs, config.net_isolate);
        setup_dev_rootless(&config.rootfs);
        mount_shm(&config.rootfs, config.shm_size);
        mount_devices(&config.rootfs, &config.devices);
        propagate_dns(&config.rootfs);
        fix_tmp_perms(&config.rootfs);
        mount_volumes(config);
        mount_tmpfs(config);
        // Always mount tmpfs at /tmp to avoid overlayfs inode overflow
        // (EOVERFLOW / "Value too large for defined data type") when creating
        // temp files.  Only if /tmp is not already a user-requested tmpfs mount.
        if !config.tmpfs_mounts.iter().any(|s| s.starts_with("/tmp")) {
            let tmp_target = format!("{}/tmp", config.rootfs);
            let _ = std::fs::create_dir_all(&tmp_target);
            if let Err(e) = mnt(
                Some("tmpfs"), &tmp_target, Some("tmpfs"),
                MsFlags::empty(), Some("mode=1777"),
            ) {
                log::debug!("default tmpfs /tmp mount failed: {}", e);
            }
        }

        if !config.port_map.is_empty() {
            if let (Some(pb), Some(ed)) = (&config.pasta_bin, &config.env_dir) {
                setup_pasta_networking(pb, ed, &config.port_map, config.ipv6, "");
            }
        }

        if let Err(e) = rustix::process::chroot(&*config.rootfs) {
            init_fatal(err_w, &format!("chroot failed: {}", e));
        }
        rustix::process::chdir("/").ok();
        apply_security(config);
    }

    // Build exec args
    let mut exec_args: Vec<CString> = Vec::new();
    for arg in &config.entrypoint { exec_args.push(c(arg)); }
    for part in config.shell.split_whitespace() { exec_args.push(c(part)); }
    if config.shell.contains("bash") && !exec_args.iter().any(|a| a.to_str() == Ok("--norc")) {
        exec_args.push(c("--norc"));
        exec_args.push(c("--noprofile"));
    }

    // Build env
    let mut env_vec: Vec<CString> = config.env.iter()
        .map(|(k, v)| c(&format!("{}={}", k, v)))
        .collect();
    env_vec.push(c(&format!("_ADL_SIGNAL_FD={}", signal_w)));

    // Working directory
    rustix::process::chdir(&*config.working_dir).ok();

    // Clear CLOEXEC on signal_w so it survives exec
    let _ = nix::fcntl::fcntl(
        borrow(signal_w),
        nix::fcntl::FcntlArg::F_SETFD(nix::fcntl::FdFlag::empty()),
    );

    // Exec via nix — on success this never returns; on failure we report and exit.
    let e = unistd::execve(&exec_args[0], &exec_args, &env_vec).unwrap_err();
    init_fatal(err_w, &format!("exec {} failed: {}", config.shell, e));
}
