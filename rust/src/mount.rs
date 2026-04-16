//! Overlay mount helpers.
//!
//! 1. **New mount API** (kernel >= 6.8): rustix `fsopen` + `fsconfig_set_string`
//!    with `lowerdir+` per-layer append. No length limit per layer.
//! 2. **Legacy mount(2)** fallback via nix: single syscall, `PAGE_SIZE` limit.

use std::io;
use std::sync::OnceLock;

// --- overlay parameter detection (matching buildkit overlayutils) ---

static NEW_API_SUPPORTED: OnceLock<bool> = OnceLock::new();
static OVERLAY_INDEX_OFF: OnceLock<bool> = OnceLock::new();
static OVERLAY_REDIRECT_DIR_OFF: OnceLock<bool> = OnceLock::new();

/// Check if `userxattr` is needed and supported (matching buildkit's
/// `NeedsUserXAttr`).  Kernel >= 5.11 in a user namespace always
/// needs it; older kernels with backports may or may not support it.
pub fn needs_userxattr() -> bool {
    *OVERLAY_USERXATTR.get_or_init(|| {
        // Parse kernel version from /proc/version
        let Ok(ver) = std::fs::read_to_string("/proc/version") else {
            return false;
        };
        // "Linux version 6.8.0-87-generic ..."
        let (major, minor) = parse_kernel_version(&ver);
        if major > 5 || (major == 5 && minor >= 11) {
            return true;
        }
        // Pre-5.11: conservative — don't use userxattr
        log::debug!("Kernel {major}.{minor} < 5.11, skipping userxattr");
        false
    })
}

static OVERLAY_USERXATTR: OnceLock<bool> = OnceLock::new();

fn parse_kernel_version(ver: &str) -> (u32, u32) {
    // "Linux version 6.8.0-87-generic ..." → (6, 8)
    for word in ver.split_whitespace() {
        if let Some(dot) = word.find('.') {
            if let Ok(major) = word[..dot].parse::<u32>() {
                let rest = &word[dot + 1..];
                let minor_end = rest
                    .find(|c: char| !c.is_ascii_digit())
                    .unwrap_or(rest.len());
                let minor = rest[..minor_end].parse::<u32>().unwrap_or(0);
                return (major, minor);
            }
        }
    }
    (0, 0)
}

/// Check if the overlay module supports the `index` parameter.
fn overlay_supports_index() -> bool {
    *OVERLAY_INDEX_OFF.get_or_init(|| {
        std::fs::read_to_string("/sys/module/overlay/parameters/index")
            .is_ok_and(|s| !s.trim().is_empty())
    })
}

/// Check if the overlay module supports `redirect_dir` (and it's enabled).
/// If enabled, we should explicitly set `redirect_dir=off` to avoid rename
/// issues (matching buildkit's `setRedirectDir` logic).
fn overlay_redirect_dir_needs_off() -> bool {
    *OVERLAY_REDIRECT_DIR_OFF.get_or_init(|| {
        std::fs::read_to_string("/sys/module/overlay/parameters/redirect_dir").is_ok_and(|s| {
            let v = s.trim();
            // "Y" or "y" or "on" means enabled → we need to disable it
            v.eq_ignore_ascii_case("y") || v.eq_ignore_ascii_case("on")
        })
    })
}

pub fn check_new_mount_api() -> bool {
    *NEW_API_SUPPORTED.get_or_init(|| {
        let Ok(fd) = rustix::mount::fsopen("overlay", rustix::mount::FsOpenFlags::FSOPEN_CLOEXEC)
        else {
            return false;
        };

        // Try lowerdir+ — if kernel < 6.8, this will EINVAL
        let supported = rustix::mount::fsconfig_set_string(&fd, "lowerdir+", "/").is_ok();

        log::debug!("New mount API (lowerdir+): {supported}");
        supported
    })
}

// --- new mount API via rustix ---

fn mount_overlay_new_api(
    lower_dirs: &[&str],
    upper_dir: &str,
    work_dir: &str,
    target: &str,
    extra_opts: &[&str],
) -> io::Result<()> {
    let fd = rustix::mount::fsopen("overlay", rustix::mount::FsOpenFlags::FSOPEN_CLOEXEC)?;

    // Add each lower layer individually (lowerdir+ appends top-to-bottom)
    for layer in lower_dirs {
        rustix::mount::fsconfig_set_string(&fd, "lowerdir+", *layer)?;
    }

    rustix::mount::fsconfig_set_string(&fd, "upperdir", upper_dir)?;
    rustix::mount::fsconfig_set_string(&fd, "workdir", work_dir)?;

    // Extra options (e.g. "userxattr" for rootless)
    for opt in extra_opts {
        if let Some((key, val)) = opt.split_once('=') {
            rustix::mount::fsconfig_set_string(&fd, key, val)?;
        } else {
            // Boolean flag — use fsconfig_set_flag
            rustix::mount::fsconfig_set_flag(&fd, *opt)?;
        }
    }

    rustix::mount::fsconfig_create(&fd)?;

    let mnt = rustix::mount::fsmount(
        &fd,
        rustix::mount::FsMountFlags::FSMOUNT_CLOEXEC,
        rustix::mount::MountAttrFlags::empty(),
    )?;

    rustix::mount::move_mount(
        &mnt,
        "",
        rustix::fs::CWD,
        target,
        rustix::mount::MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH,
    )?;

    Ok(())
}

// --- legacy mount(2) via nix ---

fn mount_overlay_legacy(
    lowerdir_spec: &str,
    upper_dir: &str,
    work_dir: &str,
    target: &str,
    extra_opts: &[&str],
) -> io::Result<()> {
    let mut options = format!("lowerdir={lowerdir_spec},upperdir={upper_dir},workdir={work_dir}");
    for opt in extra_opts {
        options.push(',');
        options.push_str(opt);
    }

    let page_size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) } as usize;

    if options.len() < page_size {
        // Fast path: mount data fits in a page
        return nix::mount::mount(
            Some("overlay"),
            target,
            Some("overlay"),
            nix::mount::MsFlags::empty(),
            Some(options.as_str()),
        )
        .map_err(|e| io::Error::from_raw_os_error(e as i32));
    }

    // Podman trick: fork, chdir to common prefix, use relative paths.
    // Find common prefix of all lowerdirs to shorten paths.
    let lowers: Vec<&str> = lowerdir_spec.split(':').collect();
    let common = common_path_prefix(&lowers);
    if common.is_empty() {
        return Err(io::Error::other(format!(
            "overlay mount data ({} bytes) exceeds page size ({page_size}), \
             no common prefix for relative path fallback",
            options.len(),
        )));
    }

    let rel_lowers: Vec<String> = lowers
        .iter()
        .map(|l| {
            l.strip_prefix(&common)
                .unwrap_or(l)
                .trim_start_matches('/')
                .to_string()
        })
        .collect();
    let rel_spec = rel_lowers.join(":");
    let mut rel_options = format!("lowerdir={rel_spec},upperdir={upper_dir},workdir={work_dir}");
    for opt in extra_opts {
        rel_options.push(',');
        rel_options.push_str(opt);
    }

    log::debug!(
        "overlay legacy: mount data too long ({} bytes), using chdir to {common} ({} bytes)",
        options.len(),
        rel_options.len(),
    );

    // Fork + chdir + mount (matching Podman's mountOverlayFrom).
    // Two-level fallback:
    //   1. chdir to common prefix, use relative paths
    //   2. open() each lowerdir as fd, chdir to /proc/self/fd, use fd numbers
    let lowers_clone = lowers.iter().map(ToString::to_string).collect::<Vec<_>>();
    let upper_s = upper_dir.to_string();
    let work_s = work_dir.to_string();
    let target_s = target.to_string();
    let extra_s: Vec<String> = extra_opts.iter().map(ToString::to_string).collect();

    match unsafe { nix::unistd::fork() } {
        Ok(nix::unistd::ForkResult::Child) => {
            let code = mount_overlay_from_child(
                &common,
                &lowers_clone,
                &upper_s,
                &work_s,
                &target_s,
                &extra_s,
                page_size,
            );
            unsafe { libc::_exit(code) };
        }
        Ok(nix::unistd::ForkResult::Parent { child }) => {
            let status = nix::sys::wait::waitpid(child, None)
                .map_err(|e| io::Error::from_raw_os_error(e as i32))?;
            match status {
                nix::sys::wait::WaitStatus::Exited(_, 0) => Ok(()),
                _ => Err(io::Error::other(
                    "overlay mount failed in chdir child process",
                )),
            }
        }
        Err(e) => Err(io::Error::from_raw_os_error(e as i32)),
    }
}

/// Child process: try relative paths, then fd-based paths (matching Podman).
fn mount_overlay_from_child(
    common: &str,
    lowers: &[String],
    upper_dir: &str,
    work_dir: &str,
    target: &str,
    extra_opts: &[String],
    page_size: usize,
) -> i32 {
    // Level 1: chdir to common prefix, use relative lowerdir paths
    let _ = nix::unistd::chdir(common);
    let rel_lowers: Vec<String> = lowers
        .iter()
        .map(|l| {
            l.strip_prefix(common)
                .unwrap_or(l)
                .trim_start_matches('/')
                .to_string()
        })
        .collect();
    let rel_spec = rel_lowers.join(":");
    let mut opts = format!("lowerdir={rel_spec},upperdir={upper_dir},workdir={work_dir}");
    for o in extra_opts {
        opts.push(',');
        opts.push_str(o);
    }

    if opts.len() < page_size {
        let ret = nix::mount::mount(
            Some("overlay"),
            target,
            Some("overlay"),
            nix::mount::MsFlags::empty(),
            Some(opts.as_str()),
        );
        return i32::from(ret.is_err());
    }

    // Level 2: open each lowerdir as fd, use /proc/self/fd/<n> paths
    // (matching Podman mount.go:139-163)
    let mut fds: Vec<std::os::fd::OwnedFd> = Vec::new();
    for lower in lowers {
        match nix::fcntl::open(
            lower.as_str(),
            nix::fcntl::OFlag::O_RDONLY,
            nix::sys::stat::Mode::empty(),
        ) {
            Ok(fd) => fds.push(fd),
            Err(_) => return 1,
        }
    }
    let fd_lowers: Vec<String> = fds
        .iter()
        .map(|fd| {
            use std::os::fd::AsRawFd;
            fd.as_raw_fd().to_string()
        })
        .collect();
    let fd_spec = fd_lowers.join(":");
    opts = format!("lowerdir={fd_spec},upperdir={upper_dir},workdir={work_dir}");
    for o in extra_opts {
        opts.push(',');
        opts.push_str(o);
    }

    if opts.len() >= page_size {
        return 1; // still too long, give up
    }

    let _ = nix::unistd::chdir("/proc/self/fd");
    let ret = nix::mount::mount(
        Some("overlay"),
        target,
        Some("overlay"),
        nix::mount::MsFlags::empty(),
        Some(opts.as_str()),
    );
    i32::from(ret.is_err())
}

/// Find the longest common directory prefix among paths.
fn common_path_prefix(paths: &[&str]) -> String {
    if paths.is_empty() {
        return String::new();
    }
    let first = paths[0];
    let mut end = first.len();
    for p in &paths[1..] {
        end = end.min(p.len());
        for (i, (a, b)) in first.bytes().zip(p.bytes()).enumerate() {
            if a != b || i >= end {
                end = i;
                break;
            }
        }
    }
    // Truncate to last '/'
    match first[..end].rfind('/') {
        Some(i) => first[..=i].to_string(),
        None => String::new(),
    }
}

// --- public API ---

/// Mount overlayfs, auto-selecting the best available method.
///
/// `extra_opts`: additional mount options (e.g. `&["userxattr"]` for rootless).
/// Passed as individual `fsconfig` flags in the new API, or comma-joined in
/// the legacy `mount(2)` data string.
///
/// Automatically adds `index=off` and `redirect_dir=off` when the kernel
/// overlay module supports them (matching buildkit's overlay snapshotter).
pub fn mount_overlay(
    lowerdir_spec: &str,
    upper_dir: &str,
    work_dir: &str,
    target: &str,
    extra_opts: &[&str],
) -> io::Result<()> {
    let lower_dirs: Vec<&str> = lowerdir_spec.split(':').collect();

    // Build effective options: caller's extra_opts + auto-detected overlay params
    let mut opts: Vec<&str> = extra_opts.to_vec();
    let has_userxattr = opts.contains(&"userxattr");

    if overlay_supports_index() {
        opts.push("index=off");
    }
    // redirect_dir conflicts with userxattr in userns (matching buildkit)
    if !has_userxattr && overlay_redirect_dir_needs_off() {
        opts.push("redirect_dir=off");
    }

    if check_new_mount_api() {
        match mount_overlay_new_api(&lower_dirs, upper_dir, work_dir, target, &opts) {
            Ok(()) => return Ok(()),
            Err(e) => {
                log::warn!("New mount API failed, falling back to legacy mount(2): {e}");
            }
        }
    }

    mount_overlay_legacy(lowerdir_spec, upper_dir, work_dir, target, &opts)
}

/// Bind mount `source` onto `target`.
pub fn bind_mount(source: &str, target: &str) -> io::Result<()> {
    nix::mount::mount(
        Some(source),
        target,
        None::<&str>,
        nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Recursive bind mount (`mount --rbind`).
pub fn rbind_mount(source: &str, target: &str) -> io::Result<()> {
    nix::mount::mount(
        Some(source),
        target,
        None::<&str>,
        nix::mount::MsFlags::MS_BIND | nix::mount::MsFlags::MS_REC,
        None::<&str>,
    )
    .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Make a mount point private (`mount --make-private`).
pub fn make_private(target: &str) -> io::Result<()> {
    nix::mount::mount(
        None::<&str>,
        target,
        None::<&str>,
        nix::mount::MsFlags::MS_PRIVATE,
        None::<&str>,
    )
    .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Remount a bind mount as read-only (`mount -o remount,ro,bind`).
pub fn remount_ro_bind(target: &str) -> io::Result<()> {
    nix::mount::mount(
        None::<&str>,
        target,
        None::<&str>,
        nix::mount::MsFlags::MS_REMOUNT
            | nix::mount::MsFlags::MS_RDONLY
            | nix::mount::MsFlags::MS_BIND,
        None::<&str>,
    )
    .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Lazy unmount (`umount -l`).
pub fn umount_lazy(target: &str) -> io::Result<()> {
    nix::mount::umount2(target, nix::mount::MntFlags::MNT_DETACH)
        .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Regular unmount.
pub fn umount(target: &str) -> io::Result<()> {
    nix::mount::umount2(target, nix::mount::MntFlags::empty())
        .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

/// Recursive lazy unmount (`umount -R -l`).
///
/// First tries recursive unmount via `MNT_DETACH`.  The kernel doesn't
/// have a single "recursive + detach" flag, so we scan `/proc/self/mountinfo`
/// and lazily unmount every sub-mount bottom-up before the target itself.
pub fn umount_recursive_lazy(target: &str) -> io::Result<()> {
    // Read mountinfo to find all sub-mounts under `target`.
    let minfo = std::fs::read_to_string("/proc/self/mountinfo")?;
    let mut sub_mounts: Vec<String> = Vec::new();

    for line in minfo.lines() {
        // Fields: id parent_id major:minor root mount_point ...
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() >= 5 {
            let mount_point = fields[4];
            if mount_point.starts_with(target) {
                sub_mounts.push(mount_point.to_string());
            }
        }
    }

    // Sort by length descending (deepest first).
    sub_mounts.sort_by_key(|m| std::cmp::Reverse(m.len()));

    for mp in &sub_mounts {
        let _ = nix::mount::umount2(mp.as_str(), nix::mount::MntFlags::MNT_DETACH);
    }

    Ok(())
}
