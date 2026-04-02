//! Overlay mount helpers.
//!
//! 1. **New mount API** (kernel >= 6.8): rustix `fsopen` + `fsconfig_set_string`
//!    with `lowerdir+` per-layer append. No length limit per layer.
//! 2. **Legacy mount(2)** fallback via nix: single syscall, `PAGE_SIZE` limit.

use std::io;
use std::sync::OnceLock;

// --- feature detection ---

static NEW_API_SUPPORTED: OnceLock<bool> = OnceLock::new();

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
) -> io::Result<()> {
    let fd = rustix::mount::fsopen("overlay", rustix::mount::FsOpenFlags::FSOPEN_CLOEXEC)?;

    // Add each lower layer individually (lowerdir+ appends top-to-bottom)
    for layer in lower_dirs {
        rustix::mount::fsconfig_set_string(&fd, "lowerdir+", *layer)?;
    }

    rustix::mount::fsconfig_set_string(&fd, "upperdir", upper_dir)?;
    rustix::mount::fsconfig_set_string(&fd, "workdir", work_dir)?;
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
) -> io::Result<()> {
    let options = format!("lowerdir={lowerdir_spec},upperdir={upper_dir},workdir={work_dir}");

    nix::mount::mount(
        Some("overlay"),
        target,
        Some("overlay"),
        nix::mount::MsFlags::empty(),
        Some(options.as_str()),
    )
    .map_err(|e| io::Error::from_raw_os_error(e as i32))
}

// --- public API ---

/// Mount overlayfs, auto-selecting the best available method.
pub fn mount_overlay(
    lowerdir_spec: &str,
    upper_dir: &str,
    work_dir: &str,
    target: &str,
) -> io::Result<()> {
    let lower_dirs: Vec<&str> = lowerdir_spec.split(':').collect();

    if check_new_mount_api() {
        match mount_overlay_new_api(&lower_dirs, upper_dir, work_dir, target) {
            Ok(()) => return Ok(()),
            Err(e) => {
                log::warn!("New mount API failed, falling back to legacy mount(2): {e}");
            }
        }
    }

    mount_overlay_legacy(lowerdir_spec, upper_dir, work_dir, target)
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
