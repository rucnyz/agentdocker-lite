//! Convert OCI whiteout files to overlayfs-native format.
//!
//! OCI images use `.wh.<name>` sentinel files to represent deletions.
//! overlayfs uses either xattrs or char device (0,0) nodes.  This module
//! does the conversion in-place using direct syscalls — no subprocess
//! spawning (the Python version spawned `setfattr` per file).

use std::ffi::CString;
use std::fs;
use std::io;
use std::path::Path;

/// Convert OCI whiteouts in a layer directory to overlayfs-native format.
///
/// `use_user_xattr`: true → `user.overlay.*` (rootless, kernel ≥ 6.7),
///                   false → `trusted.overlay.*` + mknod(0,0) (root).
///
/// Returns the number of whiteout files converted.
pub fn convert_whiteouts(layer_dir: &Path, use_user_xattr: bool) -> io::Result<u32> {
    let prefix = if use_user_xattr {
        "user.overlay"
    } else {
        "trusted.overlay"
    };
    let mut count = 0u32;
    walk_and_convert(layer_dir, prefix, use_user_xattr, &mut count)?;
    Ok(count)
}

fn walk_and_convert(
    dir: &Path,
    prefix: &str,
    use_user_xattr: bool,
    count: &mut u32,
) -> io::Result<()> {
    // Collect entries first — we'll modify the directory during iteration.
    let entries: Vec<_> = fs::read_dir(dir)?.collect::<Result<Vec<_>, _>>()?;

    for entry in &entries {
        let ft = entry.file_type()?;

        // Recurse into subdirectories first.
        if ft.is_dir() {
            walk_and_convert(&entry.path(), prefix, use_user_xattr, count)?;
        }

        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !name.starts_with(".wh.") {
            continue;
        }

        let wh_path = entry.path();

        if *name == *".wh..wh..opq" {
            // Opaque directory marker: delete sentinel, set xattr on parent.
            fs::remove_file(&wh_path)?;
            let val = if use_user_xattr { b"x" as &[u8] } else { b"y" };
            set_xattr(dir, &format!("{prefix}.opaque"), val)?;
        } else {
            // File deletion: delete sentinel, create native whiteout.
            let target_name = &name[4..]; // strip ".wh."
            let target_path = dir.join(target_name);
            fs::remove_file(&wh_path)?;

            if use_user_xattr {
                fs::File::create(&target_path)?;
                set_xattr(&target_path, &format!("{prefix}.whiteout"), b"y")?;
            } else {
                mknod_whiteout(&target_path)?;
            }
        }
        *count += 1;
    }
    Ok(())
}

// ------------------------------------------------------------------ //
//  Syscall helpers                                                     //
// ------------------------------------------------------------------ //

fn path_to_cstr(p: &Path) -> io::Result<CString> {
    CString::new(p.as_os_str().as_encoded_bytes())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))
}

fn set_xattr(path: &Path, name: &str, value: &[u8]) -> io::Result<()> {
    let c_path = path_to_cstr(path)?;
    let c_name = CString::new(name).map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e))?;

    let ret = unsafe {
        libc::setxattr(
            c_path.as_ptr(),
            c_name.as_ptr(),
            value.as_ptr().cast::<libc::c_void>(),
            value.len(),
            0, // flags: create or replace
        )
    };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

fn mknod_whiteout(path: &Path) -> io::Result<()> {
    let c_path = path_to_cstr(path)?;
    // char device (0,0), mode 0600
    let mode = 0o600 | libc::S_IFCHR;
    let dev = libc::makedev(0, 0);

    let ret = unsafe { libc::mknod(c_path.as_ptr(), mode, dev) };
    if ret < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}
