//! Kernel-level security hardening: seccomp-bpf + Landlock + capability drop.
//!
//! - Capabilities: rustix `remove_capability_from_bounding_set`
//! - `NO_NEW_PRIVS`: rustix `set_no_new_privs`
//! - Seccomp BPF: libc `prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)`
//!   (rustix's `set_secure_computing_mode` doesn't accept a filter program)
//! - Landlock: libc syscall (no crate wraps landlock structs)

use std::io;
use std::os::unix::io::RawFd;
use std::path::Path;

// ======================================================================
// Capabilities — via rustix CapabilitySet
// ======================================================================

use rustix::thread::CapabilitySet;

/// Docker default: capability numbers to KEEP (everything else is dropped).
const DOCKER_DEFAULT_CAPS: &[u32] = &[
    0,  // CAP_CHOWN
    1,  // CAP_DAC_OVERRIDE
    3,  // CAP_FOWNER
    4,  // CAP_FSETID
    5,  // CAP_KILL
    6,  // CAP_SETGID
    7,  // CAP_SETUID
    8,  // CAP_SETPCAP
    10, // CAP_NET_BIND_SERVICE
    18, // CAP_SYS_CHROOT
    27, // CAP_MKNOD
    29, // CAP_AUDIT_WRITE
    31, // CAP_SETFCAP
];

const CAP_LAST_CAP: u32 = 41;

/// Drop all capabilities except Docker defaults + `extra_keep` from bounding set.
pub fn drop_capabilities(extra_keep: &[u32]) -> io::Result<u32> {
    let mut dropped: u32 = 0;
    for cap_num in 0..=CAP_LAST_CAP {
        if DOCKER_DEFAULT_CAPS.contains(&cap_num) || extra_keep.contains(&cap_num) {
            continue;
        }
        let cap = CapabilitySet::from_bits_retain(1u64 << cap_num);
        if rustix::thread::remove_capability_from_bounding_set(cap).is_ok() {
            dropped += 1;
        }
    }
    log::debug!("Dropped {dropped} capabilities from bounding set");
    Ok(dropped)
}

// ======================================================================
// seccomp-bpf — BPF bytecode generation + install via libc prctl
// ======================================================================

// BPF instruction encoding (using libc::sock_filter)
const BPF_LD: u16 = 0x00;
const BPF_W: u16 = 0x00;
const BPF_ABS: u16 = 0x20;
const BPF_JMP: u16 = 0x05;
const BPF_JEQ: u16 = 0x10;
const BPF_JSET: u16 = 0x40;
const BPF_K: u16 = 0x00;
const BPF_RET: u16 = 0x06;

const SECCOMP_RET_ALLOW: u32 = 0x7FFF_0000;
const SECCOMP_RET_ERRNO: u32 = 0x0005_0000;
const SECCOMP_RET_KILL_PROCESS: u32 = 0x8000_0000;
const SECCOMP_RET_ENOSYS: u32 = SECCOMP_RET_ERRNO | 0x26; // ENOSYS = 38

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
#[cfg(target_arch = "aarch64")]
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;

const CLONE_NS_FLAGS: u32 =
    0x0002_0000 | 0x0400_0000 | 0x0800_0000 | 0x1000_0000 | 0x2000_0000 | 0x4000_0000 | 0x0000_0080;

const TIOCSTI: u32 = 0x5412;

fn bpf_stmt(code: u16, k: u32) -> libc::sock_filter {
    libc::sock_filter {
        code,
        jt: 0,
        jf: 0,
        k,
    }
}

fn bpf_jump(code: u16, k: u32, jt: u8, jf: u8) -> libc::sock_filter {
    libc::sock_filter { code, jt, jf, k }
}

struct ArchConfig {
    audit_arch: u32,
    blocked: &'static [(u32, &'static str)],
    clone_nr: u32,
    clone3_nr: u32,
    ioctl_nr: u32,
}

#[cfg(target_arch = "x86_64")]
static ARCH: ArchConfig = ArchConfig {
    audit_arch: AUDIT_ARCH_X86_64,
    blocked: &[
        (101, "ptrace"),
        (165, "mount"),
        (166, "umount2"),
        (155, "pivot_root"),
        (272, "unshare"),
        (308, "setns"),
        (175, "init_module"),
        (313, "finit_module"),
        (176, "delete_module"),
        (246, "kexec_load"),
        (320, "kexec_file_load"),
        (169, "reboot"),
        (170, "sethostname"),
        (171, "setdomainname"),
        (167, "swapon"),
        (168, "swapoff"),
        (163, "acct"),
        (310, "process_vm_readv"),
        (311, "process_vm_writev"),
        (304, "open_by_handle_at"),
        (303, "name_to_handle_at"),
        (321, "bpf"),
        (298, "perf_event_open"),
        (323, "userfaultfd"),
        (250, "keyctl"),
        (248, "add_key"),
        (249, "request_key"),
        (173, "ioperm"),
        (172, "iopl"),
        (425, "io_uring_setup"),
        (426, "io_uring_enter"),
        (427, "io_uring_register"),
    ],
    clone_nr: 56,
    clone3_nr: 435,
    ioctl_nr: 16,
};

#[cfg(target_arch = "aarch64")]
static ARCH: ArchConfig = ArchConfig {
    audit_arch: AUDIT_ARCH_AARCH64,
    blocked: &[
        (117, "ptrace"),
        (40, "mount"),
        (39, "umount2"),
        (41, "pivot_root"),
        (97, "unshare"),
        (268, "setns"),
        (105, "init_module"),
        (273, "finit_module"),
        (106, "delete_module"),
        (104, "kexec_load"),
        (294, "kexec_file_load"),
        (142, "reboot"),
        (161, "sethostname"),
        (162, "setdomainname"),
        (224, "swapon"),
        (225, "swapoff"),
        (89, "acct"),
        (270, "process_vm_readv"),
        (271, "process_vm_writev"),
        (265, "open_by_handle_at"),
        (264, "name_to_handle_at"),
        (280, "bpf"),
        (241, "perf_event_open"),
        (282, "userfaultfd"),
        (219, "keyctl"),
        (217, "add_key"),
        (218, "request_key"),
        (425, "io_uring_setup"),
        (426, "io_uring_enter"),
        (427, "io_uring_register"),
    ],
    clone_nr: 220,
    clone3_nr: 435,
    ioctl_nr: 29,
};

/// Build seccomp BPF bytecode.
#[allow(clippy::vec_init_then_push)]
#[must_use]
pub fn build_seccomp_bpf() -> Vec<u8> {
    let mut syscall_nrs: Vec<u32> = ARCH.blocked.iter().map(|(nr, _)| *nr).collect();
    syscall_nrs.sort_unstable();

    let mut insns: Vec<libc::sock_filter> = Vec::new();

    // 1. Arch check
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 4));
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, ARCH.audit_arch, 1, 0));
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_KILL_PROCESS));

    // 2. clone(2): allow threads, block namespace creation
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0));
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, ARCH.clone_nr, 0, 4));
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16));
    insns.push(bpf_jump(BPF_JMP | BPF_JSET | BPF_K, CLONE_NS_FLAGS, 0, 1));
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1));
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0));

    // 3. clone3 → ENOSYS
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, ARCH.clone3_nr, 0, 1));
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ENOSYS));

    // 4. ioctl(TIOCSTI)
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, ARCH.ioctl_nr, 0, 4));
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 16));
    insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, TIOCSTI, 0, 1));
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1));
    insns.push(bpf_stmt(BPF_LD | BPF_W | BPF_ABS, 0));

    // 5. Blocklist
    let n = syscall_nrs.len();
    for (i, nr) in syscall_nrs.iter().enumerate() {
        insns.push(bpf_jump(BPF_JMP | BPF_JEQ | BPF_K, *nr, (n - i) as u8, 0));
    }
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ALLOW));
    insns.push(bpf_stmt(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | 1));

    let byte_len = insns.len() * std::mem::size_of::<libc::sock_filter>();
    let ptr = insns.as_ptr().cast::<u8>();
    unsafe { std::slice::from_raw_parts(ptr, byte_len) }.to_vec()
}

/// Apply seccomp-bpf filter. Uses rustix for `NO_NEW_PRIVS`, libc for the filter install.
pub fn apply_seccomp_filter() -> io::Result<()> {
    let bpf_bytes = build_seccomp_bpf();
    let n_insns = bpf_bytes.len() / std::mem::size_of::<libc::sock_filter>();

    let prog = libc::sock_fprog {
        len: n_insns as u16,
        filter: bpf_bytes.as_ptr() as *mut libc::sock_filter,
    };

    // NO_NEW_PRIVS via rustix (type-safe)
    rustix::thread::set_no_new_privs(true)?;

    // Install BPF filter via libc (rustix doesn't support SECCOMP_MODE_FILTER with a program)
    let ret = unsafe {
        libc::prctl(
            libc::PR_SET_SECCOMP,
            libc::c_ulong::from(libc::SECCOMP_MODE_FILTER),
            &raw const prog as libc::c_ulong,
            0,
            0,
        )
    };
    if ret != 0 {
        return Err(io::Error::last_os_error());
    }

    log::debug!(
        "seccomp: blocked {} syscalls + clone NS flags + ioctl TIOCSTI",
        ARCH.blocked.len()
    );
    Ok(())
}

// ======================================================================
// Landlock — libc syscall (no crate wraps landlock structs)
// ======================================================================

const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;

const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
const LANDLOCK_ACCESS_FS_IOCTL_DEV: u64 = 1 << 15;

const LANDLOCK_ACCESS_NET_BIND_TCP: u64 = 1 << 0;
const LANDLOCK_ACCESS_NET_CONNECT_TCP: u64 = 1 << 1;

const LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET: u64 = 1 << 0;
const LANDLOCK_SCOPE_SIGNAL: u64 = 1 << 1;

const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
const LANDLOCK_RULE_NET_PORT: u32 = 2;

const LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON: u32 = 1 << 1;
const LANDLOCK_RESTRICT_SELF_TSYNC: u32 = 1 << 3;

const FS_READ: u64 =
    LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;

const FS_WRITE_V1: u64 = LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_REMOVE_DIR
    | LANDLOCK_ACCESS_FS_REMOVE_FILE
    | LANDLOCK_ACCESS_FS_MAKE_CHAR
    | LANDLOCK_ACCESS_FS_MAKE_DIR
    | LANDLOCK_ACCESS_FS_MAKE_REG
    | LANDLOCK_ACCESS_FS_MAKE_SOCK
    | LANDLOCK_ACCESS_FS_MAKE_FIFO
    | LANDLOCK_ACCESS_FS_MAKE_BLOCK
    | LANDLOCK_ACCESS_FS_MAKE_SYM;

#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
    handled_access_net: u64,
    scoped: u64,
}

#[repr(C)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: i32,
}

#[repr(C)]
struct LandlockNetPortAttr {
    allowed_access: u64,
    port: u64,
}

unsafe fn ll_syscall(nr: libc::c_long, args: &[usize]) -> libc::c_long {
    match args.len() {
        2 => unsafe { libc::syscall(nr, args[0], args[1]) },
        3 => unsafe { libc::syscall(nr, args[0], args[1], args[2]) },
        4 => unsafe { libc::syscall(nr, args[0], args[1], args[2], args[3]) },
        _ => -1,
    }
}

/// Query kernel Landlock ABI version. Returns 0 if unavailable.
#[must_use]
pub fn landlock_abi_version() -> u32 {
    let ret = unsafe {
        ll_syscall(
            libc::SYS_landlock_create_ruleset,
            &[0, 0, LANDLOCK_CREATE_RULESET_VERSION as usize],
        )
    };
    if ret > 0 { ret as u32 } else { 0 }
}

fn fs_write_mask(abi: u32) -> u64 {
    let mut mask = FS_WRITE_V1;
    if abi >= 2 {
        mask |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= 3 {
        mask |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    if abi >= 5 {
        mask |= LANDLOCK_ACCESS_FS_IOCTL_DEV;
    }
    mask
}

fn add_path_rule(ruleset_fd: RawFd, path: &str, access: u64) -> io::Result<()> {
    if !Path::new(path).exists() {
        return Ok(());
    }
    let mut flags = libc::O_PATH | libc::O_CLOEXEC;
    if Path::new(path).is_dir() {
        flags |= libc::O_DIRECTORY;
    }
    let path_c = std::ffi::CString::new(path)?;
    let fd = unsafe { libc::open(path_c.as_ptr(), flags) };
    if fd < 0 {
        return Err(io::Error::last_os_error());
    }
    let rule = LandlockPathBeneathAttr {
        allowed_access: access,
        parent_fd: fd,
    };
    unsafe {
        ll_syscall(
            libc::SYS_landlock_add_rule,
            &[
                ruleset_fd as usize,
                LANDLOCK_RULE_PATH_BENEATH as usize,
                &raw const rule as usize,
                0,
            ],
        );
        libc::close(fd);
    }
    Ok(())
}

/// Apply Landlock filesystem + network restrictions.
pub fn apply_landlock(
    read_paths: &[String],
    write_paths: &[String],
    allowed_tcp_ports: &[u16],
    strict: bool,
) -> io::Result<bool> {
    let abi = landlock_abi_version();
    if abi == 0 {
        let msg = "Landlock not available (kernel < 5.13)";
        if strict {
            return Err(io::Error::new(io::ErrorKind::Unsupported, msg));
        }
        log::debug!("{msg}");
        return Ok(false);
    }

    let fs_write = fs_write_mask(abi);
    let write_only_mask = fs_write & !FS_READ;

    let mut handled_fs: u64 = 0;
    if !read_paths.is_empty() {
        handled_fs |= FS_READ;
    }
    if !write_paths.is_empty() {
        if read_paths.is_empty() {
            handled_fs |= write_only_mask;
        } else {
            handled_fs |= fs_write;
        }
    }

    let handled_net = if !allowed_tcp_ports.is_empty() && abi >= 4 {
        LANDLOCK_ACCESS_NET_BIND_TCP | LANDLOCK_ACCESS_NET_CONNECT_TCP
    } else {
        0
    };

    let scoped = if abi >= 6 {
        LANDLOCK_SCOPE_ABSTRACT_UNIX_SOCKET | LANDLOCK_SCOPE_SIGNAL
    } else {
        0
    };

    let attr = LandlockRulesetAttr {
        handled_access_fs: handled_fs,
        handled_access_net: handled_net,
        scoped,
    };
    let ruleset_fd = unsafe {
        ll_syscall(
            libc::SYS_landlock_create_ruleset,
            &[
                &raw const attr as usize,
                std::mem::size_of::<LandlockRulesetAttr>(),
                0,
            ],
        )
    };
    if ruleset_fd < 0 {
        let msg = format!(
            "landlock_create_ruleset failed: {}",
            io::Error::last_os_error()
        );
        if strict {
            return Err(io::Error::other(msg));
        }
        log::warn!("{msg}");
        return Ok(false);
    }
    let ruleset_fd = ruleset_fd as RawFd;

    let result = (|| -> io::Result<bool> {
        for path in read_paths {
            add_path_rule(ruleset_fd, path, FS_READ & handled_fs)?;
        }
        for path in write_paths {
            // Writable paths implicitly also need read access (so the shell
            // can cat/ls files it just wrote).  Include FS_READ in the mask
            // so that write_paths get both read and write permission.
            add_path_rule(ruleset_fd, path, (fs_write | FS_READ) & handled_fs)?;
        }
        for &port in allowed_tcp_ports {
            if abi < 4 {
                break;
            }
            let rule = LandlockNetPortAttr {
                allowed_access: LANDLOCK_ACCESS_NET_CONNECT_TCP,
                port: u64::from(port),
            };
            unsafe {
                ll_syscall(
                    libc::SYS_landlock_add_rule,
                    &[
                        ruleset_fd as usize,
                        LANDLOCK_RULE_NET_PORT as usize,
                        &raw const rule as usize,
                        0,
                    ],
                );
            }
        }

        // NO_NEW_PRIVS via rustix
        rustix::thread::set_no_new_privs(true)
            .map_err(|e| io::Error::from_raw_os_error(e.raw_os_error()))?;

        let mut restrict_flags: u32 = 0;
        if abi >= 7 {
            restrict_flags |= LANDLOCK_RESTRICT_SELF_LOG_NEW_EXEC_ON;
        }
        if abi >= 8 {
            restrict_flags |= LANDLOCK_RESTRICT_SELF_TSYNC;
        }

        let mut ret = unsafe {
            ll_syscall(
                libc::SYS_landlock_restrict_self,
                &[ruleset_fd as usize, restrict_flags as usize],
            )
        };
        if ret < 0 && (restrict_flags & LANDLOCK_RESTRICT_SELF_TSYNC) != 0 {
            restrict_flags &= !LANDLOCK_RESTRICT_SELF_TSYNC;
            ret = unsafe {
                ll_syscall(
                    libc::SYS_landlock_restrict_self,
                    &[ruleset_fd as usize, restrict_flags as usize],
                )
            };
        }
        if ret < 0 {
            let msg = format!(
                "landlock_restrict_self failed: {}",
                io::Error::last_os_error()
            );
            if strict {
                return Err(io::Error::other(msg));
            }
            log::warn!("{msg}");
            return Ok(false);
        }

        log::debug!(
            "Landlock (ABI v{}): {} read, {} write paths, {} TCP ports",
            abi,
            read_paths.len(),
            write_paths.len(),
            allowed_tcp_ports.len()
        );
        Ok(true)
    })();

    unsafe { libc::close(ruleset_fd) };
    result
}
