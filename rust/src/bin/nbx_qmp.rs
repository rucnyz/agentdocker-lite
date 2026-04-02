//! nbx-qmp: Minimal QMP client for NitroBox.
//!
//! Zero dependency — raw x86-64 syscalls only. ~5KB stripped.
//!
//! Usage: nbx-qmp /path/to/qmp.sock '{"execute":"query-status"}'
//!
//! Build:
//!   rustc --edition 2024 -C opt-level=2 -C panic=abort \
//!       -C link-arg=-nostdlib -C link-arg=-static -C strip=symbols \
//!       -o nbx-qmp rust/src/bin/nbx_qmp.rs

#![no_std]
#![no_main]
#![allow(unsafe_op_in_unsafe_fn)]

use core::arch::{asm, global_asm};

// ---- Syscall numbers (x86_64) ----

const SYS_READ: u64 = 0;
const SYS_WRITE: u64 = 1;
const SYS_CLOSE: u64 = 3;
const SYS_SOCKET: u64 = 41;
const SYS_CONNECT: u64 = 42;
const SYS_EXIT: u64 = 60;

const AF_UNIX: u64 = 1;
const SOCK_STREAM: u64 = 1;

// ---- Raw syscall wrappers ----

#[inline(always)]
unsafe fn syscall1(nr: u64, a1: u64) -> i64 {
    let ret: i64;
    asm!(
        "syscall",
        in("rax") nr, in("rdi") a1,
        lateout("rax") ret,
        out("rcx") _, out("r11") _,
        options(nostack),
    );
    ret
}

#[inline(always)]
unsafe fn syscall3(nr: u64, a1: u64, a2: u64, a3: u64) -> i64 {
    let ret: i64;
    asm!(
        "syscall",
        in("rax") nr, in("rdi") a1, in("rsi") a2, in("rdx") a3,
        lateout("rax") ret,
        out("rcx") _, out("r11") _,
        options(nostack),
    );
    ret
}

// ---- Helpers ----

unsafe fn exit(code: i32) -> ! {
    syscall1(SYS_EXIT, code as u64);
    core::hint::unreachable_unchecked()
}

unsafe fn write_bytes(fd: i32, ptr: *const u8, len: usize) {
    let mut off = 0usize;
    while off < len {
        let n = syscall3(
            SYS_WRITE,
            fd as u64,
            ptr.add(off) as u64,
            (len - off) as u64,
        );
        if n <= 0 {
            break;
        }
        off += n as usize;
    }
}

unsafe fn write_str(fd: i32, s: &[u8]) {
    write_bytes(fd, s.as_ptr(), s.len());
}

fn cstrlen(s: *const u8) -> usize {
    let mut n = 0;
    unsafe {
        while *s.add(n) != 0 {
            n += 1;
        }
    }
    n
}

// LLVM intrinsics required in no_std — array zeroing, copy_nonoverlapping, etc.

#[unsafe(no_mangle)]
unsafe extern "C" fn memset(s: *mut u8, c: i32, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *s.add(i) = c as u8;
        i += 1;
    }
    s
}

#[unsafe(no_mangle)]
unsafe extern "C" fn memcpy(dest: *mut u8, src: *const u8, n: usize) -> *mut u8 {
    let mut i = 0;
    while i < n {
        *dest.add(i) = *src.add(i);
        i += 1;
    }
    dest
}

#[unsafe(no_mangle)]
unsafe extern "C" fn strlen(s: *const u8) -> usize {
    cstrlen(s)
}

/// Read until '\n'. Returns bytes written (excluding newline).
unsafe fn read_line(fd: i32, buf: *mut u8, cap: usize) -> usize {
    let mut pos = 0;
    while pos < cap - 1 {
        let mut c: u8 = 0;
        let n = syscall3(SYS_READ, fd as u64, &mut c as *mut u8 as u64, 1);
        if n <= 0 {
            break;
        }
        if c == b'\n' {
            *buf.add(pos) = 0;
            return pos;
        }
        if c == b'\r' {
            continue;
        }
        *buf.add(pos) = c;
        pos += 1;
    }
    *buf.add(pos) = 0;
    pos
}

/// Substring search in a byte buffer of known length.
unsafe fn has_key(buf: *const u8, len: usize, key: &[u8]) -> bool {
    if key.len() > len {
        return false;
    }
    'outer: for i in 0..=len - key.len() {
        for j in 0..key.len() {
            if *buf.add(i + j) != key[j] {
                continue 'outer;
            }
        }
        return true;
    }
    false
}

// ---- sockaddr_un ----

#[repr(C)]
struct SockaddrUn {
    sun_family: u16,
    sun_path: [u8; 108],
}

// ---- Main logic ----

#[unsafe(no_mangle)]
unsafe extern "C" fn _main(argc: u64, argv: *const *const u8) -> ! {
    if argc < 3 {
        write_str(2, b"usage: nbx-qmp SOCKET_PATH '{\"execute\":\"CMD\"}'\n");
        exit(1);
    }

    let sock_path = *argv.add(1);
    let cmd = *argv.add(2);
    let plen = cstrlen(sock_path);
    let clen = cstrlen(cmd);

    // 1. Create Unix socket
    let fd = syscall3(SYS_SOCKET, AF_UNIX, SOCK_STREAM, 0) as i32;
    if fd < 0 {
        write_str(2, b"nbx-qmp: socket failed\n");
        exit(1);
    }

    // 2. Connect
    if plen >= 108 {
        write_str(2, b"nbx-qmp: path too long\n");
        exit(1);
    }
    let mut addr = SockaddrUn {
        sun_family: AF_UNIX as u16,
        sun_path: [0; 108],
    };
    core::ptr::copy_nonoverlapping(sock_path, addr.sun_path.as_mut_ptr(), plen + 1);

    if syscall3(
        SYS_CONNECT,
        fd as u64,
        &addr as *const _ as u64,
        (2 + plen + 1) as u64,
    ) < 0
    {
        write_str(2, b"nbx-qmp: connect failed\n");
        exit(1);
    }

    let mut buf = [0u8; 8192];

    // 3. Read QMP greeting
    read_line(fd, buf.as_mut_ptr(), buf.len());

    // 4. Send qmp_capabilities
    write_str(fd, b"{\"execute\":\"qmp_capabilities\"}\n");

    // 5. Read capabilities response
    read_line(fd, buf.as_mut_ptr(), buf.len());

    // 6. Send the actual command
    write_bytes(fd, cmd, clen);
    write_str(fd, b"\n");

    // 7. Read response, skip async events
    loop {
        let n = read_line(fd, buf.as_mut_ptr(), buf.len());
        if n == 0 {
            break;
        }
        if has_key(buf.as_ptr(), n, b"\"return\"") || has_key(buf.as_ptr(), n, b"\"error\"") {
            write_bytes(1, buf.as_ptr(), n);
            write_str(1, b"\n");
            break;
        }
    }

    syscall1(SYS_CLOSE, fd as u64);
    exit(0);
}

// ---- ASM entry: extract argc/argv from stack, call _main ----

global_asm!(
    ".globl _start",
    "_start:",
    "  xorl %ebp, %ebp",
    "  movq (%rsp), %rdi",
    "  leaq 8(%rsp), %rsi",
    "  andq $-16, %rsp",
    "  call _main",
    "  movl $60, %eax",
    "  syscall",
    options(att_syntax),
);

#[panic_handler]
fn panic(_: &core::panic::PanicInfo) -> ! {
    unsafe { exit(1) }
}
