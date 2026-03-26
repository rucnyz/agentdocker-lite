/*
 * Minimal security + init helper for agentdocker-lite sandboxes.
 * Zero libc dependency — raw syscalls only. ~13KB stripped.
 *
 * After security setup (cap drop, proc mask, landlock, seccomp), forks:
 *   - Parent stays as PID 1 init, reaps zombies (bubblewrap do_init pattern)
 *   - Child execs the target program
 *
 * Build: gcc -static -nostdlib -Os -march=x86-64 -fno-stack-protector \
 *            -fno-builtin -o adl-seccomp adl-seccomp.c && strip adl-seccomp
 */

/* ---- Raw syscall wrappers (x86_64) ---- */

static long sc1(long nr, long a) {
    long r; __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a):"rcx","r11","memory"); return r;
}
static long sc2(long nr, long a, long b) {
    long r; __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a),"S"(b):"rcx","r11","memory"); return r;
}
static long sc3(long nr, long a, long b, long c) {
    long r; __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a),"S"(b),"d"(c):"rcx","r11","memory"); return r;
}
static long sc5(long nr, long a, long b, long c, long d, long e) {
    long r;
    register long r10 __asm__("r10") = d;
    register long r8  __asm__("r8")  = e;
    __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8):"rcx","r11","memory");
    return r;
}
static long sc6(long nr, long a, long b, long c, long d, long e, long f) {
    long r;
    register long r10 __asm__("r10") = d;
    register long r8  __asm__("r8")  = e;
    register long r9  __asm__("r9")  = f;
    __asm__ volatile("syscall":"=a"(r):"a"(nr),"D"(a),"S"(b),"d"(c),"r"(r10),"r"(r8),"r"(r9):"rcx","r11","memory");
    return r;
}

/* Syscall numbers (x86_64) */
#define NR_read    0
#define NR_write   1
#define NR_open    2
#define NR_close   3
#define NR_stat    4
#define NR_lseek   8
#define NR_mmap    9
#define NR_munmap  11
#define NR_unlink  87
#define NR_mkdir   83
#define NR_symlink 88
#define NR_mknod   133
#define NR_sethostname 170
#define NR_prctl   157
#define NR_mount   165
#define NR_clone   56
#define NR_execve  59
#define NR_exit    60
#define NR_wait4   61

/* Landlock syscall numbers (same on x86_64 and aarch64) */
#define NR_landlock_create_ruleset 444
#define NR_landlock_add_rule       445
#define NR_landlock_restrict_self  446

/* Constants */
#define MS_RDONLY  1
#define MS_NOSUID  2
#define MS_BIND    4096
#define MS_REMOUNT 32
#define S_IFCHR    0020000
#define S_IFDIR    0040000
#define MKDEV(a,b) (((a)<<8)|(b))

#define PR_CAPBSET_DROP     24
#define PR_SET_NO_NEW_PRIVS 38
#define PR_SET_SECCOMP      22
#define PR_SET_DUMPABLE     4
#define SECCOMP_MODE_FILTER 2
#define SIGCHLD 17

/* Wait status macros (match kernel encoding, same as bubblewrap) */
#define WIFEXITED(s)   (((s) & 0x7f) == 0)
#define WEXITSTATUS(s) (((s) >> 8) & 0xff)
#define WTERMSIG(s)    ((s) & 0x7f)

#define O_WRONLY  1
#define O_CREAT   0100
#define O_PATH    010000000
#define O_CLOEXEC 02000000

/* Landlock constants */
#define LL_CREATE_RULESET_VERSION (1 << 0)

/* FS access flags */
#define LL_FS_EXECUTE       (1ULL << 0)
#define LL_FS_WRITE_FILE    (1ULL << 1)
#define LL_FS_READ_FILE     (1ULL << 2)
#define LL_FS_READ_DIR      (1ULL << 3)
#define LL_FS_REMOVE_DIR    (1ULL << 4)
#define LL_FS_REMOVE_FILE   (1ULL << 5)
#define LL_FS_MAKE_CHAR     (1ULL << 6)
#define LL_FS_MAKE_DIR      (1ULL << 7)
#define LL_FS_MAKE_REG      (1ULL << 8)
#define LL_FS_MAKE_SOCK     (1ULL << 9)
#define LL_FS_MAKE_FIFO     (1ULL << 10)
#define LL_FS_MAKE_BLOCK    (1ULL << 11)
#define LL_FS_MAKE_SYM      (1ULL << 12)
#define LL_FS_REFER         (1ULL << 13)  /* ABI v2 */
#define LL_FS_TRUNCATE      (1ULL << 14)  /* ABI v3 */
#define LL_FS_IOCTL_DEV     (1ULL << 15)  /* ABI v5 */

/* Net access flags (ABI v4+) */
#define LL_NET_CONNECT_TCP  (1ULL << 1)

/* Scope flags (ABI v6+) */
#define LL_SCOPE_UNIX       (1ULL << 0)
#define LL_SCOPE_SIGNAL     (1ULL << 1)

/* Rule types */
#define LL_RULE_PATH_BENEATH 1
#define LL_RULE_NET_PORT     2

/* Composite masks */
#define LL_FS_READ (LL_FS_EXECUTE | LL_FS_READ_FILE | LL_FS_READ_DIR)
#define LL_FS_WRITE_V1 ( \
    LL_FS_WRITE_FILE | LL_FS_REMOVE_DIR | LL_FS_REMOVE_FILE | \
    LL_FS_MAKE_CHAR | LL_FS_MAKE_DIR | LL_FS_MAKE_REG | \
    LL_FS_MAKE_SOCK | LL_FS_MAKE_FIFO | LL_FS_MAKE_BLOCK | LL_FS_MAKE_SYM)

/* Minimal stat (only need st_mode at offset 24 on x86_64) */
struct kstat { char pad[24]; unsigned int st_mode; char rest[120]; };

/* BPF filter header */
struct bpf_prog { unsigned short len; void *filter; };

/* Landlock structs (match kernel UAPI layout) */
struct ll_ruleset_attr {
    unsigned long long handled_access_fs;
    unsigned long long handled_access_net;
    unsigned long long scoped;
};

struct ll_path_beneath {
    unsigned long long allowed_access;
    int parent_fd;
} __attribute__((packed));

struct ll_net_port {
    unsigned long long allowed_access;
    unsigned long long port;
};

/* ---- Helpers ---- */

static int slen(const char *s) { int n=0; while(s[n])n++; return n; }

static void writes(const char *s) { sc3(NR_write, 2, (long)s, slen(s)); }

/* ---- Security logic ---- */

static const int keep_caps[] = {0,1,3,4,5,6,7,8,10,18,27,29,31,-1};
static const char *masked[] = {
    "/proc/kcore","/proc/keys","/proc/timer_list",
    "/proc/sched_debug","/sys/firmware","/proc/scsi",0
};
static const char *ro_paths[] = {
    "/proc/bus","/proc/fs","/proc/irq","/proc/sys","/proc/sysrq-trigger",0
};

static int keep(int c) { for(int i=0;keep_caps[i]>=0;i++) if(keep_caps[i]==c) return 1; return 0; }

/* ---- Landlock ---- */

static void apply_landlock(void) {
    /* Check if config file exists */
    struct kstat st;
    if (sc2(NR_stat, (long)"/tmp/.adl_landlock", (long)&st) != 0)
        return;

    /* Read config into stack buffer */
    int fd = sc2(NR_open, (long)"/tmp/.adl_landlock", 0/*O_RDONLY*/);
    if (fd < 0) return;

    char buf[4096];
    long n = sc3(NR_read, fd, (long)buf, sizeof(buf) - 1);
    sc1(NR_close, fd);
    sc1(NR_unlink, (long)"/tmp/.adl_landlock");
    if (n <= 0) return;
    buf[n] = 0;

    /* Query Landlock ABI version */
    long abi = sc3(NR_landlock_create_ruleset, 0, 0, LL_CREATE_RULESET_VERSION);
    if (abi <= 0) return;  /* Landlock not available — skip silently */

    /* Parse mode flags from first line */
    int mode_r = 0, mode_w = 0, mode_p = 0;
    int i = 0;
    while (i < n && buf[i] != '\n') {
        if (buf[i] == 'r') mode_r = 1;
        else if (buf[i] == 'w') mode_w = 1;
        else if (buf[i] == 'p') mode_p = 1;
        i++;
    }
    if (i < n) i++;  /* skip newline */
    if (!mode_r && !mode_w && !mode_p) return;

    /* Build write mask adjusted for ABI version */
    unsigned long long fs_write = LL_FS_WRITE_V1;
    if (abi >= 2) fs_write |= LL_FS_REFER;
    if (abi >= 3) fs_write |= LL_FS_TRUNCATE;
    if (abi >= 5) fs_write |= LL_FS_IOCTL_DEV;

    /* Compute handled_access masks */
    unsigned long long handled_fs = 0;
    if (mode_r) handled_fs |= LL_FS_READ;
    if (mode_w) handled_fs |= fs_write;

    unsigned long long handled_net = 0;
    if (mode_p && abi >= 4) handled_net = LL_NET_CONNECT_TCP;

    unsigned long long scoped = 0;
    if (abi >= 6) scoped = LL_SCOPE_UNIX | LL_SCOPE_SIGNAL;

    /* Create ruleset */
    struct ll_ruleset_attr attr = { handled_fs, handled_net, scoped };
    long rs = sc3(NR_landlock_create_ruleset, (long)&attr, sizeof(attr), 0);
    if (rs < 0) return;

    /* Rule access masks: R grants read, W grants all handled FS access */
    unsigned long long r_access = handled_fs & LL_FS_READ;
    unsigned long long w_access = handled_fs;

    /* Parse and add rules line by line */
    while (i < n) {
        char type = buf[i];
        /* Skip invalid lines */
        if ((type != 'R' && type != 'W' && type != 'P') ||
            i + 1 >= n || buf[i + 1] != ' ') {
            while (i < n && buf[i] != '\n') i++;
            i++;
            continue;
        }
        i += 2;  /* skip "X " prefix */

        /* Extract value (path or port number) */
        int start = i;
        while (i < n && buf[i] != '\n') i++;
        buf[i] = 0;  /* null-terminate value */

        if ((type == 'R' || type == 'W') && buf[start]) {
            unsigned long long access = (type == 'W') ? w_access : r_access;
            if (access == 0) { i++; continue; }

            /* Open path with O_PATH for Landlock rule */
            long pfd = sc2(NR_open, (long)&buf[start], O_PATH | O_CLOEXEC);
            if (pfd >= 0) {
                struct ll_path_beneath rule = { access, (int)pfd };
                sc5(NR_landlock_add_rule, rs, LL_RULE_PATH_BENEATH,
                    (long)&rule, 0, 0);
                sc1(NR_close, pfd);
            }
        } else if (type == 'P' && abi >= 4) {
            /* Parse port number */
            unsigned long long port = 0;
            for (int j = start; buf[j] >= '0' && buf[j] <= '9'; j++)
                port = port * 10 + (buf[j] - '0');
            if (port > 0 && port <= 65535) {
                struct ll_net_port rule = { LL_NET_CONNECT_TCP, port };
                sc5(NR_landlock_add_rule, rs, LL_RULE_NET_PORT,
                    (long)&rule, 0, 0);
            }
        }
        i++;  /* advance past null terminator */
    }

    /* Enforce: NO_NEW_PRIVS required before restrict_self */
    sc5(NR_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
    sc2(NR_landlock_restrict_self, rs, 0);
    sc1(NR_close, rs);
}

/* ---- Entry point ---- */

__attribute__((used))
static void _main(long argc, char **argv, char **envp) {
    if (argc < 2) {
        writes("usage: adl-seccomp PROGRAM [ARGS...]\n");
        sc1(NR_exit, 1);
    }

    /* 1. Mount /proc + /dev (skip if marker exists — userns setup script
     *    already handled this with bind mounts instead of mknod) */
    {
        struct kstat st;
        int skip_dev = (sc2(NR_stat, (long)"/tmp/.adl_skip_dev", (long)&st) == 0);
        if (skip_dev)
            sc1(NR_unlink, (long)"/tmp/.adl_skip_dev");

        if (!skip_dev) {
            sc2(NR_mkdir, (long)"/proc", 0755);
            sc5(NR_mount, (long)"proc", (long)"/proc", (long)"proc", 0, 0);

            sc2(NR_mkdir, (long)"/dev", 0755);
            sc5(NR_mount, (long)"tmpfs", (long)"/dev", (long)"tmpfs", MS_NOSUID, (long)"mode=0755");
            sc3(NR_mknod, (long)"/dev/null",    S_IFCHR|0666, MKDEV(1,3));
            sc3(NR_mknod, (long)"/dev/zero",    S_IFCHR|0666, MKDEV(1,5));
            sc3(NR_mknod, (long)"/dev/full",    S_IFCHR|0666, MKDEV(1,7));
            sc3(NR_mknod, (long)"/dev/random",  S_IFCHR|0444, MKDEV(1,8));
            sc3(NR_mknod, (long)"/dev/urandom", S_IFCHR|0444, MKDEV(1,9));
            sc3(NR_mknod, (long)"/dev/tty",     S_IFCHR|0666, MKDEV(5,0));
            sc2(NR_symlink, (long)"/proc/self/fd",   (long)"/dev/fd");
            sc2(NR_symlink, (long)"/proc/self/fd/0", (long)"/dev/stdin");
            sc2(NR_symlink, (long)"/proc/self/fd/1", (long)"/dev/stdout");
            sc2(NR_symlink, (long)"/proc/self/fd/2", (long)"/dev/stderr");
            sc2(NR_mkdir, (long)"/dev/pts", 0755);
            sc5(NR_mount, (long)"devpts", (long)"/dev/pts", (long)"devpts", MS_NOSUID, (long)"newinstance,ptmxmode=0666");
            sc2(NR_symlink, (long)"pts/ptmx", (long)"/dev/ptmx");
            sc2(NR_mkdir, (long)"/dev/shm", 01777);

            /* 1b. Device passthrough: bind-mount from /.pivot_old */
            {
                int dfd = sc2(NR_open, (long)"/tmp/.adl_devices", 0/*O_RDONLY*/);
                if (dfd >= 0) {
                    char dbuf[2048];
                    long dn = sc3(NR_read, dfd, (long)dbuf, sizeof(dbuf) - 1);
                    sc1(NR_close, dfd);
                    sc1(NR_unlink, (long)"/tmp/.adl_devices");
                    if (dn > 0) {
                        dbuf[dn] = 0;
                        int di = 0;
                        while (di < dn) {
                            int ds = di;
                            while (di < dn && dbuf[di] != '\n') di++;
                            dbuf[di] = 0;
                            if (di > ds && dbuf[ds] == '/') {
                                /* Construct source: /.pivot_old + path */
                                char dsrc[512];
                                const char *dpfx = "/.pivot_old";
                                int dj = 0;
                                while (dpfx[dj]) { dsrc[dj] = dpfx[dj]; dj++; }
                                int dk = 0;
                                while (dbuf[ds+dk] && dj < 510) dsrc[dj++] = dbuf[ds+dk++];
                                dsrc[dj] = 0;

                                /* mkdir parent (one level, e.g. /dev/dri) */
                                char ddir[512];
                                int dl = 0, dlast = -1;
                                while (dbuf[ds+dl]) {
                                    ddir[dl] = dbuf[ds+dl];
                                    if (ddir[dl] == '/') dlast = dl;
                                    dl++;
                                }
                                ddir[dl] = 0;
                                if (dlast > 0) {
                                    ddir[dlast] = 0;
                                    sc2(NR_mkdir, (long)ddir, 0755);
                                    ddir[dlast] = '/';
                                }

                                /* Create mount point (empty file) */
                                int tfd = sc3(NR_open, (long)(dbuf+ds),
                                              O_WRONLY|O_CREAT, 0644);
                                if (tfd >= 0) sc1(NR_close, tfd);

                                /* Bind-mount device from old root */
                                sc5(NR_mount, (long)dsrc, (long)(dbuf+ds), 0, MS_BIND, 0);
                            }
                            di++;
                        }
                    }
                }
            }
        }
    }

    /* 1c. Set hostname (before cap drop and seccomp block sethostname) */
    {
        int hfd = sc2(NR_open, (long)"/tmp/.adl_hostname", 0/*O_RDONLY*/);
        if (hfd >= 0) {
            char hbuf[256];
            long hn = sc3(NR_read, hfd, (long)hbuf, sizeof(hbuf) - 1);
            sc1(NR_close, hfd);
            sc1(NR_unlink, (long)"/tmp/.adl_hostname");
            if (hn > 0) {
                /* Strip trailing newline */
                while (hn > 0 && (hbuf[hn-1] == '\n' || hbuf[hn-1] == '\r'))
                    hn--;
                if (hn > 0)
                    sc2(NR_sethostname, (long)hbuf, hn);
            }
        }
    }

    /* 2. Drop capabilities */
    for (int c = 0; c <= 41; c++)
        if (!keep(c)) sc5(NR_prctl, PR_CAPBSET_DROP, c, 0, 0, 0);

    /* 2b. Restore dumpable flag after cap drop (bubblewrap drop_privs pattern).
     *     Without this, /proc/self becomes root-owned after cap drop,
     *     preventing normal user processes from reading their own maps/status. */
    sc5(NR_prctl, PR_SET_DUMPABLE, 1, 0, 0, 0);

    /* 3. Mask paths */
    for (int i = 0; masked[i]; i++) {
        struct kstat st;
        if (sc2(NR_stat, (long)masked[i], (long)&st) != 0) continue;
        if ((st.st_mode & S_IFDIR) == S_IFDIR)
            sc5(NR_mount, (long)"tmpfs", (long)masked[i], (long)"tmpfs", 0, 0);
        else
            sc5(NR_mount, (long)"/dev/null", (long)masked[i], 0, MS_BIND, 0);
    }

    /* 4. Read-only paths */
    for (int i = 0; ro_paths[i]; i++) {
        if (sc5(NR_mount, (long)ro_paths[i], (long)ro_paths[i], 0, MS_BIND, 0) == 0)
            sc5(NR_mount, 0, (long)ro_paths[i], 0, MS_BIND|MS_REMOUNT|MS_RDONLY, 0);
    }

    /* 5. Read-only rootfs (before seccomp blocks mount) */
    {
        struct kstat st;
        if (sc2(NR_stat, (long)"/tmp/.adl_readonly", (long)&st) == 0) {
            sc1(NR_unlink, (long)"/tmp/.adl_readonly");
            sc5(NR_mount, (long)"/", (long)"/", 0, MS_BIND|MS_REMOUNT|MS_RDONLY, 0);
        }
    }

    /* 6. Landlock path/port restrictions (before seccomp blocks the syscalls) */
    apply_landlock();

    /* 7. Seccomp BPF from /tmp/.adl_seccomp.bpf */
    {
        int fd = sc2(NR_open, (long)"/tmp/.adl_seccomp.bpf", 0/*O_RDONLY*/);
        if (fd >= 0) {
            long sz = sc3(NR_lseek, fd, 0, 2/*SEEK_END*/);
            sc3(NR_lseek, fd, 0, 0/*SEEK_SET*/);
            if (sz > 0) {
                void *buf = (void*)sc6(NR_mmap, 0, sz, 1/*PROT_READ*/, 2/*MAP_PRIVATE*/, fd, 0/*offset*/);
                if ((long)buf > 0) {
                    struct bpf_prog p = { sz/8, buf };
                    sc5(NR_prctl, PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0);
                    sc3(NR_prctl, PR_SET_SECCOMP, SECCOMP_MODE_FILTER, (long)&p);
                    sc2(NR_munmap, (long)buf, sz);
                }
            }
            sc1(NR_close, fd);
            sc1(NR_unlink, (long)"/tmp/.adl_seccomp.bpf");
        }
    }

    /* 8. Fork: child execs target, parent stays as PID 1 init.
     *    Reaps orphaned zombies — follows bubblewrap do_init() pattern.
     *    See: https://github.com/containers/bubblewrap/blob/main/bubblewrap.c */
    long child_pid = sc5(NR_clone, SIGCHLD, 0, 0, 0, 0);
    if (child_pid < 0) {
        /* clone failed — fall back to direct exec (best effort) */
        sc3(NR_execve, (long)argv[1], (long)(argv+1), (long)envp);
        writes("adl-seccomp: exec failed\n");
        sc1(NR_exit, 127);
    }

    if (child_pid == 0) {
        /* Child: exec the target program */
        sc3(NR_execve, (long)argv[1], (long)(argv+1), (long)envp);
        writes("adl-seccomp: exec failed\n");
        sc1(NR_exit, 127);
    }

    /* Parent: PID 1 init — reap all children (bubblewrap do_init pattern).
     * Loops on wait4(-1) until ECHILD, propagates initial child's exit status.
     * This ensures orphaned processes are reaped instead of accumulating as
     * zombies, which bash-as-PID-1 does not reliably do. */
    {
        int init_exit = 1;
        for (;;) {
            int status = 0;
            long pid = sc5(NR_wait4, -1, (long)&status, 0, 0, 0);
            if (pid == child_pid) {
                /* Initial child exited — propagate its exit status
                 * (bash-compatible: 128 + signal for signal deaths) */
                if (WIFEXITED(status))
                    init_exit = WEXITSTATUS(status);
                else
                    init_exit = 128 + WTERMSIG(status);
            }
            if (pid < 0) {
                if (pid == -4) continue;   /* -EINTR: retry */
                break;                     /* -ECHILD or other: done */
            }
        }
        sc1(NR_exit, init_exit);
    }
}

/* ASM entry: extract argc/argv/envp from stack, call _main */
__asm__(
    ".globl _start\n"
    "_start:\n"
    "  xorl %ebp, %ebp\n"
    "  movq (%rsp), %rdi\n"          /* argc */
    "  leaq 8(%rsp), %rsi\n"         /* argv */
    "  leaq 8(%rsp,%rdi,8), %rdx\n"  /* &argv[argc] */
    "  addq $8, %rdx\n"              /* envp = skip NULL terminator */
    "  andq $-16, %rsp\n"            /* align stack */
    "  call _main\n"
    "  movl $60, %eax\n"
    "  syscall\n"
);
