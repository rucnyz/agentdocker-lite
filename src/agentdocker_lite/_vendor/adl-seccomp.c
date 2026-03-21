/*
 * Minimal security + init helper for agentdocker-lite sandboxes.
 * Zero libc dependency — raw syscalls only. ~13KB stripped.
 *
 * Build: gcc -static -nostdlib -Os -march=x86-64 -fno-stack-protector \
 *            -o adl-seccomp adl-seccomp.c && strip adl-seccomp
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
#define NR_prctl   157
#define NR_mount   165
#define NR_execve  59
#define NR_exit    60

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
#define SECCOMP_MODE_FILTER 2

/* Minimal stat (only need st_mode at offset 24 on x86_64) */
struct kstat { char pad[24]; unsigned int st_mode; char rest[120]; };

/* BPF filter header */
struct bpf_prog { unsigned short len; void *filter; };

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

/* ---- Entry point ---- */

__attribute__((used))
static void _main(long argc, char **argv, char **envp) {
    if (argc < 2) {
        writes("usage: adl-seccomp PROGRAM [ARGS...]\n");
        sc1(NR_exit, 1);
    }

    /* 1. Mount /proc + /dev */
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

    /* 2. Drop capabilities */
    for (int c = 0; c <= 41; c++)
        if (!keep(c)) sc5(NR_prctl, PR_CAPBSET_DROP, c, 0, 0, 0);

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

    /* 6. Seccomp BPF from /tmp/.adl_seccomp.bpf */
    int fd = sc2(NR_open, (long)"/tmp/.adl_seccomp.bpf", 0/*O_RDONLY*/);
    if (fd >= 0) {
        long sz = sc3(NR_lseek, fd, 0, 2/*SEEK_END*/);
        sc3(NR_lseek, fd, 0, 0/*SEEK_SET*/);
        if (sz > 0) {
            void *buf = (void*)sc5(NR_mmap, 0, sz, 1/*PROT_READ*/, 2/*MAP_PRIVATE*/, fd);
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

    /* 6. exec target */
    sc3(NR_execve, (long)argv[1], (long)(argv+1), (long)envp);
    writes("adl-seccomp: exec failed\n");
    sc1(NR_exit, 127);
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
