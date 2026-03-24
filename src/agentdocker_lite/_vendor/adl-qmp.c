/*
 * Minimal QMP (QEMU Monitor Protocol) client for agentdocker-lite.
 * Zero libc dependency — raw syscalls only. ~5KB stripped.
 *
 * Usage: adl-qmp /path/to/qmp.sock '{"execute":"query-status"}'
 *
 * Connects to QMP Unix socket, negotiates capabilities, sends
 * the command, prints the JSON response line, and exits.
 *
 * Build: gcc -static -nostdlib -Os -march=x86-64 -fno-stack-protector \
 *            -o adl-qmp adl-qmp.c && strip adl-qmp
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

/* Syscall numbers (x86_64) */
#define NR_write   1
#define NR_read    0
#define NR_close   3
#define NR_socket  41
#define NR_connect 42
#define NR_exit    60

/* Socket constants */
#define AF_UNIX    1
#define SOCK_STREAM 1

struct sockaddr_un {
    unsigned short sun_family;
    char sun_path[108];
};

/* ---- Helpers ---- */

static int slen(const char *s) { int n = 0; while (s[n]) n++; return n; }

static void writes(int fd, const char *s) { sc3(NR_write, fd, (long)s, slen(s)); }

/* Read until we get a complete JSON line (terminated by \n).
 * Returns number of bytes in buf (excluding \n). */
static int read_line(int fd, char *buf, int bufsz) {
    int pos = 0;
    while (pos < bufsz - 1) {
        char c;
        long n = sc3(NR_read, fd, (long)&c, 1);
        if (n <= 0) break;
        if (c == '\n') { buf[pos] = 0; return pos; }
        if (c == '\r') continue;
        buf[pos++] = c;
    }
    buf[pos] = 0;
    return pos;
}

/* Check if JSON line contains a key (simple substring match) */
static int has_key(const char *json, const char *key) {
    int klen = slen(key);
    for (int i = 0; json[i]; i++) {
        int j = 0;
        while (j < klen && json[i + j] == key[j]) j++;
        if (j == klen) return 1;
    }
    return 0;
}

/* ---- Entry point ---- */

__attribute__((used))
static void _main(long argc, char **argv) {
    if (argc < 3) {
        writes(2, "usage: adl-qmp SOCKET_PATH '{\"execute\":\"CMD\"}'\n");
        sc1(NR_exit, 1);
    }

    const char *sock_path = argv[1];
    const char *cmd = argv[2];

    /* 1. Create Unix socket */
    int fd = sc3(NR_socket, AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) {
        writes(2, "adl-qmp: socket failed\n");
        sc1(NR_exit, 1);
    }

    /* 2. Connect */
    struct sockaddr_un addr;
    addr.sun_family = AF_UNIX;
    int plen = slen(sock_path);
    if (plen >= 108) { writes(2, "adl-qmp: path too long\n"); sc1(NR_exit, 1); }
    for (int i = 0; i <= plen; i++) addr.sun_path[i] = sock_path[i];

    if (sc3(NR_connect, fd, (long)&addr, 2 + plen + 1) < 0) {
        writes(2, "adl-qmp: connect failed\n");
        sc1(NR_exit, 1);
    }

    char buf[8192];

    /* 3. Read QMP greeting */
    read_line(fd, buf, sizeof(buf));

    /* 4. Send qmp_capabilities */
    writes(fd, "{\"execute\":\"qmp_capabilities\"}\n");

    /* 5. Read capabilities response */
    read_line(fd, buf, sizeof(buf));

    /* 6. Send the actual command */
    sc3(NR_write, fd, (long)cmd, slen(cmd));
    writes(fd, "\n");

    /* 7. Read response, skip async events */
    while (1) {
        int n = read_line(fd, buf, sizeof(buf));
        if (n <= 0) break;
        if (has_key(buf, "\"return\"") || has_key(buf, "\"error\"")) {
            /* Print response to stdout */
            writes(1, buf);
            writes(1, "\n");
            break;
        }
        /* else: async event, skip */
    }

    sc1(NR_close, fd);
    sc1(NR_exit, 0);
}

/* ASM entry */
__asm__(
    ".globl _start\n"
    "_start:\n"
    "  xorl %ebp, %ebp\n"
    "  movq (%rsp), %rdi\n"          /* argc */
    "  leaq 8(%rsp), %rsi\n"         /* argv */
    "  andq $-16, %rsp\n"
    "  call _main\n"
    "  movl $60, %eax\n"
    "  syscall\n"
);
