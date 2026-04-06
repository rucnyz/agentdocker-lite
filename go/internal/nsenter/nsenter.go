// Package nsenter provides namespace enter helpers for sandbox popen().
package nsenter

import (
	"fmt"
	"os"
	"syscall"

	"golang.org/x/sys/unix"
)

// NsenterPreexec enters the mount namespace of targetPid, chroots to its root,
// and chdirs to "/". Used for rootful popen().
func NsenterPreexec(targetPid int) error {
	// 1. Open root fd BEFORE entering mount namespace
	rootPath := fmt.Sprintf("/proc/%d/root", targetPid)
	rootFd, err := unix.Open(rootPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}

	// 2. Open mount namespace fd
	mntNs := fmt.Sprintf("/proc/%d/ns/mnt", targetPid)
	mntFd, err := unix.Open(mntNs, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Close(rootFd)
		return err
	}

	// 3. Enter mount namespace
	if err := unix.Setns(mntFd, unix.CLONE_NEWNS); err != nil {
		unix.Close(mntFd)
		unix.Close(rootFd)
		return err
	}
	unix.Close(mntFd)

	// 4. fchdir + chroot
	if err := unix.Fchdir(rootFd); err != nil {
		unix.Close(rootFd)
		return err
	}
	unix.Close(rootFd)

	if err := unix.Chroot("."); err != nil {
		return err
	}

	// 5. chdir to /
	return unix.Chdir("/")
}

// UsersPreexec enters user+mount namespace, chroots to rootfs, chdirs to workingDir.
func UsersPreexec(targetPid int, rootfs, workingDir string) error {
	// 1. Open namespace fds
	userNs := fmt.Sprintf("/proc/%d/ns/user", targetPid)
	userFd, err := unix.Open(userNs, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return err
	}

	mntNs := fmt.Sprintf("/proc/%d/ns/mnt", targetPid)
	mntFd, err := unix.Open(mntNs, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		unix.Close(userFd)
		return err
	}

	// 2. Enter user namespace
	if err := unix.Setns(userFd, unix.CLONE_NEWUSER); err != nil {
		unix.Close(userFd)
		unix.Close(mntFd)
		return err
	}
	unix.Close(userFd)

	// 3. Enter mount namespace
	if err := unix.Setns(mntFd, unix.CLONE_NEWNS); err != nil {
		unix.Close(mntFd)
		return err
	}
	unix.Close(mntFd)

	// 4. chroot
	if err := unix.Chroot(rootfs); err != nil {
		return err
	}

	// 5. chdir
	return unix.Chdir(workingDir)
}

// NsenterExec enters a namespace and executes a command.
// This replaces the Python preexec_fn pattern — Python calls this as a subprocess.
func NsenterExec(targetPid int, rootful bool, rootfs, workingDir string, cmdArgs []string) error {
	if rootful {
		if err := NsenterPreexec(targetPid); err != nil {
			return err
		}
	} else {
		if err := UsersPreexec(targetPid, rootfs, workingDir); err != nil {
			return err
		}
	}

	// exec the command
	bin, err := LookPath(cmdArgs[0])
	if err != nil {
		return err
	}
	return syscall.Exec(bin, cmdArgs, os.Environ())
}

// LookPath finds a binary in PATH inside the chroot.
func LookPath(name string) (string, error) {
	if name[0] == '/' {
		return name, nil
	}
	paths := []string{"/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"}
	pathEnv := os.Getenv("PATH")
	if pathEnv != "" {
		paths = append([]string{}, splitPath(pathEnv)...)
	}
	for _, dir := range paths {
		full := dir + "/" + name
		if _, err := os.Stat(full); err == nil {
			return full, nil
		}
	}
	return "", fmt.Errorf("executable not found: %s", name)
}

func splitPath(path string) []string {
	var result []string
	for _, p := range splitString(path, ':') {
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

func splitString(s string, sep byte) []string {
	var result []string
	for {
		i := indexByte(s, sep)
		if i < 0 {
			result = append(result, s)
			break
		}
		result = append(result, s[:i])
		s = s[i+1:]
	}
	return result
}

func indexByte(s string, b byte) int {
	for i := 0; i < len(s); i++ {
		if s[i] == b {
			return i
		}
	}
	return -1
}
