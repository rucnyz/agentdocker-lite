// Package userns provides user namespace helpers for sandbox cleanup.
package userns

import (
	"fmt"
	"os"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/unix"
)

// FixupDirForDelete enters a user namespace and recursively chmod+chown
// a directory so the host user can rmtree it. Returns 0 on success.
func FixupDirForDelete(usernsPid int, dirPath string) (uint32, error) {
	nsPath := fmt.Sprintf("/proc/%d/ns/user", usernsPid)
	nsFd, err := unix.Open(nsPath, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err != nil {
		return 0, err
	}

	pid, _, errno := unix.Syscall(unix.SYS_FORK, 0, 0, 0)
	if errno != 0 {
		unix.Close(nsFd)
		return 0, errno
	}

	if pid == 0 {
		// Child
		if err := unix.Setns(nsFd, unix.CLONE_NEWUSER); err != nil {
			unix.Exit(1)
		}
		unix.Close(nsFd)

		walkFixup(dirPath)
		unix.Exit(0)
	}

	// Parent
	unix.Close(nsFd)

	var ws unix.WaitStatus
	_, err = unix.Wait4(int(pid), &ws, 0, nil)
	if err != nil {
		return 0, err
	}
	if ws.Exited() && ws.ExitStatus() == 0 {
		return 0, nil
	}
	return 0, fmt.Errorf("userns fixup child exited with status %d", ws.ExitStatus())
}

func walkFixup(dir string) {
	fixupEntry(dir)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return
	}
	for _, entry := range entries {
		path := filepath.Join(dir, entry.Name())
		if entry.IsDir() {
			walkFixup(path)
		} else {
			fixupEntry(path)
		}
	}
}

func fixupEntry(path string) {
	// lchown to root:root
	_ = unix.Lchown(path, 0, 0)

	// chmod: dirs 0777, files 0666
	var st unix.Stat_t
	if unix.Lstat(path, &st) == nil {
		mode := uint32(0o666)
		if st.Mode&syscall.S_IFDIR != 0 {
			mode = 0o777
		}
		_ = unix.Chmod(path, mode)
	}
}
