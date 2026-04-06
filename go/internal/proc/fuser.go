// Package proc provides process inspection helpers.
package proc

import (
	"os"
	"path/filepath"
	"strconv"

	"golang.org/x/sys/unix"
)

// FuserKill kills all processes with open fds to targetPath. Returns kill count.
func FuserKill(targetPath string) (uint32, error) {
	target, err := filepath.EvalSymlinks(targetPath)
	if err != nil {
		target = targetPath
	}

	myPid := os.Getpid()
	var killed uint32

	entries, err := os.ReadDir("/proc")
	if err != nil {
		return 0, err
	}

	for _, entry := range entries {
		pid, err := strconv.Atoi(entry.Name())
		if err != nil || pid == myPid {
			continue
		}

		fdDir := filepath.Join("/proc", entry.Name(), "fd")
		fdEntries, err := os.ReadDir(fdDir)
		if err != nil {
			continue
		}

		shouldKill := false
		for _, fdEntry := range fdEntries {
			linkTarget, err := os.Readlink(filepath.Join(fdDir, fdEntry.Name()))
			if err != nil {
				continue
			}
			if linkTarget == target {
				shouldKill = true
				break
			}
		}

		if shouldKill {
			if unix.Kill(pid, unix.SIGKILL) == nil {
				killed++
			}
		}
	}

	return killed, nil
}
