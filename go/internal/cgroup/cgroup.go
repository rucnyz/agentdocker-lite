// Package cgroup provides cgroup v2 operations.
package cgroup

import (
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const cgroupBase = "/sys/fs/cgroup/nitrobox"

// V2Available returns true if cgroup v2 is available.
func V2Available() bool {
	_, err := os.Stat("/sys/fs/cgroup/cgroup.controllers")
	return err == nil
}

// Create creates a cgroup and returns its path.
func Create(name string) (string, error) {
	path := filepath.Join(cgroupBase, name)
	if err := os.MkdirAll(path, 0o755); err != nil {
		return "", err
	}
	return path, nil
}

// EnableControllers enables required controllers on the parent cgroup.
func EnableControllers(cgroupPath string, limits map[string]string) error {
	parent := filepath.Dir(cgroupPath)
	subtreeCtl := filepath.Join(parent, "cgroup.subtree_control")
	if _, err := os.Stat(subtreeCtl); err != nil {
		return nil
	}

	controllerMap := map[string]string{
		"cpu_max":     "cpu",
		"cpu_shares":  "cpu",
		"memory_max":  "memory",
		"memory_high": "memory",
		"memory_swap": "memory",
		"pids_max":    "pids",
		"io_max":      "io",
		"cpuset_cpus": "cpuset",
		"cpuset_mems": "cpuset",
	}

	for key, ctrl := range controllerMap {
		if _, ok := limits[key]; ok {
			_ = os.WriteFile(subtreeCtl, []byte("+"+ctrl), 0o644)
		}
	}
	return nil
}

// ConvertCPUShares converts Docker CPU shares (2-262144) to cgroup v2 weight (1-10000).
func ConvertCPUShares(shares uint64) uint64 {
	if shares == 0 {
		return 100
	}
	w := (shares - 2) * 9999 / 262142
	w += 1
	if w < 1 {
		return 1
	}
	if w > 10000 {
		return 10000
	}
	return w
}

// ApplyLimits applies resource limits to a cgroup.
func ApplyLimits(cgroupPath string, limits map[string]string) error {
	limitFiles := map[string]string{
		"cpu_max":     "cpu.max",
		"memory_max":  "memory.max",
		"memory_high": "memory.high",
		"pids_max":    "pids.max",
		"io_max":      "io.max",
		"cpuset_cpus": "cpuset.cpus",
		"cpuset_mems": "cpuset.mems",
		"cpu_shares":  "cpu.weight",
		"memory_swap": "memory.swap.max",
	}

	for key, filename := range limitFiles {
		value, ok := limits[key]
		if !ok {
			continue
		}

		writeValue := value
		if key == "cpu_shares" {
			shares, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				continue
			}
			writeValue = strconv.FormatUint(ConvertCPUShares(shares), 10)
		}

		filePath := filepath.Join(cgroupPath, filename)
		if err := os.WriteFile(filePath, []byte(writeValue), 0o644); err != nil {
			// Non-fatal, log and continue
			fmt.Fprintf(os.Stderr, "warning: failed to set cgroup %s: %v\n", filename, err)
		}
	}
	return nil
}

// AddProcess moves a process into a cgroup.
func AddProcess(cgroupPath string, pid uint32) error {
	return os.WriteFile(filepath.Join(cgroupPath, "cgroup.procs"), []byte(strconv.FormatUint(uint64(pid), 10)), 0o644)
}

// Cleanup kills all processes in a cgroup and removes it.
func Cleanup(cgroupPath string) error {
	if _, err := os.Stat(cgroupPath); err != nil {
		return nil
	}

	// Kill via cgroup.kill (kernel 5.14+)
	killFile := filepath.Join(cgroupPath, "cgroup.kill")
	if _, err := os.Stat(killFile); err == nil {
		_ = os.WriteFile(killFile, []byte("1"), 0o644)
	}

	// SIGKILL remaining processes
	procsFile := filepath.Join(cgroupPath, "cgroup.procs")
	data, err := os.ReadFile(procsFile)
	if err == nil {
		for _, pidStr := range strings.Fields(string(data)) {
			pid, err := strconv.Atoi(pidStr)
			if err == nil {
				_ = unix.Kill(pid, unix.SIGKILL)
			}
		}
	}

	// Retry rmdir
	for i := 0; i < 20; i++ {
		err := os.Remove(cgroupPath)
		if err == nil {
			return nil
		}
		if i < 19 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	return nil
}
