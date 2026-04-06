// Package checkpoint provides CRIU-based process checkpoint/restore
// using the go-criu library. Replaces the Rust checkpoint helper.
package checkpoint

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
)

// DumpOpts configures a checkpoint dump.
type DumpOpts struct {
	// PID of the process tree root to dump.
	Pid int `json:"pid"`
	// Directory to save CRIU images.
	ImagesDir string `json:"images_dir"`
	// Root filesystem path (for ext-mount-map).
	Rootfs string `json:"rootfs"`
	// Keep process running after dump.
	LeaveRunning bool `json:"leave_running"`
	// Track memory changes (for incremental checkpoints).
	TrackMem bool `json:"track_mem"`
	// External mounts to preserve (e.g. ["/proc", "/dev"]).
	ExtMounts []string `json:"ext_mounts"`
	// External pipe inodes (e.g. ["pipe:[12345]"]).
	ExtPipes []string `json:"ext_pipes"`
	// Path to custom CRIU binary.
	CriuPath string `json:"criu_path"`
	// PID of sandbox process (for namespace entry via CGO constructor).
	NsPid int `json:"ns_pid"`
}

// RestoreOpts configures a checkpoint restore.
type RestoreOpts struct {
	// Directory containing CRIU images from a previous dump.
	ImagesDir string `json:"images_dir"`
	// Root filesystem path.
	Rootfs string `json:"rootfs"`
	// File to write restored PID.
	PidFile string `json:"pid_file"`
	// Inherit-fd mappings: [{"key": "pipe:[123]", "fd": 5}, ...]
	InheritFds []InheritFd `json:"inherit_fds"`
	// Path to custom CRIU binary.
	CriuPath string `json:"criu_path"`
	// PID of sandbox process (for namespace entry via CGO constructor).
	NsPid int `json:"ns_pid"`
}

// InheritFd maps a CRIU external resource to a local fd.
type InheritFd struct {
	Key string `json:"key"`
	Fd  int    `json:"fd"`
}

// DumpResult is returned after a successful dump.
type DumpResult struct {
	// Descriptors JSON (fd info for the dumped process).
	Descriptors string `json:"descriptors"`
}

// RestoreResult is returned after a successful restore.
type RestoreResult struct {
	// PID of the restored process tree root.
	Pid int `json:"pid"`
}

func findHelper() string {
	if p := os.Getenv("NITROBOX_CHECKPOINT_HELPER"); p != "" {
		return p
	}
	for _, p := range []string{
		"/usr/local/bin/nitrobox-checkpoint-helper",
		"/usr/bin/nitrobox-checkpoint-helper",
	} {
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	// Check next to our binary
	self, err := os.Executable()
	if err == nil {
		p := filepath.Join(filepath.Dir(self), "nitrobox-checkpoint-helper")
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "nitrobox-checkpoint-helper"
}

type cmdResult struct {
	err    error
	stderr string
}

func runCmd(args []string) cmdResult {
	cmd := exec.Command(args[0], args[1:]...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	err := cmd.Run()
	return cmdResult{err: err, stderr: stderr.String()}
}

func runCmdWithFds(args []string, fds []int) cmdResult {
	cmd := exec.Command(args[0], args[1:]...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	// Pass fds to child — disable close_fds
	cmd.SysProcAttr = &syscall.SysProcAttr{}
	for _, fd := range fds {
		cmd.ExtraFiles = append(cmd.ExtraFiles, os.NewFile(uintptr(fd), fmt.Sprintf("fd%d", fd)))
	}
	err := cmd.Run()
	return cmdResult{err: err, stderr: stderr.String()}
}

// Dump checkpoints a process tree using the setuid checkpoint helper.
// CRIU requires real root (uid 0), not just file capabilities, so we
// delegate to the installed nitrobox-checkpoint-helper which is setuid root.
func Dump(opts DumpOpts) (*DumpResult, error) {
	helper := findHelper()

	if err := os.MkdirAll(opts.ImagesDir, 0o700); err != nil {
		return nil, fmt.Errorf("create images dir: %w", err)
	}

	cmd := []string{
		helper, "dump",
		"--ns-pid", fmt.Sprintf("%d", opts.NsPid),
		"--tree", fmt.Sprintf("%d", opts.Pid),
		"--images-dir", opts.ImagesDir,
		"--shell-job",
	}
	if opts.LeaveRunning {
		cmd = append(cmd, "--leave-running")
	}
	if opts.TrackMem {
		cmd = append(cmd, "--track-mem")
	}
	for _, mnt := range opts.ExtMounts {
		cmd = append(cmd, "--ext-mount-map", fmt.Sprintf("%s:%s", mnt, mnt))
	}
	for _, pipe := range opts.ExtPipes {
		cmd = append(cmd, "--external", pipe)
	}

	result := runCmd(cmd)
	if result.err != nil {
		logFile := filepath.Join(opts.ImagesDir, "dump.log")
		logTail := ""
		if data, err := os.ReadFile(logFile); err == nil {
			if len(data) > 2000 {
				data = data[len(data)-2000:]
			}
			logTail = string(data)
		}
		return nil, fmt.Errorf("CRIU dump failed: %s\nstderr: %s\nlog: %s",
			result.err, result.stderr, logTail)
	}

	return &DumpResult{}, nil
}

// Restore restores a process tree from a CRIU checkpoint via the setuid helper.
func Restore(opts RestoreOpts) (*RestoreResult, error) {
	helper := findHelper()

	cmd := []string{
		helper, "restore",
		"--ns-pid", fmt.Sprintf("%d", opts.NsPid),
		"--images-dir", opts.ImagesDir,
		"--root", opts.Rootfs,
		"--shell-job",
		"--restore-sibling",
		"--restore-detached",
		"--mntns-compat-mode",
	}
	if opts.PidFile != "" {
		cmd = append(cmd, "--pidfile", opts.PidFile)
	}
	for _, ifd := range opts.InheritFds {
		cmd = append(cmd, "--inherit-fd", fmt.Sprintf("fd[%d]:%s", ifd.Fd, ifd.Key))
	}

	// pass_fds: collect all fds from inherit mappings
	var passFds []int
	for _, ifd := range opts.InheritFds {
		passFds = append(passFds, ifd.Fd)
	}

	result := runCmdWithFds(cmd, passFds)
	if result.err != nil {
		logFile := filepath.Join(opts.ImagesDir, "restore.log")
		logTail := ""
		if data, err := os.ReadFile(logFile); err == nil {
			if len(data) > 2000 {
				data = data[len(data)-2000:]
			}
			logTail = string(data)
		}
		return nil, fmt.Errorf("CRIU restore failed: %s\nstderr: %s\nlog: %s",
			result.err, result.stderr, logTail)
	}

	// Read PID from pidfile
	pid := 0
	if opts.PidFile != "" {
		if data, err := os.ReadFile(opts.PidFile); err == nil {
			fmt.Sscanf(strings.TrimSpace(string(data)), "%d", &pid)
		}
	}

	return &RestoreResult{Pid: pid}, nil
}

