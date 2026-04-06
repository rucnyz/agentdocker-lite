// Package checkpoint provides CRIU-based process checkpoint/restore
// using the go-criu library. Replaces the Rust checkpoint helper.
package checkpoint

import (
	"fmt"
	"os"
	"path/filepath"

	criu "github.com/checkpoint-restore/go-criu/v7"
	criurpc "github.com/checkpoint-restore/go-criu/v7/rpc"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
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

func findCriu(explicit string) string {
	if explicit != "" {
		return explicit
	}
	// Check next to our binary
	self, err := os.Executable()
	if err == nil {
		dir := filepath.Dir(self)
		for _, name := range []string{"criu", "../lib/nitrobox/criu"} {
			p := filepath.Join(dir, name)
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	// Check vendor path
	// The CRIU binary path can also be set via env
	if p := os.Getenv("NITROBOX_CRIU_PATH"); p != "" {
		return p
	}
	return "criu"
}

// Dump checkpoints a process tree using CRIU.
func Dump(opts DumpOpts) (*DumpResult, error) {
	c := criu.MakeCriu()
	c.SetCriuPath(findCriu(opts.CriuPath))

	if err := os.MkdirAll(opts.ImagesDir, 0o700); err != nil {
		return nil, fmt.Errorf("create images dir: %w", err)
	}

	imageDir, err := os.Open(opts.ImagesDir)
	if err != nil {
		return nil, fmt.Errorf("open images dir: %w", err)
	}
	defer imageDir.Close()

	rpcOpts := &criurpc.CriuOpts{
		ImagesDirFd:     proto.Int32(int32(imageDir.Fd())),
		LogLevel:        proto.Int32(4),
		LogFile:         proto.String("dump.log"),
		Pid:             proto.Int32(int32(opts.Pid)),
		ShellJob:        proto.Bool(true),
		LeaveRunning:    proto.Bool(opts.LeaveRunning),
		TrackMem:        proto.Bool(opts.TrackMem),
		OrphanPtsMaster: proto.Bool(true),
		NotifyScripts:   proto.Bool(false),
	}

	// External mount mappings
	for _, mnt := range opts.ExtMounts {
		rpcOpts.ExtMnt = append(rpcOpts.ExtMnt, &criurpc.ExtMountMap{
			Key: proto.String(mnt),
			Val: proto.String(mnt),
		})
	}

	// External pipes
	for _, pipe := range opts.ExtPipes {
		rpcOpts.External = append(rpcOpts.External, pipe)
	}

	if err := c.Dump(rpcOpts, criu.NoNotify{}); err != nil {
		logFile := filepath.Join(opts.ImagesDir, "dump.log")
		logTail := ""
		if data, err := os.ReadFile(logFile); err == nil {
			if len(data) > 2000 {
				data = data[len(data)-2000:]
			}
			logTail = string(data)
		}
		return nil, fmt.Errorf("CRIU dump failed: %w\nlog: %s", err, logTail)
	}

	return &DumpResult{}, nil
}

// Restore restores a process tree from a CRIU checkpoint.
func Restore(opts RestoreOpts) (*RestoreResult, error) {
	c := criu.MakeCriu()
	c.SetCriuPath(findCriu(opts.CriuPath))

	imageDir, err := os.Open(opts.ImagesDir)
	if err != nil {
		return nil, fmt.Errorf("open images dir: %w", err)
	}
	defer imageDir.Close()

	// CRIU requires --root to be a mount point.
	// Bind-mount rootfs to a temp dir (same as runc).
	criuRoot := opts.Rootfs + "-criu-root"
	os.MkdirAll(criuRoot, 0o755)
	if err := unix.Mount(opts.Rootfs, criuRoot, "", unix.MS_BIND|unix.MS_REC, ""); err != nil {
		return nil, fmt.Errorf("bind mount rootfs: %w", err)
	}
	defer func() {
		unix.Unmount(criuRoot, unix.MNT_DETACH)
		os.Remove(criuRoot)
	}()

	rpcOpts := &criurpc.CriuOpts{
		ImagesDirFd:     proto.Int32(int32(imageDir.Fd())),
		LogLevel:        proto.Int32(4),
		LogFile:         proto.String("restore.log"),
		Root:            proto.String(criuRoot),
		ShellJob:        proto.Bool(true),
		RstSibling:      proto.Bool(true),
		OrphanPtsMaster: proto.Bool(true),
		NotifyScripts:   proto.Bool(false),
	}

	rpcOpts.MntnsCompatMode = proto.Bool(true)

	// Inherit-fd mappings
	for _, ifd := range opts.InheritFds {
		rpcOpts.InheritFd = append(rpcOpts.InheritFd, &criurpc.InheritFd{
			Key: proto.String(ifd.Key),
			Fd:  proto.Int32(int32(ifd.Fd)),
		})
	}

	// Use a notify callback to capture the restored PID
	var restoredPid int32
	notify := &restoreNotify{pid: &restoredPid}

	if err := c.Restore(rpcOpts, notify); err != nil {
		logFile := filepath.Join(opts.ImagesDir, "restore.log")
		logTail := ""
		if data, err := os.ReadFile(logFile); err == nil {
			if len(data) > 2000 {
				data = data[len(data)-2000:]
			}
			logTail = string(data)
		}
		return nil, fmt.Errorf("CRIU restore failed: %w\nlog: %s", err, logTail)
	}

	return &RestoreResult{Pid: int(restoredPid)}, nil
}

// restoreNotify captures the restored PID from CRIU's notification.
type restoreNotify struct {
	criu.NoNotify
	pid *int32
}

func (n *restoreNotify) PostRestore(pid int32) error {
	*n.pid = pid
	return nil
}

