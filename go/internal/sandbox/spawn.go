package sandbox

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/opensage-agent/nitrobox/go/internal/mount"
	"github.com/opensage-agent/nitrobox/go/internal/security"
	"golang.org/x/sys/unix"
)

// Docker-default masked paths (matches runc specconv/example.go).
var maskedPaths = []string{
	"/proc/acpi", "/proc/asound", "/proc/interrupts", "/proc/kcore",
	"/proc/keys", "/proc/latency_stats", "/proc/sched_debug", "/proc/scsi",
	"/proc/timer_list", "/proc/timer_stats",
	"/sys/devices/virtual/powercap", "/sys/firmware",
}

var roPaths = []string{
	"/proc/bus", "/proc/fs", "/proc/irq", "/proc/sys", "/proc/sysrq-trigger",
}

// errPipe is the write end of the error pipe, used by child helpers.
var errPipe int = -1

func initFatal(msg string) {
	if errPipe >= 0 {
		unix.Write(errPipe, []byte("F:"+msg))
	}
	unix.Exit(1)
}

func initWarn(msg string) {
	if errPipe >= 0 {
		unix.Write(errPipe, []byte("W:"+msg+"\n"))
	}
}

func makePipe() (r, w int) {
	var fds [2]int
	unix.Pipe2(fds[:], unix.O_CLOEXEC)
	return fds[0], fds[1]
}

func ptrInt(v int) *int { return &v }

// Spawn creates a sandboxed shell process. This is a direct port of Rust spawn_sandbox.
//
// When Pre* fd fields are set in config, those fds are used instead of creating
// new pipes. This is for the Python pass_fds mode where Python creates the pipes
// and passes them to the Go binary.
func Spawn(config *SpawnConfig) (*SpawnResult, error) {
	var errR, errW int
	if config.PreErrR != nil && config.PreErrW != nil {
		errR, errW = *config.PreErrR, *config.PreErrW
	} else {
		errR, errW = makePipe()
	}

	var signalR, signalW int
	if config.PreSignalR != nil && config.PreSignalW != nil {
		signalR, signalW = *config.PreSignalR, *config.PreSignalW
	} else {
		signalR, signalW = makePipe()
	}

	var stdinR, stdinW, stdoutR, stdoutW int
	var masterFd *int

	if config.PreStdinR != nil && config.PreStdinW != nil && config.PreStdoutR != nil && config.PreStdoutW != nil {
		stdinR, stdinW = *config.PreStdinR, *config.PreStdinW
		stdoutR, stdoutW = *config.PreStdoutR, *config.PreStdoutW
	} else if config.Tty {
		master, slave, err := openPty()
		if err != nil {
			return nil, fmt.Errorf("openpty failed: %w", err)
		}
		attrs, err := unix.IoctlGetTermios(master, unix.TCGETS)
		if err == nil {
			attrs.Lflag &^= unix.ECHO
			unix.IoctlSetTermios(master, unix.TCSETS, attrs)
		}
		stdinR, stdinW = slave, master
		stdoutR, stdoutW = master, slave
		masterFd = &master
	} else {
		stdinR, stdinW = makePipe()
		stdoutR, stdoutW = makePipe()
	}

	needsUsernSync := config.Userns && config.SharedUserns == nil
	var usrReadyR, usrReadyW int = -1, -1
	var syncR, syncW int = -1, -1
	if needsUsernSync {
		usrReadyR, usrReadyW = makePipe()
		syncR, syncW = makePipe()
	}

	// Save Go's stdout/stderr fds (pipes to Python's Popen) so child can close them
	goStdout, _ := unix.Dup(1)
	goStderr, _ := unix.Dup(2)
	unix.CloseOnExec(goStdout)
	unix.CloseOnExec(goStderr)

	// Fork
	pid, _, errno := unix.Syscall(unix.SYS_FORK, 0, 0, 0)
	if errno != 0 {
		unix.Close(goStdout)
		unix.Close(goStderr)
		return nil, errno
	}

	if pid == 0 {
		// === CHILD A ===
		// Close Go's Popen stdout/stderr pipes so Python's communicate() can return
		unix.Close(goStdout)
		unix.Close(goStderr)
		unix.Dup2(stdinR, 0)
		if config.Tty {
			unix.Dup2(stdinR, 1)
			unix.Dup2(stdinR, 2)
			if stdinR > 2 {
				unix.Close(stdinR)
			}
		} else {
			unix.Dup2(stdoutW, 1)
			unix.Dup2(stdoutW, 2)
			unix.Close(stdinR)
			unix.Close(stdinW)
			unix.Close(stdoutR)
			unix.Close(stdoutW)
		}
		unix.Close(signalR)
		unix.Close(errR)
		if syncW >= 0 {
			unix.Close(syncW)
		}
		if usrReadyR >= 0 {
			unix.Close(usrReadyR)
		}

		errPipe = errW

		// Join cgroup
		if config.CgroupPath != nil {
			procs := *config.CgroupPath + "/cgroup.procs"
			os.WriteFile(procs, []byte(fmt.Sprintf("%d", unix.Getpid())), 0o644)
		}

		// Shared userns: enter existing namespaces
		if config.SharedUserns != nil {
			fd, err := unix.Open(*config.SharedUserns, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err == nil {
				if err := unix.Setns(fd, unix.CLONE_NEWUSER); err != nil {
					initFatal(fmt.Sprintf("setns shared userns failed: %v", err))
				}
				unix.Close(fd)
			}
			if config.NetNs != nil {
				fd, err := unix.Open(*config.NetNs, unix.O_RDONLY|unix.O_CLOEXEC, 0)
				if err == nil {
					if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
						initFatal(fmt.Sprintf("setns shared netns failed: %v", err))
					}
					unix.Close(fd)
				}
			}
		}

		// Build unshare flags
		nsFlags := unix.CLONE_NEWPID | unix.CLONE_NEWNS | unix.CLONE_NEWUTS | unix.CLONE_NEWIPC
		if config.Userns && config.SharedUserns == nil {
			nsFlags |= unix.CLONE_NEWUSER
		}
		if config.NetIsolate && config.NetNs == nil && config.SharedUserns == nil {
			nsFlags |= unix.CLONE_NEWNET
		}
		if config.CgroupPath != nil {
			nsFlags |= unix.CLONE_NEWCGROUP
		}

		_, _, err := unix.Syscall(unix.SYS_UNSHARE, uintptr(nsFlags), 0, 0)
		if err != 0 {
			initFatal(fmt.Sprintf("unshare failed: %v", err))
		}

		// Signal parent that userns is ready
		if usrReadyW >= 0 {
			unix.Write(usrReadyW, []byte("R"))
			unix.Close(usrReadyW)
		}

		// Wait for UID mapping from parent
		if syncR >= 0 {
			buf := make([]byte, 1)
			unix.Read(syncR, buf)
			unix.Close(syncR)
		}

		// Mount propagation slave
		if err := unix.Mount("", "/", "", unix.MS_SLAVE|unix.MS_REC, ""); err != nil {
			initFatal(fmt.Sprintf("mount propagation slave failed: %v", err))
		}

		// Join net namespace if specified
		if config.SharedUserns == nil && config.NetNs != nil {
			fd, err := unix.Open(*config.NetNs, unix.O_RDONLY|unix.O_CLOEXEC, 0)
			if err == nil {
				if err := unix.Setns(fd, unix.CLONE_NEWNET); err != nil {
					initFatal(fmt.Sprintf("setns netns failed: %v", err))
				}
				unix.Close(fd)
			}
		}

		// Fork for PID namespace
		pid2, _, errno := unix.Syscall(unix.SYS_FORK, 0, 0, 0)
		if errno != 0 {
			initFatal("fork for PID namespace failed")
		}
		if pid2 == 0 {
			// PID 1 child
			childInit(config, signalW, errW)
		}
		// Intermediate parent: wait for PID 1
		unix.Close(errW)
		var ws unix.WaitStatus
		unix.Wait4(int(pid2), &ws, 0, nil)
		code := 1
		if ws.Exited() {
			code = ws.ExitStatus()
		}
		unix.Exit(code)
	}

	// === PARENT ===
	childPid := int(pid)

	// Close saved Go stdout/stderr dups (no longer needed in parent)
	unix.Close(goStdout)
	unix.Close(goStderr)

	if config.Tty {
		unix.Close(stdinR)
	} else {
		unix.Close(stdinR)
		unix.Close(stdoutW)
	}
	unix.Close(signalW)
	unix.Close(errW)
	if usrReadyW >= 0 {
		unix.Close(usrReadyW)
	}

	// UID/GID mapping
	if syncW >= 0 {
		if usrReadyR >= 0 {
			buf := make([]byte, 1)
			unix.Read(usrReadyR, buf)
			unix.Close(usrReadyR)
		}

		outerUID := uint32(unix.Getuid())
		outerGID := uint32(unix.Getgid())
		pidS := fmt.Sprintf("%d", childPid)

		if config.SubuidRange != nil {
			subStart := config.SubuidRange[1]
			subCount := config.SubuidRange[2]
			uidS := fmt.Sprintf("%d", outerUID)
			gidS := fmt.Sprintf("%d", outerGID)
			subS := fmt.Sprintf("%d", subStart)
			cntS := fmt.Sprintf("%d", subCount)
			exec.Command("newuidmap", pidS, "0", uidS, "1", "1", subS, cntS).Run()
			exec.Command("newgidmap", pidS, "0", gidS, "1", "1", subS, cntS).Run()
		} else {
			os.WriteFile(fmt.Sprintf("/proc/%s/setgroups", pidS), []byte("deny\n"), 0o644)
			os.WriteFile(fmt.Sprintf("/proc/%s/uid_map", pidS), []byte(fmt.Sprintf("0 %d 1\n", outerUID)), 0o644)
			os.WriteFile(fmt.Sprintf("/proc/%s/gid_map", pidS), []byte(fmt.Sprintf("0 %d 1\n", outerGID)), 0o644)
		}
		unix.Close(syncW)
	}

	// Non-blocking error pipe check
	unix.SetNonblock(errR, true)
	errBuf := make([]byte, 4096)
	n, _ := unix.Read(errR, errBuf)
	if n > 0 {
		msg := string(errBuf[:n])
		hasFatal := false
		for _, line := range strings.Split(msg, "\n") {
			if strings.HasPrefix(line, "F:") {
				hasFatal = true
				break
			}
		}
		if hasFatal {
			unix.Close(errR)
			unix.Kill(childPid, unix.SIGKILL)
			var ws unix.WaitStatus
			unix.Wait4(childPid, &ws, 0, nil)
			unix.Close(stdinW)
			unix.Close(stdoutR)
			unix.Close(signalR)
			if masterFd != nil {
				unix.Close(*masterFd)
			}
			detail := strings.TrimPrefix(msg, "F:")
			return nil, fmt.Errorf("sandbox init failed: %s", strings.TrimSpace(detail))
		}
	}

	// pidfd
	pidfdVal, err := unix.PidfdOpen(childPid, 0)
	var pidfdPtr *int
	if err == nil {
		pidfdPtr = &pidfdVal
	}

	return &SpawnResult{
		Pid:          childPid,
		StdinFd:      stdinW,
		StdoutFd:     stdoutR,
		SignalRFd:    signalR,
		SignalWFdNum: signalW,
		MasterFd:     masterFd,
		Pidfd:        pidfdPtr,
		ErrRFd:       errR,
	}, nil
}

// childInit is PID 1 in the new PID namespace.
func childInit(config *SpawnConfig, signalW, errW int) {
	errPipe = errW

	// setsid
	unix.Setsid()

	if config.Rootful {
		// pivot_root path
		if err := doPivotRootPhase1(config.Rootfs); err != nil {
			initFatal(fmt.Sprintf("pivot_root failed: %v", err))
		}
		mountProc("/", config.NetIsolate, config.VmMode, "/.pivot_old/sys", config.CgroupPath)
		setupDevRootful("/")
		mountShm("/", config.ShmSize)
		mountDevicesFromOldRoot("/", "/.pivot_old", config.Devices)
		envDirInOldRoot := ""
		if config.EnvDir != nil {
			envDirInOldRoot = "/.pivot_old/" + strings.TrimPrefix(*config.EnvDir, "/")
		}
		mountVolumesAt(config.Volumes, "/", envDirInOldRoot, "/.pivot_old")
		cleanupPivotOld()
		mountTmpfsAt(config.TmpfsMounts, "/")
		applySecurity(config)
	} else {
		// chroot path
		if err := mountOverlayFs(config); err != nil {
			initFatal(fmt.Sprintf("overlay mount failed: %v", err))
		}
		precreateVolumeMountpoints(config)
		if config.ReadOnly {
			makeRootfsReadonly(config.Rootfs)
		}
		mountProc(config.Rootfs, config.NetIsolate, config.VmMode, "", config.CgroupPath)
		setupDevRootless(config.Rootfs)
		mountShm(config.Rootfs, config.ShmSize)
		mountDevices(config.Rootfs, config.Devices)
		propagateDns(config.Rootfs)
		fixTmpPerms(config.Rootfs)
		mountVolumes(config)
		mountTmpfs(config)

		if len(config.PortMap) > 0 && config.PastaBin != nil && config.EnvDir != nil {
			setupPastaNetworking(*config.PastaBin, *config.EnvDir, config.PortMap, config.Ipv6, "")
		}

		if err := unix.Chroot(config.Rootfs); err != nil {
			initFatal(fmt.Sprintf("chroot failed: %v", err))
		}
		unix.Chdir("/")
		applySecurity(config)
	}

	// Build exec args
	var execArgs []string
	execArgs = append(execArgs, config.Entrypoint...)
	execArgs = append(execArgs, strings.Fields(config.Shell)...)
	if strings.Contains(config.Shell, "bash") {
		hasNorc := false
		for _, a := range execArgs {
			if a == "--norc" {
				hasNorc = true
				break
			}
		}
		if !hasNorc {
			execArgs = append(execArgs, "--norc", "--noprofile")
		}
	}

	// Build env
	var envVec []string
	for k, v := range config.Env {
		envVec = append(envVec, k+"="+v)
	}
	envVec = append(envVec, fmt.Sprintf("_NITROBOX_SIGNAL_FD=%d", signalW))

	// Working directory
	unix.Chdir(config.WorkingDir)

	// Clear CLOEXEC on signal_w
	unix.CloseOnExec(signalW) // this actually sets it, we need to clear it
	// Use fcntl to clear FD_CLOEXEC
	flags, _ := unix.FcntlInt(uintptr(signalW), unix.F_GETFD, 0)
	unix.FcntlInt(uintptr(signalW), unix.F_SETFD, flags&^unix.FD_CLOEXEC)

	// Exec
	if len(execArgs) == 0 {
		initFatal("no exec args")
	}
	err := unix.Exec(execArgs[0], execArgs, envVec)
	initFatal(fmt.Sprintf("exec %s failed: %v", config.Shell, err))
}

// ======================================================================
// Filesystem setup
// ======================================================================

func mountOverlayFs(config *SpawnConfig) error {
	if config.LowerdirSpec == nil || config.UpperDir == nil || config.WorkDir == nil {
		return nil
	}
	lowerdir := *config.LowerdirSpec
	upper := *config.UpperDir
	work := *config.WorkDir

	// Fix 000-perm dirs left by previous overlayfs.
	// Uses exec.Command (matching Rust) — consumes PID 2 in the namespace,
	// which keeps PID numbering consistent for CRIU checkpoint/restore.
	exec.Command("chmod", "-R", "700", work).Run()
	workInner := work + "/work"
	os.RemoveAll(workInner)

	var extra []string
	if config.Userns && mount.NeedsUserXattr() {
		extra = append(extra, "userxattr")
	}
	return mount.MountOverlay(lowerdir, upper, work, config.Rootfs, extra)
}

func mountProc(rootfs string, netIsolate, vmMode bool, hostSys string, cgroupPath *string) {
	procPath := rootfs + "/proc"
	os.MkdirAll(procPath, 0o755)
	if err := unix.Mount("proc", procPath, "proc", 0, ""); err != nil {
		initWarn(fmt.Sprintf("mount /proc failed: %v", err))
	}

	// /sys
	sysPath := rootfs + "/sys"
	os.MkdirAll(sysPath, 0o755)
	if netIsolate {
		unix.Mount("sysfs", sysPath, "sysfs", 0, "")
	} else {
		src := "/sys"
		if hostSys != "" {
			src = hostSys
		}
		if unix.Mount(src, sysPath, "", unix.MS_BIND|unix.MS_REC, "") == nil {
			unix.Mount("", sysPath, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
		}
	}

	// Cgroup bind mount
	if cgroupPath != nil {
		cgTarget := rootfs + "/sys/fs/cgroup"
		os.MkdirAll(cgTarget, 0o755)
		if unix.Mount(*cgroupPath, cgTarget, "", unix.MS_BIND, "") == nil {
			unix.Mount("", cgTarget, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV|unix.MS_NOEXEC, "")
		}
	}

	if vmMode {
		runTarget := rootfs + "/run"
		os.MkdirAll(runTarget, 0o755)
		unix.Mount("tmpfs", runTarget, "tmpfs", 0, "mode=0755")
	}
}

func setupDevRootful(rootfs string) {
	dev := rootfs + "/dev"
	os.MkdirAll(dev, 0o755)
	unix.Mount("tmpfs", dev, "tmpfs", unix.MS_NOSUID, "mode=0755")

	devices := [][4]uint32{
		{1, 3, 0o666, 0}, // null
		{1, 5, 0o666, 0}, // zero
		{1, 7, 0o666, 0}, // full
		{1, 8, 0o444, 0}, // random
		{1, 9, 0o444, 0}, // urandom
		{5, 0, 0o666, 0}, // tty
	}
	names := []string{"null", "zero", "full", "random", "urandom", "tty"}
	for i, d := range devices {
		path := dev + "/" + names[i]
		unix.Mknod(path, unix.S_IFCHR|d[2], int(unix.Mkdev(d[0], d[1])))
	}
	setupDevLinks(rootfs)
}

func setupDevRootless(rootfs string) {
	dev := rootfs + "/dev"
	os.MkdirAll(dev, 0o755)
	unix.Mount("tmpfs", dev, "tmpfs", unix.MS_NOSUID, "mode=0755")

	for _, name := range []string{"null", "zero", "full", "random", "urandom", "tty"} {
		target := dev + "/" + name
		os.Create(target)
		unix.Mount("/dev/"+name, target, "", unix.MS_BIND, "")
	}
	setupDevLinks(rootfs)
}

func setupDevLinks(rootfs string) {
	dev := rootfs + "/dev"
	os.Symlink("/proc/self/fd", dev+"/fd")
	os.Symlink("/proc/self/fd/0", dev+"/stdin")
	os.Symlink("/proc/self/fd/1", dev+"/stdout")
	os.Symlink("/proc/self/fd/2", dev+"/stderr")
	if _, err := os.Stat("/proc/kcore"); err == nil {
		os.Symlink("/proc/kcore", dev+"/core")
	}
	pts := dev + "/pts"
	os.MkdirAll(pts, 0o755)
	unix.Mount("devpts", pts, "devpts", unix.MS_NOSUID, "newinstance,ptmxmode=0666")
	os.Symlink("pts/ptmx", dev+"/ptmx")
	os.MkdirAll(dev+"/shm", 0o755)
	mqueue := dev + "/mqueue"
	os.MkdirAll(mqueue, 0o755)
	unix.Mount("mqueue", mqueue, "mqueue", unix.MS_NOSUID|unix.MS_NOEXEC|unix.MS_NODEV, "")
}

func mountShm(rootfs string, shmSize *uint64) {
	size := uint64(256 * 1024 * 1024)
	if shmSize != nil {
		size = *shmSize
	}
	shm := rootfs + "/dev/shm"
	os.MkdirAll(shm, 0o755)
	unix.Mount("tmpfs", shm, "tmpfs", unix.MS_NOSUID, fmt.Sprintf("size=%d", size))
}

func mountDevices(rootfs string, devices []string) {
	for _, devPath := range devices {
		devName := strings.TrimPrefix(devPath, "/")
		target := rootfs + "/" + devName
		if parent := filepath.Dir(devName); parent != "." && parent != "" {
			os.MkdirAll(rootfs+"/"+parent, 0o755)
		}
		os.Create(target)
		unix.Mount(devPath, target, "", unix.MS_BIND, "")
	}
}

func mountDevicesFromOldRoot(rootfs, oldRoot string, devices []string) {
	for _, devPath := range devices {
		devName := strings.TrimPrefix(devPath, "/")
		target := rootfs + "/" + devName
		if parent := filepath.Dir(devName); parent != "." && parent != "" {
			os.MkdirAll(rootfs+"/"+parent, 0o755)
		}
		os.Create(target)
		source := oldRoot + "/" + devName
		unix.Mount(source, target, "", unix.MS_BIND, "")
	}
}

func mountVolumes(config *SpawnConfig) {
	mountVolumesAt(config.Volumes, config.Rootfs, deref(config.EnvDir), "")
}

func mountVolumesAt(volumes []string, rootfs, envDir, hostPrefix string) {
	for _, spec := range volumes {
		parts := strings.SplitN(spec, ":", 3)
		if len(parts) < 2 {
			continue
		}
		rawHostPath := parts[0]
		containerPath := parts[1]
		mode := "rw"
		if len(parts) > 2 {
			mode = parts[2]
		}
		target := rootfs + "/" + strings.TrimPrefix(containerPath, "/")
		os.MkdirAll(target, 0o755)

		hostPath := rawHostPath
		if hostPrefix != "" {
			hostPath = hostPrefix + "/" + strings.TrimPrefix(rawHostPath, "/")
		}

		switch mode {
		case "cow":
			if envDir != "" {
				safe := strings.Trim(strings.ReplaceAll(containerPath, "/", "_"), "_")
				cowUpper := envDir + "/cow_" + safe + "_upper"
				cowWork := envDir + "/cow_" + safe + "_work"
				os.MkdirAll(cowUpper, 0o755)
				os.MkdirAll(cowWork, 0o755)
				opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", hostPath, cowUpper, cowWork)
				unix.Mount("overlay", target, "overlay", 0, opts)
			}
		case "ro":
			if unix.Mount(hostPath, target, "", unix.MS_BIND, "") == nil {
				unix.Mount("", target, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_NOSUID|unix.MS_NODEV, "")
			}
		default:
			unix.Mount(hostPath, target, "", unix.MS_BIND, "")
		}
	}
}

func mountTmpfs(config *SpawnConfig) {
	mountTmpfsAt(config.TmpfsMounts, config.Rootfs)
}

func mountTmpfsAt(tmpfsMounts []string, rootfs string) {
	for _, spec := range tmpfsMounts {
		parts := strings.SplitN(spec, ":", 2)
		path := parts[0]
		opts := ""
		if len(parts) > 1 {
			opts = parts[1]
		}
		target := rootfs + "/" + strings.TrimPrefix(path, "/")
		os.MkdirAll(target, 0o755)
		unix.Mount("tmpfs", target, "tmpfs", 0, opts)
	}
}

func propagateDns(rootfs string) {
	sandboxResolv := rootfs + "/etc/resolv.conf"
	if _, err := os.Stat("/etc/resolv.conf"); err != nil {
		return
	}
	needsCopy := true
	if info, err := os.Stat(sandboxResolv); err == nil {
		needsCopy = info.Size() == 0
	}
	if needsCopy {
		data, err := os.ReadFile("/etc/resolv.conf")
		if err == nil {
			os.WriteFile(sandboxResolv, data, 0o644)
		}
	}
}

func fixTmpPerms(rootfs string) {
	unix.Chmod(rootfs+"/tmp", 0o1777)
}

func makeRootfsReadonly(rootfs string) {
	unix.Mount(rootfs, rootfs, "", unix.MS_BIND, "")
	unix.Mount("", rootfs, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
}

func precreateVolumeMountpoints(config *SpawnConfig) {
	for _, spec := range config.Volumes {
		parts := strings.SplitN(spec, ":", 3)
		if len(parts) < 2 {
			continue
		}
		target := config.Rootfs + "/" + strings.TrimPrefix(parts[1], "/")
		os.MkdirAll(target, 0o755)
	}
}

// ======================================================================
// Security
// ======================================================================

func maskPath(path string) {
	if _, err := os.Stat(path); err != nil {
		return
	}
	info, _ := os.Stat(path)
	if info != nil && info.IsDir() {
		unix.Mount("tmpfs", path, "tmpfs", unix.MS_RDONLY, "size=0")
	} else {
		unix.Mount("/dev/null", path, "", unix.MS_BIND, "")
	}
}

func applySecurity(config *SpawnConfig) {
	if config.Hostname != nil {
		unix.Sethostname([]byte(*config.Hostname))
	}

	security.DropCapabilities(config.CapAdd, config.CapDrop)

	if !config.VmMode {
		for _, p := range maskedPaths {
			maskPath(p)
		}
		// Dynamic: mask thermal_throttle
		entries, err := os.ReadDir("/sys/devices/system/cpu")
		if err == nil {
			for _, e := range entries {
				name := e.Name()
				if strings.HasPrefix(name, "cpu") && len(name) > 3 && name[3] >= '0' && name[3] <= '9' {
					maskPath("/sys/devices/system/cpu/" + name + "/thermal_throttle")
				}
			}
		}
		// Read-only paths
		for _, p := range roPaths {
			if unix.Mount(p, p, "", unix.MS_BIND, "") == nil {
				unix.Mount("", p, "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
			}
		}
	}

	if config.ReadOnly {
		unix.Mount("", "/", "", unix.MS_BIND|unix.MS_REMOUNT|unix.MS_RDONLY, "")
	}

	// Landlock
	for _, p := range config.LandlockWritePaths {
		os.MkdirAll(p, 0o755)
	}
	for _, p := range config.LandlockReadPaths {
		os.MkdirAll(p, 0o755)
	}
	if len(config.LandlockReadPaths) > 0 || len(config.LandlockWritePaths) > 0 || len(config.LandlockPorts) > 0 {
		security.ApplyLandlock(config.LandlockReadPaths, config.LandlockWritePaths, config.LandlockPorts, config.LandlockStrict)
	}

	if config.Seccomp && !config.VmMode {
		security.ApplySeccompFilter()
	}
}

// ======================================================================
// Pivot root
// ======================================================================

func doPivotRootPhase1(rootfs string) error {
	unix.Mount("", "/", "", unix.MS_SLAVE|unix.MS_REC, "")
	if err := unix.Mount(rootfs, rootfs, "", unix.MS_BIND, ""); err != nil {
		return err
	}
	if err := unix.Chdir(rootfs); err != nil {
		return err
	}
	pivotOld := rootfs + "/.pivot_old"
	os.MkdirAll(pivotOld, 0o755)
	if err := unix.PivotRoot(".", ".pivot_old"); err != nil {
		return err
	}
	unix.Chdir("/")
	unix.Mount("", "/.pivot_old", "", unix.MS_SLAVE|unix.MS_REC, "")
	return nil
}

func cleanupPivotOld() {
	unix.Unmount("/.pivot_old", unix.MNT_DETACH)
	os.Remove("/.pivot_old")
}

// ======================================================================
// Pasta networking
// ======================================================================

func setupPastaNetworking(pastaBin, envDir string, portMap []string, ipv6 bool, hostPrefix string) {
	actualPasta := pastaBin
	actualEnvDir := envDir
	if hostPrefix != "" {
		actualPasta = hostPrefix + pastaBin
		actualEnvDir = hostPrefix + envDir
	}
	netnsFile := actualEnvDir + "/.netns"
	os.Create(netnsFile)

	// Fork + unshare(CLONE_NEWNET) + bind mount
	pid, _, errno := unix.Syscall(unix.SYS_FORK, 0, 0, 0)
	if errno != 0 {
		return
	}
	if pid == 0 {
		unix.Unshare(unix.CLONE_NEWNET)
		unix.Mount("/proc/self/ns/net", netnsFile, "", unix.MS_BIND, "")
		unix.Exit(0)
	}
	var ws unix.WaitStatus
	unix.Wait4(int(pid), &ws, 0, nil)

	// Start pasta
	args := []string{"--config-net"}
	if unix.Getuid() == 0 {
		args = append(args, "--runas", "0:0")
	}
	if !ipv6 {
		args = append(args, "--ipv4-only")
	}
	for _, m := range portMap {
		args = append(args, "-t", m)
	}
	args = append(args, "-u", "none", "-T", "none", "-U", "none",
		"--dns-forward", "169.254.1.1", "--no-map-gw", "--quiet",
		"--netns", netnsFile, "--map-guest-addr", "169.254.1.2")

	exec.Command(actualPasta, args...).Run()

	// Enter netns
	fd, err := unix.Open(netnsFile, unix.O_RDONLY|unix.O_CLOEXEC, 0)
	if err == nil {
		unix.Setns(fd, unix.CLONE_NEWNET)
		unix.Close(fd)
	}

	// Bring up loopback via netlink (simpler than ioctl)
	bringUpLoopback()
}

func bringUpLoopback() {
	sock, err := unix.Socket(unix.AF_INET, unix.SOCK_DGRAM, 0)
	if err != nil {
		return
	}
	defer unix.Close(sock)

	// struct ifreq for "lo"
	type ifreq struct {
		Name  [unix.IFNAMSIZ]byte
		Flags int16
		_     [22]byte // padding
	}
	var ifr ifreq
	copy(ifr.Name[:], "lo")

	// SIOCGIFFLAGS
	_, _, errno := unix.Syscall(unix.SYS_IOCTL, uintptr(sock), uintptr(unix.SIOCGIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
	if errno != 0 {
		return
	}
	ifr.Flags |= unix.IFF_UP
	unix.Syscall(unix.SYS_IOCTL, uintptr(sock), uintptr(unix.SIOCSIFFLAGS), uintptr(unsafe.Pointer(&ifr)))
}

func deref(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

// openPty opens a pseudo-terminal pair. Returns (master, slave, error).
func openPty() (int, int, error) {
	master, err := unix.Open("/dev/ptmx", unix.O_RDWR|unix.O_NOCTTY|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, -1, err
	}
	// unlockpt via ioctl
	val := 0
	unix.IoctlSetPointerInt(master, unix.TIOCSPTLCK, val)
	// Get slave number
	n, err := unix.IoctlGetInt(master, unix.TIOCGPTN)
	if err != nil {
		unix.Close(master)
		return -1, -1, err
	}
	slaveName := fmt.Sprintf("/dev/pts/%d", n)
	slave, err := unix.Open(slaveName, unix.O_RDWR|unix.O_NOCTTY, 0)
	if err != nil {
		unix.Close(master)
		return -1, -1, err
	}
	return master, slave, nil
}
