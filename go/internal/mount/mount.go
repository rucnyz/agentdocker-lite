// Package mount provides overlay and bind mount operations.
package mount

import (
	"bufio"
	"fmt"
	"os"
	"sort"
	"strings"
	"sync"

	"golang.org/x/sys/unix"
)

var (
	newAPIOnce      sync.Once
	newAPISupported bool

	indexOnce      sync.Once
	indexSupported bool

	redirectOnce    sync.Once
	redirectNeedOff bool

	userxattrOnce   sync.Once
	userxattrNeeded bool
)

// CheckNewMountAPI returns true if the kernel supports fsopen + lowerdir+ (>= 6.8).
func CheckNewMountAPI() bool {
	newAPIOnce.Do(func() {
		fd, err := unix.Fsopen("overlay", unix.FSOPEN_CLOEXEC)
		if err != nil {
			return
		}
		defer unix.Close(fd)
		// Try lowerdir+ — EINVAL on kernel < 6.8
		err = unix.FsconfigSetString(fd, "lowerdir+", "/")
		newAPISupported = err == nil
	})
	return newAPISupported
}

// NeedsUserXattr returns true if userxattr is needed for rootless overlay (kernel >= 5.11).
func NeedsUserXattr() bool {
	userxattrOnce.Do(func() {
		data, err := os.ReadFile("/proc/version")
		if err != nil {
			return
		}
		major, minor := parseKernelVersion(string(data))
		userxattrNeeded = major > 5 || (major == 5 && minor >= 11)
	})
	return userxattrNeeded
}

func parseKernelVersion(ver string) (int, int) {
	for _, word := range strings.Fields(ver) {
		dot := strings.IndexByte(word, '.')
		if dot < 0 {
			continue
		}
		major := 0
		for _, c := range word[:dot] {
			if c < '0' || c > '9' {
				major = 0
				break
			}
			major = major*10 + int(c-'0')
		}
		if major == 0 && word[:dot] != "0" {
			continue
		}
		rest := word[dot+1:]
		minor := 0
		for _, c := range rest {
			if c < '0' || c > '9' {
				break
			}
			minor = minor*10 + int(c-'0')
		}
		return major, minor
	}
	return 0, 0
}

func overlaySupportsIndex() bool {
	indexOnce.Do(func() {
		data, err := os.ReadFile("/sys/module/overlay/parameters/index")
		indexSupported = err == nil && len(strings.TrimSpace(string(data))) > 0
	})
	return indexSupported
}

func overlayRedirectDirNeedOff() bool {
	redirectOnce.Do(func() {
		data, err := os.ReadFile("/sys/module/overlay/parameters/redirect_dir")
		if err != nil {
			return
		}
		v := strings.TrimSpace(string(data))
		redirectNeedOff = strings.EqualFold(v, "y") || strings.EqualFold(v, "on")
	})
	return redirectNeedOff
}

// MountOverlay mounts overlayfs, auto-selecting the best method.
func MountOverlay(lowerdirSpec, upperDir, workDir, target string, extraOpts []string) error {
	lowerDirs := strings.Split(lowerdirSpec, ":")

	opts := make([]string, len(extraOpts))
	copy(opts, extraOpts)

	hasUserXattr := false
	for _, o := range opts {
		if o == "userxattr" {
			hasUserXattr = true
			break
		}
	}

	if overlaySupportsIndex() {
		opts = append(opts, "index=off")
	}
	if !hasUserXattr && overlayRedirectDirNeedOff() {
		opts = append(opts, "redirect_dir=off")
	}

	if CheckNewMountAPI() {
		err := mountOverlayNewAPI(lowerDirs, upperDir, workDir, target, opts)
		if err == nil {
			return nil
		}
		// Fall through to legacy
	}

	return mountOverlayLegacy(lowerdirSpec, upperDir, workDir, target, opts)
}

func mountOverlayNewAPI(lowerDirs []string, upperDir, workDir, target string, extraOpts []string) error {
	fd, err := unix.Fsopen("overlay", unix.FSOPEN_CLOEXEC)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	for _, layer := range lowerDirs {
		if err := unix.FsconfigSetString(fd, "lowerdir+", layer); err != nil {
			return err
		}
	}
	if err := unix.FsconfigSetString(fd, "upperdir", upperDir); err != nil {
		return err
	}
	if err := unix.FsconfigSetString(fd, "workdir", workDir); err != nil {
		return err
	}

	for _, opt := range extraOpts {
		if k, v, ok := strings.Cut(opt, "="); ok {
			if err := unix.FsconfigSetString(fd, k, v); err != nil {
				return err
			}
		} else {
			if err := unix.FsconfigSetFlag(fd, opt); err != nil {
				return err
			}
		}
	}

	if err := unix.FsconfigCreate(fd); err != nil {
		return err
	}

	mntFd, err := unix.Fsmount(fd, unix.FSMOUNT_CLOEXEC, 0)
	if err != nil {
		return err
	}
	defer unix.Close(mntFd)

	return unix.MoveMount(mntFd, "", unix.AT_FDCWD, target, unix.MOVE_MOUNT_F_EMPTY_PATH)
}

func mountOverlayLegacy(lowerdirSpec, upperDir, workDir, target string, extraOpts []string) error {
	options := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", lowerdirSpec, upperDir, workDir)
	for _, opt := range extraOpts {
		options += "," + opt
	}

	pageSize := os.Getpagesize()
	if len(options) < pageSize {
		return unix.Mount("overlay", target, "overlay", 0, options)
	}

	// Fork + chdir trick for long mount data (matching Podman)
	lowers := strings.Split(lowerdirSpec, ":")
	common := commonPathPrefix(lowers)
	if common == "" {
		return fmt.Errorf("overlay mount data (%d bytes) exceeds page size (%d), no common prefix", len(options), pageSize)
	}

	// Fork child to chdir + mount with relative paths
	pid, _, errno := unix.RawSyscall(unix.SYS_FORK, 0, 0, 0)
	if errno != 0 {
		return errno
	}
	if pid == 0 {
		// Child
		code := mountOverlayFromChild(common, lowers, upperDir, workDir, target, extraOpts, pageSize)
		unix.Exit(code)
	}
	// Parent — wait for child
	var ws unix.WaitStatus
	_, err := unix.Wait4(int(pid), &ws, 0, nil)
	if err != nil {
		return err
	}
	if ws.ExitStatus() != 0 {
		return fmt.Errorf("overlay mount failed in chdir child process")
	}
	return nil
}

func mountOverlayFromChild(common string, lowers []string, upperDir, workDir, target string, extraOpts []string, pageSize int) int {
	_ = unix.Chdir(common)

	relLowers := make([]string, len(lowers))
	for i, l := range lowers {
		rel := strings.TrimPrefix(l, common)
		relLowers[i] = strings.TrimPrefix(rel, "/")
	}
	relSpec := strings.Join(relLowers, ":")
	opts := fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", relSpec, upperDir, workDir)
	for _, o := range extraOpts {
		opts += "," + o
	}

	if len(opts) < pageSize {
		if unix.Mount("overlay", target, "overlay", 0, opts) == nil {
			return 0
		}
		return 1
	}

	// Level 2: fd-based paths
	fds := make([]int, 0, len(lowers))
	for _, lower := range lowers {
		fd, err := unix.Open(lower, unix.O_RDONLY, 0)
		if err != nil {
			return 1
		}
		fds = append(fds, fd)
	}
	fdStrs := make([]string, len(fds))
	for i, fd := range fds {
		fdStrs[i] = fmt.Sprintf("%d", fd)
	}
	fdSpec := strings.Join(fdStrs, ":")
	opts = fmt.Sprintf("lowerdir=%s,upperdir=%s,workdir=%s", fdSpec, upperDir, workDir)
	for _, o := range extraOpts {
		opts += "," + o
	}
	if len(opts) >= pageSize {
		return 1
	}
	_ = unix.Chdir("/proc/self/fd")
	if unix.Mount("overlay", target, "overlay", 0, opts) != nil {
		return 1
	}
	return 0
}

func commonPathPrefix(paths []string) string {
	if len(paths) == 0 {
		return ""
	}
	first := paths[0]
	end := len(first)
	for _, p := range paths[1:] {
		if len(p) < end {
			end = len(p)
		}
		for i := 0; i < end; i++ {
			if first[i] != p[i] {
				end = i
				break
			}
		}
	}
	idx := strings.LastIndex(first[:end], "/")
	if idx < 0 {
		return ""
	}
	return first[:idx+1]
}

// BindMount performs a bind mount.
func BindMount(source, target string) error {
	return unix.Mount(source, target, "", unix.MS_BIND, "")
}

// RbindMount performs a recursive bind mount.
func RbindMount(source, target string) error {
	return unix.Mount(source, target, "", unix.MS_BIND|unix.MS_REC, "")
}

// MakePrivate makes a mount point private.
func MakePrivate(target string) error {
	return unix.Mount("", target, "", unix.MS_PRIVATE, "")
}

// RemountROBind remounts a bind mount as read-only.
func RemountROBind(target string) error {
	return unix.Mount("", target, "", unix.MS_REMOUNT|unix.MS_RDONLY|unix.MS_BIND, "")
}

// UmountLazy performs a lazy unmount.
func UmountLazy(target string) error {
	return unix.Unmount(target, unix.MNT_DETACH)
}

// Umount performs a regular unmount.
func Umount(target string) error {
	return unix.Unmount(target, 0)
}

// UmountRecursiveLazy lazily unmounts all sub-mounts under target (deepest first).
func UmountRecursiveLazy(target string) error {
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer f.Close()

	var subMounts []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) >= 5 {
			mp := fields[4]
			if strings.HasPrefix(mp, target) {
				subMounts = append(subMounts, mp)
			}
		}
	}

	// Sort deepest first
	sort.Slice(subMounts, func(i, j int) bool {
		return len(subMounts[i]) > len(subMounts[j])
	})

	for _, mp := range subMounts {
		_ = unix.Unmount(mp, unix.MNT_DETACH)
	}
	return nil
}

