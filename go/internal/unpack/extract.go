// Package unpack provides UID-preserving layer extraction with whiteout conversion.
package unpack

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"

	"go.podman.io/storage/pkg/archive"
	"golang.org/x/sys/unix"
)

const overflowID = 65534

// ExtractTarInUserns extracts a tar file inside a user namespace with full UID/GID mapping.
// Uses re-exec pattern instead of raw fork (Go's runtime is not fork-safe).
func ExtractTarInUserns(tarPath, dest string, outerUID, outerGID, subStart, subCount uint32) error {
	// Re-exec self with a special subcommand that does the extraction.
	// The child process is started with CLONE_NEWUSER via SysProcAttr.
	self := coreBinary()

	usernsPipeR, usernsPipeW, _ := os.Pipe()
	goPipeR, goPipeW, _ := os.Pipe()

	cmd := exec.Command(self, "_extract-worker")
	cmd.Stdin = nil
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.ExtraFiles = []*os.File{usernsPipeW, goPipeR} // fd 3 = usernsPipeW, fd 4 = goPipeR
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("_NBX_TAR_PATH=%s", tarPath),
		fmt.Sprintf("_NBX_DEST=%s", dest),
		fmt.Sprintf("_NBX_MAX_ID=%d", subCount),
	)
	cmd.SysProcAttr = &unix.SysProcAttr{
		Cloneflags: unix.CLONE_NEWUSER,
	}

	if err := cmd.Start(); err != nil {
		usernsPipeR.Close()
		usernsPipeW.Close()
		goPipeR.Close()
		goPipeW.Close()
		return fmt.Errorf("start extract worker: %w", err)
	}
	usernsPipeW.Close()
	goPipeR.Close()

	// Wait for child to signal userns ready
	buf := make([]byte, 1)
	usernsPipeR.Read(buf)
	usernsPipeR.Close()

	// Set up UID/GID mapping
	mappingErr := setupIDMapping(cmd.Process.Pid, outerUID, outerGID, subStart, subCount)

	// Signal child to proceed
	goPipeW.Write([]byte("G"))
	goPipeW.Close()

	if mappingErr != nil {
		cmd.Process.Kill()
		cmd.Wait()
		return mappingErr
	}

	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("layer extraction in userns failed: %w", err)
	}
	return nil
}

// ExtractWorker is the re-exec entry point for extraction inside a user namespace.
// Called as: nitrobox-core _extract-worker (with env vars and extra fds).
func ExtractWorker() {
	tarPath := os.Getenv("_NBX_TAR_PATH")
	dest := os.Getenv("_NBX_DEST")
	maxIDStr := os.Getenv("_NBX_MAX_ID")
	maxID := uint32(65536)
	fmt.Sscanf(maxIDStr, "%d", &maxID)

	// fd 3 = usernsPipeW, fd 4 = goPipeR (from ExtraFiles)
	usernsPipeW := os.NewFile(3, "usernsPipeW")
	goPipeR := os.NewFile(4, "goPipeR")

	// Signal parent that userns is ready
	usernsPipeW.Write([]byte("R"))
	usernsPipeW.Close()

	// Wait for UID mapping from parent
	buf := make([]byte, 1)
	goPipeR.Read(buf)
	goPipeR.Close()

	// Debug: verify UID/GID mapping is set
	if data, err := os.ReadFile("/proc/self/uid_map"); err == nil {
		fmt.Fprintf(os.Stderr, "uid_map: %s", string(data))
	}
	if data, err := os.ReadFile("/proc/self/gid_map"); err == nil {
		fmt.Fprintf(os.Stderr, "gid_map: %s", string(data))
	}
	// Test lchown directly
	tmpf, _ := os.CreateTemp("", "lchown_test")
	if tmpf != nil {
		tmpf.Close()
		err := unix.Lchown(tmpf.Name(), 100, 100)
		fmt.Fprintf(os.Stderr, "test lchown(100,100): %v\n", err)
		os.Remove(tmpf.Name())
	}

	if err := doExtract(tarPath, dest); err != nil {
		fmt.Fprintf(os.Stderr, "nitrobox: layer extraction failed: %v\n", err)
		os.Exit(2)
	}
	os.Exit(0)
}

// RmtreeInUserns removes a directory tree containing files with mapped UIDs.
func RmtreeInUserns(path string, outerUID, outerGID, subStart, subCount uint32) error {
	self := coreBinary()

	usernsPipeR, usernsPipeW, _ := os.Pipe()
	goPipeR, goPipeW, _ := os.Pipe()

	cmd := exec.Command(self, "_rmtree-worker")
	cmd.ExtraFiles = []*os.File{usernsPipeW, goPipeR}
	cmd.Env = append(os.Environ(), fmt.Sprintf("_NBX_RM_PATH=%s", path))
	cmd.SysProcAttr = &unix.SysProcAttr{
		Cloneflags: unix.CLONE_NEWUSER,
	}

	if err := cmd.Start(); err != nil {
		usernsPipeR.Close()
		usernsPipeW.Close()
		goPipeR.Close()
		goPipeW.Close()
		return err
	}
	usernsPipeW.Close()
	goPipeR.Close()

	buf := make([]byte, 1)
	usernsPipeR.Read(buf)
	usernsPipeR.Close()

	_ = setupIDMapping(cmd.Process.Pid, outerUID, outerGID, subStart, subCount)

	goPipeW.Write([]byte("G"))
	goPipeW.Close()

	cmd.Wait()
	return nil
}

// coreBinary returns the path to the nitrobox-core binary for re-exec.
// In c-shared mode, os.Executable() returns the Python interpreter, so we
// check NITROBOX_CORE_BIN env var first.
func coreBinary() string {
	if p := os.Getenv("NITROBOX_CORE_BIN"); p != "" {
		return p
	}
	self, err := os.Executable()
	if err != nil {
		return "nitrobox-core"
	}
	return self
}

// closeInheritedStdio redirects stdout/stderr to /dev/null in forked children.
// When Go runs as a subprocess (Python's Popen), the child inherits the Popen
// stdout/stderr pipes. If we don't close them, Python's subprocess.run() blocks
// forever waiting for the pipe to close.
func closeInheritedStdio() {
	devnull, err := unix.Open("/dev/null", unix.O_WRONLY, 0)
	if err == nil {
		unix.Dup2(devnull, 1)
		unix.Dup2(devnull, 2)
		unix.Close(devnull)
	}
}

type pipe struct{ r, w int }

func makePipe() pipe {
	var fds [2]int
	unix.Pipe2(fds[:], unix.O_CLOEXEC)
	return pipe{r: fds[0], w: fds[1]}
}

func setupIDMapping(childPid int, outerUID, outerGID, subStart, subCount uint32) error {
	pidS := fmt.Sprintf("%d", childPid)
	uidS := fmt.Sprintf("%d", outerUID)
	gidS := fmt.Sprintf("%d", outerGID)
	subS := fmt.Sprintf("%d", subStart)
	cntS := fmt.Sprintf("%d", subCount)

	out, err := exec.Command("newuidmap", pidS, "0", uidS, "1", "1", subS, cntS).CombinedOutput()
	if err != nil {
		return fmt.Errorf("newuidmap failed: %s", string(out))
	}
	out, err = exec.Command("newgidmap", pidS, "0", gidS, "1", "1", subS, cntS).CombinedOutput()
	if err != nil {
		return fmt.Errorf("newgidmap failed: %s", string(out))
	}
	return nil
}

// doExtract is the child-side extraction logic.
// Uses containers-storage's archive.Unpack() for full compatibility with
// Podman/Docker layer extraction (UID mapping, whiteout, breakout prevention).
// Runs INSIDE the user namespace (after unshare+newuidmap), so lchown with
// container UIDs works directly — kernel maps them via the UID mapping.
// No UIDMaps/GIDMaps needed in TarOptions because we're already in the userns.
func doExtract(tarPath, dest string) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	// Read all into memory for FIFO support (FIFOs don't support Seek)
	data, err := io.ReadAll(f)
	f.Close()
	if err != nil {
		return fmt.Errorf("read tar failed: %w", err)
	}

	// Detect gzip
	var reader io.Reader
	if len(data) >= 2 && data[0] == 0x1f && data[1] == 0x8b {
		gz, err := gzip.NewReader(bytes.NewReader(data))
		if err != nil {
			return fmt.Errorf("gzip open failed: %w", err)
		}
		defer gz.Close()
		reader = gz
	} else {
		reader = bytes.NewReader(data)
	}

	// We run inside the user namespace where we ARE root (uid 0 mapped to
	// host uid). lchown(uid=1000) works because kernel maps 1000 → host
	// sub_start+999 via the UID mapping set by newuidmap.
	// This matches how Podman/buildah extract layers: inside the userns,
	// tar UIDs are used directly without remapping.
	opts := &archive.TarOptions{
		InUserNS:       true,
		WhiteoutFormat: archive.OverlayWhiteoutFormat,
	}
	return archive.Unpack(reader, dest, opts)
}
