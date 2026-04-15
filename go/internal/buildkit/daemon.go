// Package buildkit manages a rootless buildkitd subprocess and provides
// a gRPC client for image builds with in-memory layer caching.
package buildkit

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// Daemon manages the lifecycle of a rootless buildkitd subprocess.
type Daemon struct {
	RootDir    string // e.g. ~/.local/share/nitrobox/buildkit
	SocketPath string // Unix socket for gRPC
	cmd        *exec.Cmd
	pid        int
}

// DefaultRootDir returns the default buildkitd root directory.
func DefaultRootDir() string {
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".local/share/nitrobox/buildkit")
}

// DefaultSocketPath returns the default Unix socket path.
func DefaultSocketPath() string {
	uid := os.Getuid()
	return fmt.Sprintf("/tmp/nitrobox-buildkitd-%d/buildkitd.sock", uid)
}

// NewDaemon creates a Daemon with default paths.
func NewDaemon() *Daemon {
	return &Daemon{
		RootDir:    DefaultRootDir(),
		SocketPath: DefaultSocketPath(),
	}
}

// Start launches buildkitd via rootlesskit if not already running.
// Returns the socket path for client connections.
func (d *Daemon) Start(buildkitdBin string) error {
	// Check if already running
	if d.IsRunning() {
		return nil
	}

	// Ensure directories exist
	socketDir := filepath.Dir(d.SocketPath)
	if err := os.MkdirAll(socketDir, 0o700); err != nil {
		return fmt.Errorf("mkdir socket dir: %w", err)
	}
	if err := os.MkdirAll(d.RootDir, 0o700); err != nil {
		return fmt.Errorf("mkdir root dir: %w", err)
	}

	// Clean up stale socket
	os.Remove(d.SocketPath)

	// Find rootlesskit
	rootlesskit, err := exec.LookPath("rootlesskit")
	if err != nil {
		return fmt.Errorf("rootlesskit not found: %w", err)
	}

	// Start buildkitd via rootlesskit
	stateDir := filepath.Join(d.RootDir, "rootlesskit")
	os.MkdirAll(stateDir, 0o700)

	d.cmd = exec.Command(rootlesskit,
		"--state-dir", stateDir,
		buildkitdBin,
		"--oci-worker-no-process-sandbox",
		"--root", filepath.Join(d.RootDir, "root"),
		"--addr", "unix://"+d.SocketPath,
	)
	d.cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	// Redirect stderr to a log file for debugging
	logPath := filepath.Join(d.RootDir, "buildkitd.log")
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
	if err != nil {
		return fmt.Errorf("open log file: %w", err)
	}
	d.cmd.Stderr = logFile
	d.cmd.Stdout = logFile

	if err := d.cmd.Start(); err != nil {
		logFile.Close()
		return fmt.Errorf("start buildkitd: %w", err)
	}
	d.pid = d.cmd.Process.Pid
	logFile.Close()

	// Write PID file
	pidPath := filepath.Join(d.RootDir, "buildkitd.pid")
	os.WriteFile(pidPath, []byte(strconv.Itoa(d.pid)), 0o644)

	// Wait for socket to appear
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := d.waitForSocket(ctx); err != nil {
		d.Stop()
		return fmt.Errorf("buildkitd failed to start: %w", err)
	}

	return nil
}

// IsRunning checks if the buildkitd socket is responsive.
func (d *Daemon) IsRunning() bool {
	conn, err := net.DialTimeout("unix", d.SocketPath, 2*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// Stop gracefully stops the managed buildkitd process.
func (d *Daemon) Stop() error {
	// Try reading PID from file if we don't have a cmd
	if d.cmd == nil {
		pidPath := filepath.Join(d.RootDir, "buildkitd.pid")
		data, err := os.ReadFile(pidPath)
		if err != nil {
			return nil // nothing to stop
		}
		pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil {
			return nil
		}
		proc, err := os.FindProcess(pid)
		if err != nil {
			return nil
		}
		proc.Signal(syscall.SIGTERM)
		os.Remove(pidPath)
		return nil
	}

	d.cmd.Process.Signal(syscall.SIGTERM)
	done := make(chan error, 1)
	go func() { done <- d.cmd.Wait() }()

	select {
	case <-done:
	case <-time.After(5 * time.Second):
		d.cmd.Process.Kill()
		<-done
	}

	os.Remove(filepath.Join(d.RootDir, "buildkitd.pid"))
	d.cmd = nil
	return nil
}

// waitForSocket polls until the Unix socket is connectable.
func (d *Daemon) waitForSocket(ctx context.Context) error {
	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timeout waiting for buildkitd socket at %s", d.SocketPath)
		default:
		}
		conn, err := net.DialTimeout("unix", d.SocketPath, 500*time.Millisecond)
		if err == nil {
			conn.Close()
			return nil
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// SnapshotRoot returns the path to BuildKit's snapshot directory.
// Layer directories are at: {SnapshotRoot}/snapshots/{id}/fs/
func (d *Daemon) SnapshotRoot() string {
	return filepath.Join(d.RootDir, "root", "runc-overlayfs", "snapshots", "snapshots")
}
