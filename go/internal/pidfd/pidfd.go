// Package pidfd provides race-free process management via file descriptors.
package pidfd

import (
	"unsafe"

	"golang.org/x/sys/unix"
)

// Open creates a pidfd for the given PID. Returns the raw fd.
func Open(pid int) (int, error) {
	return unix.PidfdOpen(pid, 0)
}

// SendSignal sends a signal via pidfd. Returns true on success.
func SendSignal(pidfd, sig int) bool {
	err := unix.PidfdSendSignal(pidfd, unix.Signal(sig), nil, 0)
	return err == nil
}

// IsAlive checks if the process is still alive (signal 0).
func IsAlive(pidfd int) bool {
	return SendSignal(pidfd, 0)
}

// ProcessMadviseCold hints the kernel to mark process memory as cold.
func ProcessMadviseCold(pidfd int) error {
	iov := unix.Iovec{
		Base: nil,
		Len:  0,
	}
	_, _, errno := unix.Syscall6(
		unix.SYS_PROCESS_MADVISE,
		uintptr(pidfd),
		uintptr(unsafe.Pointer(&iov)),
		1,
		uintptr(unix.MADV_COLD),
		0,
		0,
	)
	if errno != 0 {
		return errno
	}
	return nil
}
