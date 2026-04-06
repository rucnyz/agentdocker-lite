// Package main builds libnitrobox.so (c-shared) for in-process FFI from Python.
//
// Build: go build -buildmode=c-shared -o libnitrobox.so ./cshared/
//
// All exported functions use C-compatible types. Strings are passed as
// *C.char (null-terminated) and must be freed by the caller when returned.
// Errors are returned as *C.char (caller must free with NbxFree).
package main

/*
#include <stdlib.h>
*/
import "C"
import (
	"encoding/json"
	"os"
	"unsafe"

	"github.com/opensage-agent/nitrobox/go/internal/cgroup"
	"github.com/opensage-agent/nitrobox/go/internal/imageref"
	"github.com/opensage-agent/nitrobox/go/internal/mount"
	"github.com/opensage-agent/nitrobox/go/internal/pidfd"
	"github.com/opensage-agent/nitrobox/go/internal/proc"
	"github.com/opensage-agent/nitrobox/go/internal/qmp"
	"github.com/opensage-agent/nitrobox/go/internal/security"
	"github.com/opensage-agent/nitrobox/go/internal/userns"
	"github.com/opensage-agent/nitrobox/go/internal/whiteout"
)

// coreBinPath stores the path to the nitrobox-core binary for re-exec.
// Set from Python via NbxSetCoreBin() since Go's os.Getenv() in c-shared
// mode doesn't see env vars set by Python at runtime.
var coreBinPath string

//export NbxSetCoreBin
func NbxSetCoreBin(path *C.char) {
	p := C.GoString(path)
	coreBinPath = p
	// Also set it in the actual environment for child processes
	os.Setenv("NITROBOX_CORE_BIN", p)
}

// errStr returns a C string for an error (caller must free), or nil on success.
func errStr(err error) *C.char {
	if err == nil {
		return nil
	}
	return C.CString(err.Error())
}

// ======================================================================
// Memory management
// ======================================================================

//export NbxFree
func NbxFree(p *C.char) {
	C.free(unsafe.Pointer(p))
}

// ======================================================================
// Mount operations
// ======================================================================

//export NbxCheckNewMountAPI
func NbxCheckNewMountAPI() C.int {
	if mount.CheckNewMountAPI() {
		return 1
	}
	return 0
}

//export NbxMountOverlay
func NbxMountOverlay(lowerdirSpec, upperDir, workDir, target *C.char) *C.char {
	return errStr(mount.MountOverlay(
		C.GoString(lowerdirSpec), C.GoString(upperDir),
		C.GoString(workDir), C.GoString(target), nil,
	))
}

//export NbxBindMount
func NbxBindMount(source, target *C.char) *C.char {
	return errStr(mount.BindMount(C.GoString(source), C.GoString(target)))
}

//export NbxRbindMount
func NbxRbindMount(source, target *C.char) *C.char {
	return errStr(mount.RbindMount(C.GoString(source), C.GoString(target)))
}

//export NbxMakePrivate
func NbxMakePrivate(target *C.char) *C.char {
	return errStr(mount.MakePrivate(C.GoString(target)))
}

//export NbxRemountROBind
func NbxRemountROBind(target *C.char) *C.char {
	return errStr(mount.RemountROBind(C.GoString(target)))
}

//export NbxUmount
func NbxUmount(target *C.char) *C.char {
	return errStr(mount.Umount(C.GoString(target)))
}

//export NbxUmountLazy
func NbxUmountLazy(target *C.char) *C.char {
	return errStr(mount.UmountLazy(C.GoString(target)))
}

//export NbxUmountRecursiveLazy
func NbxUmountRecursiveLazy(target *C.char) *C.char {
	return errStr(mount.UmountRecursiveLazy(C.GoString(target)))
}

// ======================================================================
// Cgroup operations
// ======================================================================

//export NbxCgroupV2Available
func NbxCgroupV2Available() C.int {
	if cgroup.V2Available() {
		return 1
	}
	return 0
}

//export NbxCreateCgroup
func NbxCreateCgroup(name *C.char, outPath **C.char) *C.char {
	path, err := cgroup.Create(C.GoString(name))
	if err != nil {
		return errStr(err)
	}
	*outPath = C.CString(path)
	return nil
}

//export NbxApplyCgroupLimits
func NbxApplyCgroupLimits(cgroupPath, limitsJSON *C.char) *C.char {
	var limits map[string]string
	if err := json.Unmarshal([]byte(C.GoString(limitsJSON)), &limits); err != nil {
		return errStr(err)
	}
	return errStr(cgroup.ApplyLimits(C.GoString(cgroupPath), limits))
}

//export NbxCgroupAddProcess
func NbxCgroupAddProcess(cgroupPath *C.char, pid C.uint) *C.char {
	return errStr(cgroup.AddProcess(C.GoString(cgroupPath), uint32(pid)))
}

//export NbxCleanupCgroup
func NbxCleanupCgroup(cgroupPath *C.char) *C.char {
	return errStr(cgroup.Cleanup(C.GoString(cgroupPath)))
}

//export NbxConvertCPUShares
func NbxConvertCPUShares(shares C.ulong) C.ulong {
	return C.ulong(cgroup.ConvertCPUShares(uint64(shares)))
}

// ======================================================================
// Pidfd operations
// ======================================================================

//export NbxPidfdOpen
func NbxPidfdOpen(pid C.int, outFd *C.int) C.int {
	fd, err := pidfd.Open(int(pid))
	if err != nil {
		return -1
	}
	*outFd = C.int(fd)
	return 0
}

//export NbxPidfdSendSignal
func NbxPidfdSendSignal(pfd, sig C.int) C.int {
	if pidfd.SendSignal(int(pfd), int(sig)) {
		return 1
	}
	return 0
}

//export NbxPidfdIsAlive
func NbxPidfdIsAlive(pfd C.int) C.int {
	if pidfd.IsAlive(int(pfd)) {
		return 1
	}
	return 0
}

//export NbxProcessMadviseCold
func NbxProcessMadviseCold(pfd C.int) C.int {
	if pidfd.ProcessMadviseCold(int(pfd)) == nil {
		return 1
	}
	return 0
}

// ======================================================================
// Process helpers
// ======================================================================

//export NbxFuserKill
func NbxFuserKill(targetPath *C.char, outCount *C.uint) *C.char {
	count, err := proc.FuserKill(C.GoString(targetPath))
	if err != nil {
		return errStr(err)
	}
	*outCount = C.uint(count)
	return nil
}

// ======================================================================
// QMP
// ======================================================================

//export NbxQmpSend
func NbxQmpSend(socketPath, commandJSON *C.char, timeoutSecs C.ulong, outResp **C.char) *C.char {
	resp, err := qmp.Send(C.GoString(socketPath), C.GoString(commandJSON), uint64(timeoutSecs))
	if err != nil {
		return errStr(err)
	}
	*outResp = C.CString(resp)
	return nil
}

// ======================================================================
// Whiteout conversion
// ======================================================================

//export NbxConvertWhiteouts
func NbxConvertWhiteouts(layerDir *C.char, useUserXattr C.int, outCount *C.uint) *C.char {
	count, err := whiteout.ConvertWhiteouts(C.GoString(layerDir), useUserXattr != 0)
	if err != nil {
		return errStr(err)
	}
	*outCount = C.uint(count)
	return nil
}

// ======================================================================
// Image reference parsing
// ======================================================================

//export NbxParseImageRef
func NbxParseImageRef(image *C.char, outDomain, outRepo, outTag **C.char) *C.char {
	domain, repo, tag, err := imageref.Parse(C.GoString(image))
	if err != nil {
		return errStr(err)
	}
	*outDomain = C.CString(domain)
	*outRepo = C.CString(repo)
	*outTag = C.CString(tag)
	return nil
}

// ======================================================================
// Security
// ======================================================================

//export NbxLandlockABIVersion
func NbxLandlockABIVersion() C.uint {
	return C.uint(security.LandlockABIVersion())
}

//export NbxBuildSeccompBPF
func NbxBuildSeccompBPF(outBuf *unsafe.Pointer, outLen *C.int) {
	bpf := security.BuildSeccompBPF()
	// Allocate C memory and copy BPF bytes into it (caller must free)
	p := C.malloc(C.size_t(len(bpf)))
	copy((*[1 << 30]byte)(p)[:len(bpf)], bpf)
	*outBuf = p
	*outLen = C.int(len(bpf))
}

//export NbxApplySeccompFilter
func NbxApplySeccompFilter() *C.char {
	return errStr(security.ApplySeccompFilter())
}

//export NbxDropCapabilities
func NbxDropCapabilities(extraKeepJSON, extraDropJSON *C.char, outDropped *C.uint) *C.char {
	var extraKeep, extraDrop []uint32
	if extraKeepJSON != nil {
		json.Unmarshal([]byte(C.GoString(extraKeepJSON)), &extraKeep)
	}
	if extraDropJSON != nil {
		json.Unmarshal([]byte(C.GoString(extraDropJSON)), &extraDrop)
	}
	dropped, err := security.DropCapabilities(extraKeep, extraDrop)
	if err != nil {
		return errStr(err)
	}
	*outDropped = C.uint(dropped)
	return nil
}

//export NbxApplyLandlock
func NbxApplyLandlock(readPathsJSON, writePathsJSON, portsJSON *C.char, strict C.int, outApplied *C.int) *C.char {
	var readPaths, writePaths []string
	var ports []uint16
	if readPathsJSON != nil {
		json.Unmarshal([]byte(C.GoString(readPathsJSON)), &readPaths)
	}
	if writePathsJSON != nil {
		json.Unmarshal([]byte(C.GoString(writePathsJSON)), &writePaths)
	}
	if portsJSON != nil {
		json.Unmarshal([]byte(C.GoString(portsJSON)), &ports)
	}
	applied, err := security.ApplyLandlock(readPaths, writePaths, ports, strict != 0)
	if err != nil {
		return errStr(err)
	}
	if applied {
		*outApplied = 1
	} else {
		*outApplied = 0
	}
	return nil
}

// ======================================================================
// Namespace operations
// ======================================================================

//export NbxUsernFixupForDelete
func NbxUsernFixupForDelete(usernsPid C.int, dirPath *C.char, outCount *C.uint) *C.char {
	count, err := userns.FixupDirForDelete(int(usernsPid), C.GoString(dirPath))
	if err != nil {
		return errStr(err)
	}
	*outCount = C.uint(count)
	return nil
}


// ======================================================================
// Spawn — uses JSON config because of the large number of parameters
// ======================================================================

//export NbxSpawnSandbox
func NbxSpawnSandbox(configJSON *C.char, outResultJSON **C.char) *C.char {
	// For spawn, we still need subprocess because of fd passing semantics.
	// The Go c-shared library runs in the Python process, so fork IS the
	// Python process forking — which has the same Go runtime safety issues.
	// Spawn must remain as subprocess call to nitrobox-core binary.
	// Return a special error to signal the caller to use subprocess fallback.
	return C.CString("__USE_SUBPROCESS__")
}

func main() {}
