// Package unpack provides UID-preserving layer extraction with whiteout conversion.
package unpack

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

const overflowID = 65534

// ExtractTarInUserns extracts a tar file inside a user namespace with full UID/GID mapping.
func ExtractTarInUserns(tarPath, dest string, outerUID, outerGID, subStart, subCount uint32) error {
	usernsPipe := makePipe()
	goPipe := makePipe()

	pid, _, errno := unix.Syscall(unix.SYS_FORK, 0, 0, 0)
	if errno != 0 {
		return errno
	}

	if pid == 0 {
		// Child
		unix.Close(usernsPipe.r)
		unix.Close(goPipe.w)

		if _, _, err := unix.Syscall(unix.SYS_UNSHARE, uintptr(unix.CLONE_NEWUSER), 0, 0); err != 0 {
			unix.Exit(1)
		}

		unix.Write(usernsPipe.w, []byte("R"))
		unix.Close(usernsPipe.w)

		buf := make([]byte, 1)
		unix.Read(goPipe.r, buf)
		unix.Close(goPipe.r)

		if err := doExtract(tarPath, dest, subCount); err != nil {
			fmt.Fprintf(os.Stderr, "nitrobox: layer extraction failed: %v\n", err)
			unix.Exit(2)
		}
		unix.Exit(0)
	}

	// Parent
	unix.Close(usernsPipe.w)
	unix.Close(goPipe.r)

	buf := make([]byte, 1)
	unix.Read(usernsPipe.r, buf)
	unix.Close(usernsPipe.r)

	mappingErr := setupIDMapping(int(pid), outerUID, outerGID, subStart, subCount)

	unix.Write(goPipe.w, []byte("G"))
	unix.Close(goPipe.w)

	if mappingErr != nil {
		unix.Kill(int(pid), unix.SIGKILL)
		var ws unix.WaitStatus
		unix.Wait4(int(pid), &ws, 0, nil)
		return mappingErr
	}

	var ws unix.WaitStatus
	_, err := unix.Wait4(int(pid), &ws, 0, nil)
	if err != nil {
		return err
	}
	if ws.Exited() && ws.ExitStatus() == 0 {
		return nil
	}
	return fmt.Errorf("layer extraction in userns failed (exit code %d)", ws.ExitStatus())
}

// RmtreeInUserns removes a directory tree containing files with mapped UIDs.
func RmtreeInUserns(path string, outerUID, outerGID, subStart, subCount uint32) error {
	usernsPipe := makePipe()
	goPipe := makePipe()

	pid, _, errno := unix.Syscall(unix.SYS_FORK, 0, 0, 0)
	if errno != 0 {
		return errno
	}

	if pid == 0 {
		// Child
		unix.Close(usernsPipe.r)
		unix.Close(goPipe.w)

		if _, _, err := unix.Syscall(unix.SYS_UNSHARE, uintptr(unix.CLONE_NEWUSER), 0, 0); err != 0 {
			unix.Exit(1)
		}

		unix.Write(usernsPipe.w, []byte("R"))
		unix.Close(usernsPipe.w)

		buf := make([]byte, 1)
		unix.Read(goPipe.r, buf)
		unix.Close(goPipe.r)

		// exec rm -rf
		unix.Exec("/bin/rm", []string{"rm", "-rf", path}, os.Environ())
		unix.Exit(127)
		return nil // unreachable
	}

	// Parent
	unix.Close(usernsPipe.w)
	unix.Close(goPipe.r)

	buf := make([]byte, 1)
	unix.Read(usernsPipe.r, buf)
	unix.Close(usernsPipe.r)

	_ = setupIDMapping(int(pid), outerUID, outerGID, subStart, subCount)

	unix.Write(goPipe.w, []byte("G"))
	unix.Close(goPipe.w)

	var ws unix.WaitStatus
	unix.Wait4(int(pid), &ws, 0, nil)
	return nil
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
func doExtract(tarPath, dest string, maxID uint32) error {
	f, err := os.Open(tarPath)
	if err != nil {
		return err
	}
	defer f.Close()

	// Try gzip first
	gz, gzErr := gzip.NewReader(f)
	var reader io.Reader
	if gzErr == nil {
		reader = gz
		defer gz.Close()
	} else {
		f.Seek(0, io.SeekStart)
		reader = f
	}

	return unpackTar(tar.NewReader(reader), dest, maxID)
}

func unpackTar(tr *tar.Reader, dest string, maxID uint32) error {
	type dirMtime struct {
		path  string
		mtime int64
	}
	var dirHeaders []dirMtime

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}

		cleaned := filepath.Clean(hdr.Name)
		// Breakout check
		fullPath := filepath.Join(dest, cleaned)
		resolved := filepath.Clean(fullPath)
		if !strings.HasPrefix(resolved, filepath.Clean(dest)) {
			return fmt.Errorf("path breakout: %s is outside %s", hdr.Name, dest)
		}

		// Parent directory creation
		if parent := filepath.Dir(fullPath); parent != dest {
			if _, err := os.Stat(parent); err != nil {
				if err := os.MkdirAll(parent, 0o777); err != nil {
					return err
				}
				unix.Lchown(parent, 0, 0)
			}
		}

		uid := uint32(hdr.Uid)
		gid := uint32(hdr.Gid)
		if uid > maxID {
			uid = overflowID
		}
		if gid > maxID {
			gid = overflowID
		}
		mode := uint32(hdr.Mode & 0o7777)
		mtime := hdr.ModTime.Unix()

		fileName := filepath.Base(cleaned)

		// Skip device nodes
		if hdr.Typeflag == tar.TypeBlock || hdr.Typeflag == tar.TypeChar {
			continue
		}

		// Whiteout handling
		if strings.HasPrefix(fileName, ".wh.") {
			parent := filepath.Dir(fullPath)
			if fileName == ".wh..wh..opq" {
				unix.Setxattr(parent, "user.overlay.opaque", []byte("y"), 0)
			} else {
				originalName := fileName[4:]
				originalPath := filepath.Join(parent, originalName)
				if err := unix.Mknod(originalPath, unix.S_IFCHR, 0); err != nil {
					if err == unix.ENOTDIR {
						continue
					}
					// Fallback: xattr whiteout
					f, _ := os.Create(originalPath)
					if f != nil {
						f.Close()
					}
					unix.Setxattr(originalPath, "user.overlay.whiteout", []byte("y"), 0)
				} else {
					unix.Lchown(originalPath, int(uid), int(gid))
				}
			}
			continue
		}

		// Remove existing
		if info, err := os.Lstat(fullPath); err == nil {
			if info.IsDir() && cleaned == "." {
				continue
			}
			if !(info.IsDir() && hdr.Typeflag == tar.TypeDir) {
				os.Remove(fullPath)
				os.RemoveAll(fullPath)
			}
		}

		// Create entry
		switch hdr.Typeflag {
		case tar.TypeDir:
			if info, err := os.Lstat(fullPath); err != nil || !info.IsDir() {
				if err := os.Mkdir(fullPath, os.FileMode(mode)); err != nil {
					return err
				}
			}
		case tar.TypeReg, tar.TypeRegA:
			f, err := os.OpenFile(fullPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, os.FileMode(mode))
			if err != nil {
				return err
			}
			if _, err := io.Copy(f, tr); err != nil {
				f.Close()
				return err
			}
			f.Close()
		case tar.TypeSymlink:
			linkTarget := hdr.Linkname
			if !filepath.IsAbs(linkTarget) {
				resolvedLink := filepath.Clean(filepath.Join(filepath.Dir(fullPath), linkTarget))
				if !strings.HasPrefix(resolvedLink, filepath.Clean(dest)) {
					return fmt.Errorf("symlink breakout: %s -> %s", fullPath, linkTarget)
				}
			}
			if err := os.Symlink(linkTarget, fullPath); err != nil {
				return err
			}
		case tar.TypeLink:
			linkTarget := hdr.Linkname
			targetAbs := filepath.Join(dest, linkTarget)
			if !strings.HasPrefix(filepath.Clean(targetAbs), filepath.Clean(dest)) {
				return fmt.Errorf("hardlink breakout: %s -> %s", fullPath, linkTarget)
			}
			if err := os.Link(targetAbs, fullPath); err != nil {
				return err
			}
		case tar.TypeFifo:
			if err := unix.Mkfifo(fullPath, mode); err != nil {
				return err
			}
		case tar.TypeXGlobalHeader, tar.TypeXHeader:
			continue
		default:
			continue
		}

		// lchown
		unix.Lchown(fullPath, int(uid), int(gid))

		// chmod (skip symlinks)
		if hdr.Typeflag == tar.TypeLink {
			if info, err := os.Lstat(fullPath); err == nil && info.Mode()&os.ModeSymlink == 0 {
				unix.Chmod(fullPath, mode)
			}
		} else if hdr.Typeflag != tar.TypeSymlink {
			unix.Chmod(fullPath, mode)
		}

		// chtimes
		ts := []unix.Timespec{
			{Sec: mtime, Nsec: 0},
			{Sec: mtime, Nsec: 0},
		}
		if hdr.Typeflag == tar.TypeSymlink {
			unix.UtimesNanoAt(unix.AT_FDCWD, fullPath, ts, unix.AT_SYMLINK_NOFOLLOW)
		} else if hdr.Typeflag == tar.TypeLink {
			if info, err := os.Lstat(fullPath); err == nil && info.Mode()&os.ModeSymlink == 0 {
				unix.UtimesNanoAt(unix.AT_FDCWD, fullPath, ts, 0)
			}
		} else if hdr.Typeflag == tar.TypeDir {
			dirHeaders = append(dirHeaders, dirMtime{path: fullPath, mtime: mtime})
		} else {
			unix.UtimesNanoAt(unix.AT_FDCWD, fullPath, ts, 0)
		}

		// PAX xattrs
		for key, val := range hdr.PAXRecords {
			if xattrKey, ok := strings.CutPrefix(key, "SCHILY.xattr."); ok {
				_ = unix.Lsetxattr(fullPath, xattrKey, []byte(val), 0)
			}
		}
	}

	// Deferred directory mtime
	for _, dh := range dirHeaders {
		ts := []unix.Timespec{
			{Sec: dh.mtime, Nsec: 0},
			{Sec: dh.mtime, Nsec: 0},
		}
		unix.UtimesNanoAt(unix.AT_FDCWD, dh.path, ts, 0)
	}

	return nil
}
