// Package whiteout converts OCI whiteout files to overlayfs-native format.
package whiteout

import (
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/sys/unix"
)

// ConvertWhiteouts converts OCI whiteouts in a layer directory.
// Returns the number of whiteout files converted.
func ConvertWhiteouts(layerDir string, useUserXattr bool) (uint32, error) {
	prefix := "trusted.overlay"
	if useUserXattr {
		prefix = "user.overlay"
	}
	var count uint32
	err := walkAndConvert(layerDir, prefix, useUserXattr, &count)
	return count, err
}

func walkAndConvert(dir, prefix string, useUserXattr bool, count *uint32) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			if err := walkAndConvert(filepath.Join(dir, entry.Name()), prefix, useUserXattr, count); err != nil {
				return err
			}
		}

		name := entry.Name()
		if !strings.HasPrefix(name, ".wh.") {
			continue
		}

		whPath := filepath.Join(dir, name)

		if name == ".wh..wh..opq" {
			// Opaque directory marker
			if err := os.Remove(whPath); err != nil {
				return err
			}
			val := []byte("x")
			if !useUserXattr {
				val = []byte("y")
			}
			if err := unix.Setxattr(dir, prefix+".opaque", val, 0); err != nil {
				return err
			}
		} else {
			// File deletion whiteout
			targetName := name[4:] // strip ".wh."
			targetPath := filepath.Join(dir, targetName)
			if err := os.Remove(whPath); err != nil {
				return err
			}
			if useUserXattr {
				f, err := os.Create(targetPath)
				if err != nil {
					return err
				}
				f.Close()
				if err := unix.Setxattr(targetPath, prefix+".whiteout", []byte("y"), 0); err != nil {
					return err
				}
			} else {
				if err := unix.Mknod(targetPath, 0o600|unix.S_IFCHR, 0); err != nil {
					return err
				}
			}
		}
		*count++
	}
	return nil
}
