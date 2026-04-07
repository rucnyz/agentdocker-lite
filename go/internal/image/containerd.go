// Package image — containerd layer resolution for direct Docker layer access.
//
// Reads containerd's boltdb metadata and content store to resolve
// image name → overlay layer filesystem paths. No daemon communication.
// Requires CAP_DAC_READ_SEARCH to read root-owned containerd directories.

package image

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	bolt "go.etcd.io/bbolt"
)

// openBoltReadOnly opens a boltdb read-only, working around containerd's
// exclusive lock. Copies the file to a temp location first — boltdb mmap
// needs exclusive flock but containerd already holds one on the original.
// The copy is <10ms for a 370MB file (just metadata pages, OS cache hot).
func openBoltReadOnly(path string) (*bolt.DB, error) {
	// bbolt uses flock which blocks if containerd holds LOCK_EX.
	// Copy the file to /tmp so bbolt gets its own flock.
	src, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", path, err)
	}

	dst, err := os.CreateTemp("/tmp", ".nbx-bolt-*.db")
	if err != nil {
		src.Close()
		return nil, err
	}
	tmpPath := dst.Name()
	_, err = io.Copy(dst, src)
	src.Close()
	dst.Close()
	if err != nil {
		os.Remove(tmpPath)
		return nil, fmt.Errorf("copy %s: %w", path, err)
	}

	db, err := bolt.Open(tmpPath, 0, &bolt.Options{ReadOnly: true})
	os.Remove(tmpPath)
	if err != nil {
		return nil, err
	}
	return db, nil
}

// ContainerdPaths holds the relevant containerd directory paths.
type ContainerdPaths struct {
	MetaDB     string // /var/lib/containerd/io.containerd.metadata.v1.bolt/meta.db
	ContentDir string // /var/lib/containerd/io.containerd.content.v1.content/blobs/sha256
	SnapDB     string // /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/metadata.db
	SnapDir    string // /var/lib/containerd/io.containerd.snapshotter.v1.overlayfs/snapshots
}

// DefaultContainerdPaths returns paths for a standard containerd installation.
func DefaultContainerdPaths() ContainerdPaths {
	root := "/var/lib/containerd"
	return ContainerdPaths{
		MetaDB:     filepath.Join(root, "io.containerd.metadata.v1.bolt", "meta.db"),
		ContentDir: filepath.Join(root, "io.containerd.content.v1.content", "blobs", "sha256"),
		SnapDB:     filepath.Join(root, "io.containerd.snapshotter.v1.overlayfs", "metadata.db"),
		SnapDir:    filepath.Join(root, "io.containerd.snapshotter.v1.overlayfs", "snapshots"),
	}
}

// DockerLocalLayers resolves an image name to its overlay layer paths
// by reading containerd's metadata directly (no daemon communication).
//
// Returns layer paths ordered bottom-to-top (base layer first).
func DockerLocalLayers(imageRef string, paths ContainerdPaths) ([]string, error) {
	// Normalize image name (add docker.io prefix, :latest tag)
	imageRef = normalizeImageRef(imageRef)

	// 1. meta.db: image name → manifest digest
	manifestDigest, err := lookupImageDigest(paths.MetaDB, imageRef)
	if err != nil {
		return nil, fmt.Errorf("image %q: %w", imageRef, err)
	}

	// 2. content store: manifest → config digest
	configDigest, err := readConfigDigest(paths.ContentDir, manifestDigest)
	if err != nil {
		return nil, fmt.Errorf("manifest %s: %w", manifestDigest[:20], err)
	}

	// 3. content store: config → diff_ids
	diffIDs, err := readDiffIDs(paths.ContentDir, configDigest)
	if err != nil {
		return nil, fmt.Errorf("config %s: %w", configDigest[:20], err)
	}

	// 4. Compute chain_ids from diff_ids
	chainIDs := computeChainIDs(diffIDs)

	// 5. snapshotter metadata.db: chain_id → snapshot numeric ID → path
	layerPaths, err := resolveSnapshotPaths(paths.SnapDB, paths.SnapDir, chainIDs)
	if err != nil {
		return nil, fmt.Errorf("snapshot resolve: %w", err)
	}

	return layerPaths, nil
}

// normalizeImageRef adds docker.io prefix and :latest tag if missing.
func normalizeImageRef(ref string) string {
	// Strip transport prefixes
	for _, p := range []string{"docker://", "docker-daemon:"} {
		ref = strings.TrimPrefix(ref, p)
	}

	// Add docker.io/ prefix
	if !strings.Contains(ref, "/") {
		ref = "docker.io/library/" + ref
	} else if !strings.Contains(strings.Split(ref, "/")[0], ".") {
		ref = "docker.io/" + ref
	}

	// Add :latest tag
	if !strings.Contains(ref, ":") && !strings.Contains(ref, "@") {
		ref += ":latest"
	}

	return ref
}

// lookupImageDigest reads containerd meta.db to find image → manifest digest.
func lookupImageDigest(metaDB, imageName string) (string, error) {
	db, err := openBoltReadOnly(metaDB)
	if err != nil {
		return "", fmt.Errorf("open meta.db: %w", err)
	}
	defer db.Close()

	var digest string
	err = db.View(func(tx *bolt.Tx) error {
		v1 := tx.Bucket([]byte("v1"))
		if v1 == nil {
			return fmt.Errorf("no v1 bucket")
		}
		moby := v1.Bucket([]byte("moby"))
		if moby == nil {
			return fmt.Errorf("no moby namespace")
		}
		images := moby.Bucket([]byte("images"))
		if images == nil {
			return fmt.Errorf("no images bucket")
		}

		imgBucket := images.Bucket([]byte(imageName))
		if imgBucket == nil {
			return fmt.Errorf("not found in containerd")
		}

		target := imgBucket.Bucket([]byte("target"))
		if target == nil {
			return fmt.Errorf("no target")
		}

		d := target.Get([]byte("digest"))
		if d == nil {
			return fmt.Errorf("no digest")
		}
		digest = string(d)
		return nil
	})

	return digest, err
}

// manifestJSON is the minimal structure we need from an OCI/Docker manifest.
type manifestJSON struct {
	MediaType string `json:"mediaType"`
	Config    struct {
		Digest string `json:"digest"`
	} `json:"config"`
	Manifests []struct {
		Digest   string `json:"digest"`
		Platform struct {
			Architecture string `json:"architecture"`
			OS           string `json:"os"`
		} `json:"platform"`
	} `json:"manifests"`
}

// readConfigDigest reads a manifest blob and returns the config digest.
// Handles both manifest lists (OCI index) and direct manifests.
func readConfigDigest(contentDir, digest string) (string, error) {
	data, err := readBlob(contentDir, digest)
	if err != nil {
		return "", err
	}

	var m manifestJSON
	if err := json.Unmarshal(data, &m); err != nil {
		return "", fmt.Errorf("parse manifest: %w", err)
	}

	// If it's a manifest list / OCI index, find the amd64 manifest
	if len(m.Manifests) > 0 {
		for _, entry := range m.Manifests {
			if entry.Platform.Architecture == "amd64" && entry.Platform.OS == "linux" {
				return readConfigDigest(contentDir, entry.Digest)
			}
		}
		return "", fmt.Errorf("no linux/amd64 manifest found")
	}

	if m.Config.Digest == "" {
		return "", fmt.Errorf("no config digest in manifest")
	}
	return m.Config.Digest, nil
}

// configJSON is the minimal structure we need from an OCI image config.
type configJSON struct {
	RootFS struct {
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
}

// readDiffIDs reads a config blob and returns the rootfs diff_ids.
func readDiffIDs(contentDir, digest string) ([]string, error) {
	data, err := readBlob(contentDir, digest)
	if err != nil {
		return nil, err
	}

	var c configJSON
	if err := json.Unmarshal(data, &c); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if len(c.RootFS.DiffIDs) == 0 {
		return nil, fmt.Errorf("no diff_ids in config")
	}
	return c.RootFS.DiffIDs, nil
}

// readBlob reads a content store blob by digest.
func readBlob(contentDir, digest string) ([]byte, error) {
	hash := strings.TrimPrefix(digest, "sha256:")
	path := filepath.Join(contentDir, hash)
	data, err := os.ReadFile(path)
	return data, err
}

// computeChainIDs computes containerd chain IDs from diff IDs.
// chain[0] = diff[0]
// chain[i] = sha256(chain[i-1] + " " + diff[i])
func computeChainIDs(diffIDs []string) []string {
	chain := make([]string, len(diffIDs))
	chain[0] = diffIDs[0]
	for i := 1; i < len(diffIDs); i++ {
		h := sha256.Sum256([]byte(chain[i-1] + " " + diffIDs[i]))
		chain[i] = fmt.Sprintf("sha256:%x", h)
	}
	return chain
}

// resolveSnapshotPaths looks up snapshot filesystem paths from chain IDs.
func resolveSnapshotPaths(snapDB, snapDir string, chainIDs []string) ([]string, error) {
	db, err := openBoltReadOnly(snapDB)
	if err != nil {
		return nil, fmt.Errorf("open snapshotter db: %w", err)
	}
	defer db.Close()

	// Build a lookup map: chain_id → snapshot numeric ID
	// Snapshot names in boltdb: "moby/{numeric_id}/sha256:{chain_id}"
	chainToID := make(map[string]string) // chain_id → numeric_id

	db.View(func(tx *bolt.Tx) error {
		snapshots := tx.Bucket([]byte("v1")).Bucket([]byte("snapshots"))
		if snapshots == nil {
			return fmt.Errorf("no snapshots bucket")
		}

		// Build set of chain_ids we need
		need := make(map[string]bool)
		for _, cid := range chainIDs {
			need[cid] = true
		}

		snapshots.ForEach(func(k, _ []byte) error {
			name := string(k)
			// Format: "moby/{numeric_id}/sha256:{chain_id}"
			parts := strings.SplitN(name, "/", 3)
			if len(parts) != 3 || parts[0] != "moby" {
				return nil
			}
			numericID := parts[1]
			chainID := parts[2]

			if need[chainID] {
				// Prefer the latest (highest) numeric ID for each chain_id
				if existing, ok := chainToID[chainID]; ok {
					if numericID > existing {
						chainToID[chainID] = numericID
					}
				} else {
					chainToID[chainID] = numericID
				}
			}
			return nil
		})
		return nil
	})

	// Build ordered layer paths
	paths := make([]string, 0, len(chainIDs))
	for _, cid := range chainIDs {
		numID, ok := chainToID[cid]
		if !ok {
			return nil, fmt.Errorf("snapshot not found for chain_id %s", cid[:20]+"...")
		}
		p := filepath.Join(snapDir, numID, "fs")
		if _, err := os.Stat(p); err != nil {
			return nil, fmt.Errorf("snapshot dir missing: %s", p)
		}
		paths = append(paths, p)
	}

	return paths, nil
}
