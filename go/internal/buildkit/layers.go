package buildkit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// ImageLayers returns the overlay diff directory paths for an image built by
// BuildKit, ordered bottom-to-top (base layer first).
//
// manifestDigest is the SHA256 digest of the OCI manifest (with or without
// "sha256:" prefix). This is returned by BuildImage.
//
// This function reads the content store (which is plain files, not locked by
// buildkitd) and scans the snapshot directories to find layer paths.
func ImageLayers(rootDir, manifestDigest string) ([]string, error) {
	contentDir := filepath.Join(rootDir, "root", "runc-overlayfs", "content", "blobs", "sha256")
	snapshotDir := filepath.Join(rootDir, "root", "runc-overlayfs", "snapshots", "snapshots")

	manifestDigest = trimSHA256(manifestDigest)

	// Step 1: Read manifest to get config digest.
	manifest, err := readJSON[ociManifest](filepath.Join(contentDir, manifestDigest))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	// Step 2: Read config to get diff IDs and OCI config.
	configDigest := trimSHA256(manifest.Config.Digest)
	config, err := readJSON[ociConfig](filepath.Join(contentDir, configDigest))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	// Step 3: Compute chain IDs from diff IDs.
	chainIDs := computeChainIDs(config.RootFS.DiffIDs)

	// Cannot read metadata.db while buildkitd is running (bbolt exclusive lock).
	// Use BuildImage instead, which resolves layers during the build.
	_ = snapshotDir
	return nil, fmt.Errorf("use BuildImage instead — metadata.db is locked by buildkitd; chainIDs=%v", chainIDs)
}

// BuildResult contains the output of a BuildKit build.
type BuildResult struct {
	ManifestDigest string   `json:"manifest_digest"`
	ConfigDigest   string   `json:"config_digest"`
	LayerPaths     []string `json:"layer_paths"`
}

// --- OCI types (minimal) ---

type ociManifest struct {
	Config ociDescriptor   `json:"config"`
	Layers []ociDescriptor `json:"layers"`
}

type ociDescriptor struct {
	Digest string `json:"digest"`
}

type ociConfig struct {
	RootFS struct {
		DiffIDs []string `json:"diff_ids"`
	} `json:"rootfs"`
	Config struct {
		Env        []string `json:"Env"`
		Cmd        []string `json:"Cmd"`
		WorkingDir string   `json:"WorkingDir"`
		Entrypoint []string `json:"Entrypoint"`
	} `json:"config"`
}

// --- helpers ---

func trimSHA256(s string) string {
	if strings.HasPrefix(s, "sha256:") {
		return s[7:]
	}
	return s
}

func readJSON[T any](path string) (T, error) {
	var v T
	data, err := os.ReadFile(path)
	if err != nil {
		return v, err
	}
	err = json.Unmarshal(data, &v)
	return v, err
}

// computeChainIDs computes OCI chain IDs from an ordered list of diff IDs.
// ChainID[0] = DiffID[0]
// ChainID[n] = SHA256(ChainID[n-1] + " " + DiffID[n])
func computeChainIDs(diffIDs []string) []string {
	if len(diffIDs) == 0 {
		return nil
	}
	chainIDs := make([]string, len(diffIDs))
	chainIDs[0] = diffIDs[0]
	for i := 1; i < len(diffIDs); i++ {
		h := sha256.Sum256([]byte(chainIDs[i-1] + " " + diffIDs[i]))
		chainIDs[i] = fmt.Sprintf("sha256:%x", h)
	}
	return chainIDs
}

// ReadImageConfig reads the OCI image config from the BuildKit content store.
func ReadImageConfig(rootDir, manifestDigest string) (*ociConfig, error) {
	contentDir := filepath.Join(rootDir, "root", "runc-overlayfs", "content", "blobs", "sha256")
	manifestDigest = trimSHA256(manifestDigest)

	manifest, err := readJSON[ociManifest](filepath.Join(contentDir, manifestDigest))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	configDigest := trimSHA256(manifest.Config.Digest)
	config, err := readJSON[ociConfig](filepath.Join(contentDir, configDigest))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	return &config, nil
}
