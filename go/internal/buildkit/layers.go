// OCI types and utilities for manifest/config parsing and chain ID computation.
package buildkit

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

// BuildResult contains the output of a build or pull operation.
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

// DefaultRootDir returns the default buildkitd root directory.
func DefaultRootDir() string {
	home, _ := os.UserHomeDir()
	return home + "/.local/share/nitrobox/buildkit"
}
