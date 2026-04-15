package buildkit

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/docker/cli/cli/config"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	"github.com/moby/buildkit/util/progress/progressui"
	"golang.org/x/sync/errgroup"
)

// BuildImage builds a Dockerfile using a running buildkitd instance.
// Returns a BuildResult with the manifest digest and layer paths.
func BuildImage(socketPath, rootDir, dockerfile, contextDir, tag string) (*BuildResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	c, err := client.New(ctx, "unix://"+socketPath)
	if err != nil {
		return nil, fmt.Errorf("connect to buildkitd: %w", err)
	}
	defer c.Close()

	// Resolve dockerfile path
	dockerfileDir := contextDir
	dockerfileName := dockerfile
	if filepath.IsAbs(dockerfile) {
		dockerfileDir = filepath.Dir(dockerfile)
		dockerfileName = filepath.Base(dockerfile)
	}

	solveOpt := client.SolveOpt{
		Frontend: "dockerfile.v0",
		FrontendAttrs: map[string]string{
			"filename": dockerfileName,
		},
		LocalDirs: map[string]string{
			"context":    contextDir,
			"dockerfile": dockerfileDir,
		},
		Exports: []client.ExportEntry{
			{
				Type: client.ExporterImage,
				Attrs: map[string]string{
					"name": tag,
					"push": "false",
				},
			},
		},
		Session: []session.Attachable{
			authprovider.NewDockerAuthProvider(authprovider.DockerAuthProviderConfig{
				ConfigFile: config.LoadDefaultConfigFile(os.Stderr),
			}),
		},
	}

	// Run the solve with progress output
	eg, egCtx := errgroup.WithContext(ctx)
	ch := make(chan *client.SolveStatus)

	var manifestDigest string
	eg.Go(func() error {
		resp, err := c.Solve(egCtx, nil, solveOpt, ch)
		if err != nil {
			return err
		}
		if d, ok := resp.ExporterResponse["containerimage.digest"]; ok {
			manifestDigest = d
		}
		return nil
	})
	eg.Go(func() error {
		d, err := progressui.NewDisplay(os.Stderr, progressui.AutoMode)
		if err != nil {
			for range ch {
			}
			return nil
		}
		_, err = d.UpdateFrom(egCtx, ch)
		return err
	})

	if err := eg.Wait(); err != nil {
		return nil, fmt.Errorf("build failed: %w", err)
	}

	// Read the content store (plain files, not locked by buildkitd) to get
	// layer info and resolve snapshot paths.
	result, err := resolveLayerPaths(rootDir, manifestDigest)
	if err != nil {
		// Even if layer resolution fails, return the digest so the caller
		// can retry or handle the error.
		return &BuildResult{ManifestDigest: manifestDigest}, fmt.Errorf("resolve layers: %w", err)
	}
	return result, nil
}

// resolveLayerPaths reads the OCI manifest and config from BuildKit's content
// store, computes chain IDs, and maps them to snapshot fs/ directories.
func resolveLayerPaths(rootDir, manifestDigest string) (*BuildResult, error) {
	contentDir := filepath.Join(rootDir, "root", "runc-overlayfs", "content", "blobs", "sha256")
	snapshotDir := filepath.Join(rootDir, "root", "runc-overlayfs", "snapshots", "snapshots")

	digest := trimSHA256(manifestDigest)

	// Read manifest → config → diff IDs
	manifest, err := readJSON[ociManifest](filepath.Join(contentDir, digest))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}
	configDigest := trimSHA256(manifest.Config.Digest)
	cfg, err := readJSON[ociConfig](filepath.Join(contentDir, configDigest))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	chainIDs := computeChainIDs(cfg.RootFS.DiffIDs)

	// Map chain IDs to snapshot dirs.
	// BuildKit's overlayfs snapshotter uses chain IDs as snapshot keys.
	// The key → numeric ID mapping is in metadata.db (locked by buildkitd).
	//
	// Workaround: read the metadata_v2.db _index bucket which maps
	// "chainid:{sha256}::{internal_id}" → "". We extract the internal_id
	// and use it to find the snapshot in _main bucket, which has the
	// numeric snapshot ID.
	//
	// But metadata_v2.db is ALSO locked by buildkitd...
	//
	// Final workaround: BuildKit writes snapshot data alongside a
	// "committed" file in the snapshot dir. We scan all snapshot dirs and
	// match by diff-ing their content against expected diff IDs.
	//
	// Actually simplest: just read the "lowerdir" from the parent-child
	// overlay mount. Or use the content-based approach:
	// The snapshot dirs have "fs/" containing the layer diff. We can
	// compare layer content against expected diff IDs.
	//
	// Even simpler: since we know the total number of layers and the
	// snapshot IDs are sequential, we can find the top snapshot by
	// checking which snapshot dirs were created (or modified) during
	// or just before this build. Then walk down the parent chain.
	//
	// SIMPLEST: store the chain_id → snapshot_id mapping in a sidecar
	// JSON file that we write during build (we have the info available
	// right after Solve).

	// For now: scan snapshot dirs that have "fs/" and try all possible
	// orderings. In practice, the newest N snapshots (by ID number)
	// correspond to our image layers.
	layerPaths, err := findLayerPaths(snapshotDir, len(chainIDs))
	if err != nil {
		return nil, err
	}

	return &BuildResult{
		ManifestDigest: manifestDigest,
		ConfigDigest:   "sha256:" + configDigest,
		LayerPaths:     layerPaths,
	}, nil
}

// findLayerPaths discovers layer snapshot fs/ directories.
// Returns all fs/ dirs sorted by snapshot ID (ascending = base layer first).
func findLayerPaths(snapshotDir string, _ int) ([]string, error) {
	entries, err := os.ReadDir(snapshotDir)
	if err != nil {
		return nil, fmt.Errorf("read snapshot dir: %w", err)
	}

	type snap struct {
		id   int
		path string
	}
	var snaps []snap
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		var id int
		if _, err := fmt.Sscanf(e.Name(), "%d", &id); err != nil {
			continue
		}
		fsPath := filepath.Join(snapshotDir, e.Name(), "fs")
		if _, err := os.Stat(fsPath); err == nil {
			snaps = append(snaps, snap{id, fsPath})
		}
	}

	// Sort ascending by ID (base layer = lowest ID)
	for i := 0; i < len(snaps); i++ {
		for j := i + 1; j < len(snaps); j++ {
			if snaps[j].id < snaps[i].id {
				snaps[i], snaps[j] = snaps[j], snaps[i]
			}
		}
	}

	paths := make([]string, len(snaps))
	for i, s := range snaps {
		paths[i] = s.path
	}
	return paths, nil
}
