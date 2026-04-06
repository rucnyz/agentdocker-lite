// Package image provides containers/storage integration for zero-copy layer access.
package image

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/containers/buildah/define"
	"github.com/containers/buildah/imagebuildah"
	cp "go.podman.io/image/v5/copy"
	"go.podman.io/image/v5/signature"
	imgstorage "go.podman.io/image/v5/storage"
	"go.podman.io/image/v5/transports/alltransports"
	imagetypes "go.podman.io/image/v5/types"
	"go.podman.io/storage"
	"go.podman.io/storage/types"
)

// StoreConfig configures the containers/storage store.
type StoreConfig struct {
	GraphRoot string `json:"graph_root"` // e.g. ~/.local/share/containers/storage
	RunRoot   string `json:"run_root"`   // e.g. /run/user/{uid}/containers
	Driver    string `json:"driver"`     // "overlay" (default)
}

// DefaultStoreConfig returns default rootless config.
func DefaultStoreConfig() StoreConfig {
	home, _ := os.UserHomeDir()
	uid := os.Getuid()
	return StoreConfig{
		GraphRoot: filepath.Join(home, ".local/share/containers/storage"),
		RunRoot:   fmt.Sprintf("/run/user/%d/containers", uid),
		Driver:    "overlay",
	}
}

// OpenStore opens a containers/storage store.
func OpenStore(cfg StoreConfig) (storage.Store, error) {
	opts := types.StoreOptions{
		GraphRoot:       cfg.GraphRoot,
		RunRoot:         cfg.RunRoot,
		GraphDriverName: cfg.Driver,
		GraphDriverOptions: []string{
			"overlay.mount_program=/usr/bin/fuse-overlayfs",
			"overlay.mountopt=userxattr",
		},
	}
	// For rootless on ext4: if native overlay doesn't work, fall back to vfs.
	// But first try native overlay which works on kernel >= 5.11 with userxattr.
	store, err := storage.GetStore(opts)
	if err != nil {
		// Fallback: try without mount_program
		opts.GraphDriverOptions = []string{"overlay.mountopt=userxattr"}
		store, err = storage.GetStore(opts)
	}
	if err != nil {
		// Final fallback: vfs driver
		opts.GraphDriverName = "vfs"
		opts.GraphDriverOptions = nil
		store, err = storage.GetStore(opts)
	}
	return store, err
}

// ImageLayers returns the overlay diff directory paths for an image's layers,
// ordered bottom-to-top (base layer first).
func ImageLayers(store storage.Store, imageRef string) ([]string, error) {
	// Find image by name or ID
	img, err := store.Image(imageRef)
	if err != nil {
		// Try by name
		images, err2 := store.Images()
		if err2 != nil {
			return nil, fmt.Errorf("list images: %w", err2)
		}
		for i := range images {
			for _, name := range images[i].Names {
				if name == imageRef || strings.HasPrefix(name, imageRef) {
					img = &images[i]
					break
				}
			}
			if img != nil {
				break
			}
		}
		if img == nil {
			return nil, fmt.Errorf("image %q not found: %w", imageRef, err)
		}
	}

	// Walk the layer chain from top to bottom
	graphRoot := store.GraphRoot()
	driverName := store.GraphDriverName()

	var layerIDs []string
	layerID := img.TopLayer
	for layerID != "" {
		layerIDs = append(layerIDs, layerID)
		layer, err := store.Layer(layerID)
		if err != nil {
			break
		}
		layerID = layer.Parent
	}

	// Build paths based on driver type
	// overlay: {graphRoot}/overlay/{id}/diff/
	// vfs:     {graphRoot}/vfs/dir/{id}/
	paths := make([]string, len(layerIDs))
	for i, id := range layerIDs {
		var p string
		switch driverName {
		case "vfs":
			p = filepath.Join(graphRoot, "vfs", "dir", id)
		default: // overlay
			p = filepath.Join(graphRoot, driverName, id, "diff")
		}
		paths[len(layerIDs)-1-i] = p // reverse: bottom-to-top
	}

	return paths, nil
}

// PullImage pulls an image from a registry into the containers/storage store.
func PullImage(store storage.Store, imageRef string, systemCtx *imagetypes.SystemContext) error {
	ctx := context.Background()

	// Parse source reference.
	// Supports: "docker://image:tag", "docker-daemon:image:tag", "image:tag" (default docker://)
	srcName := imageRef
	if !strings.Contains(srcName, "://") && !strings.HasPrefix(srcName, "docker-daemon:") {
		srcName = "docker://" + srcName
	}
	srcRef, err := alltransports.ParseImageName(srcName)
	if err != nil {
		return fmt.Errorf("parse source %q: %w", imageRef, err)
	}

	// Destination: use ParseStoreReference with our store (avoids default store init)
	storageName := imageRef
	// Strip transport prefix for storage name
	for _, prefix := range []string{"docker://", "docker-daemon:"} {
		storageName = strings.TrimPrefix(storageName, prefix)
	}
	stTransport := imgstorage.Transport
	destRef, err := stTransport.ParseStoreReference(store, storageName)
	if err != nil {
		return fmt.Errorf("parse dest: %w", err)
	}

	// Policy context (accept all)
	policy, err := signature.NewPolicyContext(&signature.Policy{
		Default: []signature.PolicyRequirement{
			signature.NewPRInsecureAcceptAnything(),
		},
	})
	if err != nil {
		return fmt.Errorf("policy: %w", err)
	}
	defer policy.Destroy()

	_, err = cp.Image(ctx, policy, destRef, srcRef, &cp.Options{
		SourceCtx: systemCtx,
	})
	if err != nil {
		return fmt.Errorf("pull %q: %w", imageRef, err)
	}

	return nil
}

// BuildImage builds a Dockerfile using buildah.
func BuildImage(store storage.Store, dockerfile, contextDir, tag string) (string, error) {
	ctx := context.Background()

	opts := define.BuildOptions{
		Output:           tag,
		ContextDirectory: contextDir,
		CommonBuildOpts:  &define.CommonBuildOptions{},
		Layers:           true,
		RemoveIntermediateCtrs: true,
	}

	imageID, _, err := imagebuildah.BuildDockerfiles(ctx, store, opts, dockerfile)
	if err != nil {
		return "", fmt.Errorf("build failed: %w", err)
	}

	return imageID, nil
}

// ListImages returns JSON info about all images in the store.
func ListImages(store storage.Store) (string, error) {
	images, err := store.Images()
	if err != nil {
		return "", err
	}

	type imageInfo struct {
		ID     string   `json:"id"`
		Names  []string `json:"names"`
		Top    string   `json:"top_layer"`
		Layers int      `json:"layer_count"`
	}

	var result []imageInfo
	for _, img := range images {
		count := 0
		lid := img.TopLayer
		for lid != "" {
			count++
			l, err := store.Layer(lid)
			if err != nil {
				break
			}
			lid = l.Parent
		}
		result = append(result, imageInfo{
			ID:     img.ID,
			Names:  img.Names,
			Top:    img.TopLayer,
			Layers: count,
		})
	}

	data, err := json.Marshal(result)
	return string(data), err
}
