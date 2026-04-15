package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"go.podman.io/storage/pkg/reexec"
	"go.podman.io/storage/pkg/unshare"

	nbxbuildkit "github.com/opensage-agent/nitrobox/go/internal/buildkit"
	nbximage "github.com/opensage-agent/nitrobox/go/internal/image"
	"github.com/spf13/cobra"
)

func main() {
	// Ignore SIGPIPE — buildah's reexec children may close pipes before we finish writing.
	signal.Ignore(syscall.SIGPIPE)

	// containers/storage requires reexec.Init() for chroot-based layer operations.
	reexec.Init()

	rootCmd := &cobra.Command{
		Use:           "nitrobox-core",
		Short:         "nitrobox image management (containers/storage + buildah)",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	rootCmd.AddCommand(&cobra.Command{
		Use:   "image-pull",
		Short: "Pull an image into containers/storage",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Image     string `json:"image"`
				GraphRoot string `json:"graph_root"`
				RunRoot   string `json:"run_root"`
				Driver    string `json:"driver"`
			}
			if configEnv := os.Getenv("_NITROBOX_PULL_CONFIG"); configEnv != "" {
				json.Unmarshal([]byte(configEnv), &req)
			} else {
				if err := readJSON(&req); err != nil {
					return err
				}
				reqJSON, _ := json.Marshal(req)
				os.Setenv("_NITROBOX_PULL_CONFIG", string(reqJSON))
			}

			unshare.MaybeReexecUsingUserNamespace(false)
			os.Unsetenv("_NITROBOX_PULL_CONFIG")

			store, err := nbximage.OpenStore(storeConfig(req.GraphRoot, req.RunRoot, req.Driver))
			if err != nil {
				return err
			}
			defer store.Free()
			result, err := nbximage.PullImage(store, req.Image, nil)
			if err != nil {
				return err
			}
			return writeJSON(result)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "image-delete",
		Short: "Delete an image from containers/storage (mirrors docker rmi)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Image     string `json:"image"`
				GraphRoot string `json:"graph_root"`
				RunRoot   string `json:"run_root"`
				Driver    string `json:"driver"`
			}
			if configEnv := os.Getenv("_NITROBOX_DELETE_CONFIG"); configEnv != "" {
				json.Unmarshal([]byte(configEnv), &req)
			} else {
				if err := readJSON(&req); err != nil {
					return err
				}
				reqJSON, _ := json.Marshal(req)
				os.Setenv("_NITROBOX_DELETE_CONFIG", string(reqJSON))
			}
			unshare.MaybeReexecUsingUserNamespace(false)
			os.Unsetenv("_NITROBOX_DELETE_CONFIG")

			store, err := nbximage.OpenStore(storeConfig(req.GraphRoot, req.RunRoot, req.Driver))
			if err != nil {
				return err
			}
			defer store.Free()
			return nbximage.DeleteImage(store, req.Image)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "image-layers",
		Short: "Get overlay diff paths for an image",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Image     string `json:"image"`
				GraphRoot string `json:"graph_root"`
				RunRoot   string `json:"run_root"`
				Driver    string `json:"driver"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			store, err := nbximage.OpenStore(storeConfig(req.GraphRoot, req.RunRoot, req.Driver))
			if err != nil {
				return err
			}
			defer store.Free()
			paths, err := nbximage.ImageLayers(store, req.Image)
			if err != nil {
				return err
			}
			return writeJSON(paths)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "image-list",
		Short: "List images in containers/storage",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				GraphRoot string `json:"graph_root"`
				RunRoot   string `json:"run_root"`
				Driver    string `json:"driver"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			store, err := nbximage.OpenStore(storeConfig(req.GraphRoot, req.RunRoot, req.Driver))
			if err != nil {
				return err
			}
			defer store.Free()
			result, err := nbximage.ListImages(store)
			if err != nil {
				return err
			}
			fmt.Println(result)
			return nil
		},
	})

	// -- BuildKit commands ------------------------------------------------

	rootCmd.AddCommand(&cobra.Command{
		Use:   "buildkit-serve",
		Short: "Run embedded buildkitd (manages rootless userns via rootlesskit)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				RootDir string `json:"root_dir"`
			}
			// Read config from env (survives re-exec) or stdin
			if configEnv := os.Getenv("_NITROBOX_BUILDKIT_CONFIG"); configEnv != "" {
				json.Unmarshal([]byte(configEnv), &req)
			} else {
				if err := readJSON(&req); err != nil {
					return err
				}
				reqJSON, _ := json.Marshal(req)
				os.Setenv("_NITROBOX_BUILDKIT_CONFIG", string(reqJSON))
			}

			rootDir := req.RootDir
			if rootDir == "" {
				rootDir = nbxbuildkit.DefaultRootDir()
			}

			if nbxbuildkit.IsRootlessChild() {
				// We're the rootlesskit child — complete userns setup
				// and exec buildkit-serve-inner (the actual server)
				return nbxbuildkit.RunChild([]string{"buildkit-serve-inner"})
			}

			// We're the original parent — create userns via rootlesskit
			// and re-exec ourselves as child
			return nbxbuildkit.RunParent(rootDir, []string{"buildkit-serve"})
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:    "buildkit-serve-inner",
		Short:  "Internal: run buildkitd inside rootlesskit userns",
		Hidden: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// We're inside the userns. Read config from env.
			var req struct {
				RootDir string `json:"root_dir"`
			}
			if configEnv := os.Getenv("_NITROBOX_BUILDKIT_CONFIG"); configEnv != "" {
				json.Unmarshal([]byte(configEnv), &req)
			}
			rootDir := req.RootDir
			if rootDir == "" {
				rootDir = nbxbuildkit.DefaultRootDir()
			}

			srv := nbxbuildkit.NewServer(rootDir)
			socketPath, err := srv.Start()
			if err != nil {
				return err
			}

			// Write socket info to well-known file
			infoPath := filepath.Join(rootDir, "server.json")
			infoJSON, _ := json.Marshal(map[string]string{
				"socket_path": socketPath,
				"root_dir":    rootDir,
			})
			os.WriteFile(infoPath, infoJSON, 0644)
			fmt.Fprintf(os.Stderr, "buildkit-serve: ready at %s\n", socketPath)

			// Block until signal
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
			<-sigCh

			srv.Stop()
			return nil
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "buildkit-start",
		Short: "Start managed buildkitd daemon (external process)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				BuildkitdBin string `json:"buildkitd_bin"`
				RootDir      string `json:"root_dir"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			d := nbxbuildkit.NewDaemon()
			if req.RootDir != "" {
				d.RootDir = req.RootDir
			}
			if err := d.Start(req.BuildkitdBin); err != nil {
				return err
			}
			return writeJSON(map[string]string{
				"socket_path":   d.SocketPath,
				"snapshot_root": d.SnapshotRoot(),
			})
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "buildkit-stop",
		Short: "Stop managed buildkitd daemon",
		RunE: func(cmd *cobra.Command, args []string) error {
			d := nbxbuildkit.NewDaemon()
			return d.Stop()
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "buildkit-layers",
		Short: "Get layer paths from BuildKit snapshots",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				RootDir        string `json:"root_dir"`
				ManifestDigest string `json:"manifest_digest"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			rootDir := req.RootDir
			if rootDir == "" {
				rootDir = nbxbuildkit.DefaultRootDir()
			}
			// Strip "sha256:" prefix if present
			digest := req.ManifestDigest
			if len(digest) > 7 && digest[:7] == "sha256:" {
				digest = digest[7:]
			}
			paths, err := nbxbuildkit.ImageLayers(rootDir, digest)
			if err != nil {
				return err
			}
			return writeJSON(map[string]any{"layers": paths})
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "buildkit-pull",
		Short: "Pull an image via BuildKit LLB",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				SocketPath string `json:"socket_path"`
				RootDir    string `json:"root_dir"`
				ImageRef   string `json:"image_ref"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			rootDir := req.RootDir
			if rootDir == "" {
				rootDir = nbxbuildkit.DefaultRootDir()
			}
			result, err := nbxbuildkit.PullImage(
				req.SocketPath, rootDir, req.ImageRef,
			)
			if err != nil {
				return err
			}
			return writeJSON(result)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "buildkit-build",
		Short: "Build a Dockerfile via BuildKit",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				SocketPath string `json:"socket_path"`
				RootDir    string `json:"root_dir"`
				Dockerfile string `json:"dockerfile"`
				Context    string `json:"context"`
				Tag        string `json:"tag"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			rootDir := req.RootDir
			if rootDir == "" {
				rootDir = nbxbuildkit.DefaultRootDir()
			}
			result, err := nbxbuildkit.BuildImage(
				req.SocketPath, rootDir, req.Dockerfile, req.Context, req.Tag,
			)
			if err != nil {
				return err
			}
			return writeJSON(result)
		},
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func storeConfig(graphRoot, runRoot, driver string) nbximage.StoreConfig {
	cfg := nbximage.DefaultStoreConfig()
	if graphRoot != "" {
		cfg.GraphRoot = graphRoot
	}
	if runRoot != "" {
		cfg.RunRoot = runRoot
	}
	if driver != "" {
		cfg.Driver = driver
	}
	return cfg
}

func readJSON(v any) error {
	return json.NewDecoder(os.Stdin).Decode(v)
}

func writeJSON(v any) error {
	return json.NewEncoder(os.Stdout).Encode(v)
}
