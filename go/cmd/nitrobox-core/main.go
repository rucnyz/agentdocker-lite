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

			// Preserve Docker config path before entering userns
			// (HOME changes to /root inside userns)
			if os.Getenv("DOCKER_CONFIG") == "" {
				home, _ := os.UserHomeDir()
				dockerCfg := filepath.Join(home, ".docker")
				if _, err := os.Stat(filepath.Join(dockerCfg, "config.json")); err == nil {
					os.Setenv("DOCKER_CONFIG", dockerCfg)
				}
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

			// Start the nitrobox handler (JSON-over-Unix-socket)
			handlerPath, err := srv.StartHandler()
			if err != nil {
				srv.Stop()
				return fmt.Errorf("start handler: %w", err)
			}

			// Write server info (overwrite earlier file)
			infoPath = filepath.Join(rootDir, "server.json")
			infoJSON, _ = json.Marshal(map[string]string{
				"socket_path":  socketPath,
				"handler_path": handlerPath,
				"root_dir":     rootDir,
			})
			os.WriteFile(infoPath, infoJSON, 0644)

			// Signal readiness
			readyPath := filepath.Join(rootDir, "ready")
			os.WriteFile(readyPath, []byte("1"), 0644)
			fmt.Fprintf(os.Stderr, "buildkit-serve: ready at %s (handler: %s)\n", socketPath, handlerPath)

			// Block until signal
			sigCh := make(chan os.Signal, 1)
			signal.Notify(sigCh, syscall.SIGTERM, syscall.SIGINT)
			<-sigCh

			srv.Stop()
			return nil
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
