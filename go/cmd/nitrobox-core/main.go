package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"go.podman.io/storage/pkg/reexec"
	"go.podman.io/storage/pkg/unshare"

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
		Use:   "image-build",
		Short: "Build a Dockerfile using buildah",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Dockerfile string `json:"dockerfile"`
				Context    string `json:"context"`
				Tag        string `json:"tag"`
				GraphRoot  string `json:"graph_root"`
				RunRoot    string `json:"run_root"`
				Driver     string `json:"driver"`
			}
			if configEnv := os.Getenv("_NITROBOX_BUILD_CONFIG"); configEnv != "" {
				json.Unmarshal([]byte(configEnv), &req)
			} else {
				if err := readJSON(&req); err != nil {
					return err
				}
				reqJSON, _ := json.Marshal(req)
				os.Setenv("_NITROBOX_BUILD_CONFIG", string(reqJSON))
			}
			unshare.MaybeReexecUsingUserNamespace(false)
			os.Unsetenv("_NITROBOX_BUILD_CONFIG")

			if devnull, err := os.Open("/dev/null"); err == nil {
				syscall.Dup2(int(devnull.Fd()), 0)
				devnull.Close()
			}

			store, err := nbximage.OpenStore(storeConfig(req.GraphRoot, req.RunRoot, req.Driver))
			if err != nil {
				return err
			}
			defer store.Free()
			imageID, err := nbximage.BuildImage(store, req.Dockerfile, req.Context, req.Tag)
			if err != nil {
				return err
			}
			return writeJSON(imageID)
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
