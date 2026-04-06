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
	"github.com/opensage-agent/nitrobox/go/internal/imageref"
	"github.com/opensage-agent/nitrobox/go/internal/unpack"
	"github.com/opensage-agent/nitrobox/go/internal/userns"
	"github.com/opensage-agent/nitrobox/go/internal/whiteout"
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

	// --- image operations ---

	rootCmd.AddCommand(&cobra.Command{
		Use:   "image-layers",
		Short: "Get overlay diff paths for an image from containers/storage",
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
			cfg := nbximage.DefaultStoreConfig()
			if req.GraphRoot != "" {
				cfg.GraphRoot = req.GraphRoot
			}
			if req.RunRoot != "" {
				cfg.RunRoot = req.RunRoot
			}
			if req.Driver != "" {
				cfg.Driver = req.Driver
			}
			store, err := nbximage.OpenStore(cfg)
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
		Use:   "image-pull",
		Short: "Pull an image into containers/storage",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Image     string `json:"image"`
				GraphRoot string `json:"graph_root"`
				RunRoot   string `json:"run_root"`
				Driver    string `json:"driver"`
			}

			// MaybeReexec re-execs the binary in a userns. Stdin doesn't
			// survive re-exec, so pass config via env var.
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

			cfg := nbximage.DefaultStoreConfig()
			if req.GraphRoot != "" {
				cfg.GraphRoot = req.GraphRoot
			}
			if req.RunRoot != "" {
				cfg.RunRoot = req.RunRoot
			}
			if req.Driver != "" {
				cfg.Driver = req.Driver
			}
			store, err := nbximage.OpenStore(cfg)
			if err != nil {
				return err
			}
			defer store.Free()
			return nbximage.PullImage(store, req.Image, nil)
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

			// MaybeReexec re-execs the binary in a userns. Stdin doesn't
			// survive re-exec, so pass config via env var.
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

			cfg := nbximage.DefaultStoreConfig()
			if req.GraphRoot != "" {
				cfg.GraphRoot = req.GraphRoot
			}
			if req.RunRoot != "" {
				cfg.RunRoot = req.RunRoot
			}
			if req.Driver != "" {
				cfg.Driver = req.Driver
			}

			// Redirect stdin to /dev/null after reading JSON config
			if devnull, err := os.Open("/dev/null"); err == nil {
				syscall.Dup2(int(devnull.Fd()), 0)
				devnull.Close()
			}

			store, err := nbximage.OpenStore(cfg)
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

			// MaybeReexec into userns so we open the same store driver
			// that was used during pull (overlay works in userns).
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

			cfg := nbximage.DefaultStoreConfig()
			if req.GraphRoot != "" {
				cfg.GraphRoot = req.GraphRoot
			}
			if req.RunRoot != "" {
				cfg.RunRoot = req.RunRoot
			}
			if req.Driver != "" {
				cfg.Driver = req.Driver
			}
			store, err := nbximage.OpenStore(cfg)
			if err != nil {
				return err
			}
			defer store.Free()
			return nbximage.DeleteImage(store, req.Image)
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
			cfg := nbximage.DefaultStoreConfig()
			if req.GraphRoot != "" {
				cfg.GraphRoot = req.GraphRoot
			}
			if req.RunRoot != "" {
				cfg.RunRoot = req.RunRoot
			}
			if req.Driver != "" {
				cfg.Driver = req.Driver
			}
			store, err := nbximage.OpenStore(cfg)
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

	// --- utility subcommands ---

	rootCmd.AddCommand(&cobra.Command{
		Use:   "parse-image-ref",
		Short: "Parse Docker image reference",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Image string `json:"image"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			domain, repo, tag, err := imageref.Parse(req.Image)
			if err != nil {
				return err
			}
			return writeJSON([]string{domain, repo, tag})
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "convert-whiteouts",
		Short: "Convert OCI whiteouts to overlayfs format",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				LayerDir     string `json:"layer_dir"`
				UseUserXattr bool   `json:"use_user_xattr"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			count, err := whiteout.ConvertWhiteouts(req.LayerDir, req.UseUserXattr)
			if err != nil {
				return err
			}
			return writeJSON(count)
		},
	})

	// --- userns helpers ---

	rootCmd.AddCommand(&cobra.Command{
		Use:   "userns-fixup-for-delete",
		Short: "Fix permissions for sandbox deletion",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				UsernsPid int    `json:"userns_pid"`
				DirPath   string `json:"dir_path"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			count, err := userns.FixupDirForDelete(req.UsernsPid, req.DirPath)
			if err != nil {
				return err
			}
			return writeJSON(count)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "extract-tar-in-userns",
		Short: "Extract tar in user namespace with UID mapping",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				TarPath  string `json:"tar_path"`
				Dest     string `json:"dest"`
				OuterUID uint32 `json:"outer_uid"`
				OuterGID uint32 `json:"outer_gid"`
				SubStart uint32 `json:"sub_start"`
				SubCount uint32 `json:"sub_count"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return unpack.ExtractTarInUserns(req.TarPath, req.Dest, req.OuterUID, req.OuterGID, req.SubStart, req.SubCount)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "rmtree-in-userns",
		Short: "Remove directory tree in user namespace",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Path     string `json:"path"`
				OuterUID uint32 `json:"outer_uid"`
				OuterGID uint32 `json:"outer_gid"`
				SubStart uint32 `json:"sub_start"`
				SubCount uint32 `json:"sub_count"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return unpack.RmtreeInUserns(req.Path, req.OuterUID, req.OuterGID, req.SubStart, req.SubCount)
		},
	})

	// Internal re-exec workers (not user-facing)
	rootCmd.AddCommand(&cobra.Command{
		Use:    "_extract-worker",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			unpack.ExtractWorker()
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:    "_rmtree-worker",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			path := os.Getenv("_NBX_RM_PATH")
			if path != "" {
				os.RemoveAll(path)
			}
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:    "_fixup-worker",
		Hidden: true,
		Run: func(cmd *cobra.Command, args []string) {
			userns.FixupWorker()
		},
	})

	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

// readJSON reads JSON from stdin into the given struct.
func readJSON(v any) error {
	return json.NewDecoder(os.Stdin).Decode(v)
}

// writeJSON writes JSON to stdout.
func writeJSON(v any) error {
	return json.NewEncoder(os.Stdout).Encode(v)
}
