package main

import (
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"go.podman.io/storage/pkg/reexec"
	"go.podman.io/storage/pkg/unshare"

	"github.com/opensage-agent/nitrobox/go/internal/cgroup"
	nbximage "github.com/opensage-agent/nitrobox/go/internal/image"
	"github.com/opensage-agent/nitrobox/go/internal/imageref"
	"github.com/opensage-agent/nitrobox/go/internal/mount"
	_ "github.com/opensage-agent/nitrobox/go/internal/nsenter" // CGO constructor for namespace entry
	"github.com/opensage-agent/nitrobox/go/internal/pidfd"
	"github.com/opensage-agent/nitrobox/go/internal/proc"
	"github.com/opensage-agent/nitrobox/go/internal/qmp"
	"github.com/opensage-agent/nitrobox/go/internal/sandbox"
	"github.com/opensage-agent/nitrobox/go/internal/security"
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
		Short:         "nitrobox low-level syscall interface",
		SilenceUsage:  true,
		SilenceErrors: true,
	}

	// --- mount ---
	rootCmd.AddCommand(&cobra.Command{
		Use:   "mount-overlay",
		Short: "Mount overlayfs",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				LowerdirSpec string   `json:"lowerdir_spec"`
				UpperDir     string   `json:"upper_dir"`
				WorkDir      string   `json:"work_dir"`
				Target       string   `json:"target"`
				ExtraOpts    []string `json:"extra_opts"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return mount.MountOverlay(req.LowerdirSpec, req.UpperDir, req.WorkDir, req.Target, req.ExtraOpts)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "bind-mount",
		Short: "Bind mount source to target",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Source string `json:"source"`
				Target string `json:"target"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return mount.BindMount(req.Source, req.Target)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "rbind-mount",
		Short: "Recursive bind mount",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Source string `json:"source"`
				Target string `json:"target"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return mount.RbindMount(req.Source, req.Target)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "umount",
		Short: "Unmount",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Target string `json:"target"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return mount.Umount(req.Target)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "umount-lazy",
		Short: "Lazy unmount",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Target string `json:"target"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return mount.UmountLazy(req.Target)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "umount-recursive-lazy",
		Short: "Recursive lazy unmount",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Target string `json:"target"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return mount.UmountRecursiveLazy(req.Target)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "make-private",
		Short: "Make mount private",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Target string `json:"target"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return mount.MakePrivate(req.Target)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "remount-ro-bind",
		Short: "Remount bind as read-only",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Target string `json:"target"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return mount.RemountROBind(req.Target)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "check-new-mount-api",
		Short: "Check if new mount API (lowerdir+) is supported",
		RunE: func(cmd *cobra.Command, args []string) error {
			result := mount.CheckNewMountAPI()
			return writeJSON(result)
		},
	})

	// --- cgroup ---
	rootCmd.AddCommand(&cobra.Command{
		Use:   "cgroup-v2-available",
		Short: "Check cgroup v2 availability",
		RunE: func(cmd *cobra.Command, args []string) error {
			return writeJSON(cgroup.V2Available())
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "create-cgroup",
		Short: "Create a cgroup",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Name string `json:"name"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			path, err := cgroup.Create(req.Name)
			if err != nil {
				return err
			}
			return writeJSON(path)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "apply-cgroup-limits",
		Short: "Apply cgroup limits",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				CgroupPath string            `json:"cgroup_path"`
				Limits     map[string]string `json:"limits"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return cgroup.ApplyLimits(req.CgroupPath, req.Limits)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "cgroup-add-process",
		Short: "Add process to cgroup",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				CgroupPath string `json:"cgroup_path"`
				Pid        uint32 `json:"pid"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return cgroup.AddProcess(req.CgroupPath, req.Pid)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "cleanup-cgroup",
		Short: "Kill processes and remove cgroup",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				CgroupPath string `json:"cgroup_path"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return cgroup.Cleanup(req.CgroupPath)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "convert-cpu-shares",
		Short: "Convert Docker CPU shares to cgroup v2 weight",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Shares uint64 `json:"shares"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return writeJSON(cgroup.ConvertCPUShares(req.Shares))
		},
	})

	// --- pidfd ---
	rootCmd.AddCommand(&cobra.Command{
		Use:   "pidfd-open",
		Short: "Open a pidfd",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Pid int `json:"pid"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			fd, err := pidfd.Open(req.Pid)
			if err != nil {
				return writeJSON(nil)
			}
			return writeJSON(fd)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "pidfd-send-signal",
		Short: "Send signal via pidfd",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Pidfd int `json:"pidfd"`
				Sig   int `json:"sig"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return writeJSON(pidfd.SendSignal(req.Pidfd, req.Sig))
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "pidfd-is-alive",
		Short: "Check if process is alive via pidfd",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Pidfd int `json:"pidfd"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return writeJSON(pidfd.IsAlive(req.Pidfd))
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "process-madvise-cold",
		Short: "Mark process memory as cold",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Pidfd int `json:"pidfd"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			err := pidfd.ProcessMadviseCold(req.Pidfd)
			if err != nil {
				return writeJSON(false)
			}
			return writeJSON(true)
		},
	})

	// --- proc (fuser) ---
	rootCmd.AddCommand(&cobra.Command{
		Use:   "fuser-kill",
		Short: "Kill processes with fds to path",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				TargetPath string `json:"target_path"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			count, err := proc.FuserKill(req.TargetPath)
			if err != nil {
				return err
			}
			return writeJSON(count)
		},
	})

	// --- qmp ---
	rootCmd.AddCommand(&cobra.Command{
		Use:   "qmp-send",
		Short: "Send QMP command",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				SocketPath  string `json:"socket_path"`
				CommandJSON string `json:"command_json"`
				TimeoutSecs uint64 `json:"timeout_secs"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			resp, err := qmp.Send(req.SocketPath, req.CommandJSON, req.TimeoutSecs)
			if err != nil {
				return err
			}
			return writeJSON(resp)
		},
	})

	// --- whiteout ---
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

	// --- image ref ---
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

	// --- security ---
	rootCmd.AddCommand(&cobra.Command{
		Use:   "landlock-abi-version",
		Short: "Get Landlock ABI version",
		RunE: func(cmd *cobra.Command, args []string) error {
			return writeJSON(security.LandlockABIVersion())
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "build-seccomp-bpf",
		Short: "Generate seccomp BPF bytecode",
		RunE: func(cmd *cobra.Command, args []string) error {
			bpf := security.BuildSeccompBPF()
			// Write raw bytes to stdout (not JSON)
			_, err := os.Stdout.Write(bpf)
			return err
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "apply-seccomp-filter",
		Short: "Install seccomp-bpf filter",
		RunE: func(cmd *cobra.Command, args []string) error {
			return security.ApplySeccompFilter()
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "drop-capabilities",
		Short: "Drop capabilities from bounding set",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				ExtraKeep []uint32 `json:"extra_keep"`
				ExtraDrop []uint32 `json:"extra_drop"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			dropped, err := security.DropCapabilities(req.ExtraKeep, req.ExtraDrop)
			if err != nil {
				return err
			}
			return writeJSON(dropped)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "apply-landlock",
		Short: "Apply Landlock filesystem/network restrictions",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				ReadPaths       []string `json:"read_paths"`
				WritePaths      []string `json:"write_paths"`
				AllowedTCPPorts []uint16 `json:"allowed_tcp_ports"`
				Strict          bool     `json:"strict"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			applied, err := security.ApplyLandlock(req.ReadPaths, req.WritePaths, req.AllowedTCPPorts, req.Strict)
			if err != nil {
				return err
			}
			return writeJSON(applied)
		},
	})

	// --- userns ---
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

	// --- unpack ---
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

	// --- nsenter ---
	// --- sandbox spawn ---
	rootCmd.AddCommand(&cobra.Command{
		Use:   "spawn",
		Short: "Spawn a sandboxed shell process",
		RunE: func(cmd *cobra.Command, args []string) error {
			var config sandbox.SpawnConfig
			if err := readJSON(&config); err != nil {
				return err
			}
			result, err := sandbox.Spawn(&config)
			if err != nil {
				return err
			}
			return writeJSON(result)
		},
	})

	// Internal re-exec subcommand for extraction worker (not user-facing)
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
			// fd 3 = usernsPipeW, fd 4 = goPipeR
			usernsPipeW := os.NewFile(3, "usernsPipeW")
			goPipeR := os.NewFile(4, "goPipeR")
			usernsPipeW.Write([]byte("R"))
			usernsPipeW.Close()
			buf := make([]byte, 1)
			goPipeR.Read(buf)
			goPipeR.Close()

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

	// --- containers/storage image operations ---
	rootCmd.AddCommand(&cobra.Command{
		Use:   "image-layers",
		Short: "Get overlay diff paths for an image from containers/storage",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				Image      string `json:"image"`
				GraphRoot  string `json:"graph_root"`
				RunRoot    string `json:"run_root"`
				Driver     string `json:"driver"`
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
				// We're in the re-exec'd process — read config from env
				json.Unmarshal([]byte(configEnv), &req)
			} else {
				// First invocation — read from stdin, save to env, then re-exec
				if err := readJSON(&req); err != nil {
					return err
				}
				reqJSON, _ := json.Marshal(req)
				os.Setenv("_NITROBOX_BUILD_CONFIG", string(reqJSON))
			}

			// Enter user namespace (same as podman/buildah does).
			// On first call: re-execs into userns (never returns).
			// On re-exec: already in userns, returns immediately.
			unshare.MaybeReexecUsingUserNamespace(false)

			// Clear config env so buildah reexec children don't see it
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

// Ensure imports are used.
var (
	_ = strconv.Atoi
	_ = strings.Join
)
