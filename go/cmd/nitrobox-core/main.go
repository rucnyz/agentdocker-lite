package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/opensage-agent/nitrobox/go/internal/cgroup"
	"github.com/opensage-agent/nitrobox/go/internal/imageref"
	"github.com/opensage-agent/nitrobox/go/internal/mount"
	"github.com/opensage-agent/nitrobox/go/internal/nsenter"
	"github.com/opensage-agent/nitrobox/go/internal/pidfd"
	"github.com/opensage-agent/nitrobox/go/internal/proc"
	"github.com/opensage-agent/nitrobox/go/internal/qmp"
	"github.com/opensage-agent/nitrobox/go/internal/security"
	"github.com/opensage-agent/nitrobox/go/internal/unpack"
	"github.com/opensage-agent/nitrobox/go/internal/userns"
	"github.com/opensage-agent/nitrobox/go/internal/whiteout"
	"github.com/spf13/cobra"
)

func main() {
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
	rootCmd.AddCommand(&cobra.Command{
		Use:   "nsenter-preexec",
		Short: "Enter mount namespace and chroot (rootful popen)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				TargetPid int `json:"target_pid"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return nsenter.NsenterPreexec(req.TargetPid)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:   "userns-preexec",
		Short: "Enter user+mount namespace and chroot (userns popen)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var req struct {
				TargetPid  int    `json:"target_pid"`
				Rootfs     string `json:"rootfs"`
				WorkingDir string `json:"working_dir"`
			}
			if err := readJSON(&req); err != nil {
				return err
			}
			return nsenter.UsersPreexec(req.TargetPid, req.Rootfs, req.WorkingDir)
		},
	})

	rootCmd.AddCommand(&cobra.Command{
		Use:                "nsenter-exec",
		Short:              "Enter namespace and exec command",
		DisableFlagParsing: true,
		RunE: func(cmd *cobra.Command, args []string) error {
			// Usage: nsenter-exec --pid N [--rootful|--rootfs PATH --workdir PATH] -- cmd args...
			var targetPid int
			var rootful bool
			var rootfs, workDir string
			var cmdArgs []string

			i := 0
			for i < len(args) {
				switch args[i] {
				case "--pid":
					i++
					fmt.Sscanf(args[i], "%d", &targetPid)
				case "--rootful":
					rootful = true
				case "--rootfs":
					i++
					rootfs = args[i]
				case "--workdir":
					i++
					workDir = args[i]
				case "--":
					cmdArgs = args[i+1:]
					i = len(args)
					continue
				}
				i++
			}
			if len(cmdArgs) == 0 {
				return fmt.Errorf("no command specified after --")
			}
			return nsenter.NsenterExec(targetPid, rootful, rootfs, workDir, cmdArgs)
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
