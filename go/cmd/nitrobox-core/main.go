package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/nichochar/nitrobox/go/internal/cgroup"
	"github.com/nichochar/nitrobox/go/internal/imageref"
	"github.com/nichochar/nitrobox/go/internal/mount"
	"github.com/nichochar/nitrobox/go/internal/pidfd"
	"github.com/nichochar/nitrobox/go/internal/proc"
	"github.com/nichochar/nitrobox/go/internal/qmp"
	"github.com/nichochar/nitrobox/go/internal/whiteout"
	"github.com/spf13/cobra"
	"golang.org/x/sys/unix"
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

	// --- landlock ---
	rootCmd.AddCommand(&cobra.Command{
		Use:   "landlock-abi-version",
		Short: "Get Landlock ABI version",
		RunE: func(cmd *cobra.Command, args []string) error {
			ver := landlockABIVersion()
			return writeJSON(ver)
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

// landlockABIVersion returns the Landlock ABI version (0 if unsupported).
// Uses raw syscall since x/sys doesn't wrap landlock_create_ruleset.
func landlockABIVersion() uint32 {
	// SYS_LANDLOCK_CREATE_RULESET = 444 on x86_64
	const sysLandlockCreateRuleset = 444
	const landlockCreateRulesetVersion = 1 << 0

	r1, _, errno := unix.Syscall(sysLandlockCreateRuleset, 0, 0, landlockCreateRulesetVersion)
	if errno != 0 {
		return 0
	}
	unix.Close(int(r1))
	return uint32(r1)
}

// Ensure imports are used.
var (
	_ = strconv.Atoi
	_ = strings.Join
)
