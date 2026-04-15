// Rootless lifecycle management using rootlesskit library.
//
// Uses rootlesskit's parent/child Go packages to properly manage the
// user namespace, UID/GID mapping, and signal forwarding for the
// embedded buildkitd server. Same mechanism as Docker rootless.
package buildkit

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/rootless-containers/rootlesskit/v2/pkg/child"
	"github.com/rootless-containers/rootlesskit/v2/pkg/parent"
)

const (
	pipeFDEnvKey             = "_NITROBOX_RK_PIPEFD"
	childActivationEnvKey    = "_NITROBOX_RK_ACTIVATION"
	runActivationHelperKey   = "_NITROBOX_RK_RUNHELPER"
	stateDirEnvKey           = "_NITROBOX_RK_STATEDIR"
)

// IsRootlessChild returns true if we're running inside the rootlesskit
// child process (user namespace already set up).
func IsRootlessChild() bool {
	return os.Getenv(pipeFDEnvKey) != ""
}

// RunParent runs the rootlesskit parent process. It re-execs the current
// binary as the child inside a new user namespace, then waits for it to exit.
// The innerCmd is the command the child should execute (e.g., ["buildkit-serve-inner"]).
func RunParent(rootDir string, innerCmd []string) error {
	stateDir := filepath.Join(rootDir, "rootlesskit")
	if err := os.MkdirAll(stateDir, 0o700); err != nil {
		return fmt.Errorf("mkdir state dir: %w", err)
	}

	// Save outer UID for socket path
	if os.Getenv("_NITROBOX_OUTER_UID") == "" {
		os.Setenv("_NITROBOX_OUTER_UID", fmt.Sprintf("%d", os.Getuid()))
	}

	opt := parent.Opt{
		PipeFDEnvKey:             pipeFDEnvKey,
		ChildUseActivationEnvKey: childActivationEnvKey,
		StateDir:                 stateDir,
		StateDirEnvKey:           stateDirEnvKey,
		ParentEUIDEnvKey:         "_NITROBOX_OUTER_UID",
	}

	return parent.Parent(opt)
}

// RunChild runs the rootlesskit child process. It completes the user
// namespace setup and then execs the inner command (buildkitd server).
func RunChild(innerCmd []string) error {
	selfExe, err := os.Executable()
	if err != nil {
		return fmt.Errorf("executable: %w", err)
	}

	// The target command is our own binary with the inner subcommand
	targetCmd := append([]string{selfExe}, innerCmd...)

	opt := child.Opt{
		PipeFDEnvKey:              pipeFDEnvKey,
		ChildUseActivationEnvKey:  childActivationEnvKey,
		RunActivationHelperEnvKey: runActivationHelperKey,
		StateDirEnvKey:            stateDirEnvKey,
		TargetCmd:                 targetCmd,
		MountProcfs:               false,
		Reaper:                    false,
	}

	return child.Child(opt)
}
