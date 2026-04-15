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
// Returns the image digest.
func BuildImage(socketPath, dockerfile, contextDir, tag string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	c, err := client.New(ctx, "unix://"+socketPath)
	if err != nil {
		return "", fmt.Errorf("connect to buildkitd: %w", err)
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
		// Output the image to BuildKit's internal image store (no push).
		// The layers remain in the snapshot directory for us to read.
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

	eg.Go(func() error {
		_, err := c.Solve(egCtx, nil, solveOpt, ch)
		return err
	})
	eg.Go(func() error {
		// Display progress to stderr
		d, err := progressui.NewDisplay(os.Stderr, progressui.AutoMode)
		if err != nil {
			// If display fails, just drain the channel
			for range ch {
			}
			return nil
		}
		_, err = d.UpdateFrom(egCtx, ch)
		return err
	})

	if err := eg.Wait(); err != nil {
		return "", fmt.Errorf("build failed: %w", err)
	}

	return tag, nil
}
