// Custom request handler for the embedded buildkitd.
//
// Listens on a separate Unix socket (nitrobox.sock) alongside the
// BuildKit gRPC socket. Accepts JSON requests for build, pull,
// layer resolution, and config reading — all handled in-process
// with direct snapshotter access.
package buildkit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/docker/cli/cli/config"
	"github.com/moby/buildkit/client"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/session/auth/authprovider"
	"github.com/moby/buildkit/util/bklog"
	"golang.org/x/sync/errgroup"
)

// Request from Python.
type Request struct {
	Action       string `json:"action"`        // "build", "pull", "config"
	Dockerfile   string `json:"dockerfile"`    // for build
	Context      string `json:"context"`       // for build
	Tag          string `json:"tag"`           // for build/pull
	ImageRef     string `json:"image_ref"`     // for pull
	Digest       string `json:"digest"`        // for config
	DockerConfig string `json:"docker_config"` // path to Docker config dir (for auth)
}

// Response to Python.
type Response struct {
	OK             bool            `json:"ok"`
	Error          string          `json:"error,omitempty"`
	ManifestDigest string          `json:"manifest_digest,omitempty"`
	LayerPaths     []string        `json:"layer_paths,omitempty"`
	Config         json.RawMessage `json:"config,omitempty"`
}

// StartHandler listens on a separate Unix socket for JSON requests.
// Each connection handles one request-response, then closes.
func (s *Server) StartHandler() (string, error) {
	handlerPath := strings.TrimSuffix(s.socketPath, ".sock") + "-nbx.sock"
	os.Remove(handlerPath)

	ln, err := net.Listen("unix", handlerPath)
	if err != nil {
		return "", fmt.Errorf("handler listen: %w", err)
	}

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return // listener closed
			}
			go func() {
				defer func() {
					if r := recover(); r != nil {
						fmt.Fprintf(os.Stderr, "handler panic: %v\n", r)
					}
				}()
				s.handleConn(conn)
			}()
		}
	}()

	bklog.L.Infof("nitrobox handler at %s", handlerPath)
	return handlerPath, nil
}

func (s *Server) handleConn(conn net.Conn) {
	defer conn.Close()

	scanner := bufio.NewScanner(conn)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	if !scanner.Scan() {
		return
	}

	var req Request
	if err := json.Unmarshal(scanner.Bytes(), &req); err != nil {
		json.NewEncoder(conn).Encode(Response{Error: fmt.Sprintf("invalid: %v", err)})
		return
	}

	var resp Response
	switch req.Action {
	case "build":
		resp = s.doBuild(req)
	case "pull":
		resp = s.doPull(req)
	case "config":
		resp = s.doConfig(req)
	default:
		resp = Response{Error: fmt.Sprintf("unknown action: %s", req.Action)}
	}

	json.NewEncoder(conn).Encode(resp)
}

func (s *Server) loadDockerConfig(dockerConfigDir string) authprovider.DockerAuthProviderConfig {
	if dockerConfigDir != "" {
		// Load from explicit path (passed from outside userns)
		cfg, err := config.Load(dockerConfigDir)
		if err == nil {
			return authprovider.DockerAuthProviderConfig{ConfigFile: cfg}
		}
	}
	// Fallback to default (DOCKER_CONFIG env or ~/.docker/)
	return authprovider.DockerAuthProviderConfig{
		ConfigFile: config.LoadDefaultConfigFile(os.Stderr),
	}
}

func (s *Server) doBuild(req Request) Response {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	c, err := client.New(ctx, "unix://"+s.socketPath)
	if err != nil {
		return Response{Error: fmt.Sprintf("connect: %v", err)}
	}
	defer c.Close()

	dockerfileDir := req.Context
	dockerfileName := req.Dockerfile
	if filepath.IsAbs(req.Dockerfile) {
		dockerfileDir = filepath.Dir(req.Dockerfile)
		dockerfileName = filepath.Base(req.Dockerfile)
	}

	solveOpt := client.SolveOpt{
		Frontend: "dockerfile.v0",
		FrontendAttrs: map[string]string{"filename": dockerfileName},
		LocalDirs: map[string]string{
			"context":    req.Context,
			"dockerfile": dockerfileDir,
		},
		Exports: []client.ExportEntry{{
			Type:  client.ExporterImage,
			Attrs: map[string]string{"name": req.Tag, "push": "false"},
		}},
		Session: []session.Attachable{
			authprovider.NewDockerAuthProvider(s.loadDockerConfig(req.DockerConfig)),
		},
	}

	var manifestDigest string
	eg, egCtx := errgroup.WithContext(ctx)
	ch := make(chan *client.SolveStatus)
	eg.Go(func() error {
		resp, err := c.Solve(egCtx, nil, solveOpt, ch)
		if err != nil {
			return err
		}
		if d, ok := resp.ExporterResponse["containerimage.digest"]; ok {
			manifestDigest = d
		}
		return nil
	})
	eg.Go(func() error {
		for range ch {
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return Response{Error: formatBuildError(req.Tag, err)}
	}

	// Resolve layers via snapshotter (in-process!)
	paths, err := s.GetLayerPaths(ctx, manifestDigest)
	if err != nil {
		return Response{
			ManifestDigest: manifestDigest,
			Error:          fmt.Sprintf("resolve layers: %v", err),
		}
	}

	return Response{
		OK:             true,
		ManifestDigest: manifestDigest,
		LayerPaths:     paths,
	}
}

func (s *Server) doPull(req Request) Response {
	// Pull via Dockerfile frontend: "FROM {image}\nRUN true"
	// The RUN instruction forces full layer extraction (unpacking lazy blobs).
	// This is the same mechanism Docker uses — build triggers unpack.
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	c, err := client.New(ctx, "unix://"+s.socketPath)
	if err != nil {
		return Response{Error: fmt.Sprintf("connect: %v", err)}
	}
	defer c.Close()

	// Create a temporary Dockerfile
	tmpDir, err := os.MkdirTemp("", "nitrobox-pull-*")
	if err != nil {
		return Response{Error: fmt.Sprintf("tmpdir: %v", err)}
	}
	defer os.RemoveAll(tmpDir)

	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	os.WriteFile(dockerfilePath, []byte(fmt.Sprintf("FROM %s\nRUN true\n", req.ImageRef)), 0644)

	solveOpt := client.SolveOpt{
		Frontend:      "dockerfile.v0",
		FrontendAttrs: map[string]string{"filename": "Dockerfile"},
		LocalDirs: map[string]string{
			"context":    tmpDir,
			"dockerfile": tmpDir,
		},
		Exports: []client.ExportEntry{{
			Type:  client.ExporterImage,
			Attrs: map[string]string{"name": req.ImageRef, "push": "false"},
		}},
		Session: []session.Attachable{
			authprovider.NewDockerAuthProvider(s.loadDockerConfig(req.DockerConfig)),
		},
	}

	var manifestDigest string
	eg, egCtx := errgroup.WithContext(ctx)
	ch := make(chan *client.SolveStatus)
	eg.Go(func() error {
		resp, err := c.Solve(egCtx, nil, solveOpt, ch)
		if err != nil {
			return err
		}
		if d, ok := resp.ExporterResponse["containerimage.digest"]; ok {
			manifestDigest = d
		}
		return nil
	})
	eg.Go(func() error {
		for range ch {
		}
		return nil
	})

	if err := eg.Wait(); err != nil {
		return Response{Error: fmt.Sprintf("pull failed: %v", err)}
	}

	paths, err := s.GetLayerPaths(ctx, manifestDigest)
	if err != nil {
		return Response{
			ManifestDigest: manifestDigest,
			Error:          fmt.Sprintf("resolve layers: %v", err),
		}
	}

	return Response{
		OK:             true,
		ManifestDigest: manifestDigest,
		LayerPaths:     paths,
	}
}

func (s *Server) doConfig(req Request) Response {
	contentDir := filepath.Join(s.rootDir, "runc-overlayfs", "content", "blobs", "sha256")
	d := trimSHA256(req.Digest)

	manifest, err := readJSON[ociManifest](filepath.Join(contentDir, d))
	if err != nil {
		return Response{Error: fmt.Sprintf("read manifest: %v", err)}
	}
	configDigest := trimSHA256(manifest.Config.Digest)
	cfg, err := readJSON[ociConfig](filepath.Join(contentDir, configDigest))
	if err != nil {
		return Response{Error: fmt.Sprintf("read config: %v", err)}
	}
	cfgJSON, _ := json.Marshal(cfg)

	return Response{
		OK:     true,
		Config: cfgJSON,
	}
}

func formatBuildError(tag string, err error) string {
	stderr := err.Error()
	if strings.Contains(stderr, "invalid argument") &&
		(strings.Contains(stderr, "subuid") || strings.Contains(stderr, "subgid") || strings.Contains(stderr, "Lchown")) {
		return fmt.Sprintf(
			"UID/GID mapping range too small for %s. "+
				"Expand /etc/subuid and /etc/subgid, then restart: "+
				"nitrobox buildkit-stop", tag)
	}
	if len(stderr) > 1000 {
		stderr = stderr[len(stderr)-1000:]
	}
	return fmt.Sprintf("build failed for %s: %s", tag, stderr)
}
