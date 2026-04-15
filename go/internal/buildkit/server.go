// Embedded buildkitd server — runs BuildKit's solver in-process.
//
// Eliminates the need for a separate buildkitd binary and gives
// direct access to the snapshotter for layer path discovery.
package buildkit

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/containerd/containerd/v2/plugins/snapshots/overlay"
	"github.com/moby/buildkit/control"
	"github.com/moby/buildkit/executor/oci"
	"github.com/moby/buildkit/frontend"
	dockerfile "github.com/moby/buildkit/frontend/dockerfile/builder"
	"github.com/moby/buildkit/frontend/gateway/forwarder"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/snapshot"
	"github.com/moby/buildkit/solver"
	"github.com/moby/buildkit/solver/bboltcachestorage"
	"github.com/moby/buildkit/util/bklog"
	"github.com/moby/buildkit/util/db/boltutil"
	"github.com/moby/buildkit/util/network/netproviders"
	"github.com/moby/buildkit/util/resolver"
	"github.com/moby/buildkit/worker"
	"github.com/moby/buildkit/worker/base"
	"github.com/moby/buildkit/worker/runc"

	ctdsnapshots "github.com/containerd/containerd/v2/core/snapshots"

	"google.golang.org/grpc"
)

// Server is an embedded buildkitd that runs in-process.
type Server struct {
	rootDir     string
	controller  *control.Controller
	grpcServer  *grpc.Server
	listener    net.Listener
	socketPath  string
	snapshotter snapshot.Snapshotter // saved from WorkerOpt before NewWorker

	mu       sync.Mutex
	started  bool
	stopFunc context.CancelFunc
}

// NewServer creates a new embedded BuildKit server.
func NewServer(rootDir string) *Server {
	return &Server{rootDir: rootDir}
}

// Start initializes and starts the embedded buildkitd.
func (s *Server) Start() (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.started {
		return s.socketPath, nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	s.stopFunc = cancel

	if err := os.MkdirAll(s.rootDir, 0o700); err != nil {
		cancel()
		return "", fmt.Errorf("mkdir root: %w", err)
	}

	// Socket path — use outer UID (passed via env before userns re-exec)
	// so the socket is accessible from outside the user namespace.
	outerUID := os.Getenv("_NITROBOX_OUTER_UID")
	if outerUID == "" {
		outerUID = fmt.Sprintf("%d", os.Getuid())
	}
	socketDir := fmt.Sprintf("/tmp/nitrobox-buildkitd-%s", outerUID)
	os.MkdirAll(socketDir, 0o700)
	s.socketPath = filepath.Join(socketDir, "buildkitd.sock")
	os.Remove(s.socketPath)

	sessionManager, err := session.NewManager()
	if err != nil {
		cancel()
		return "", fmt.Errorf("session manager: %w", err)
	}

	hosts := resolver.NewRegistryConfig(nil)

	// OCI worker (rootless, overlayfs, no process sandbox)
	snFactory := runc.SnapshotterFactory{
		Name: "overlayfs",
		New: func(root string) (ctdsnapshots.Snapshotter, error) {
			return overlay.NewSnapshotter(root, overlay.AsynchronousRemove)
		},
	}
	opt, err := runc.NewWorkerOpt(
		s.rootDir, snFactory,
		true, oci.NoProcessSandbox,
		nil, nil,
		netproviders.Opt{Mode: "host"},
		nil, "", "", false, nil, "", "", nil,
	)
	if err != nil {
		cancel()
		return "", fmt.Errorf("worker opt: %w", err)
	}
	opt.RegistryHosts = hosts

	// Save snapshotter before it gets wrapped by NewWorker
	s.snapshotter = opt.Snapshotter

	w, err := base.NewWorker(ctx, opt)
	if err != nil {
		cancel()
		return "", fmt.Errorf("new worker: %w", err)
	}

	wc := &worker.Controller{}
	if err := wc.Add(w); err != nil {
		cancel()
		return "", fmt.Errorf("add worker: %w", err)
	}

	frontends := map[string]frontend.Frontend{
		"dockerfile.v0": forwarder.NewGatewayForwarder(wc.Infos(), dockerfile.Build),
	}

	cacheStorage, err := bboltcachestorage.NewStore(filepath.Join(s.rootDir, "cache.db"))
	if err != nil {
		cancel()
		return "", fmt.Errorf("cache storage: %w", err)
	}

	historyDB, err := boltutil.Open(filepath.Join(s.rootDir, "history.db"), 0600, nil)
	if err != nil {
		cancel()
		return "", fmt.Errorf("history db: %w", err)
	}

	ctrl, err := control.NewController(control.Opt{
		SessionManager:   sessionManager,
		WorkerController: wc,
		Frontends:        frontends,
		CacheManager:     solver.NewCacheManager(ctx, "local", cacheStorage, worker.NewCacheResultStorage(wc)),
		HistoryDB:        historyDB,
		CacheStore:       cacheStorage,
		LeaseManager:     w.LeaseManager(),
		ContentStore:     w.ContentStore(),
		GarbageCollect:   w.GarbageCollect,
		GracefulStop:     ctx.Done(),
	})
	if err != nil {
		cancel()
		return "", fmt.Errorf("controller: %w", err)
	}
	s.controller = ctrl

	s.grpcServer = grpc.NewServer()
	ctrl.Register(s.grpcServer)

	s.listener, err = net.Listen("unix", s.socketPath)
	if err != nil {
		cancel()
		return "", fmt.Errorf("listen: %w", err)
	}

	go func() {
		bklog.L.Infof("gRPC server starting on %s", s.socketPath)
		if err := s.grpcServer.Serve(s.listener); err != nil {
			bklog.L.Errorf("gRPC serve FAILED: %v", err)
			fmt.Fprintf(os.Stderr, "GRPC SERVE ERROR: %v\n", err)
		} else {
			bklog.L.Infof("gRPC server stopped cleanly")
		}
	}()

	s.started = true
	bklog.L.Infof("embedded buildkitd started at %s", s.socketPath)
	return s.socketPath, nil
}

// Stop gracefully stops the embedded server.
func (s *Server) Stop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.started {
		return
	}
	if s.stopFunc != nil {
		s.stopFunc()
	}
	if s.grpcServer != nil {
		s.grpcServer.GracefulStop()
	}
	if s.listener != nil {
		s.listener.Close()
	}
	os.Remove(s.socketPath)
	s.started = false
}

// SocketPath returns the Unix socket path.
func (s *Server) SocketPath() string { return s.socketPath }

// RootDir returns the BuildKit root directory.
func (s *Server) RootDir() string { return s.rootDir }

// GetLayerPaths resolves a manifest digest to overlay layer directory paths.
// Uses the snapshotter directly (in-process) — no DB lock issues.
func (s *Server) GetLayerPaths(ctx context.Context, manifestDigest string) ([]string, error) {
	if s.snapshotter == nil {
		return nil, fmt.Errorf("snapshotter not initialized")
	}

	// Read manifest → config → diff IDs from content store (plain files)
	contentDir := filepath.Join(s.rootDir, "runc-overlayfs", "content", "blobs", "sha256")
	digest := strings.TrimPrefix(manifestDigest, "sha256:")

	manifest, err := readJSON[ociManifest](filepath.Join(contentDir, digest))
	if err != nil {
		return nil, fmt.Errorf("read manifest: %w", err)
	}

	configDigest := trimSHA256(manifest.Config.Digest)
	config, err := readJSON[ociConfig](filepath.Join(contentDir, configDigest))
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	chainIDs := computeChainIDs(config.RootFS.DiffIDs)

	// Query snapshotter for each chain ID → get mount paths
	var paths []string
	for _, chainID := range chainIDs {
		mountable, err := s.snapshotter.Mounts(ctx, chainID)
		if err != nil {
			bklog.L.Debugf("snapshotter.Mounts(%s) failed: %v", chainID, err)
			continue
		}
		mounts, release, err := mountable.Mount()
		if err != nil {
			bklog.L.Debugf("mountable.Mount(%s) failed: %v", chainID, err)
			continue
		}
		defer release()

		// Extract the fs directory from overlay mount options
		for _, m := range mounts {
			if m.Type == "bind" {
				paths = append(paths, m.Source)
				break
			}
			// For overlay: first layer is bind mount, subsequent have lowerdir+upperdir
			for _, opt := range m.Options {
				if strings.HasPrefix(opt, "upperdir=") {
					paths = append(paths, opt[len("upperdir="):])
				}
			}
		}
	}

	if len(paths) != len(chainIDs) {
		return nil, fmt.Errorf("resolved %d/%d layers", len(paths), len(chainIDs))
	}

	return paths, nil
}
