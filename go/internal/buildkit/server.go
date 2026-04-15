// Embedded buildkitd server — runs BuildKit's solver in-process.
//
// Inlines runc.NewWorkerOpt to get access to the containerd metadata DB
// for proper Image → Unpack → Snapshotter.Mounts() layer resolution.
package buildkit

import (
	"context"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"

	"github.com/containerd/containerd/v2/core/diff/apply"
	ctdmetadata "github.com/containerd/containerd/v2/core/metadata"
	ctdsnapshots "github.com/containerd/containerd/v2/core/snapshots"
	"github.com/containerd/containerd/v2/plugins/content/local"
	"github.com/containerd/containerd/v2/plugins/diff/walking"
	"github.com/containerd/containerd/v2/plugins/snapshots/overlay"
	"github.com/containerd/platforms"

	"github.com/moby/buildkit/cache"
	"github.com/moby/buildkit/cache/metadata"
	"github.com/moby/buildkit/control"
	"github.com/moby/buildkit/executor/oci"
	"github.com/moby/buildkit/executor/resources"
	"github.com/moby/buildkit/executor/runcexecutor"
	"github.com/moby/buildkit/frontend"
	dockerfile "github.com/moby/buildkit/frontend/dockerfile/builder"
	"github.com/moby/buildkit/frontend/gateway/forwarder"
	"github.com/moby/buildkit/session"
	"github.com/moby/buildkit/snapshot"
	containerdsnapshot "github.com/moby/buildkit/snapshot/containerd"
	"github.com/moby/buildkit/solver"
	"github.com/moby/buildkit/solver/bboltcachestorage"
	"github.com/moby/buildkit/util/bklog"
	"github.com/moby/buildkit/util/db/boltutil"
	"github.com/moby/buildkit/util/leaseutil"
	"github.com/moby/buildkit/util/network/netproviders"
	"github.com/moby/buildkit/util/resolver"
	"github.com/moby/buildkit/util/winlayers"
	"github.com/moby/buildkit/worker"
	"github.com/moby/buildkit/worker/base"
	wlabel "github.com/moby/buildkit/worker/label"

	ocispecs "github.com/opencontainers/image-spec/specs-go/v1"
	bolt "go.etcd.io/bbolt"
	"google.golang.org/grpc"
)

// Server is an embedded buildkitd that runs in-process.
type Server struct {
	rootDir     string
	controller  *control.Controller
	grpcServer  *grpc.Server
	listener    net.Listener
	socketPath  string
	snapshotter   snapshot.Snapshotter   // BuildKit-wrapped snapshotter
	metaDB        *ctdmetadata.DB       // containerd metadata DB
	cacheManager  cache.Manager         // BuildKit cache manager
	metadataStore *metadata.Store       // BuildKit metadata store (chain ID index)

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

	// Socket path — use outer UID so it's accessible from outside userns.
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

	// --- Inline runc.NewWorkerOpt to expose mdb ---
	snName := "overlayfs"
	workerRoot := filepath.Join(s.rootDir, "runc-"+snName)
	os.MkdirAll(workerRoot, 0o700)

	log := func(msg string, args ...any) {
		bklog.L.Infof(msg, args...)
	}

	// Network
	log("setting up network providers...")
	np, npResolvedMode, err := netproviders.Providers(netproviders.Opt{Mode: "host"})
	if err != nil {
		cancel()
		return "", fmt.Errorf("network: %w", err)
	}
	log("network OK (mode=%s)", npResolvedMode)

	// Executor
	log("creating resource monitor...")
	rm, err := resources.NewMonitor()
	if err != nil {
		cancel()
		return "", fmt.Errorf("resource monitor: %w", err)
	}
	log("creating runc executor (rootless, no-sandbox)...")
	exe, err := runcexecutor.New(runcexecutor.Opt{
		Root:        filepath.Join(workerRoot, "executor"),
		Rootless:    true,
		ProcessMode: oci.NoProcessSandbox,
	}, np)
	if err != nil {
		cancel()
		return "", fmt.Errorf("executor: %w", err)
	}
	log("executor OK")

	// Snapshotter
	log("creating overlay snapshotter...")
	rawSnap, err := overlay.NewSnapshotter(filepath.Join(workerRoot, "snapshots"), overlay.AsynchronousRemove)
	if err != nil {
		cancel()
		return "", fmt.Errorf("snapshotter: %w", err)
	}
	log("snapshotter OK")

	// Content store
	log("creating content store...")
	localstore, err := local.NewStore(filepath.Join(workerRoot, "content"))
	if err != nil {
		cancel()
		return "", fmt.Errorf("content store: %w", err)
	}

	log("content store OK")

	// Containerd metadata DB
	log("opening containerd metadata DB...")
	metaDBPath := filepath.Join(workerRoot, "containerdmeta.db")
	bdb, err := bolt.Open(metaDBPath, 0644, nil)
	if err != nil {
		cancel()
		return "", fmt.Errorf("metadata db: %w", err)
	}
	mdb := ctdmetadata.NewDB(bdb, localstore, map[string]ctdsnapshots.Snapshotter{
		snName: rawSnap,
	})
	if err := mdb.Init(ctx); err != nil {
		cancel()
		return "", fmt.Errorf("init metadata db: %w", err)
	}
	s.metaDB = mdb
	log("metadata DB OK")

	// BuildKit-namespaced wrappers
	contentStore := containerdsnapshot.NewContentStore(mdb.ContentStore(), "buildkit")
	lm := leaseutil.WithNamespace(ctdmetadata.NewLeaseManager(mdb), "buildkit")
	snap := containerdsnapshot.NewSnapshotter(snName, mdb.Snapshotter(snName), "buildkit", nil)
	s.snapshotter = snap

	// Migrate metadata
	if err := cache.MigrateV2(
		ctx,
		filepath.Join(workerRoot, "metadata.db"),
		filepath.Join(workerRoot, "metadata_v2.db"),
		contentStore, snap, lm,
	); err != nil {
		cancel()
		return "", fmt.Errorf("migrate: %w", err)
	}

	md, err := metadata.NewStore(filepath.Join(workerRoot, "metadata_v2.db"))
	if err != nil {
		cancel()
		return "", fmt.Errorf("metadata store: %w", err)
	}

	id, _ := base.ID(workerRoot)
	hostname, _ := os.Hostname()

	opt := base.WorkerOpt{
		ID:   id,
		Root: workerRoot,
		Labels: map[string]string{
			wlabel.Executor:       "oci",
			wlabel.Snapshotter:    snName,
			wlabel.Hostname:       hostname,
			wlabel.Network:        npResolvedMode,
			wlabel.OCIProcessMode: oci.NoProcessSandbox.String(),
			wlabel.SELinuxEnabled: strconv.FormatBool(false),
		},
		MetadataStore:    md,
		NetworkProviders: np,
		Executor:         exe,
		Snapshotter:      snap,
		ContentStore:     contentStore,
		Applier:          winlayers.NewFileSystemApplierWithWindows(contentStore, apply.NewFileSystemApplier(contentStore)),
		Differ:           winlayers.NewWalkingDiffWithWindows(contentStore, walking.NewWalkingDiff(contentStore)),
		ImageStore:       nil,
		Platforms:        []ocispecs.Platform{platforms.Normalize(platforms.DefaultSpec())},
		LeaseManager:     lm,
		GarbageCollect:   mdb.GarbageCollect,
		ResourceMonitor:  rm,
		MountPoolRoot:    filepath.Join(workerRoot, "cachemounts"),
	}
	maps.Copy(opt.Labels, map[string]string{}) // ensure non-nil
	opt.RegistryHosts = hosts

	// --- End inline NewWorkerOpt ---

	log("creating worker...")
	w, err := base.NewWorker(ctx, opt)
	if err != nil {
		cancel()
		return "", fmt.Errorf("new worker: %w", err)
	}
	s.cacheManager = w.CacheManager()
	log("worker OK")
	s.metadataStore = md

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

	log("creating controller...")
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

	log("controller OK")

	log("starting gRPC server...")
	s.grpcServer = grpc.NewServer()
	ctrl.Register(s.grpcServer)

	s.listener, err = net.Listen("unix", s.socketPath)
	if err != nil {
		cancel()
		return "", fmt.Errorf("listen: %w", err)
	}

	go func() {
		if err := s.grpcServer.Serve(s.listener); err != nil {
			bklog.L.Errorf("gRPC serve error: %v", err)
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
	// Also remove handler socket
	handlerPath := strings.TrimSuffix(s.socketPath, ".sock") + "-nbx.sock"
	os.Remove(handlerPath)
	s.started = false
}

// SocketPath returns the Unix socket path.
func (s *Server) SocketPath() string { return s.socketPath }

// RootDir returns the BuildKit root directory.
func (s *Server) RootDir() string { return s.rootDir }

// GetLayerPaths resolves a manifest digest to overlay layer directory paths.
// Uses BuildKit's cache manager to find the snapshot ref by chain ID,
// then calls ref.Mount() to get the actual overlay mount paths.
// This is the correct API — no direct snapshotter key guessing needed.
func (s *Server) GetLayerPaths(ctx context.Context, manifestDigest string) ([]string, error) {
	if s.cacheManager == nil {
		return nil, fmt.Errorf("cache manager not initialized")
	}

	// Read manifest → config → diff IDs from content store
	workerRoot := filepath.Join(s.rootDir, "runc-overlayfs")
	contentDir := filepath.Join(workerRoot, "content", "blobs", "sha256")
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
	if len(chainIDs) == 0 {
		return nil, fmt.Errorf("no layers in image")
	}

	// Search BuildKit's metadata store for the cache record matching
	// the final chain ID, then use the cache manager to get the ref.
	finalChainID := chainIDs[len(chainIDs)-1]

	// Search index: "chainid:sha256:xxx"
	sis, err := s.metadataStore.Search(ctx, "chainid:"+finalChainID, false)
	if err != nil || len(sis) == 0 {
		return nil, fmt.Errorf("chain %s not found in metadata (search err: %v, results: %d)",
			finalChainID[:20], err, len(sis))
	}
	recordID := sis[0].ID()

	// Pass Unlazy session to force layer extraction (otherwise lazy blobs
	// from pull-only operations won't be unpacked to the snapshotter).
	ref, err := s.cacheManager.Get(ctx, recordID, nil, cache.Unlazy(session.NewGroup()))
	if err != nil {
		return nil, fmt.Errorf("cache get %s: %w", finalChainID[:20], err)
	}
	defer ref.Release(context.TODO())

	// Mount read-only to get overlay mount info
	mountable, err := ref.Mount(ctx, true, session.NewGroup())
	if err != nil {
		return nil, fmt.Errorf("mount: %w", err)
	}
	mountList, release, err := mountable.Mount()
	if err != nil {
		return nil, fmt.Errorf("get mounts: %w", err)
	}
	defer release()

	// Parse overlay mount options to extract layer paths
	var paths []string
	for _, m := range mountList {
		if m.Type == "bind" {
			paths = append(paths, m.Source)
		} else if m.Type == "overlay" {
			for _, opt := range m.Options {
				if strings.HasPrefix(opt, "lowerdir=") {
					dirs := strings.Split(opt[9:], ":")
					// lowerdir is top-to-bottom; reverse to bottom-to-top
					for i := len(dirs) - 1; i >= 0; i-- {
						paths = append(paths, dirs[i])
					}
				}
				if strings.HasPrefix(opt, "upperdir=") {
					paths = append(paths, opt[9:])
				}
			}
		}
	}

	if len(paths) == 0 {
		return nil, fmt.Errorf("no layer paths from mounts")
	}
	return paths, nil
}
