// Copyright 2026 The Tessera authors. All Rights Reserved.
// Modifications Copyright 2026 TrustEngine. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package awspsql is a Tessera storage backend that uses S3 for
// object storage (tiles, entry bundles, checkpoints) and PostgreSQL for
// coordination, sequencing and integration metadata.
//
// Multi-tenancy is enforced on two layers:
//
//  1. S3: every object key is prefixed with "tenants/<TenantID>/" so that
//     two tenants cannot collide in the bucket namespace. The prefix sits
//     beneath any optional Config.BucketPrefix.
//  2. PostgreSQL: every coordination row carries a tenant_id column, and
//     Row Level Security policies restrict access to rows whose tenant_id
//     matches the session-local app.tenant_id GUC. Tessera transactions set
//     this GUC at BEGIN time, providing defense in depth against missing
//     WHERE clauses.
//
// One Storage value serves one tenant; an upstream router is expected to
// select the correct Storage based on the per-request tenant ID extracted
// by TenantMiddleware / TenantUnaryServerInterceptor.
package awspsql

import (
	"bytes"
	"context"
	"encoding/gob"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/internal/fetcher"
	"github.com/transparency-dev/tessera/internal/migrate"
	"github.com/transparency-dev/tessera/internal/otel"
	"github.com/transparency-dev/tessera/internal/parse"
	storage "github.com/transparency-dev/tessera/storage/internal"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/trace"
	"go.uber.org/zap"
	"golang.org/x/sync/errgroup"
)

const (
	logContType           = "application/octet-stream"
	ckptContType          = "text/plain; charset=utf-8"
	logCacheControl       = "max-age=604800,immutable"
	ckptCacheControl      = "no-cache"
	minCheckpointInterval = time.Second

	DefaultPushbackMaxOutstanding = 4096
	DefaultIntegrationSizeLimit   = 5 * 4096

	// SchemaCompatibilityVersion represents the expected version of stored data.
	SchemaCompatibilityVersion = 1

	defaultIntegrationTimeout = 10 * time.Second
	defaultPublicationTimeout = 5 * time.Second
	defaultGCTimeout          = 30 * time.Second

	// tenantPrefix is the literal segment under which all per-tenant keys live.
	tenantPrefix = "tenants"
)

// Storage is a multi-tenant S3 + PostgreSQL storage implementation for Tessera.
//
// Each Storage value is bound to a single tenant identified by cfg.TenantID.
type Storage struct {
	cfg Config
}

// objStore stores and retrieves opaque objects scoped to a single tenant.
type objStore interface {
	getObject(ctx context.Context, obj string) ([]byte, error)
	setObject(ctx context.Context, obj string, data []byte, contType string, cacheControl string) error
	setObjectIfNoneMatch(ctx context.Context, obj string, data []byte, contType string, cacheControl string) error
	deleteObjectsWithPrefix(ctx context.Context, prefix string) error
}

// sequencer is a tenant-scoped durable, multi-process-safe sequencer.
type sequencer interface {
	assignEntries(ctx context.Context, entries []*tessera.Entry) error
	consumeEntries(ctx context.Context, limit uint64, f consumeFunc, forceUpdate bool) (bool, error)
	currentTree(ctx context.Context) (uint64, []byte, error)
	nextIndex(ctx context.Context) (uint64, error)
	publishCheckpoint(ctx context.Context, minStaleActive, minStaleRepub time.Duration, f func(ctx context.Context, size uint64, root []byte) error) error
	garbageCollect(ctx context.Context, treeSize uint64, maxDeletes uint, removePrefix func(ctx context.Context, prefix string) error, entriesPath func(uint64, uint8) string) error
}

type consumeFunc func(ctx context.Context, from uint64, entries []storage.SequencedEntry) ([]byte, error)

// New creates a new instance of the multi-tenant S3 + PostgreSQL Storage.
//
// cfg.TenantID must be non-empty; an upstream layer is expected to look up the
// tenant ID from request context (see TenantMiddleware) and pick or create the
// matching Storage.
func New(ctx context.Context, cfg Config) (tessera.Driver, error) {
	if strings.TrimSpace(cfg.TenantID) == "" {
		return nil, errors.New("Config.TenantID is required")
	}
	if cfg.Bucket == "" {
		return nil, errors.New("Config.Bucket is required")
	}
	if cfg.PGConnStr == "" {
		return nil, errors.New("Config.PGConnStr is required")
	}

	if cfg.SDKConfig == nil {
		sdkConfig, err := config.LoadDefaultConfig(ctx)
		if err != nil {
			return nil, fmt.Errorf("failed to load default AWS configuration: %v", err)
		}
		cfg.SDKConfig = &sdkConfig
		cfg.S3Options = func(_ *s3.Options) {}
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = http.DefaultClient
	}

	return &Storage{cfg: cfg}, nil
}

// Appender creates a new tessera.Appender lifecycle object for this tenant.
func (s *Storage) Appender(ctx context.Context, opts *tessera.AppendOptions) (*tessera.Appender, tessera.LogReader, error) {
	seq, err := newPGSequencer(ctx, s.cfg, uint64(opts.PushbackMaxOutstanding()), s.cfg.MaxOpenConns)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create PostgreSQL sequencer: %v", err)
	}

	s3Store := newS3Storage(&s.cfg)

	a, lr, err := s.newAppender(ctx, s3Store, seq, opts)
	if err != nil {
		return nil, nil, err
	}
	return &tessera.Appender{
		Add: a.Add,
	}, lr, nil
}

func (s *Storage) newAppender(ctx context.Context, o objStore, seq sequencer, opts *tessera.AppendOptions) (*Appender, tessera.LogReader, error) {
	if opts.CheckpointInterval() < minCheckpointInterval {
		return nil, nil, fmt.Errorf("requested CheckpointInterval (%v) is less than minimum permitted %v", opts.CheckpointInterval(), minCheckpointInterval)
	}

	logStore := &logResourceStore{
		objStore:    o,
		entriesPath: opts.EntriesPath(),
		integratedSize: func(ctx context.Context) (uint64, error) {
			s, _, err := seq.currentTree(ctx)
			return s, err
		},
		nextIndex: func(ctx context.Context) (uint64, error) {
			return seq.nextIndex(ctx)
		},
	}

	r := &Appender{
		tenantID:    s.cfg.TenantID,
		logStore:    logStore,
		sequencer:   seq,
		queue:       storage.NewQueue(ctx, opts.BatchMaxAge(), opts.BatchMaxSize(), seq.assignEntries),
		newCP:       opts.CheckpointPublisher(logStore, s.cfg.HTTPClient),
		treeUpdated: make(chan struct{}),
	}

	if err := r.init(ctx); err != nil {
		return nil, nil, fmt.Errorf("failed to initialise log storage: %v", err)
	}

	// Background goroutines outlive the construction context: derive a
	// long-lived background ctx but preserve the tenant identity and logger.
	bg := r.backgroundContext(ctx)

	go r.integrateEntriesJob(bg)
	go r.publishCheckpointJob(bg, opts.CheckpointInterval(), opts.CheckpointRepublishInterval())

	if i := opts.GarbageCollectionInterval(); i > 0 {
		go r.garbageCollectorJob(bg, i)
	}

	return r, r.logStore, nil
}

// Appender implements the Tessera appender lifecycle for a single tenant.
type Appender struct {
	tenantID string

	newCP func(context.Context, uint64, []byte) ([]byte, error)

	sequencer sequencer
	logStore  *logResourceStore

	queue *storage.Queue

	treeUpdated chan struct{}
}

// backgroundContext returns a Context suitable for long-lived goroutines: it
// is not derived from the request-scoped parent, but it inherits the tenant
// ID and per-tenant logger so downstream code keeps emitting tenant-tagged
// log lines and traces.
func (a *Appender) backgroundContext(parent context.Context) context.Context {
	bg := context.Background()
	bg = WithTenantID(bg, a.tenantID)
	if l := LoggerFromContext(parent); l != nil {
		bg = WithTenantLogger(bg, l.With(zap.String("tenant_id", a.tenantID)))
	}
	return bg
}

func (a *Appender) integrateEntriesJob(ctx context.Context) {
	t := time.NewTicker(1 * time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}

		if err := otel.TraceErr(ctx, "tessera.storage.s3psqlmt.integrateEntriesJob", tracer, func(ctx context.Context, span trace.Span) error {
			span.SetAttributes(tenantIDKey.String(a.tenantID))
			ctx, cancel := context.WithTimeout(ctx, defaultIntegrationTimeout)
			defer cancel()

			if _, err := a.sequencer.consumeEntries(ctx, DefaultIntegrationSizeLimit, a.integrateEntries, false); err != nil {
				return err
			}
			select {
			case a.treeUpdated <- struct{}{}:
			default:
			}
			return nil
		}, trace.WithAttributes(otel.PeriodicKey.Bool(true))); err != nil {
			logFromCtx(ctx).Error("integrateEntries", zap.Error(err))
		}
	}
}

func (a *Appender) publishCheckpointJob(ctx context.Context, pubInterval, republishInterval time.Duration) {
	t := time.NewTicker(pubInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-a.treeUpdated:
		case <-t.C:
		}
		if err := otel.TraceErr(ctx, "tessera.storage.s3psqlmt.publishCheckpointJob", tracer, func(ctx context.Context, span trace.Span) error {
			span.SetAttributes(tenantIDKey.String(a.tenantID))
			ctx, cancel := context.WithTimeout(ctx, defaultPublicationTimeout)
			defer cancel()

			if err := a.sequencer.publishCheckpoint(ctx, pubInterval, republishInterval, a.updateCheckpoint); err != nil {
				return fmt.Errorf("publishCheckpoint failed: %v", err)
			}
			return nil
		}, trace.WithAttributes(otel.PeriodicKey.Bool(true))); err != nil {
			logFromCtx(ctx).Error("Failed to execute checkpoint publisher job", zap.Error(err))
		}
	}
}

func (a *Appender) garbageCollectorJob(ctx context.Context, i time.Duration) {
	t := time.NewTicker(i)
	defer t.Stop()

	maxBundlesPerRun := uint(100)

	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
		if err := otel.TraceErr(ctx, "tessera.storage.s3psqlmt.garbageCollectJob", tracer, func(ctx context.Context, span trace.Span) error {
			span.SetAttributes(tenantIDKey.String(a.tenantID))
			ctx, cancel := context.WithTimeout(ctx, defaultGCTimeout)
			defer cancel()

			cp, err := a.logStore.ReadCheckpoint(ctx)
			if err != nil {
				return fmt.Errorf("failed to get published checkpoint: %v", err)
			}
			_, pubSize, _, err := parse.CheckpointUnsafe(cp)
			if err != nil {
				return fmt.Errorf("failed to parse published checkpoint: %v", err)
			}

			if err := a.sequencer.garbageCollect(ctx, pubSize, maxBundlesPerRun, a.logStore.objStore.deleteObjectsWithPrefix, a.logStore.entriesPath); err != nil {
				return fmt.Errorf("garbageCollect failed: %v", err)
			}
			return nil
		}, trace.WithAttributes(otel.PeriodicKey.Bool(true))); err != nil {
			logFromCtx(ctx).Warn("Failed to execute garbage collector job", zap.Error(err))
		}
	}
}

// Add is the entrypoint for adding entries to the tenant's log.
//
// If a tenant ID is present on the incoming context it must match this
// Appender's tenant; otherwise the call is rejected to prevent cross-tenant
// writes through a misrouted request.
func (a *Appender) Add(ctx context.Context, e *tessera.Entry) tessera.IndexFuture {
	if reqTenant, ok := TenantIDFromContext(ctx); ok && reqTenant != a.tenantID {
		return func() (tessera.Index, error) {
			return tessera.Index{}, fmt.Errorf("tenant mismatch: request tenant %q routed to appender for tenant %q", reqTenant, a.tenantID)
		}
	}
	ctx = WithTenantID(ctx, a.tenantID)
	return a.queue.Add(ctx, e)
}

// init ensures the storage represents a log in a valid state.
func (a *Appender) init(ctx context.Context) error {
	_, err := a.logStore.ReadCheckpoint(ctx)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			ctx, c := context.WithTimeout(ctx, 10*time.Second)
			defer c()
			if _, err := a.sequencer.consumeEntries(ctx, DefaultIntegrationSizeLimit, a.integrateEntries, true); err != nil {
				return fmt.Errorf("forced integrate: %v", err)
			}
			select {
			case a.treeUpdated <- struct{}{}:
			default:
			}
			return nil
		}
		return fmt.Errorf("failed to read checkpoint: %v", err)
	}
	return nil
}

func (a *Appender) updateCheckpoint(ctx context.Context, size uint64, root []byte) error {
	cpRaw, err := a.newCP(ctx, size, root)
	if err != nil {
		return fmt.Errorf("newCP: %v", err)
	}
	if err := a.logStore.setCheckpoint(ctx, cpRaw); err != nil {
		return fmt.Errorf("writeCheckpoint: %v", err)
	}
	logFromCtx(ctx).Debug("Stored latest checkpoint",
		zap.Uint64("size", size),
		zap.String("root", fmt.Sprintf("%x", root)))
	return nil
}

func (a *Appender) integrateEntries(ctx context.Context, fromSeq uint64, entries []storage.SequencedEntry) ([]byte, error) {
	var newRoot []byte

	errG := errgroup.Group{}

	errG.Go(func() error {
		if err := a.updateEntryBundles(ctx, fromSeq, entries); err != nil {
			return fmt.Errorf("updateEntryBundles: %v", err)
		}
		return nil
	})

	errG.Go(func() error {
		lh := make([][]byte, len(entries))
		for i, e := range entries {
			lh[i] = e.LeafHash
		}
		r, err := integrate(ctx, fromSeq, lh, a.logStore)
		if err != nil {
			return fmt.Errorf("integrate: %v", err)
		}
		newRoot = r
		return nil
	})

	err := errG.Wait()
	return newRoot, err
}

func (a *Appender) updateEntryBundles(ctx context.Context, fromSeq uint64, entries []storage.SequencedEntry) error {
	if len(entries) == 0 {
		return nil
	}

	bundleIndex, entriesInBundle := fromSeq/layout.EntryBundleWidth, fromSeq%layout.EntryBundleWidth
	bundleWriter := &bytes.Buffer{}
	if entriesInBundle > 0 {
		part, err := a.logStore.getEntryBundle(ctx, bundleIndex, uint8(entriesInBundle))
		if err != nil {
			return err
		}
		if _, err := bundleWriter.Write(part); err != nil {
			return fmt.Errorf("bundleWriter: %v", err)
		}
	}

	seqErr := errgroup.Group{}

	goSetEntryBundle := func(ctx context.Context, bundleIndex uint64, p uint8, bundleRaw []byte) {
		seqErr.Go(func() error {
			return a.logStore.setEntryBundle(ctx, bundleIndex, p, bundleRaw)
		})
	}

	for _, e := range entries {
		if _, err := bundleWriter.Write(e.BundleData); err != nil {
			return fmt.Errorf("bundlewriter.Write: %v", err)
		}
		entriesInBundle++
		fromSeq++
		if entriesInBundle == layout.EntryBundleWidth {
			goSetEntryBundle(ctx, bundleIndex, 0, bundleWriter.Bytes())
			bundleIndex++
			entriesInBundle = 0
			bundleWriter = &bytes.Buffer{}
		}
	}
	if entriesInBundle > 0 {
		goSetEntryBundle(ctx, bundleIndex, uint8(entriesInBundle), bundleWriter.Bytes())
	}
	return seqErr.Wait()
}

// MigrationWriter creates a new tenant-scoped storage for the MigrationWriter lifecycle.
func (s *Storage) MigrationWriter(ctx context.Context, opts *tessera.MigrationOptions) (migrate.MigrationWriter, tessera.LogReader, error) {
	s3Store := newS3Storage(&s.cfg)
	logStore := &logResourceStore{
		objStore:    s3Store,
		entriesPath: opts.EntriesPath(),
	}
	seq, err := newPGSequencer(ctx, s.cfg, DefaultPushbackMaxOutstanding, s.cfg.MaxOpenConns)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create PostgreSQL sequencer: %v", err)
	}
	m := &MigrationStorage{
		s:            s,
		pool:         seq.pool,
		tenantID:     s.cfg.TenantID,
		bundleHasher: opts.LeafHasher(),
		sequencer:    seq,
		logStore:     logStore,
	}
	return m, logStore, nil
}

// MigrationStorage implements the tessera.MigrationStorage lifecycle contract.
type MigrationStorage struct {
	s            *Storage
	pool         *pgxpool.Pool
	tenantID     string
	bundleHasher func([]byte) ([][]byte, error)
	sequencer    sequencer
	logStore     *logResourceStore
}

var _ migrate.MigrationWriter = &MigrationStorage{}

func (m *MigrationStorage) AwaitIntegration(ctx context.Context, sourceSize uint64) ([]byte, error) {
	t := time.NewTicker(time.Second)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-t.C:
			from, _, err := m.sequencer.currentTree(ctx)
			if err != nil && !errors.Is(err, os.ErrNotExist) {
				logFromCtx(ctx).Warn("readTreeState", zap.Error(err))
				continue
			}
			logFromCtx(ctx).Info("Integrating",
				zap.Uint64("from", from),
				zap.Uint64("target", sourceSize))
			newSize, newRoot, err := m.buildTree(ctx, sourceSize)
			if err != nil {
				logFromCtx(ctx).Warn("integrate", zap.Error(err))
			}
			if newSize == sourceSize {
				logFromCtx(ctx).Info("Integration complete",
					zap.Uint64("size", newSize),
					zap.String("root", fmt.Sprintf("%x", newRoot)))
				return newRoot, nil
			}
		}
	}
}

func (m *MigrationStorage) SetEntryBundle(ctx context.Context, index uint64, partial uint8, bundle []byte) error {
	return m.logStore.setEntryBundle(ctx, index, partial, bundle)
}

func (m *MigrationStorage) IntegratedSize(ctx context.Context) (uint64, error) {
	sz, _, err := m.sequencer.currentTree(ctx)
	return sz, err
}

func (m *MigrationStorage) fetchLeafHashes(ctx context.Context, from, to, sourceSize uint64) ([][]byte, error) {
	const maxBundles = 300

	toBeAdded := sync.Map{}
	eg := errgroup.Group{}
	n := 0
	for ri := range layout.Range(from, to, sourceSize) {
		ri := ri
		eg.Go(func() error {
			b, err := m.logStore.getEntryBundle(ctx, ri.Index, ri.Partial)
			if err != nil {
				return fmt.Errorf("getEntryBundle(%d.%d): %v", ri.Index, ri.Partial, err)
			}
			bh, err := m.bundleHasher(b)
			if err != nil {
				return fmt.Errorf("bundleHasherFunc for bundle index %d: %v", ri.Index, err)
			}
			toBeAdded.Store(ri.Index, bh[ri.First:ri.First+ri.N])
			return nil
		})
		n++
		if n >= maxBundles {
			break
		}
	}
	if err := eg.Wait(); err != nil {
		return nil, err
	}

	lh := make([][]byte, 0, maxBundles)
	for i := from / layout.EntryBundleWidth; ; i++ {
		v, ok := toBeAdded.LoadAndDelete(i)
		if !ok {
			break
		}
		lh = append(lh, v.([][]byte)...)
	}
	return lh, nil
}

func (m *MigrationStorage) buildTree(ctx context.Context, sourceSize uint64) (uint64, []byte, error) {
	tx, err := m.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return 0, nil, fmt.Errorf("failed to begin Tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if err := setLocalTenant(ctx, tx, m.tenantID); err != nil {
		return 0, nil, err
	}

	var from uint64
	var rootHash []byte
	if err := tx.QueryRow(ctx,
		`SELECT seq, root_hash FROM int_coord WHERE tenant_id = $1 AND id = 0 FOR UPDATE`,
		m.tenantID).Scan(&from, &rootHash); err != nil {
		return 0, nil, fmt.Errorf("failed to read int_coord: %v", err)
	}

	logFromCtx(ctx).Debug("Integrating", zap.Uint64("from", from))

	lh, err := m.fetchLeafHashes(ctx, from, sourceSize, sourceSize)
	if err != nil {
		return 0, nil, fmt.Errorf("fetchLeafHashes(%d, %d, %d): %v", from, sourceSize, sourceSize, err)
	}

	if len(lh) == 0 {
		return from, rootHash, nil
	}

	added := uint64(len(lh))
	newRoot, err := integrate(ctx, from, lh, m.logStore)
	if err != nil {
		return 0, nil, fmt.Errorf("integrate failed: %v", err)
	}
	newSize := from + added

	if _, err := tx.Exec(ctx,
		`UPDATE int_coord SET seq = $1, root_hash = $2 WHERE tenant_id = $3 AND id = 0`,
		newSize, newRoot, m.tenantID); err != nil {
		return 0, nil, fmt.Errorf("update int_coord: %v", err)
	}

	if err := tx.Commit(ctx); err != nil {
		return 0, nil, fmt.Errorf("failed to commit Tx: %v", err)
	}
	return newSize, newRoot, nil
}

// logResourceStore reads/writes log resources via a tenant-scoped objStore.
type logResourceStore struct {
	objStore       objStore
	entriesPath    func(uint64, uint8) string
	integratedSize func(context.Context) (uint64, error)
	nextIndex      func(context.Context) (uint64, error)
}

func (lr *logResourceStore) ReadCheckpoint(ctx context.Context) ([]byte, error) {
	r, err := lr.get(ctx, layout.CheckpointPath)
	if err != nil {
		var nske *types.NoSuchKey
		if errors.As(err, &nske) {
			return r, os.ErrNotExist
		}
	}
	return r, err
}

func (lr *logResourceStore) ReadTile(ctx context.Context, l, i uint64, p uint8) ([]byte, error) {
	return fetcher.PartialOrFullResource(ctx, p, func(ctx context.Context, p uint8) ([]byte, error) {
		return lr.get(ctx, layout.TilePath(l, i, p))
	})
}

func (lr *logResourceStore) ReadEntryBundle(ctx context.Context, i uint64, p uint8) ([]byte, error) {
	return fetcher.PartialOrFullResource(ctx, p, func(ctx context.Context, p uint8) ([]byte, error) {
		return lr.get(ctx, lr.entriesPath(i, p))
	})
}

func (lr *logResourceStore) IntegratedSize(ctx context.Context) (uint64, error) {
	return lr.integratedSize(ctx)
}

func (lr *logResourceStore) NextIndex(ctx context.Context) (uint64, error) {
	return lr.nextIndex(ctx)
}

func (lr *logResourceStore) get(ctx context.Context, p string) ([]byte, error) {
	return lr.objStore.getObject(ctx, p)
}

func (lr *logResourceStore) setCheckpoint(ctx context.Context, cpRaw []byte) error {
	return lr.objStore.setObject(ctx, layout.CheckpointPath, cpRaw, ckptContType, ckptCacheControl)
}

func (lr *logResourceStore) setTile(ctx context.Context, level, index, logSize uint64, tile *api.HashTile) error {
	start := time.Now()
	data, err := tile.MarshalText()
	if err != nil {
		return err
	}
	tPath := layout.TilePath(level, index, layout.PartialTileSize(level, index, logSize))
	logFromCtx(ctx).Debug("StoreTile",
		zap.String("tpath", tPath),
		zap.Int("count", len(tile.Nodes)))

	err = lr.objStore.setObjectIfNoneMatch(ctx, tPath, data, logContType, logCacheControl)
	opsHistogram.Record(ctx, time.Since(start).Milliseconds(), metric.WithAttributes(opNameKey.String("writeTile")))
	return err
}

func (lr *logResourceStore) getTiles(ctx context.Context, tileIDs []storage.TileID, logSize uint64) ([]*api.HashTile, error) {
	r := make([]*api.HashTile, len(tileIDs))
	errG := errgroup.Group{}
	for i, id := range tileIDs {
		i, id := i, id
		errG.Go(func() error {
			objName := layout.TilePath(id.Level, id.Index, layout.PartialTileSize(id.Level, id.Index, logSize))
			data, err := lr.objStore.getObject(ctx, objName)
			if err != nil {
				var nske *types.NoSuchKey
				if errors.As(err, &nske) {
					return nil
				}
				return err
			}
			t := &api.HashTile{}
			if err := t.UnmarshalText(data); err != nil {
				return fmt.Errorf("unmarshal(%q): %v", objName, err)
			}
			r[i] = t
			return nil
		})
	}
	if err := errG.Wait(); err != nil {
		return nil, err
	}
	return r, nil
}

func (lr *logResourceStore) getEntryBundle(ctx context.Context, bundleIndex uint64, p uint8) ([]byte, error) {
	objName := lr.entriesPath(bundleIndex, p)
	data, err := lr.objStore.getObject(ctx, objName)
	if err != nil {
		var nske *types.NoSuchKey
		if errors.As(err, &nske) {
			return nil, fmt.Errorf("%v: %w", objName, os.ErrNotExist)
		}
		return nil, err
	}
	return data, nil
}

func (lr *logResourceStore) setEntryBundle(ctx context.Context, bundleIndex uint64, p uint8, bundleRaw []byte) error {
	objName := lr.entriesPath(bundleIndex, p)
	if err := lr.objStore.setObjectIfNoneMatch(ctx, objName, bundleRaw, logContType, logCacheControl); err != nil {
		return fmt.Errorf("setObjectIfNoneMatch(%q): %v", objName, err)
	}
	return nil
}

func integrate(ctx context.Context, fromSeq uint64, lh [][]byte, lrs *logResourceStore) ([]byte, error) {
	getTiles := func(ctx context.Context, tileIDs []storage.TileID, treeSize uint64) ([]*api.HashTile, error) {
		n, err := lrs.getTiles(ctx, tileIDs, treeSize)
		if err != nil {
			return nil, fmt.Errorf("getTiles: %w", err)
		}
		return n, nil
	}

	newSize, newRoot, tiles, err := storage.Integrate(ctx, getTiles, fromSeq, lh)
	if err != nil {
		return nil, fmt.Errorf("tessera.Integrate: %v", err)
	}
	errG := errgroup.Group{}
	for k, v := range tiles {
		k, v := k, v
		errG.Go(func() error {
			return lrs.setTile(ctx, uint64(k.Level), k.Index, newSize, v)
		})
	}
	if err := errG.Wait(); err != nil {
		return nil, err
	}
	logFromCtx(ctx).Debug("New tree",
		zap.Uint64("size", newSize),
		zap.String("root", fmt.Sprintf("%x", newRoot)))
	return newRoot, nil
}

// pgSequencer uses PostgreSQL to provide a durable, multi-process-safe,
// tenant-scoped sequencer.
type pgSequencer struct {
	pool           *pgxpool.Pool
	tenantID       string
	maxOutstanding uint64
}

// Transactions in this file use READ COMMITTED isolation (pgx.TxOptions{}).
//
// Correctness rationale: every read-modify-write cycle on a coordination row
// (SeqCoord, IntCoord, PubCoord, GCCoord) acquires the row with SELECT ...
// FOR UPDATE before reading. This row-level lock serializes concurrent writers
// independent of the surrounding isolation level. Pure informational reads
// (where the caller does not act on the result within the same transaction)
// are safe under RC because they do not participate in any consistency
// invariant.
//
// Why not REPEATABLE READ: PostgreSQL's RR uses MVCC snapshots, which under
// concurrent updates surface as serialization failures (SQLSTATE 40001) that
// require explicit retry logic. RR provides no additional correctness here
// because our serialization comes from explicit FOR UPDATE, so we keep RC and
// avoid the retry complexity.
//
// When extending this file: any new query that reads a coord row and acts on
// the result within the same transaction MUST use FOR UPDATE. Pure reads are
// fine without it.

func newPGSequencer(ctx context.Context, cfg Config, maxOutstanding uint64, maxOpenConns int) (*pgSequencer, error) {
	poolCfg, err := pgxpool.ParseConfig(cfg.PGConnStr)
	if err != nil {
		return nil, fmt.Errorf("invalid PostgreSQL config: %v", err)
	}
	if maxOpenConns > 0 {
		poolCfg.MaxConns = int32(maxOpenConns)
	}

	// Tenant pinning is done exclusively via transaction-local set_config in
	// setLocalTenant. We deliberately do NOT pin app.tenant_id at the session
	// level (e.g. via SET app.tenant_id without LOCAL).
	//
	// Why: under transaction-pooling proxies like pgbouncer (transaction mode)
	// or RDS Proxy (multiplexing), the physical connection backing a logical
	// session is rotated between transactions. A session-scoped GUC would
	// persist on the rotated connection, so tenant A's previous transaction
	// could leave app.tenant_id = 'tenant-a' active when tenant B's next
	// transaction reuses that connection. RLS policies would then read
	// tenant A's data into tenant B's request — silent cross-tenant leakage.
	//
	// Transaction-local set_config (third arg = true) is automatically reset
	// at commit/rollback, eliminating this risk. If a future caller forgets
	// to invoke setLocalTenant at the start of a transaction, RLS policies
	// see an empty app.tenant_id and return zero rows, surfacing the bug as
	// missing-data rather than silent leakage.
	//
	// When extending this file: every transaction that touches RLS-protected
	// tables MUST call setLocalTenant before any query. Do not introduce
	// session-scoped tenant context.

	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to PostgreSQL: %v", err)
	}
	if err := pool.Ping(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to ping PostgreSQL: %v", err)
	}

	r := &pgSequencer{
		pool:           pool,
		tenantID:       cfg.TenantID,
		maxOutstanding: maxOutstanding,
	}

	if err := r.initDB(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("failed to initDB: %v", err)
	}
	if err := r.checkDataCompatibility(ctx); err != nil {
		pool.Close()
		return nil, fmt.Errorf("schema is not compatible with this version: %v", err)
	}
	return r, nil
}

// setLocalTenant pins the session-local tenant so that RLS policies can
// resolve current_setting('app.tenant_id') for the lifetime of the
// transaction. Must be called immediately after BEGIN.
func setLocalTenant(ctx context.Context, tx pgx.Tx, tenantID string) error {
	if _, err := tx.Exec(ctx, `SELECT set_config('app.tenant_id', $1, true)`, tenantID); err != nil {
		return fmt.Errorf("failed to set local tenant: %v", err)
	}
	return nil
}

func (s *pgSequencer) checkDataCompatibility(ctx context.Context) error {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return fmt.Errorf("failed to begin Tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := setLocalTenant(ctx, tx, s.tenantID); err != nil {
		return err
	}
	var gotVersion uint64
	if err := tx.QueryRow(ctx,
		`SELECT compatibility_version FROM tessera WHERE tenant_id = $1 AND id = 0`,
		s.tenantID).Scan(&gotVersion); err != nil {
		return fmt.Errorf("failed to read schema compatibility version: %v", err)
	}
	if gotVersion != SchemaCompatibilityVersion {
		return fmt.Errorf("schema compatibility_version (%d) != library compatibility_version (%d)", gotVersion, SchemaCompatibilityVersion)
	}
	return nil
}

// initDB ensures the coordination DB is initialised correctly for this tenant.
//
// Tables are created if absent, RLS is enabled and policies that key on
// current_setting('app.tenant_id') are installed. The per-tenant default
// rows (initial sequence number, empty-tree root, etc.) are inserted if
// missing. All DDL is idempotent.
func (s *pgSequencer) initDB(ctx context.Context) error {
	emptyRoot := rfc6962.DefaultHasher.EmptyRoot()

	ddl := []string{
		`CREATE TABLE IF NOT EXISTS tessera (
			tenant_id TEXT NOT NULL,
			id INTEGER NOT NULL,
			compatibility_version BIGINT NOT NULL,
			PRIMARY KEY (tenant_id, id)
		)`,
		`CREATE TABLE IF NOT EXISTS seq_coord (
			tenant_id TEXT NOT NULL,
			id INTEGER NOT NULL,
			next BIGINT NOT NULL,
			PRIMARY KEY (tenant_id, id)
		)`,
		`CREATE TABLE IF NOT EXISTS seq (
			tenant_id TEXT NOT NULL,
			id INTEGER NOT NULL,
			seq BIGINT NOT NULL,
			v BYTEA,
			PRIMARY KEY (tenant_id, id, seq)
		)`,
		`CREATE TABLE IF NOT EXISTS int_coord (
			tenant_id TEXT NOT NULL,
			id INTEGER NOT NULL,
			seq BIGINT NOT NULL,
			root_hash BYTEA NOT NULL,
			PRIMARY KEY (tenant_id, id)
		)`,
		`CREATE TABLE IF NOT EXISTS pub_coord (
			tenant_id TEXT NOT NULL,
			id INTEGER NOT NULL,
			published_at BIGINT NOT NULL,
			size BIGINT,
			PRIMARY KEY (tenant_id, id)
		)`,
		`CREATE TABLE IF NOT EXISTS gc_coord (
			tenant_id TEXT NOT NULL,
			id INTEGER NOT NULL,
			from_size BIGINT NOT NULL,
			PRIMARY KEY (tenant_id, id)
		)`,
	}
	for _, q := range ddl {
		if _, err := s.pool.Exec(ctx, q); err != nil {
			return fmt.Errorf("ddl: %v", err)
		}
	}

	// Enable RLS and install policies. Drop+create makes the policy
	// definition itself idempotent across deploys.
	rlsTables := []string{"tessera", "seq_coord", "seq", "int_coord", "pub_coord", "gc_coord"}
	for _, t := range rlsTables {
		if _, err := s.pool.Exec(ctx, fmt.Sprintf(`ALTER TABLE %s ENABLE ROW LEVEL SECURITY`, t)); err != nil {
			return fmt.Errorf("enable RLS on %s: %v", t, err)
		}
		// FORCE so even table owners are subject to RLS.
		if _, err := s.pool.Exec(ctx, fmt.Sprintf(`ALTER TABLE %s FORCE ROW LEVEL SECURITY`, t)); err != nil {
			return fmt.Errorf("force RLS on %s: %v", t, err)
		}
		policy := t + "_tenant_isolation"
		if _, err := s.pool.Exec(ctx, fmt.Sprintf(`DROP POLICY IF EXISTS %s ON %s`, policy, t)); err != nil {
			return fmt.Errorf("drop policy on %s: %v", t, err)
		}
		if _, err := s.pool.Exec(ctx, fmt.Sprintf(
			`CREATE POLICY %s ON %s
				USING (tenant_id = current_setting('app.tenant_id', true))
				WITH CHECK (tenant_id = current_setting('app.tenant_id', true))`,
			policy, t)); err != nil {
			return fmt.Errorf("create policy on %s: %v", t, err)
		}
	}

	// Seed per-tenant default rows in a transaction so RLS sees the
	// configured tenant_id during the inserts.
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("begin seed tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := setLocalTenant(ctx, tx, s.tenantID); err != nil {
		return err
	}

	seedQueries := []struct {
		q    string
		args []any
	}{
		{`INSERT INTO tessera (tenant_id, id, compatibility_version) VALUES ($1, 0, $2) ON CONFLICT DO NOTHING`,
			[]any{s.tenantID, SchemaCompatibilityVersion}},
		{`INSERT INTO seq_coord (tenant_id, id, next) VALUES ($1, 0, 0) ON CONFLICT DO NOTHING`,
			[]any{s.tenantID}},
		{`INSERT INTO int_coord (tenant_id, id, seq, root_hash) VALUES ($1, 0, 0, $2) ON CONFLICT DO NOTHING`,
			[]any{s.tenantID, emptyRoot}},
		{`INSERT INTO pub_coord (tenant_id, id, published_at, size) VALUES ($1, 0, 0, 0) ON CONFLICT DO NOTHING`,
			[]any{s.tenantID}},
		{`INSERT INTO gc_coord (tenant_id, id, from_size) VALUES ($1, 0, 0) ON CONFLICT DO NOTHING`,
			[]any{s.tenantID}},
	}
	for _, sq := range seedQueries {
		if _, err := tx.Exec(ctx, sq.q, sq.args...); err != nil {
			return fmt.Errorf("seed: %v", err)
		}
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit seed tx: %v", err)
	}
	return nil
}

// assignEntries durably assigns each entry an index in the log.
func (s *pgSequencer) assignEntries(ctx context.Context, entries []*tessera.Entry) error {
	return otel.TraceErr(ctx, "tessera.storage.s3psqlmt.assignEntries", tracer, func(ctx context.Context, span trace.Span) error {
		span.SetAttributes(numEntriesKey.Int(len(entries)), tenantIDKey.String(s.tenantID))

		tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
		if err != nil {
			return fmt.Errorf("failed to begin Tx: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if err := setLocalTenant(ctx, tx, s.tenantID); err != nil {
			return err
		}

		// Snapshot the integrated tree size for back-pressure decisions.
		// Read inside the tx so the tx-local app.tenant_id GUC is in effect
		// — required for RLS visibility under transaction-pooling proxies.
		var treeSize uint64
		err = tx.QueryRow(ctx,
			`SELECT seq FROM int_coord WHERE tenant_id = $1 AND id = 0`,
			s.tenantID).Scan(&treeSize)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil
		} else if err != nil {
			return fmt.Errorf("failed to read int_coord: %v", err)
		}

		var next uint64
		if err := tx.QueryRow(ctx,
			`SELECT next FROM seq_coord WHERE tenant_id = $1 AND id = 0 FOR UPDATE`,
			s.tenantID).Scan(&next); err != nil {
			return fmt.Errorf("failed to read seq_coord: %v", err)
		}

		if outstanding := next - treeSize; outstanding > s.maxOutstanding {
			return tessera.ErrPushbackIntegration
		}

		sequencedEntries := make([]storage.SequencedEntry, len(entries))
		for i, e := range entries {
			sequencedEntries[i] = storage.SequencedEntry{
				BundleData: e.MarshalBundleData(next + uint64(i)),
				LeafHash:   e.LeafHash(),
			}
		}

		b := &bytes.Buffer{}
		if err := gob.NewEncoder(b).Encode(sequencedEntries); err != nil {
			return fmt.Errorf("failed to serialise batch: %v", err)
		}
		num := uint64(len(entries))

		if _, err := tx.Exec(ctx,
			`INSERT INTO seq (tenant_id, id, seq, v) VALUES ($1, 0, $2, $3)`,
			s.tenantID, next, b.Bytes()); err != nil {
			return fmt.Errorf("insert into seq: %v", err)
		}
		if _, err := tx.Exec(ctx,
			`UPDATE seq_coord SET next = $1 WHERE tenant_id = $2 AND id = 0`,
			next+num, s.tenantID); err != nil {
			return fmt.Errorf("update seq_coord: %v", err)
		}
		if err := tx.Commit(ctx); err != nil {
			return fmt.Errorf("failed to commit Tx: %v", err)
		}
		return nil
	}, trace.WithAttributes(otel.PeriodicKey.Bool(true)))
}

// consumeEntries calls f with previously sequenced entries and removes them on success.
func (s *pgSequencer) consumeEntries(ctx context.Context, limit uint64, f consumeFunc, forceUpdate bool) (bool, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to begin Tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := setLocalTenant(ctx, tx, s.tenantID); err != nil {
		return false, err
	}

	var fromSeq uint64
	var rootHash []byte
	err = tx.QueryRow(ctx,
		`SELECT seq, root_hash FROM int_coord WHERE tenant_id = $1 AND id = 0 FOR UPDATE`,
		s.tenantID).Scan(&fromSeq, &rootHash)
	if errors.Is(err, pgx.ErrNoRows) {
		return false, nil
	} else if err != nil {
		return false, fmt.Errorf("failed to read int_coord: %v", err)
	}
	logFromCtx(ctx).Debug("Consuming", zap.Uint64("fromseq", fromSeq))

	rows, err := tx.Query(ctx,
		`SELECT seq, v FROM seq WHERE tenant_id = $1 AND id = 0 AND seq >= $2 ORDER BY seq LIMIT $3 FOR UPDATE`,
		s.tenantID, fromSeq, limit)
	if err != nil {
		return false, fmt.Errorf("failed to read seq: %v", err)
	}

	seqsConsumed := []int64{}
	entries := make([]storage.SequencedEntry, 0, limit)
	orderCheck := fromSeq
	for rows.Next() {
		var vGob []byte
		var seq int64
		if err := rows.Scan(&seq, &vGob); err != nil {
			rows.Close()
			return false, fmt.Errorf("failed to scan seq row: %v", err)
		}
		if orderCheck != uint64(seq) {
			rows.Close()
			return false, fmt.Errorf("integrity fail - expected seq %d, but found %d", orderCheck, seq)
		}
		b := []storage.SequencedEntry{}
		if err := gob.NewDecoder(bytes.NewReader(vGob)).Decode(&b); err != nil {
			rows.Close()
			return false, fmt.Errorf("failed to deserialise v from seq: %v", err)
		}
		entries = append(entries, b...)
		seqsConsumed = append(seqsConsumed, seq)
		orderCheck += uint64(len(b))
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return false, fmt.Errorf("rows iteration: %v", err)
	}

	if len(seqsConsumed) == 0 && !forceUpdate {
		return false, nil
	}

	newRoot, err := f(ctx, fromSeq, entries)
	if err != nil {
		return false, err
	}

	if _, err := tx.Exec(ctx,
		`UPDATE int_coord SET seq = $1, root_hash = $2 WHERE tenant_id = $3 AND id = 0`,
		orderCheck, newRoot, s.tenantID); err != nil {
		return false, fmt.Errorf("update int_coord: %v", err)
	}

	if len(seqsConsumed) > 0 {
		if _, err := tx.Exec(ctx,
			`DELETE FROM seq WHERE tenant_id = $1 AND id = 0 AND seq = ANY($2::bigint[])`,
			s.tenantID, seqsConsumed); err != nil {
			return false, fmt.Errorf("delete from seq: %v", err)
		}
	}

	if err := tx.Commit(ctx); err != nil {
		return false, fmt.Errorf("failed to commit Tx: %v", err)
	}
	return true, nil
}

func (s *pgSequencer) currentTree(ctx context.Context) (uint64, []byte, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return 0, nil, fmt.Errorf("failed to begin Tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := setLocalTenant(ctx, tx, s.tenantID); err != nil {
		return 0, nil, err
	}
	var fromSeq uint64
	var rootHash []byte
	if err := tx.QueryRow(ctx,
		`SELECT seq, root_hash FROM int_coord WHERE tenant_id = $1 AND id = 0`,
		s.tenantID).Scan(&fromSeq, &rootHash); err != nil {
		return 0, nil, fmt.Errorf("failed to read int_coord: %v", err)
	}
	return fromSeq, rootHash, nil
}

func (s *pgSequencer) nextIndex(ctx context.Context) (uint64, error) {
	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return 0, fmt.Errorf("failed to begin Tx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := setLocalTenant(ctx, tx, s.tenantID); err != nil {
		return 0, err
	}
	var nextSeq uint64
	if err := tx.QueryRow(ctx,
		`SELECT next FROM seq_coord WHERE tenant_id = $1 AND id = 0`,
		s.tenantID).Scan(&nextSeq); err != nil {
		return 0, fmt.Errorf("failed to read DB: %v", err)
	}
	return nextSeq, nil
}

// publishCheckpoint serialises publish attempts via FOR UPDATE on pub_coord
// and only invokes f if either the tree has grown since the last publish or
// minStaleRepub has elapsed.
func (s *pgSequencer) publishCheckpoint(ctx context.Context, minStaleActive, minStaleRepub time.Duration, f func(context.Context, uint64, []byte) error) (errR error) {
	start := time.Now()
	defer func() {
		if errR != nil {
			publishCount.Add(ctx, 1, metric.WithAttributes(errorTypeKey.String("error"), tenantIDKey.String(s.tenantID)))
		}
	}()

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := setLocalTenant(ctx, tx, s.tenantID); err != nil {
		return err
	}

	var pubAt int64
	var lastSize *int64
	if err := tx.QueryRow(ctx,
		`SELECT published_at, size FROM pub_coord WHERE tenant_id = $1 AND id = 0 FOR UPDATE`,
		s.tenantID).Scan(&pubAt, &lastSize); err != nil {
		return fmt.Errorf("failed to read pub_coord: %v", err)
	}
	cpAge := time.Since(time.Unix(pubAt, 0))
	if cpAge < minStaleActive {
		publishCount.Add(ctx, 1, metric.WithAttributes(errorTypeKey.String("skipped"), tenantIDKey.String(s.tenantID)))
		return nil
	}

	var fromSeq uint64
	var rootHash []byte
	if err := tx.QueryRow(ctx,
		`SELECT seq, root_hash FROM int_coord WHERE tenant_id = $1 AND id = 0`,
		s.tenantID).Scan(&fromSeq, &rootHash); err != nil {
		return fmt.Errorf("failed to read int_coord: %v", err)
	}

	currentSize := fromSeq
	shouldPublish := minStaleRepub > 0 && cpAge >= minStaleRepub
	if !shouldPublish {
		if lastSize == nil || currentSize > uint64(*lastSize) {
			shouldPublish = true
		}
	}
	if !shouldPublish {
		publishCount.Add(ctx, 1, metric.WithAttributes(errorTypeKey.String("skipped_no_growth"), tenantIDKey.String(s.tenantID)))
		return nil
	}

	if err := f(ctx, fromSeq, rootHash); err != nil {
		return err
	}

	if _, err := tx.Exec(ctx,
		`UPDATE pub_coord SET published_at = $1, size = $2 WHERE tenant_id = $3 AND id = 0`,
		time.Now().Unix(), int64(currentSize), s.tenantID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	opsHistogram.Record(ctx, time.Since(start).Milliseconds(), metric.WithAttributes(opNameKey.String("publishCheckpoint"), tenantIDKey.String(s.tenantID)))
	publishCount.Add(ctx, 1, metric.WithAttributes(tenantIDKey.String(s.tenantID)))
	return nil
}

// garbageCollect identifies up to maxBundles unneeded partial entry bundles
// (and their parent partial tiles) and removes them.
func (s *pgSequencer) garbageCollect(ctx context.Context, treeSize uint64, maxBundles uint, deleteWithPrefix func(ctx context.Context, prefix string) error, entriesPath func(uint64, uint8) string) error {
	const numWorkers = 5

	tx, err := s.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := setLocalTenant(ctx, tx, s.tenantID); err != nil {
		return err
	}

	var fromSize uint64
	if err := tx.QueryRow(ctx,
		`SELECT from_size FROM gc_coord WHERE tenant_id = $1 AND id = 0 FOR UPDATE`,
		s.tenantID).Scan(&fromSize); err != nil {
		return fmt.Errorf("failed to read gc_coord: %v", err)
	}

	if fromSize == treeSize {
		return nil
	}

	d := uint(0)
	work := make(chan string, maxBundles*3)

	eg := errgroup.Group{}
	eg.Go(func() error {
		for ri := range layout.Range(fromSize, treeSize-fromSize, treeSize) {
			if ri.Partial > 0 || d > maxBundles {
				break
			}
			work <- entriesPath(ri.Index, 0) + ".p/"
			work <- layout.TilePath(0, ri.Index, 0) + ".p/"
			fromSize += uint64(ri.N)
			d++

			pL, pIdx := uint64(0), ri.Index
			for isLastLeafInParent(pIdx) {
				pL, pIdx = pL+1, pIdx>>layout.TileHeight
				work <- layout.TilePath(pL, pIdx, 0) + ".p/"
			}
		}
		close(work)
		return nil
	})
	for range numWorkers {
		eg.Go(func() error {
			errs := []error{}
			for prefix := range work {
				if err := deleteWithPrefix(ctx, prefix); err != nil {
					errs = append(errs, err)
				}
			}
			return errors.Join(errs...)
		})
	}
	if err := eg.Wait(); err != nil {
		return fmt.Errorf("failed to delete one or more objects: %v", err)
	}

	if _, err := tx.Exec(ctx,
		`UPDATE gc_coord SET from_size = $1 WHERE tenant_id = $2 AND id = 0`,
		fromSize, s.tenantID); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

func isLastLeafInParent(i uint64) bool {
	return i%layout.TileWidth == layout.TileWidth-1
}

// s3Storage is a tenant-scoped S3 object store. Every key is prefixed with
// "<BucketPrefix?>/tenants/<TenantID>/" before hitting S3.
type s3Storage struct {
	bucket       string
	bucketPrefix string
	tenantID     string
	s3Client     *s3.Client
}

func newS3Storage(cfg *Config) *s3Storage {
	return &s3Storage{
		bucket:       cfg.Bucket,
		bucketPrefix: cfg.BucketPrefix,
		tenantID:     cfg.TenantID,
		s3Client:     s3.NewFromConfig(*cfg.SDKConfig, cfg.S3Options),
	}
}

// resolve produces the physical S3 key for a logical object name, applying
// the optional bucket prefix and the per-tenant prefix.
func (s *s3Storage) resolve(obj string) string {
	parts := []string{}
	if s.bucketPrefix != "" {
		parts = append(parts, s.bucketPrefix)
	}
	parts = append(parts, tenantPrefix, s.tenantID, obj)
	return path.Join(parts...)
}

func (s *s3Storage) getObject(ctx context.Context, obj string) ([]byte, error) {
	key := s.resolve(obj)
	r, err := s.s3Client.GetObject(ctx, &s3.GetObjectInput{
		Bucket: aws.String(s.bucket),
		Key:    aws.String(key),
	})
	if err != nil {
		return nil, fmt.Errorf("getObject: failed to create reader for object %q in bucket %q: %w", key, s.bucket, err)
	}
	d, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, fmt.Errorf("getObject: failed to read %q: %v", key, err)
	}
	return d, r.Body.Close()
}

func (s *s3Storage) setObject(ctx context.Context, objName string, data []byte, contType string, cacheControl string) error {
	key := s.resolve(objName)
	put := &s3.PutObjectInput{
		Bucket:       aws.String(s.bucket),
		Key:          aws.String(key),
		Body:         bytes.NewReader(data),
		ContentType:  aws.String(contType),
		CacheControl: aws.String(cacheControl),
	}
	if _, err := s.s3Client.PutObject(ctx, put); err != nil {
		return fmt.Errorf("failed to write object %q to bucket %q: %w", key, s.bucket, err)
	}
	return nil
}

// setObjectIfNoneMatch idempotently writes data, returning successfully if
// an object with identical bytes already exists at the same key.
func (s *s3Storage) setObjectIfNoneMatch(ctx context.Context, objName string, data []byte, contType string, cacheControl string) error {
	key := s.resolve(objName)
	put := &s3.PutObjectInput{
		Bucket:       aws.String(s.bucket),
		Key:          aws.String(key),
		Body:         bytes.NewReader(data),
		ContentType:  aws.String(contType),
		CacheControl: aws.String(cacheControl),
		IfNoneMatch:  aws.String("*"),
	}

	if _, err := s.s3Client.PutObject(ctx, put); err != nil {
		var apiErr smithy.APIError
		if errors.As(err, &apiErr) && apiErr.ErrorCode() == "PreconditionFailed" {
			existing, gerr := s.getObject(ctx, objName)
			if gerr != nil {
				return fmt.Errorf("failed to fetch existing content for %q: %v", key, gerr)
			}
			if !bytes.Equal(existing, data) {
				logFromCtx(ctx).Error("Resource non-idempotent write",
					zap.String("objname", key),
					zap.String("diff", cmp.Diff(existing, data)))
				return fmt.Errorf("precondition failed: resource content for %q differs from data to-be-written", key)
			}
			return nil
		}
		return fmt.Errorf("failed to write object %q to bucket %q: %w", key, s.bucket, err)
	}
	return nil
}

func (s *s3Storage) deleteObjectsWithPrefix(ctx context.Context, objPrefix string) error {
	return otel.TraceErr(ctx, "tessera.storage.s3psqlmt.deleteObject", tracer, func(ctx context.Context, span trace.Span) error {
		fullPrefix := s.resolve(objPrefix)
		span.SetAttributes(objectPathKey.String(fullPrefix), tenantIDKey.String(s.tenantID))

		l, err := s.s3Client.ListObjectsV2(ctx, &s3.ListObjectsV2Input{
			Bucket: aws.String(s.bucket),
			Prefix: aws.String(fullPrefix),
		})
		if err != nil {
			return fmt.Errorf("failed to list objects with prefix %q: %v", fullPrefix, err)
		}
		if len(l.Contents) == 0 {
			return nil
		}
		di := &s3.DeleteObjectsInput{
			Bucket: aws.String(s.bucket),
			Delete: &types.Delete{
				Objects: make([]types.ObjectIdentifier, 0, len(l.Contents)),
			},
		}
		for _, k := range l.Contents {
			di.Delete.Objects = append(di.Delete.Objects, types.ObjectIdentifier{Key: k.Key})
		}
		if _, err := s.s3Client.DeleteObjects(ctx, di); err != nil {
			return fmt.Errorf("failed to delete objects: %v", err)
		}
		return nil
	})
}

// logFromCtx returns the per-tenant zap logger from context, or a no-op logger.
func logFromCtx(ctx context.Context) *zap.Logger {
	if l := LoggerFromContext(ctx); l != nil {
		return l
	}
	return zap.NewNop()
}
