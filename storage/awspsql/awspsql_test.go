// Copyright 2026 The Rekor authors. All Rights Reserved.
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

// Tests for the multi-tenant S3 + PostgreSQL Tessera backend.
//
// PG-dependent tests require a running PostgreSQL reachable at the URI
// provided by -pg_uri. They are skipped automatically when -is_pg_test_optional
// is true (default) and the DB is unreachable. Run with -parallel=1 since
// mustDropTables wipes shared coordination tables.
//
// Sample command to start a local PostgreSQL using Docker:
//
//	docker run --name test-psql -p 5432:5432 -e POSTGRES_PASSWORD=postgres \
//	    -e POSTGRES_DB=test_tessera -d postgres:16

package awspsql

import (
	"bytes"
	"context"
	"crypto/sha256"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/google/go-cmp/cmp"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/transparency-dev/merkle/rfc6962"
	"github.com/transparency-dev/tessera"
	"github.com/transparency-dev/tessera/api"
	"github.com/transparency-dev/tessera/api/layout"
	"github.com/transparency-dev/tessera/fsck"
	"github.com/transparency-dev/tessera/internal/parse"
	storage "github.com/transparency-dev/tessera/storage/internal"
	"go.uber.org/zap"
	"golang.org/x/mod/sumdb/note"
)

var (
	pgURI            = flag.String("pg_uri", "postgres://postgres:postgres@localhost:6432/test_tessera?sslmode=disable", "Connection string for a PostgreSQL test database")
	isPGTestOptional = flag.Bool("is_pg_test_optional", true, "If true and PG is unreachable, PG-dependent tests are skipped instead of failing")
)

func TestMain(m *testing.M) {
	flag.Parse()
	// If -pg_uri is reachable AND connects as a superuser, bootstrap a
	// non-super tessera_test role and rewrite -pg_uri to use it. This
	// makes RLS-enforcement tests actually validate behaviour against an
	// off-the-shelf Postgres container (which by default exposes only the
	// `postgres` superuser).
	if uri, ok := upgradeToNonSuperURI(); ok {
		*pgURI = uri
	}
	os.Exit(m.Run())
}

// upgradeToNonSuperURI ensures tests run under a role that is subject to
// RLS. If -pg_uri already points at a non-super role, returns ("", false)
// and the URI is left alone. If it points at a superuser, this creates
// the `tessera_test` role (idempotently), grants it the privileges it
// needs to recreate the schema, drops any tables that the superuser may
// have left behind from a previous run (so the new role owns the next
// CREATE TABLE), and returns a URI for the new role.
//
// Failures are silent: on any error we return ("", false) and let the
// individual tests skip via canSkipPGTest / skipIfRLSBypassed.
func upgradeToNonSuperURI() (string, bool) {
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, *pgURI)
	if err != nil {
		return "", false
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return "", false
	}

	var isSuper bool
	if err := pool.QueryRow(ctx,
		`SELECT rolsuper FROM pg_roles WHERE rolname = current_user`).Scan(&isSuper); err != nil {
		return "", false
	}
	if !isSuper {
		return "", false
	}

	const role = "tessera_test"
	const pwd = "tessera_test"

	bootstrap := []string{
		fmt.Sprintf(`DO $$ BEGIN
			IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '%s') THEN
				CREATE ROLE %s LOGIN PASSWORD '%s' NOSUPERUSER NOBYPASSRLS;
			END IF;
		END $$`, role, role, pwd),
		fmt.Sprintf(`GRANT ALL ON SCHEMA public TO %s`, role),
		// Drop tables left over from a previous superuser-owned run so
		// the next CREATE TABLE makes tessera_test the owner; otherwise
		// ALTER TABLE ... ENABLE ROW LEVEL SECURITY would fail.
		`DROP TABLE IF EXISTS tessera, seq_coord, seq, int_coord, pub_coord, gc_coord CASCADE`,
	}
	for _, q := range bootstrap {
		if _, err := pool.Exec(ctx, q); err != nil {
			return "", false
		}
	}

	newURI, err := rewriteURIRole(*pgURI, role, pwd)
	if err != nil {
		return "", false
	}
	return newURI, true
}

// rewriteURIRole returns uri with its userinfo replaced by user:pwd.
// Only handles URL-style connection strings; libpq key=value form is
// returned unchanged (caller treats that as failure).
func rewriteURIRole(uri, user, pwd string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", err
	}
	if u.Scheme != "postgres" && u.Scheme != "postgresql" {
		return "", fmt.Errorf("not a URL-style connection string: %q", uri)
	}
	u.User = url.UserPassword(user, pwd)
	return u.String(), nil
}

// canSkipPGTest returns true when the PG test DB is unreachable and
// -is_pg_test_optional is set. Otherwise it fails the test.
func canSkipPGTest(t *testing.T, ctx context.Context) bool {
	t.Helper()
	pool, err := pgxpool.New(ctx, *pgURI)
	if err != nil {
		if *isPGTestOptional {
			return true
		}
		t.Fatalf("failed to open PG test db: %v", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		if *isPGTestOptional {
			return true
		}
		t.Fatalf("failed to ping PG test db: %v", err)
	}
	return false
}

// skipIfRLSBypassed skips the test when the connected role bypasses RLS
// (superuser or BYPASSRLS). Such roles silently ignore the row-level
// security policies, so any test that asserts RLS behaviour would either
// false-pass or false-fail.
//
// To run the RLS-enforcement tests, point -pg_uri at a non-superuser role
// without the BYPASSRLS attribute that has been granted SELECT/INSERT/etc.
// on the coordination tables.
func skipIfRLSBypassed(t *testing.T, ctx context.Context) {
	t.Helper()
	pool, err := pgxpool.New(ctx, *pgURI)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	var isSuper, byPass bool
	if err := pool.QueryRow(ctx,
		`SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user`).
		Scan(&isSuper, &byPass); err != nil {
		t.Fatalf("check role: %v", err)
	}
	if isSuper || byPass {
		t.Skipf("connected role bypasses RLS (rolsuper=%v, rolbypassrls=%v); RLS-enforcement tests require a restricted role", isSuper, byPass)
	}
}

// mustDropTables removes every coordination table. Call before each PG test.
func mustDropTables(t *testing.T, ctx context.Context) {
	t.Helper()
	pool, err := pgxpool.New(ctx, *pgURI)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx,
		`DROP TABLE IF EXISTS tessera, seq_coord, seq, int_coord, pub_coord, gc_coord CASCADE`); err != nil {
		t.Fatalf("drop tables: %v", err)
	}
}

func mustNewSequencer(t *testing.T, ctx context.Context, tenantID string) *pgSequencer {
	t.Helper()
	cfg := Config{
		TenantID:  tenantID,
		Bucket:    "test",
		PGConnStr: *pgURI,
	}
	s, err := newPGSequencer(ctx, cfg, DefaultPushbackMaxOutstanding, 0)
	if err != nil {
		t.Fatalf("newPGSequencer(%q): %v", tenantID, err)
	}
	t.Cleanup(func() { s.pool.Close() })
	return s
}

// ---------------------------------------------------------------------------
// Constructor validation (no DB).
// ---------------------------------------------------------------------------

func TestNewRequiresTenantID(t *testing.T) {
	for _, id := range []string{"", "   ", "\t"} {
		if _, err := New(context.Background(), Config{TenantID: id, Bucket: "b", PGConnStr: "x"}); err == nil ||
			!strings.Contains(err.Error(), "TenantID") {
			t.Errorf("New with TenantID=%q: got err=%v, want TenantID-required", id, err)
		}
	}
}

func TestNewRequiresBucket(t *testing.T) {
	if _, err := New(context.Background(), Config{TenantID: "t", PGConnStr: "x"}); err == nil ||
		!strings.Contains(err.Error(), "Bucket") {
		t.Fatalf("got %v, want Bucket-required", err)
	}
}

func TestNewRequiresPGConnStr(t *testing.T) {
	if _, err := New(context.Background(), Config{TenantID: "t", Bucket: "b"}); err == nil ||
		!strings.Contains(err.Error(), "PGConnStr") {
		t.Fatalf("got %v, want PGConnStr-required", err)
	}
}

// ---------------------------------------------------------------------------
// Tenant context propagation (no DB).
// ---------------------------------------------------------------------------

func TestTenantIDContextRoundTrip(t *testing.T) {
	ctx := WithTenantID(context.Background(), "alpha")
	got, ok := TenantIDFromContext(ctx)
	if !ok || got != "alpha" {
		t.Fatalf("TenantIDFromContext = (%q,%v); want (alpha,true)", got, ok)
	}
}

func TestTenantIDFromContextEmpty(t *testing.T) {
	if id, ok := TenantIDFromContext(context.Background()); ok || id != "" {
		t.Fatalf("TenantIDFromContext on bare ctx = (%q,%v); want (\"\",false)", id, ok)
	}
}

func TestTenantLoggerContextRoundTrip(t *testing.T) {
	logger := zap.NewNop()
	ctx := WithTenantLogger(context.Background(), logger)
	if got := LoggerFromContext(ctx); got != logger {
		t.Fatalf("LoggerFromContext returned different pointer")
	}
	if got := LoggerFromContext(context.Background()); got != nil {
		t.Fatalf("LoggerFromContext on bare ctx = %v; want nil", got)
	}
}

// ---------------------------------------------------------------------------
// S3 key resolution (no DB, no S3): exercises the per-tenant prefix logic.
// ---------------------------------------------------------------------------

func TestS3StorageResolveKey(t *testing.T) {
	for _, tc := range []struct {
		name         string
		bucketPrefix string
		tenantID     string
		obj          string
		want         string
	}{
		{
			name:     "no_bucket_prefix",
			tenantID: "alpha",
			obj:      "checkpoint",
			want:     "tenants/alpha/checkpoint",
		},
		{
			name:         "with_bucket_prefix",
			bucketPrefix: "logs",
			tenantID:     "alpha",
			obj:          "tile/0/x01",
			want:         "logs/tenants/alpha/tile/0/x01",
		},
		{
			name:     "tenant_with_slashes",
			tenantID: "team/a",
			obj:      "checkpoint",
			want:     "tenants/team/a/checkpoint",
		},
		{
			name:     "nested_object_path",
			tenantID: "alpha",
			obj:      "tile/0/000",
			want:     "tenants/alpha/tile/0/000",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := &s3Storage{bucketPrefix: tc.bucketPrefix, tenantID: tc.tenantID}
			if got := s.resolve(tc.obj); got != tc.want {
				t.Errorf("resolve(%q) = %q; want %q", tc.obj, got, tc.want)
			}
		})
	}
}

func TestS3StorageTenantsDoNotCollide(t *testing.T) {
	a := &s3Storage{tenantID: "alpha"}
	b := &s3Storage{tenantID: "beta"}
	for _, obj := range []string{"checkpoint", "tile/0/0", "tile/0/0.p/3", "x"} {
		ka, kb := a.resolve(obj), b.resolve(obj)
		if ka == kb {
			t.Errorf("tenant prefixes collided for obj %q: both resolve to %q", obj, ka)
		}
		if !strings.HasPrefix(ka, "tenants/alpha/") || !strings.HasPrefix(kb, "tenants/beta/") {
			t.Errorf("expected tenants/<id>/ prefix; got alpha=%q beta=%q", ka, kb)
		}
	}
}

// ---------------------------------------------------------------------------
// Tile / bundle round-trip via in-memory object store (no DB, no S3).
// ---------------------------------------------------------------------------

func makeTile(t *testing.T, size uint64) *api.HashTile {
	t.Helper()
	r := &api.HashTile{Nodes: make([][]byte, size)}
	for i := uint64(0); i < size; i++ {
		h := sha256.Sum256(fmt.Appendf(nil, "%d", i))
		r.Nodes[i] = h[:]
	}
	return r
}

func TestTileRoundtrip(t *testing.T) {
	ctx := context.Background()
	m := newMemObjStore()
	s := &logResourceStore{objStore: m}

	for _, test := range []struct {
		name     string
		level    uint64
		index    uint64
		logSize  uint64
		tileSize uint64
	}{
		{
			name:     "ok",
			level:    0,
			index:    3 * layout.TileWidth,
			logSize:  3*layout.TileWidth + 20,
			tileSize: 20,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			wantTile := makeTile(t, test.tileSize)
			if err := s.setTile(ctx, test.level, test.index, test.logSize, wantTile); err != nil {
				t.Fatalf("setTile: %v", err)
			}
			expPath := layout.TilePath(test.level, test.index, layout.PartialTileSize(test.level, test.index, test.logSize))
			if _, ok := m.mem[expPath]; !ok {
				t.Fatalf("want tile at %v but found none", expPath)
			}
			got, err := s.getTiles(ctx, []storage.TileID{{Level: test.level, Index: test.index}}, test.logSize)
			if err != nil {
				t.Fatalf("getTiles: %v", err)
			}
			if !cmp.Equal(got[0], wantTile) {
				t.Fatal("roundtrip returned different data")
			}
		})
	}
}

func makeBundle(t *testing.T, idx uint64, size int) []byte {
	t.Helper()
	r := &bytes.Buffer{}
	if size == 0 {
		size = layout.EntryBundleWidth
	}
	for i := range size {
		e := tessera.NewEntry(fmt.Appendf(nil, "%d:%d", idx, i))
		if _, err := r.Write(e.MarshalBundleData(uint64(i))); err != nil {
			t.Fatalf("MarshalBundleData: %v", err)
		}
	}
	return r.Bytes()
}

func TestBundleRoundtrip(t *testing.T) {
	ctx := context.Background()
	m := newMemObjStore()
	s := &logResourceStore{objStore: m, entriesPath: layout.EntriesPath}

	for _, test := range []struct {
		name       string
		index      uint64
		p          uint8
		bundleSize int
	}{
		{name: "ok", index: 3 * layout.EntryBundleWidth, p: 20, bundleSize: 20},
	} {
		t.Run(test.name, func(t *testing.T) {
			wantBundle := makeBundle(t, 0, test.bundleSize)
			if err := s.setEntryBundle(ctx, test.index, test.p, wantBundle); err != nil {
				t.Fatalf("setEntryBundle: %v", err)
			}
			expPath := layout.EntriesPath(test.index, test.p)
			if _, ok := m.mem[expPath]; !ok {
				t.Fatalf("want bundle at %v but found none", expPath)
			}
			got, err := s.getEntryBundle(ctx, test.index, test.p)
			if err != nil {
				t.Fatalf("getEntryBundle: %v", err)
			}
			if !cmp.Equal(got, wantBundle) {
				t.Fatal("roundtrip returned different data")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Cross-tenant Add rejection (no DB).
// ---------------------------------------------------------------------------

// TestAppenderAddRejectsCrossTenantContext is the critical multi-tenant
// safety test: a request whose context names a different tenant than the
// one this Appender serves must be rejected before any DB or S3 work.
func TestAppenderAddRejectsCrossTenantContext(t *testing.T) {
	a := &Appender{tenantID: "alpha"}
	ctx := WithTenantID(context.Background(), "beta")
	f := a.Add(ctx, tessera.NewEntry([]byte("payload")))
	_, err := f()
	if err == nil {
		t.Fatalf("Add: expected tenant mismatch error, got nil")
	}
	if !strings.Contains(err.Error(), "tenant mismatch") ||
		!strings.Contains(err.Error(), "alpha") ||
		!strings.Contains(err.Error(), "beta") {
		t.Fatalf("Add error = %q; want it to mention both tenants and 'tenant mismatch'", err)
	}
}

// TestAppenderAddRejectsBeforeQueue verifies that a misrouted request never
// touches the queue. We construct an Appender with a nil queue: the cross-
// tenant rejection path must short-circuit before queue.Add would nil-panic.
func TestAppenderAddRejectsBeforeQueue(t *testing.T) {
	a := &Appender{tenantID: "alpha", queue: nil}
	ctx := WithTenantID(context.Background(), "beta")
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("Add panicked instead of rejecting: %v", r)
		}
	}()
	f := a.Add(ctx, tessera.NewEntry([]byte("payload")))
	if _, err := f(); err == nil {
		t.Fatalf("Add: expected tenant mismatch error")
	}
}

// ---------------------------------------------------------------------------
// PG sequencer: basic functionality (parity with aws_test.go).
// ---------------------------------------------------------------------------

func TestPGSequencerAssignEntries(t *testing.T) {
	ctx := context.Background()
	if canSkipPGTest(t, ctx) {
		slog.WarnContext(ctx, "PostgreSQL not available, skipping", slog.String("name", t.Name()))
		t.Skip("PostgreSQL not available, skipping test")
	}
	mustDropTables(t, ctx)

	seq := mustNewSequencer(t, ctx, "alpha")

	want := uint64(0)
	for chunks := range 10 {
		entries := []*tessera.Entry{}
		for i := range 10 + chunks {
			entries = append(entries, tessera.NewEntry(fmt.Appendf(nil, "item %d/%d", chunks, i)))
		}
		if err := seq.assignEntries(ctx, entries); err != nil {
			t.Fatalf("assignEntries: %v", err)
		}
		for i, e := range entries {
			if got := *e.Index(); got != want {
				t.Errorf("Chunk %d entry %d got seq %d, want %d", chunks, i, got, want)
			}
			want++
		}
	}
}

func TestPGSequencerPushback(t *testing.T) {
	ctx := context.Background()
	if canSkipPGTest(t, ctx) {
		slog.WarnContext(ctx, "PostgreSQL not available, skipping", slog.String("name", t.Name()))
		t.Skip("PostgreSQL not available, skipping test")
	}
	mustDropTables(t, ctx)

	for _, test := range []struct {
		name           string
		threshold      uint64
		initialEntries int
		wantPushback   bool
	}{
		{name: "no pushback: num < threshold", threshold: 10, initialEntries: 5},
		{name: "no pushback: num = threshold", threshold: 10, initialEntries: 10},
		{name: "pushback: initial > threshold", threshold: 10, initialEntries: 15, wantPushback: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			mustDropTables(t, ctx)
			seq := mustNewSequencer(t, ctx, "alpha")
			seq.maxOutstanding = test.threshold

			entries := []*tessera.Entry{}
			for i := range test.initialEntries {
				entries = append(entries, tessera.NewEntry(fmt.Appendf(nil, "initial item %d", i)))
			}
			if err := seq.assignEntries(ctx, entries); err != nil {
				t.Fatalf("initial assignEntries: %v", err)
			}

			err := seq.assignEntries(ctx, []*tessera.Entry{tessera.NewEntry([]byte("additional"))})
			gotPushback := errors.Is(err, tessera.ErrPushbackIntegration) || errors.Is(err, tessera.ErrPushback)
			if gotPushback != test.wantPushback {
				t.Fatalf("assignEntries pushback=%t (err=%v), want pushback=%t", gotPushback, err, test.wantPushback)
			}
			if !gotPushback && err != nil {
				t.Fatalf("assignEntries: %v", err)
			}
		})
	}
}

func TestPGSequencerRoundTrip(t *testing.T) {
	ctx := context.Background()
	if canSkipPGTest(t, ctx) {
		slog.WarnContext(ctx, "PostgreSQL not available, skipping", slog.String("name", t.Name()))
		t.Skip("PostgreSQL not available, skipping test")
	}
	mustDropTables(t, ctx)

	s := mustNewSequencer(t, ctx, "alpha")

	seq := 0
	wantEntries := []storage.SequencedEntry{}
	for chunks := range 10 {
		entries := []*tessera.Entry{}
		for range 10 + chunks {
			e := tessera.NewEntry(fmt.Appendf(nil, "item %d", seq))
			entries = append(entries, e)
			wantEntries = append(wantEntries, storage.SequencedEntry{
				BundleData: e.MarshalBundleData(uint64(seq)),
				LeafHash:   e.LeafHash(),
			})
			seq++
		}
		if err := s.assignEntries(ctx, entries); err != nil {
			t.Fatalf("assignEntries: %v", err)
		}
	}

	seenIdx := uint64(0)
	f := func(_ context.Context, fromSeq uint64, entries []storage.SequencedEntry) ([]byte, error) {
		if fromSeq != seenIdx {
			return nil, fmt.Errorf("f called with fromSeq %d, want %d", fromSeq, seenIdx)
		}
		for i, e := range entries {
			if got, want := e, wantEntries[int(seenIdx)]; !reflect.DeepEqual(got, want) {
				return nil, fmt.Errorf("entry %d+%d != want[%d]", fromSeq, i, seenIdx)
			}
			seenIdx++
		}
		return []byte("newroot"), nil
	}

	more, err := s.consumeEntries(ctx, 7, f, false)
	if err != nil {
		t.Errorf("consumeEntries: %v", err)
	}
	if !more {
		t.Errorf("more: false, expected true")
	}
}

// ---------------------------------------------------------------------------
// PG: multi-tenant isolation tests (the new use cases).
// ---------------------------------------------------------------------------

// TestPGSequencerTenantIsolation confirms that two tenants sharing one
// PostgreSQL instance maintain independent sequence counters and that one
// tenant's reads do not see the other's data.
func TestPGSequencerTenantIsolation(t *testing.T) {
	ctx := context.Background()
	if canSkipPGTest(t, ctx) {
		slog.WarnContext(ctx, "PostgreSQL not available, skipping", slog.String("name", t.Name()))
		t.Skip("PostgreSQL not available, skipping test")
	}
	mustDropTables(t, ctx)

	seqA := mustNewSequencer(t, ctx, "alpha")
	seqB := mustNewSequencer(t, ctx, "beta")

	entriesA := []*tessera.Entry{}
	for i := range 5 {
		entriesA = append(entriesA, tessera.NewEntry(fmt.Appendf(nil, "A-%d", i)))
	}
	if err := seqA.assignEntries(ctx, entriesA); err != nil {
		t.Fatalf("seqA.assignEntries: %v", err)
	}

	entriesB := []*tessera.Entry{}
	for i := range 3 {
		entriesB = append(entriesB, tessera.NewEntry(fmt.Appendf(nil, "B-%d", i)))
	}
	if err := seqB.assignEntries(ctx, entriesB); err != nil {
		t.Fatalf("seqB.assignEntries: %v", err)
	}

	// Each tenant's nextIndex tracks only its own entries.
	if got, err := seqA.nextIndex(ctx); err != nil || got != 5 {
		t.Errorf("seqA.nextIndex = (%d,%v); want (5,nil)", got, err)
	}
	if got, err := seqB.nextIndex(ctx); err != nil || got != 3 {
		t.Errorf("seqB.nextIndex = (%d,%v); want (3,nil)", got, err)
	}

	// Entries should be sequenced from 0 within each tenant — they are
	// not sharing a global counter.
	for i, e := range entriesA {
		if idx := *e.Index(); idx != uint64(i) {
			t.Errorf("entriesA[%d].Index = %d; want %d", i, idx, i)
		}
	}
	for i, e := range entriesB {
		if idx := *e.Index(); idx != uint64(i) {
			t.Errorf("entriesB[%d].Index = %d; want %d", i, idx, i)
		}
	}

	// Each consumer integrates only its own tenant's entries.
	consumed := map[string]int{}
	consume := func(tenant string) consumeFunc {
		return func(_ context.Context, _ uint64, entries []storage.SequencedEntry) ([]byte, error) {
			consumed[tenant] += len(entries)
			return []byte("root-" + tenant), nil
		}
	}
	if _, err := seqA.consumeEntries(ctx, 1000, consume("alpha"), false); err != nil {
		t.Fatalf("seqA.consumeEntries: %v", err)
	}
	if _, err := seqB.consumeEntries(ctx, 1000, consume("beta"), false); err != nil {
		t.Fatalf("seqB.consumeEntries: %v", err)
	}
	if consumed["alpha"] != 5 || consumed["beta"] != 3 {
		t.Errorf("consumed = %v; want map[alpha:5 beta:3]", consumed)
	}

	// And tree state read after consumption is per-tenant.
	szA, _, err := seqA.currentTree(ctx)
	if err != nil || szA != 5 {
		t.Errorf("seqA.currentTree = (%d,_,%v); want (5,_,nil)", szA, err)
	}
	szB, _, err := seqB.currentTree(ctx)
	if err != nil || szB != 3 {
		t.Errorf("seqB.currentTree = (%d,_,%v); want (3,_,nil)", szB, err)
	}
}

// TestPGRLSEnforcement confirms the database-side defence-in-depth: even if
// a query forgets a tenant_id WHERE clause, the row-level security policy
// keyed on app.tenant_id hides other tenants' rows.
func TestPGRLSEnforcement(t *testing.T) {
	ctx := context.Background()
	if canSkipPGTest(t, ctx) {
		slog.WarnContext(ctx, "PostgreSQL not available, skipping", slog.String("name", t.Name()))
		t.Skip("PostgreSQL not available, skipping test")
	}
	skipIfRLSBypassed(t, ctx)
	mustDropTables(t, ctx)

	seqA := mustNewSequencer(t, ctx, "alpha")
	_ = mustNewSequencer(t, ctx, "beta")

	if err := seqA.assignEntries(ctx, []*tessera.Entry{tessera.NewEntry([]byte("hello"))}); err != nil {
		t.Fatalf("seqA.assignEntries: %v", err)
	}

	tx, err := seqA.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := setLocalTenant(ctx, tx, "beta"); err != nil {
		t.Fatalf("setLocalTenant: %v", err)
	}
	// Note: deliberately omits tenant_id WHERE clause. RLS must hide
	// alpha's row regardless.
	var next uint64
	if err := tx.QueryRow(ctx, `SELECT next FROM seq_coord WHERE id = 0`).Scan(&next); err != nil {
		t.Fatalf("query under beta tenant: %v", err)
	}
	if next != 0 {
		t.Errorf("beta saw alpha's seq_coord (next=%d); RLS not enforcing isolation", next)
	}
}

// TestPGRLSDeniesUnsetTenant confirms that with no app.tenant_id session
// setting, RLS hides all rows. This guards against forgotten setLocalTenant
// calls leaking data across tenants via a connection that bypasses the
// per-request setting.
func TestPGRLSDeniesUnsetTenant(t *testing.T) {
	ctx := context.Background()
	if canSkipPGTest(t, ctx) {
		slog.WarnContext(ctx, "PostgreSQL not available, skipping", slog.String("name", t.Name()))
		t.Skip("PostgreSQL not available, skipping test")
	}
	skipIfRLSBypassed(t, ctx)
	mustDropTables(t, ctx)

	seqA := mustNewSequencer(t, ctx, "alpha")
	if err := seqA.assignEntries(ctx, []*tessera.Entry{tessera.NewEntry([]byte("hello"))}); err != nil {
		t.Fatalf("seqA.assignEntries: %v", err)
	}

	pool, err := pgxpool.New(ctx, *pgURI)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()

	for _, table := range []string{"tessera", "seq_coord", "seq", "int_coord", "pub_coord", "gc_coord"} {
		var n int
		if err := pool.QueryRow(ctx, fmt.Sprintf(`SELECT COUNT(*) FROM %s`, table)).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		if n != 0 {
			t.Errorf("RLS allowed read of %s with no app.tenant_id set: count=%d", table, n)
		}
	}
}

// TestPGProxyLeakIsolation simulates the failure mode introduced by a
// transaction-pooling proxy (pgbouncer transaction mode, RDS Proxy
// multiplexing) where a connection retains a session-level app.tenant_id
// from a previous tenant. Our tx-local setLocalTenant must override the
// session value for the duration of every query, so tenant beta's reads
// must see beta's data even on a connection pre-poisoned with alpha.
func TestPGProxyLeakIsolation(t *testing.T) {
	ctx := context.Background()
	if canSkipPGTest(t, ctx) {
		slog.WarnContext(ctx, "PostgreSQL not available, skipping", slog.String("name", t.Name()))
		t.Skip("PostgreSQL not available, skipping test")
	}
	skipIfRLSBypassed(t, ctx)
	mustDropTables(t, ctx)

	// Seed both tenants with distinguishable state.
	seqAlpha := mustNewSequencer(t, ctx, "alpha")
	seqBeta := mustNewSequencer(t, ctx, "beta")
	for i := range 7 {
		if err := seqAlpha.assignEntries(ctx, []*tessera.Entry{tessera.NewEntry(fmt.Appendf(nil, "alpha-%d", i))}); err != nil {
			t.Fatalf("alpha assign: %v", err)
		}
	}
	for i := range 3 {
		if err := seqBeta.assignEntries(ctx, []*tessera.Entry{tessera.NewEntry(fmt.Appendf(nil, "beta-%d", i))}); err != nil {
			t.Fatalf("beta assign: %v", err)
		}
	}

	// Build a pinned pool of size 1 and pre-poison its single backend
	// connection with alpha's session-level GUC. This is exactly what a
	// transaction-pooling proxy would expose us to if a previous tenant's
	// session GUC stuck around.
	cfg, err := pgxpool.ParseConfig(*pgURI)
	if err != nil {
		t.Fatalf("ParseConfig: %v", err)
	}
	cfg.MaxConns = 1
	cfg.MinConns = 1
	poisoned, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatalf("NewWithConfig: %v", err)
	}
	defer poisoned.Close()
	if _, err := poisoned.Exec(ctx, `SELECT set_config('app.tenant_id', 'alpha', false)`); err != nil {
		t.Fatalf("poison: %v", err)
	}

	// Build a pgSequencer for beta that uses the poisoned pool. All four
	// previously-non-tx reads (currentTree, nextIndex, checkDataCompatibility,
	// the assignEntries back-pressure read) must still return beta's view.
	betaOnPoisoned := &pgSequencer{pool: poisoned, tenantID: "beta", maxOutstanding: DefaultPushbackMaxOutstanding}

	if err := betaOnPoisoned.checkDataCompatibility(ctx); err != nil {
		t.Errorf("checkDataCompatibility on poisoned conn: %v", err)
	}
	if got, _, err := betaOnPoisoned.currentTree(ctx); err != nil || got != 0 {
		t.Errorf("currentTree on poisoned conn = (%d, %v); want (0, nil)", got, err)
	}
	if got, err := betaOnPoisoned.nextIndex(ctx); err != nil || got != 3 {
		t.Errorf("nextIndex on poisoned conn = (%d, %v); want (3, nil)", got, err)
	}
	// assignEntries reads int_coord for back-pressure inside its own tx;
	// poisoning must not let beta see alpha's tree size (7) instead of its
	// own (0). We can't easily assert the read directly, but a successful
	// assign + correct post-state is sufficient evidence that the read
	// resolved to beta.
	if err := betaOnPoisoned.assignEntries(ctx, []*tessera.Entry{tessera.NewEntry([]byte("beta-poisoned"))}); err != nil {
		t.Errorf("assignEntries on poisoned conn: %v", err)
	}
	if got, err := betaOnPoisoned.nextIndex(ctx); err != nil || got != 4 {
		t.Errorf("post-assign nextIndex = (%d, %v); want (4, nil)", got, err)
	}
}

// TestPGSchemaCompatibilityMismatch confirms the version guard fires when
// the on-disk schema doesn't match this binary.
func TestPGSchemaCompatibilityMismatch(t *testing.T) {
	ctx := context.Background()
	if canSkipPGTest(t, ctx) {
		slog.WarnContext(ctx, "PostgreSQL not available, skipping", slog.String("name", t.Name()))
		t.Skip("PostgreSQL not available, skipping test")
	}
	mustDropTables(t, ctx)

	// First initialisation seeds the version row.
	_ = mustNewSequencer(t, ctx, "alpha")

	// Bump the on-disk version to something this binary doesn't understand.
	pool, err := pgxpool.New(ctx, *pgURI)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	defer pool.Close()
	tx, err := pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := setLocalTenant(ctx, tx, "alpha"); err != nil {
		t.Fatalf("setLocalTenant: %v", err)
	}
	if _, err := tx.Exec(ctx,
		`UPDATE tessera SET compatibility_version = $1 WHERE id = 0`,
		SchemaCompatibilityVersion+999); err != nil {
		t.Fatalf("UPDATE tessera: %v", err)
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatalf("commit: %v", err)
	}

	cfg := Config{TenantID: "alpha", Bucket: "b", PGConnStr: *pgURI}
	if _, err := newPGSequencer(ctx, cfg, DefaultPushbackMaxOutstanding, 0); err == nil ||
		!strings.Contains(err.Error(), "compatibility") {
		t.Fatalf("expected schema compatibility error, got: %v", err)
	}
}

// TestPGSequencerConcurrentTwoTenants drives assignEntries on two tenants
// in parallel from many goroutines. It catches any unexpected global
// serialization, deadlock, or cross-tenant leak that the sequential
// isolation tests would miss.
func TestPGSequencerConcurrentTwoTenants(t *testing.T) {
	ctx := context.Background()
	if canSkipPGTest(t, ctx) {
		slog.WarnContext(ctx, "PostgreSQL not available, skipping", slog.String("name", t.Name()))
		t.Skip("PostgreSQL not available, skipping test")
	}
	mustDropTables(t, ctx)

	seqA := mustNewSequencer(t, ctx, "alpha")
	seqB := mustNewSequencer(t, ctx, "beta")

	const batches = 16
	const batchSize = 4

	var wg sync.WaitGroup
	errC := make(chan error, 2*batches)
	assign := func(s *pgSequencer, tag string, batchIdx int) {
		defer wg.Done()
		entries := make([]*tessera.Entry, batchSize)
		for j := range entries {
			entries[j] = tessera.NewEntry(fmt.Appendf(nil, "%s-batch%d-%d", tag, batchIdx, j))
		}
		if err := s.assignEntries(ctx, entries); err != nil {
			errC <- fmt.Errorf("%s assignEntries: %v", tag, err)
		}
	}
	for i := range batches {
		wg.Add(2)
		go assign(seqA, "alpha", i)
		go assign(seqB, "beta", i)
	}
	wg.Wait()
	close(errC)
	for err := range errC {
		t.Errorf("%v", err)
	}

	wantPerTenant := uint64(batches * batchSize)
	if got, err := seqA.nextIndex(ctx); err != nil || got != wantPerTenant {
		t.Errorf("seqA.nextIndex = (%d,%v); want (%d,nil)", got, err, wantPerTenant)
	}
	if got, err := seqB.nextIndex(ctx); err != nil || got != wantPerTenant {
		t.Errorf("seqB.nextIndex = (%d,%v); want (%d,nil)", got, err, wantPerTenant)
	}

	// Each tenant's consume sees only its own entries. Exhaust both
	// queues across multiple consume calls — assignEntries inserts one
	// row per batch and consumeEntries respects orderCheck contiguity,
	// so a single call is enough only if it fits within the limit, but
	// we drive a loop to be robust.
	consumed := map[string]uint64{}
	for tenant, seq := range map[string]*pgSequencer{"alpha": seqA, "beta": seqB} {
		f := func(_ context.Context, _ uint64, entries []storage.SequencedEntry) ([]byte, error) {
			consumed[tenant] += uint64(len(entries))
			return []byte("root-" + tenant), nil
		}
		for {
			more, err := seq.consumeEntries(ctx, 1000, f, false)
			if err != nil {
				t.Fatalf("consumeEntries(%s): %v", tenant, err)
			}
			if !more {
				break
			}
		}
	}
	if consumed["alpha"] != wantPerTenant || consumed["beta"] != wantPerTenant {
		t.Errorf("consumed = %v; want both = %d", consumed, wantPerTenant)
	}
}

// TestTwoTenantAppenderLifecycle runs the full Appender lifecycle for two
// tenants concurrently against a single Postgres instance. Each tenant has
// its own object store (modelling per-tenant S3 prefixing) and its own
// signed checkpoint. Verifies that both tenants integrate to the expected
// independent sizes and that neither tenant's checkpoint leaks into the
// other's store.
func TestTwoTenantAppenderLifecycle(t *testing.T) {
	ctx := context.Background()
	if canSkipPGTest(t, ctx) {
		slog.WarnContext(ctx, "PostgreSQL not available, skipping", slog.String("name", t.Name()))
		t.Skip("PostgreSQL not available, skipping test")
	}
	mustDropTables(t, ctx)

	const entriesPerTenant = 200
	const batchSize = 50

	type tenantHarness struct {
		id       string
		store    *memObjStore
		appender *Appender
		lr       tessera.LogReader
		verifier note.Verifier
	}

	makeHarness := func(id string) *tenantHarness {
		seq := mustNewSequencer(t, ctx, id)
		sk, vk := mustGenerateKeys(t)
		m := newMemObjStore()
		stg := &Storage{cfg: Config{TenantID: id}}
		opts := tessera.NewAppendOptions().
			WithCheckpointInterval(time.Second).
			WithBatching(uint(batchSize), 50*time.Millisecond).
			WithGarbageCollectionInterval(time.Duration(0)).
			WithCheckpointSigner(sk)
		app, lr, err := stg.newAppender(ctx, m, seq, opts)
		if err != nil {
			t.Fatalf("newAppender(%s): %v", id, err)
		}
		if err := app.updateCheckpoint(ctx, 0, []byte("")); err != nil {
			t.Fatalf("updateCheckpoint(%s): %v", id, err)
		}
		return &tenantHarness{id: id, store: m, appender: app, lr: lr, verifier: vk}
	}

	tenants := []*tenantHarness{makeHarness("alpha"), makeHarness("beta")}

	// Drive Adds for both tenants in parallel.
	var wg sync.WaitGroup
	addErr := make(chan error, 2*entriesPerTenant)
	for _, th := range tenants {
		wg.Add(1)
		go func(th *tenantHarness) {
			defer wg.Done()
			a := tessera.NewPublicationAwaiter(ctx, th.lr.ReadCheckpoint, 100*time.Millisecond)
			var lastF tessera.IndexFuture
			for i := range entriesPerTenant {
				lastF = th.appender.Add(ctx, tessera.NewEntry(fmt.Appendf(nil, "%s entry %d", th.id, i)))
			}
			if _, _, err := a.Await(ctx, lastF); err != nil {
				addErr <- fmt.Errorf("%s Await: %v", th.id, err)
			}
		}(th)
	}
	wg.Wait()
	close(addErr)
	for err := range addErr {
		t.Errorf("%v", err)
	}

	// Each tenant's checkpoint reports its own size, and the two stores
	// don't leak into each other.
	for _, th := range tenants {
		cp, err := th.lr.ReadCheckpoint(ctx)
		if err != nil {
			t.Fatalf("%s ReadCheckpoint: %v", th.id, err)
		}
		_, size, _, err := parse.CheckpointUnsafe(cp)
		if err != nil {
			t.Fatalf("%s parse checkpoint: %v", th.id, err)
		}
		if size != entriesPerTenant {
			t.Errorf("%s checkpoint size = %d; want %d", th.id, size, entriesPerTenant)
		}

		// fsck the per-tenant tree.
		f := fsck.New(th.verifier.Name(), th.verifier, th.lr, defaultMerkleLeafHasher, fsck.Opts{N: 1})
		if err := f.Check(ctx); err != nil {
			t.Errorf("%s fsck: %v", th.id, err)
		}
	}

	// Sanity: the two stores aren't pointing at the same underlying map
	// and they ended up with different content (each holds its own
	// checkpoint at minimum).
	cpA, _ := tenants[0].store.getObject(ctx, layout.CheckpointPath)
	cpB, _ := tenants[1].store.getObject(ctx, layout.CheckpointPath)
	if bytes.Equal(cpA, cpB) {
		t.Errorf("alpha and beta produced byte-identical checkpoints; expected per-tenant divergence")
	}
}

// ---------------------------------------------------------------------------
// PG: publish + GC end-to-end.
// ---------------------------------------------------------------------------

func TestPublishTree(t *testing.T) {
	ctx := context.Background()
	if canSkipPGTest(t, ctx) {
		slog.WarnContext(ctx, "PostgreSQL not available, skipping", slog.String("name", t.Name()))
		t.Skip("PostgreSQL not available, skipping test")
	}

	for _, test := range []struct {
		name              string
		publishInterval   time.Duration
		republishInterval time.Duration
		attempts          []time.Duration
		wantUpdates       int
	}{
		{
			name:              "works ok",
			publishInterval:   100 * time.Millisecond,
			republishInterval: 100 * time.Millisecond,
			attempts:          []time.Duration{1 * time.Second},
			wantUpdates:       1,
		},
		{
			name:              "too soon, skip update",
			publishInterval:   10 * time.Second,
			republishInterval: 10 * time.Second,
			attempts:          []time.Duration{100 * time.Millisecond},
			wantUpdates:       0,
		},
		{
			name:              "too soon, skip update, but recovers",
			publishInterval:   2 * time.Second,
			republishInterval: 2 * time.Second,
			attempts:          []time.Duration{100 * time.Millisecond, 2 * time.Second},
			wantUpdates:       1,
		},
		{
			name:              "republish needed",
			publishInterval:   1 * time.Second,
			republishInterval: 2 * time.Second,
			attempts:          []time.Duration{1500 * time.Millisecond, 2500 * time.Millisecond},
			wantUpdates:       1,
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			mustDropTables(t, ctx)

			s := mustNewSequencer(t, ctx, "alpha")
			m := newMemObjStore()
			storage := &Appender{
				tenantID: "alpha",
				logStore: &logResourceStore{
					objStore:    m,
					entriesPath: layout.EntriesPath,
				},
				sequencer: s,
				newCP: func(_ context.Context, size uint64, hash []byte) ([]byte, error) {
					return fmt.Appendf(nil, "%d/%x,", size, hash), nil
				},
			}
			if err := storage.init(ctx); err != nil {
				t.Fatalf("storage.init: %v", err)
			}
			if err := s.publishCheckpoint(ctx, test.publishInterval, test.republishInterval, storage.updateCheckpoint); err != nil {
				t.Fatalf("publishCheckpoint: %v", err)
			}
			cpOld := []byte("bananas")
			if err := m.setObject(ctx, layout.CheckpointPath, cpOld, "", ""); err != nil {
				t.Fatalf("setObject(bananas): %v", err)
			}
			updatesSeen := 0
			for _, d := range test.attempts {
				time.Sleep(d)
				if err := s.publishCheckpoint(ctx, test.publishInterval, test.republishInterval, storage.updateCheckpoint); err != nil {
					t.Fatalf("publishCheckpoint: %v", err)
				}
				cpNew, err := m.getObject(ctx, layout.CheckpointPath)
				if err != nil {
					t.Fatalf("getObject: %v", err)
				}
				if !bytes.Equal(cpOld, cpNew) {
					updatesSeen++
					cpOld = cpNew
				}
			}
			if updatesSeen != test.wantUpdates {
				t.Fatalf("Saw %d updates, want %d", updatesSeen, test.wantUpdates)
			}
		})
	}
}

func TestGarbageCollect(t *testing.T) {
	ctx := t.Context()
	if canSkipPGTest(t, ctx) {
		slog.WarnContext(ctx, "PostgreSQL not available, skipping", slog.String("name", t.Name()))
		t.Skip("PostgreSQL not available, skipping test")
	}
	mustDropTables(t, ctx)

	batchSize := uint64(60000)
	integrateEvery := uint64(31234)

	s := mustNewSequencer(t, ctx, "alpha")

	sk, vk := mustGenerateKeys(t)

	m := newMemObjStore()
	storage := &Storage{cfg: Config{TenantID: "alpha"}}

	opts := tessera.NewAppendOptions().
		WithCheckpointInterval(1200*time.Millisecond).
		WithBatching(uint(batchSize), 100*time.Millisecond).
		// Disable periodic GC so we can drive it manually below.
		WithGarbageCollectionInterval(time.Duration(0)).
		WithCheckpointSigner(sk)
	appender, lr, err := storage.newAppender(ctx, m, s, opts)
	if err != nil {
		t.Fatalf("newAppender: %v", err)
	}
	if err := appender.updateCheckpoint(ctx, 0, []byte("")); err != nil {
		t.Fatalf("updateCheckpoint: %v", err)
	}

	treeSize := uint64(256 * 384)

	a := tessera.NewPublicationAwaiter(ctx, lr.ReadCheckpoint, 100*time.Millisecond)

	for size := uint64(0); size < treeSize; {
		t.Logf("Adding entries from %d", size)
		for range batchSize {
			f := appender.Add(ctx, tessera.NewEntry(fmt.Appendf(nil, "entry %d", size)))
			if size%integrateEvery == 0 {
				if _, _, err := a.Await(ctx, f); err != nil {
					t.Fatalf("Await: %v", err)
				}
			}
			size++
		}
		if _, _, err := a.Await(ctx, func() (tessera.Index, error) { return tessera.Index{Index: size - 1}, nil }); err != nil {
			t.Fatalf("Await final tree: %v", err)
		}

		t.Logf("Running GC at size %d", size)
		if err := s.garbageCollect(ctx, size, 1000, m.deleteObjectsWithPrefix, appender.logStore.entriesPath); err != nil {
			t.Fatalf("garbageCollect: %v", err)
		}

		wantPartialPrefixes := make(map[string]struct{})
		for _, p := range expectedPartialPrefixes(size, appender.logStore.entriesPath) {
			wantPartialPrefixes[p] = struct{}{}
		}
		for k := range m.mem {
			if strings.Contains(k, ".p/") {
				p := strings.SplitAfter(k, ".p/")[0]
				if _, ok := wantPartialPrefixes[p]; !ok {
					t.Errorf("Found unwanted partial: %s", k)
				}
			}
		}
	}

	f := fsck.New(vk.Name(), vk, lr, defaultMerkleLeafHasher, fsck.Opts{N: 1})
	if err := f.Check(ctx); err != nil {
		t.Fatalf("FSCK failed: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

// expectedPartialPrefixes returns the set of resource prefixes where it is
// acceptable for a tree of the given size to retain partial resources.
func expectedPartialPrefixes(size uint64, entriesPath func(uint64, uint8) string) []string {
	r := []string{}
	for l, c := uint64(0), size; c > 0; l, c = l+1, c>>8 {
		idx, p := c/256, c%256
		if p != 0 {
			if l == 0 {
				r = append(r, entriesPath(idx, 0)+".p/")
			}
			r = append(r, layout.TilePath(l, idx, 0)+".p/")
		}
	}
	return r
}

type memObjStore struct {
	sync.RWMutex
	mem map[string][]byte
}

func newMemObjStore() *memObjStore {
	return &memObjStore{mem: make(map[string][]byte)}
}

func (m *memObjStore) getObject(_ context.Context, obj string) ([]byte, error) {
	m.RLock()
	defer m.RUnlock()
	d, ok := m.mem[obj]
	if !ok {
		return nil, fmt.Errorf("obj %q not found: %w", obj, &types.NoSuchKey{})
	}
	return d, nil
}

func (m *memObjStore) setObject(_ context.Context, obj string, data []byte, _, _ string) error {
	m.Lock()
	defer m.Unlock()
	m.mem[obj] = data
	return nil
}

func (m *memObjStore) setObjectIfNoneMatch(_ context.Context, obj string, data []byte, _, _ string) error {
	m.Lock()
	defer m.Unlock()
	d, ok := m.mem[obj]
	if ok && !bytes.Equal(d, data) {
		return &smithy.GenericAPIError{Code: "PreconditionFailed"}
	}
	m.mem[obj] = data
	return nil
}

func (m *memObjStore) deleteObjectsWithPrefix(_ context.Context, prefix string) error {
	m.Lock()
	defer m.Unlock()
	for k := range m.mem {
		if strings.HasPrefix(k, prefix) {
			delete(m.mem, k)
		}
	}
	return nil
}

func mustGenerateKeys(t *testing.T) (note.Signer, note.Verifier) {
	t.Helper()
	sk, vk, err := note.GenerateKey(nil, "testlog")
	if err != nil {
		t.Fatalf("GenerateKey: %v", err)
	}
	s, err := note.NewSigner(sk)
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	v, err := note.NewVerifier(vk)
	if err != nil {
		t.Fatalf("NewVerifier: %v", err)
	}
	return s, v
}

// defaultMerkleLeafHasher parses a C2SP tlog-tile bundle and returns the
// Merkle leaf hashes of each entry it contains.
func defaultMerkleLeafHasher(bundle []byte) ([][]byte, error) {
	eb := &api.EntryBundle{}
	if err := eb.UnmarshalText(bundle); err != nil {
		return nil, fmt.Errorf("unmarshal: %v", err)
	}
	r := make([][]byte, 0, len(eb.Entries))
	for _, e := range eb.Entries {
		h := rfc6962.DefaultHasher.HashLeaf(e)
		r = append(r, h[:])
	}
	return r, nil
}

// emptyTreeRoot returns the well-known empty-tree root used to seed int_coord.
// Kept for clarity in tests that read the seeded row directly.
func emptyTreeRoot() []byte {
	return rfc6962.DefaultHasher.EmptyRoot()
}
