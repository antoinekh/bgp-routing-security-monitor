package ripestat

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// stubServer serves a fixture from an httptest server and counts requests.
// Tests point Config.BaseURL at it so no test ever reaches stat.ripe.net.
type stubServer struct {
	*httptest.Server
	requests atomic.Int64
	queries  chan string
}

func newStubServer(t *testing.T, handler func(w http.ResponseWriter, r *http.Request)) *stubServer {
	t.Helper()
	s := &stubServer{queries: make(chan string, 64)}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.requests.Add(1)
		select {
		case s.queries <- r.URL.Query().Get("resource"):
		default:
		}
		handler(w, r)
	}))
	t.Cleanup(s.Close)
	return s
}

// serveFixture returns a handler that always replies with the named fixture.
func serveFixture(t *testing.T, name string) func(http.ResponseWriter, *http.Request) {
	t.Helper()
	body := fixture(t, name)
	return func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(body)
	}
}

// fakeClock is a manually advanced clock for cache and rate-limiter tests.
type fakeClock struct {
	mu sync.Mutex
	t  time.Time
}

func newFakeClock() *fakeClock {
	return &fakeClock{t: time.Date(2026, 9, 8, 12, 0, 0, 0, time.UTC)}
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return p
}

// ─── TestNewValidatesBaseURL ───

func TestNewValidatesBaseURL(t *testing.T) {
	tests := []struct {
		name    string
		baseURL string
		wantErr bool
	}{
		{"default when empty", "", false},
		{"https", "https://stat.ripe.net", false},
		{"http for a local stub", "http://127.0.0.1:8080", false},
		{"trailing slash tolerated", "https://stat.ripe.net/", false},
		{"missing scheme", "stat.ripe.net", true},
		{"unsupported scheme", "ftp://stat.ripe.net", true},
		{"missing host", "https://", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := New(Config{BaseURL: tt.baseURL})
			if (err != nil) != tt.wantErr {
				t.Fatalf("New(%q) error = %v, wantErr %v", tt.baseURL, err, tt.wantErr)
			}
		})
	}
}

func TestNewAppliesDefaults(t *testing.T) {
	c, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if c.baseURL != DefaultBaseURL {
		t.Errorf("baseURL = %q, want %q", c.baseURL, DefaultBaseURL)
	}
	if c.cacheTTL != DefaultCacheTTL {
		t.Errorf("cacheTTL = %v, want %v", c.cacheTTL, DefaultCacheTTL)
	}
	if c.limiter.capacity != DefaultRateLimitPerMin {
		t.Errorf("rate limit capacity = %v, want %v", c.limiter.capacity, DefaultRateLimitPerMin)
	}
	if c.Name() != ProviderName {
		t.Errorf("Name() = %q, want %q", c.Name(), ProviderName)
	}
}

// ─── TestGlobalOriginsQueriesLookingGlass ───

func TestGlobalOriginsQueriesLookingGlass(t *testing.T) {
	var gotPath, gotResource, gotSourceApp string
	srv := newStubServer(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotResource = r.URL.Query().Get("resource")
		gotSourceApp = r.URL.Query().Get("sourceapp")
		serveFixture(t, "looking-glass-moas.json")(w, r)
	})

	c, err := New(Config{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	summary, err := c.GlobalOrigins(context.Background(), mustPrefix(t, "203.0.113.0/24"), 0)
	if err != nil {
		t.Fatalf("GlobalOrigins: %v", err)
	}

	if gotPath != lookingGlassPath {
		t.Errorf("path = %q, want %q", gotPath, lookingGlassPath)
	}
	if gotResource != "203.0.113.0/24" {
		t.Errorf("resource = %q, want 203.0.113.0/24", gotResource)
	}
	if gotSourceApp != sourceApp {
		t.Errorf("sourceapp = %q, want %q", gotSourceApp, sourceApp)
	}
	if len(summary.Origins) != 2 || summary.Origins[0].ASN != 64511 {
		t.Errorf("Origins = %+v, want AS64511 first", summary.Origins)
	}
}

// A host-bit-carrying prefix is normalised before it reaches the API, so the
// cache cannot be defeated by an unmasked spelling of the same prefix.
func TestGlobalOriginsMasksPrefix(t *testing.T) {
	srv := newStubServer(t, serveFixture(t, "looking-glass-empty.json"))
	c, err := New(Config{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if _, err := c.GlobalOrigins(context.Background(), mustPrefix(t, "203.0.113.7/24"), 0); err != nil {
		t.Fatalf("GlobalOrigins: %v", err)
	}
	if got := <-srv.queries; got != "203.0.113.0/24" {
		t.Errorf("resource = %q, want masked 203.0.113.0/24", got)
	}
}

// ─── TestGlobalOriginsCache ───

// A second lookup inside the TTL window must be served from cache: no HTTP
// request, and no rate-limit token consumed.
func TestGlobalOriginsCacheSuppressesDuplicateCalls(t *testing.T) {
	srv := newStubServer(t, serveFixture(t, "looking-glass-moas.json"))
	clock := newFakeClock()
	c, err := New(Config{
		BaseURL:  srv.URL,
		CacheTTL: 60 * time.Second,
		Clock:    clock.Now,
		// A budget of exactly 1 proves the cache hits never spend tokens:
		// if any of the repeat lookups reached the limiter, it would fail.
		RateLimitPerMin: 1,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	prefix := mustPrefix(t, "203.0.113.0/24")
	for i := range 5 {
		clock.Advance(5 * time.Second) // 5s..25s, all inside the 60s TTL
		summary, err := c.GlobalOrigins(context.Background(), prefix, 0)
		if err != nil {
			t.Fatalf("lookup %d: %v", i, err)
		}
		if summary.CollectorCount != 5 {
			t.Errorf("lookup %d: CollectorCount = %d, want 5", i, summary.CollectorCount)
		}
	}

	if got := srv.requests.Load(); got != 1 {
		t.Errorf("HTTP requests = %d, want 1 (4 later lookups should be cache hits)", got)
	}
}

// Past the TTL the entry is stale and a fresh query goes out.
func TestGlobalOriginsCacheExpires(t *testing.T) {
	srv := newStubServer(t, serveFixture(t, "looking-glass-moas.json"))
	clock := newFakeClock()
	c, err := New(Config{
		BaseURL:         srv.URL,
		CacheTTL:        60 * time.Second,
		RateLimitPerMin: 100,
		Clock:           clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	prefix := mustPrefix(t, "203.0.113.0/24")
	if _, err := c.GlobalOrigins(context.Background(), prefix, 0); err != nil {
		t.Fatalf("first lookup: %v", err)
	}

	clock.Advance(59 * time.Second)
	if _, err := c.GlobalOrigins(context.Background(), prefix, 0); err != nil {
		t.Fatalf("lookup at 59s: %v", err)
	}
	if got := srv.requests.Load(); got != 1 {
		t.Fatalf("HTTP requests at 59s = %d, want 1", got)
	}

	clock.Advance(2 * time.Second) // now 61s old, past the TTL
	if _, err := c.GlobalOrigins(context.Background(), prefix, 0); err != nil {
		t.Fatalf("lookup at 61s: %v", err)
	}
	if got := srv.requests.Load(); got != 2 {
		t.Errorf("HTTP requests at 61s = %d, want 2", got)
	}
}

// maxAge is the caller's freshness requirement: a stricter maxAge than the
// entry's age forces a refetch even though the entry is still within the
// client TTL.
func TestGlobalOriginsMaxAgeOverridesCache(t *testing.T) {
	srv := newStubServer(t, serveFixture(t, "looking-glass-moas.json"))
	clock := newFakeClock()
	c, err := New(Config{
		BaseURL:         srv.URL,
		CacheTTL:        60 * time.Second,
		RateLimitPerMin: 100,
		Clock:           clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	prefix := mustPrefix(t, "203.0.113.0/24")
	if _, err := c.GlobalOrigins(context.Background(), prefix, 0); err != nil {
		t.Fatalf("first lookup: %v", err)
	}
	clock.Advance(20 * time.Second)

	// Relaxed requirement: still a hit.
	if _, err := c.GlobalOrigins(context.Background(), prefix, 30*time.Second); err != nil {
		t.Fatalf("lookup with 30s maxAge: %v", err)
	}
	if got := srv.requests.Load(); got != 1 {
		t.Fatalf("HTTP requests with 30s maxAge = %d, want 1", got)
	}

	// Stricter requirement than the entry's 20s age: refetch.
	if _, err := c.GlobalOrigins(context.Background(), prefix, 10*time.Second); err != nil {
		t.Fatalf("lookup with 10s maxAge: %v", err)
	}
	if got := srv.requests.Load(); got != 2 {
		t.Errorf("HTTP requests with 10s maxAge = %d, want 2", got)
	}
}

// An empty result is cached too: a prefix no collector carries must not be
// re-queried on every event of a flapping route.
func TestGlobalOriginsCachesEmptyResult(t *testing.T) {
	srv := newStubServer(t, serveFixture(t, "looking-glass-empty.json"))
	clock := newFakeClock()
	c, err := New(Config{
		BaseURL:         srv.URL,
		CacheTTL:        60 * time.Second,
		RateLimitPerMin: 100,
		Clock:           clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	prefix := mustPrefix(t, "203.0.113.0/24")
	for range 3 {
		clock.Advance(time.Second)
		summary, err := c.GlobalOrigins(context.Background(), prefix, 0)
		if err != nil {
			t.Fatalf("GlobalOrigins: %v", err)
		}
		if len(summary.Origins) != 0 {
			t.Errorf("Origins = %+v, want empty", summary.Origins)
		}
	}
	if got := srv.requests.Load(); got != 1 {
		t.Errorf("HTTP requests = %d, want 1", got)
	}
}

// Distinct prefixes are cached independently.
func TestGlobalOriginsCacheKeyedByPrefix(t *testing.T) {
	srv := newStubServer(t, serveFixture(t, "looking-glass-empty.json"))
	clock := newFakeClock()
	c, err := New(Config{
		BaseURL:         srv.URL,
		CacheTTL:        60 * time.Second,
		RateLimitPerMin: 100,
		Clock:           clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	for _, p := range []string{"203.0.113.0/24", "198.51.100.0/24", "203.0.113.0/24"} {
		if _, err := c.GlobalOrigins(context.Background(), mustPrefix(t, p), 0); err != nil {
			t.Fatalf("GlobalOrigins(%s): %v", p, err)
		}
	}
	if got := srv.requests.Load(); got != 2 {
		t.Errorf("HTTP requests = %d, want 2 (third lookup repeats the first prefix)", got)
	}
}

// ─── TestRateLimit ───

// Once the budget is spent, further uncached lookups are rejected locally
// rather than sent to RIPEstat.
func TestGlobalOriginsRateLimited(t *testing.T) {
	srv := newStubServer(t, serveFixture(t, "looking-glass-empty.json"))
	clock := newFakeClock()
	c, err := New(Config{
		BaseURL:         srv.URL,
		CacheTTL:        time.Nanosecond, // effectively disable the cache
		RateLimitPerMin: 3,
		Clock:           clock.Now,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Distinct prefixes so nothing can be served from cache.
	prefixes := []string{
		"203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24",
		"203.0.113.128/25", "198.51.100.128/25",
	}
	var rejected int
	for _, p := range prefixes {
		_, err := c.GlobalOrigins(context.Background(), mustPrefix(t, p), 0)
		if errors.Is(err, ErrRateLimited) {
			rejected++
			continue
		}
		if err != nil {
			t.Fatalf("GlobalOrigins(%s): unexpected error: %v", p, err)
		}
	}

	if rejected != 2 {
		t.Errorf("rejected = %d, want 2 (5 lookups against a budget of 3)", rejected)
	}
	if got := srv.requests.Load(); got != 3 {
		t.Errorf("HTTP requests = %d, want 3 — rate-limited lookups must not reach the API", got)
	}
}

// The bucket refills over time at budget/60 per second.
func TestRateLimitRefills(t *testing.T) {
	clock := newFakeClock()
	b := newTokenBucket(6, clock.Now) // one token per 10s

	for i := range 6 {
		if !b.allow() {
			t.Fatalf("allow %d: want true, initial burst is the full budget", i)
		}
	}
	if b.allow() {
		t.Fatal("allow after budget spent: want false")
	}

	clock.Advance(9 * time.Second)
	if b.allow() {
		t.Fatal("allow after 9s: want false, refill is one token per 10s")
	}
	clock.Advance(2 * time.Second)
	if !b.allow() {
		t.Fatal("allow after 11s: want true")
	}

	// Refill is capped at capacity, not accrued indefinitely.
	clock.Advance(time.Hour)
	for i := range 6 {
		if !b.allow() {
			t.Fatalf("allow %d after an hour: want true", i)
		}
	}
	if b.allow() {
		t.Fatal("allow past capacity after an hour: want false, burst is capped at the budget")
	}
}

// ─── TestGlobalOriginsFailureModes ───

// Every transport and protocol failure surfaces as an error for Correlate to
// turn into ConsensusInconclusive. None of them may panic.
func TestGlobalOriginsFailureModes(t *testing.T) {
	tests := []struct {
		name    string
		handler func(w http.ResponseWriter, r *http.Request)
	}{
		{
			name: "HTTP 500",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusInternalServerError)
			},
		},
		{
			name: "HTTP 429",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusTooManyRequests)
			},
		},
		{
			name: "not JSON",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				_, _ = w.Write([]byte("<html>service unavailable</html>"))
			},
		},
		{
			name: "empty body",
			handler: func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Type", "application/json")
			},
		},
		{
			name: "data call error status",
			handler: func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(fixture(t, "looking-glass-error-status.json"))
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			srv := newStubServer(t, tt.handler)
			c, err := New(Config{BaseURL: srv.URL})
			if err != nil {
				t.Fatalf("New: %v", err)
			}
			if _, err := c.GlobalOrigins(context.Background(), mustPrefix(t, "203.0.113.0/24"), 0); err == nil {
				t.Fatal("GlobalOrigins: want error, got nil")
			}
		})
	}
}

// A slow endpoint is bounded by the caller's context, and the failure does
// not poison the cache.
func TestGlobalOriginsContextCancelled(t *testing.T) {
	release := make(chan struct{})
	srv := newStubServer(t, func(w http.ResponseWriter, r *http.Request) {
		<-release
		serveFixture(t, "looking-glass-empty.json")(w, r)
	})
	t.Cleanup(func() { close(release) })

	c, err := New(Config{BaseURL: srv.URL})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if _, err := c.GlobalOrigins(ctx, mustPrefix(t, "203.0.113.0/24"), 0); err == nil {
		t.Fatal("GlobalOrigins: want error on context timeout, got nil")
	}

	c.mu.Lock()
	cached := len(c.cache)
	c.mu.Unlock()
	if cached != 0 {
		t.Errorf("cache holds %d entries after a failed fetch, want 0", cached)
	}
}

func TestGlobalOriginsInvalidPrefix(t *testing.T) {
	c, err := New(Config{})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	// The zero Prefix must be rejected before any network call is attempted;
	// the default base URL means a request here would hit the real API.
	if _, err := c.GlobalOrigins(context.Background(), netip.Prefix{}, 0); err == nil {
		t.Fatal("GlobalOrigins(zero prefix): want error, got nil")
	}
}

// ─── TestGlobalOriginsConcurrent ───

// The client is documented as safe for concurrent use; run under -race.
func TestGlobalOriginsConcurrent(t *testing.T) {
	srv := newStubServer(t, serveFixture(t, "looking-glass-moas.json"))
	c, err := New(Config{BaseURL: srv.URL, RateLimitPerMin: 1000})
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	prefixes := []string{"203.0.113.0/24", "198.51.100.0/24", "192.0.2.0/24"}
	var wg sync.WaitGroup
	for i := range 30 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _ = c.GlobalOrigins(context.Background(), mustPrefix(t, prefixes[i%len(prefixes)]), 0)
		}()
	}
	wg.Wait()
}
