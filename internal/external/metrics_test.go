package external

import (
	"context"
	"errors"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// counterValue reads raven_global_check_total for one label pair straight off
// the default gatherer, the same path a Prometheus scrape takes. Returns 0
// when the series does not exist yet, which is how a CounterVec behaves
// before its first observation.
func counterValue(t *testing.T, source, result string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != "raven_global_check_total" {
			continue
		}
		for _, m := range mf.GetMetric() {
			var gotSource, gotResult string
			for _, l := range m.GetLabel() {
				switch l.GetName() {
				case "source":
					gotSource = l.GetValue()
				case "result":
					gotResult = l.GetValue()
				}
			}
			if gotSource == source && gotResult == result {
				return m.GetCounter().GetValue()
			}
		}
	}
	return 0
}

// sourceCounterValue reads a {source}-labelled counter off the default
// gatherer. Returns 0 before the series exists.
func sourceCounterValue(t *testing.T, name, source string) float64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == "source" && l.GetValue() == source {
					return m.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func rateLimitedValue(t *testing.T, source string) float64 {
	t.Helper()
	return sourceCounterValue(t, "raven_global_check_rate_limited_total", source)
}

func cacheHitsValue(t *testing.T, source string) float64 {
	t.Helper()
	return sourceCounterValue(t, "raven_global_check_cache_hits_total", source)
}

// histogramCount returns the observation count of
// raven_global_check_latency_seconds, or -1 if the metric is absent.
func histogramCount(t *testing.T) int64 {
	t.Helper()
	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather metrics: %v", err)
	}
	for _, mf := range families {
		if mf.GetName() != "raven_global_check_latency_seconds" {
			continue
		}
		for _, m := range mf.GetMetric() {
			return int64(m.GetHistogram().GetSampleCount())
		}
	}
	return -1
}

// ─── TestCorrelateRecordsMetrics ───

// Every completed correlation must land on
// raven_global_check_total{source,result} with the consensus as the result
// label, and contribute one observation to the latency histogram.
func TestCorrelateRecordsMetrics(t *testing.T) {
	prefix := mustPrefix(t, "203.0.113.0/24")

	tests := []struct {
		name       string
		provider   GlobalVisibilityProvider
		local      uint32
		wantResult string
	}{
		{
			name: "match",
			provider: &fakeProvider{name: "ripestat", summary: GlobalOriginSummary{
				Origins:        []GlobalOriginObservation{{ASN: 64511, CollectorCount: 9}},
				CollectorCount: 9,
			}},
			local:      64511,
			wantResult: "match",
		},
		{
			name: "divergent",
			provider: &fakeProvider{name: "ripestat", summary: GlobalOriginSummary{
				Origins:        []GlobalOriginObservation{{ASN: 65000, CollectorCount: 9}},
				CollectorCount: 9,
			}},
			local:      64511,
			wantResult: "divergent",
		},
		{
			name:       "local_only",
			provider:   &fakeProvider{name: "ripestat"},
			local:      64511,
			wantResult: "local_only",
		},
		{
			name:       "inconclusive",
			provider:   &fakeProvider{name: "ripestat", err: errors.New("boom")},
			local:      64511,
			wantResult: "inconclusive",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The metrics are process-global, so assert on deltas.
			startCounter := counterValue(t, "ripestat", tt.wantResult)
			startHist := histogramCount(t)
			startCacheHits := cacheHitsValue(t, "ripestat")

			Correlate(context.Background(), tt.provider, prefix, tt.local, 0)

			if got := counterValue(t, "ripestat", tt.wantResult) - startCounter; got != 1 {
				t.Errorf("raven_global_check_total{source=\"ripestat\",result=%q} delta = %v, want 1",
					tt.wantResult, got)
			}
			if got := histogramCount(t); got != startHist+1 {
				t.Errorf("raven_global_check_latency_seconds count = %d, want %d", got, startHist+1)
			}
			// None of these providers reports a cache hit, so the round-trip
			// they model belongs only in the histogram.
			if got := cacheHitsValue(t, "ripestat"); got != startCacheHits {
				t.Errorf("raven_global_check_cache_hits_total moved from %v to %v for a live fetch, want no change",
					startCacheHits, got)
			}
		})
	}
}

// ─── TestCorrelateCacheHitMetrics ───

// A cache hit is a real check — it gets a raven_global_check_total row — but
// it made no network round-trip, so it must stay out of the latency histogram
// and land on its own counter instead. Mixing in-process map reads with real
// RIPEstat round-trips pulls p50/p95 toward zero exactly when the cache is
// warm, hiding the provider latency degradation an operator alerts on.
func TestCorrelateCacheHitMetrics(t *testing.T) {
	prefix := mustPrefix(t, "203.0.113.0/24")
	p := &fakeProvider{name: "ripestat", summary: GlobalOriginSummary{
		Origins:        []GlobalOriginObservation{{ASN: 64511, CollectorCount: 9}},
		CollectorCount: 9,
		CacheHit:       true,
	}}

	startCacheHits := cacheHitsValue(t, "ripestat")
	startCounter := counterValue(t, "ripestat", "match")
	startHist := histogramCount(t)

	Correlate(context.Background(), p, prefix, 64511, 0)

	if got := cacheHitsValue(t, "ripestat") - startCacheHits; got != 1 {
		t.Errorf("raven_global_check_cache_hits_total{source=\"ripestat\"} delta = %v, want 1", got)
	}
	if got := histogramCount(t); got != startHist {
		t.Errorf("raven_global_check_latency_seconds count moved from %d to %d, want no change — "+
			"a cache hit is a map read, not a round-trip", startHist, got)
	}
	// Still counted as a check: the correlation happened and produced a
	// verdict, so cache hits must not vanish from raven_global_check_total.
	if got := counterValue(t, "ripestat", "match") - startCounter; got != 1 {
		t.Errorf("raven_global_check_total{source=\"ripestat\",result=\"match\"} delta = %v, want 1", got)
	}
}

// A rate-limited lookup is not a cache hit either — the two non-network paths
// must stay on separate counters.
func TestCorrelateRateLimitedIsNotACacheHit(t *testing.T) {
	prefix := mustPrefix(t, "203.0.113.0/24")
	p := &fakeProvider{name: "ripestat", err: ErrRateLimited}

	startCacheHits := cacheHitsValue(t, "ripestat")
	Correlate(context.Background(), p, prefix, 64511, 0)

	if got := cacheHitsValue(t, "ripestat"); got != startCacheHits {
		t.Errorf("raven_global_check_cache_hits_total moved from %v to %v for a rate-limited lookup, want no change",
			startCacheHits, got)
	}
}

// ─── TestCorrelateRateLimitedMetrics ───

// A rate-limited lookup gets its own counter and touches nothing else.
// Folding it into raven_global_check_total{result="inconclusive"} made a
// policy decision — near-zero cost, no network call — indistinguishable from
// a provider RAVEN could not reach, and its sub-microsecond timing dragged
// the latency histogram toward zero.
func TestCorrelateRateLimitedMetrics(t *testing.T) {
	prefix := mustPrefix(t, "203.0.113.0/24")
	p := &fakeProvider{name: "ripestat", err: ErrRateLimited}

	// The metrics are process-global, so assert on deltas.
	startRateLimited := rateLimitedValue(t, "ripestat")
	startInconclusive := counterValue(t, "ripestat", "inconclusive")
	startHist := histogramCount(t)

	Correlate(context.Background(), p, prefix, 64511, 0)

	if got := rateLimitedValue(t, "ripestat") - startRateLimited; got != 1 {
		t.Errorf("raven_global_check_rate_limited_total{source=\"ripestat\"} delta = %v, want 1", got)
	}
	if got := counterValue(t, "ripestat", "inconclusive"); got != startInconclusive {
		t.Errorf("raven_global_check_total{result=\"inconclusive\"} moved from %v to %v, want no change — "+
			"a rate-limit rejection is not a check result", startInconclusive, got)
	}
	if got := histogramCount(t); got != startHist {
		t.Errorf("raven_global_check_latency_seconds count moved from %d to %d, want no change — "+
			"no network call was made, so there is no latency to observe", startHist, got)
	}
}

// A nil provider is not a check, so it must not be counted — otherwise a
// misconfigured deployment would look like a stream of real inconclusive
// results.
func TestCorrelateNilProviderNotCounted(t *testing.T) {
	prefix := mustPrefix(t, "203.0.113.0/24")
	startCounter := counterValue(t, "", "inconclusive")
	startHist := histogramCount(t)

	Correlate(context.Background(), nil, prefix, 64511, 0)

	if got := counterValue(t, "", "inconclusive"); got != startCounter {
		t.Errorf("counter moved from %v to %v for a nil provider, want no change", startCounter, got)
	}
	if got := histogramCount(t); got != startHist {
		t.Errorf("histogram count moved from %d to %d for a nil provider, want no change", startHist, got)
	}
}
