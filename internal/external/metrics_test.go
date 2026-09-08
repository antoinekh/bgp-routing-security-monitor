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

			Correlate(context.Background(), tt.provider, prefix, tt.local, 0)

			if got := counterValue(t, "ripestat", tt.wantResult) - startCounter; got != 1 {
				t.Errorf("raven_global_check_total{source=\"ripestat\",result=%q} delta = %v, want 1",
					tt.wantResult, got)
			}
			if got := histogramCount(t); got != startHist+1 {
				t.Errorf("raven_global_check_latency_seconds count = %d, want %d", got, startHist+1)
			}
		})
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
