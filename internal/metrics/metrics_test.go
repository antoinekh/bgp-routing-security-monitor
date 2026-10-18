package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// Bounded label sets are exported at 0 before anything increments them, so
// an alert can tell zero from absent.
func TestBoundedSeriesExportedAtZero(t *testing.T) {
	mfs, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatal(err)
	}
	type series struct{ name, labels string }
	got := map[series]bool{}
	for _, mf := range mfs {
		for _, m := range mf.GetMetric() {
			labels := ""
			for _, l := range m.GetLabel() {
				labels += l.GetName() + "=" + l.GetValue() + ","
			}
			zero := m.GetCounter().GetValue() == 0 && m.GetHistogram().GetSampleCount() == 0
			got[series{mf.GetName(), labels}] = zero
		}
	}
	for _, want := range []series{
		{"raven_bmp_rejected_connections_total", "reason=not_allowed,"},
		{"raven_bmp_rejected_connections_total", "reason=bad_remote_addr,"},
		{"raven_revalidation_duration_seconds", "mode=incremental,"},
		{"raven_revalidation_duration_seconds", "mode=full,"},
		{"raven_revalidation_routes_total", "mode=incremental,result=checked,"},
		{"raven_revalidation_routes_total", "mode=incremental,result=changed,"},
		{"raven_revalidation_routes_total", "mode=full,result=checked,"},
		{"raven_revalidation_routes_total", "mode=full,result=changed,"},
	} {
		zero, ok := got[want]
		if !ok || !zero {
			t.Errorf("%s{%s} exported=%v at zero=%v, want exported at 0", want.name, want.labels, ok, zero)
		}
	}
}
