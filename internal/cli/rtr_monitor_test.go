package cli

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/telemetry"
)

// A cache that answers Error Report code 2 (No Data Available, e.g.
// Routinator's "Running initial validation" at startup) is not ready yet,
// not faulty: rtr monitor reports a low-severity cache_not_ready event, not a
// high-severity structural anomaly. Driven end to end, from the cache's
// Error Report through the client's telemetry to the monitor's detector.
func TestRTRMonitorClassifiesNoDataAvailableAsCacheNotReady(t *testing.T) {
	cache := rtrtest.NewCache(t)
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	rec := telemetry.NewRecorder(io.Discard, 16, log)
	client, err := rtr.NewClient(cache.Addr(), "tcp", nil, store.NewVRPStore(), store.NewASPAStore(), 2, log)
	if err != nil {
		t.Fatal(err)
	}
	client.SetTelemetry(rec)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		client.Start(ctx)
	}()
	defer func() {
		cancel()
		<-done
	}()

	q := cache.Next(5 * time.Second)
	q.Conn.Send(rtrtest.ErrorReport(2, 2, "Running initial validation"))

	detector := telemetry.NewDetector(telemetry.DefaultAnomalyConfig())
	deadline := time.After(5 * time.Second)
	for {
		select {
		case ev := <-rec.Events():
			if ev.EventType != telemetry.EventError {
				continue
			}
			anomaly, _ := observeRTREvent(detector, ev, log)
			if anomaly == nil || anomaly.Trigger != "cache_not_ready" || anomaly.Severity != "low" {
				t.Fatalf("Error Report code 2 classified as %+v, want a low-severity cache_not_ready event", anomaly)
			}
			return
		case <-deadline:
			t.Fatal("no error event recorded for the cache's Error Report")
		}
	}
}

// Any other Error Report is still a high-severity structural anomaly.
func TestRTRMonitorOtherErrorReportsStayHighSeverity(t *testing.T) {
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	detector := telemetry.NewDetector(telemetry.DefaultAnomalyConfig())
	for _, code := range []*uint16{nil, ptr(uint16(0)), ptr(uint16(4))} {
		ev := telemetry.SessionEvent{Cache: "c", EventType: telemetry.EventError, ErrorCode: code, Timestamp: time.Now()}
		anomaly, _ := observeRTREvent(detector, ev, log)
		if anomaly == nil || anomaly.Category != "structural" || anomaly.Severity != "high" || anomaly.Trigger != "error_report" {
			t.Errorf("error code %v classified as %+v, want a high-severity structural error_report", code, anomaly)
		}
	}
}

func ptr[T any](v T) *T { return &v }
