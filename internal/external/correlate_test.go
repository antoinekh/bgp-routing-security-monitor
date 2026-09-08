package external

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"
)

// fakeProvider is a GlobalVisibilityProvider stand-in. It records the calls it
// received so tests can assert on maxAge propagation without any network.
type fakeProvider struct {
	name    string
	summary GlobalOriginSummary
	err     error
	delay   time.Duration

	calls      int
	lastPrefix netip.Prefix
	lastMaxAge time.Duration
}

func (f *fakeProvider) Name() string {
	if f.name == "" {
		return "fake"
	}
	return f.name
}

func (f *fakeProvider) GlobalOrigins(
	ctx context.Context,
	prefix netip.Prefix,
	maxAge time.Duration,
) (GlobalOriginSummary, error) {
	f.calls++
	f.lastPrefix = prefix
	f.lastMaxAge = maxAge
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return GlobalOriginSummary{}, ctx.Err()
		}
	}
	if f.err != nil {
		return GlobalOriginSummary{}, f.err
	}
	return f.summary, nil
}

func mustPrefix(t *testing.T, s string) netip.Prefix {
	t.Helper()
	p, err := netip.ParsePrefix(s)
	if err != nil {
		t.Fatalf("parse prefix %q: %v", s, err)
	}
	return p
}

// ─── TestCorrelate ───

func TestCorrelate(t *testing.T) {
	prefix := mustPrefix(t, "203.0.113.0/24")

	t.Run("match", func(t *testing.T) {
		p := &fakeProvider{
			name: "ripestat",
			summary: GlobalOriginSummary{
				Origins:        []GlobalOriginObservation{{ASN: 64511, CollectorCount: 20}},
				CollectorCount: 20,
			},
		}
		got := Correlate(context.Background(), p, prefix, 64511, 0)

		if got.Consensus != ConsensusMatch {
			t.Errorf("Consensus = %q, want %q", got.Consensus, ConsensusMatch)
		}
		if !got.Queried {
			t.Error("Queried = false, want true")
		}
		if got.Source != "ripestat" {
			t.Errorf("Source = %q, want ripestat", got.Source)
		}
		if got.LocalOrigin != 64511 {
			t.Errorf("LocalOrigin = %d, want 64511", got.LocalOrigin)
		}
		if got.CollectorCount != 20 {
			t.Errorf("CollectorCount = %d, want 20", got.CollectorCount)
		}
		if got.Error != "" {
			t.Errorf("Error = %q, want empty", got.Error)
		}
		if got.QueriedAt.IsZero() {
			t.Error("QueriedAt is zero, want a timestamp")
		}
	})

	t.Run("divergent", func(t *testing.T) {
		p := &fakeProvider{summary: GlobalOriginSummary{
			Origins:        []GlobalOriginObservation{{ASN: 65000, CollectorCount: 18}},
			CollectorCount: 18,
		}}
		got := Correlate(context.Background(), p, prefix, 64511, 0)
		if got.Consensus != ConsensusDivergent {
			t.Errorf("Consensus = %q, want %q", got.Consensus, ConsensusDivergent)
		}
		if asn, ok := got.MajorityOrigin(); !ok || asn != 65000 {
			t.Errorf("MajorityOrigin = (%d, %v), want (65000, true)", asn, ok)
		}
	})

	t.Run("local only", func(t *testing.T) {
		p := &fakeProvider{summary: GlobalOriginSummary{}}
		got := Correlate(context.Background(), p, prefix, 64511, 0)
		if got.Consensus != ConsensusLocalOnly {
			t.Errorf("Consensus = %q, want %q", got.Consensus, ConsensusLocalOnly)
		}
		if len(got.GlobalOrigins) != 0 {
			t.Errorf("GlobalOrigins = %+v, want empty", got.GlobalOrigins)
		}
	})

	// Correlate sorts whatever the provider returns, so a provider that does
	// not sort cannot skew the majority pick.
	t.Run("sorts unsorted provider output", func(t *testing.T) {
		p := &fakeProvider{summary: GlobalOriginSummary{
			Origins: []GlobalOriginObservation{
				{ASN: 65000, CollectorCount: 2},
				{ASN: 64511, CollectorCount: 30},
			},
			CollectorCount: 32,
		}}
		got := Correlate(context.Background(), p, prefix, 64511, 0)
		if got.Consensus != ConsensusMatch {
			t.Errorf("Consensus = %q, want %q", got.Consensus, ConsensusMatch)
		}
		if got.GlobalOrigins[0].ASN != 64511 {
			t.Errorf("GlobalOrigins[0].ASN = %d, want 64511", got.GlobalOrigins[0].ASN)
		}
	})

	t.Run("passes maxAge through to the provider", func(t *testing.T) {
		p := &fakeProvider{summary: GlobalOriginSummary{}}
		Correlate(context.Background(), p, prefix, 64511, 90*time.Second)
		if p.lastMaxAge != 90*time.Second {
			t.Errorf("provider maxAge = %v, want 90s", p.lastMaxAge)
		}
		if p.lastPrefix != prefix {
			t.Errorf("provider prefix = %v, want %v", p.lastPrefix, prefix)
		}
	})
}

// ─── TestCorrelateFailsOpen ───

// Correlate never returns an error. Every failure mode must resolve to
// ConsensusInconclusive with the cause recorded, so callers can attach the
// result unconditionally.
func TestCorrelateFailsOpen(t *testing.T) {
	prefix := mustPrefix(t, "203.0.113.0/24")

	t.Run("provider error", func(t *testing.T) {
		p := &fakeProvider{err: errors.New("query RIPEstat: connection refused")}
		got := Correlate(context.Background(), p, prefix, 64511, 0)

		if got.Consensus != ConsensusInconclusive {
			t.Errorf("Consensus = %q, want %q", got.Consensus, ConsensusInconclusive)
		}
		if got.Error == "" {
			t.Error("Error is empty, want the provider failure recorded")
		}
		if !got.Queried {
			t.Error("Queried = false, want true — a provider was consulted")
		}
	})

	t.Run("nil provider", func(t *testing.T) {
		got := Correlate(context.Background(), nil, prefix, 64511, 0)

		if got.Consensus != ConsensusInconclusive {
			t.Errorf("Consensus = %q, want %q", got.Consensus, ConsensusInconclusive)
		}
		if got.Queried {
			t.Error("Queried = true, want false — nothing was consulted")
		}
		if got.Source != "" {
			t.Errorf("Source = %q, want empty", got.Source)
		}
		if got.Error == "" {
			t.Error("Error is empty, want an explanation")
		}
	})

	t.Run("context timeout", func(t *testing.T) {
		p := &fakeProvider{delay: time.Second}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
		defer cancel()

		got := Correlate(ctx, p, prefix, 64511, 0)
		if got.Consensus != ConsensusInconclusive {
			t.Errorf("Consensus = %q, want %q", got.Consensus, ConsensusInconclusive)
		}
		if got.Error == "" {
			t.Error("Error is empty, want the timeout recorded")
		}
	})

	t.Run("no local origin", func(t *testing.T) {
		p := &fakeProvider{summary: GlobalOriginSummary{
			Origins:        []GlobalOriginObservation{{ASN: 65000, CollectorCount: 5}},
			CollectorCount: 5,
		}}
		got := Correlate(context.Background(), p, prefix, 0, 0)
		if got.Consensus != ConsensusInconclusive {
			t.Errorf("Consensus = %q, want %q", got.Consensus, ConsensusInconclusive)
		}
		if got.Error == "" {
			t.Error("Error is empty, want an explanation")
		}
		// The observations are still attached — they are useful to the
		// operator even without a local baseline.
		if len(got.GlobalOrigins) != 1 {
			t.Errorf("GlobalOrigins = %+v, want the observations retained", got.GlobalOrigins)
		}
	})
}
