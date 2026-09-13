// Package external correlates RAVEN's local BMP-observed routing state
// against routing data observed by third-party collectors.
//
// RAVEN's ROV and ASPA validation is entirely local-vantage-point: it knows
// only what the BMP-attached routers received. That cannot distinguish a real
// hijack the rest of the internet also sees from a purely local leak or
// misconfiguration. This package closes that gap by asking an external
// looking-glass provider which origin ASNs the world sees for a prefix and
// comparing that against the local origin.
//
// External correlation is never on the BMP ingest or validation path. It runs
// only on explicit CLI invocation or from the Event Engine's own goroutines,
// behind a cache and a rate limiter. Every failure mode degrades to
// ConsensusInconclusive rather than propagating an error.
package external

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// ErrRateLimited is the sentinel a provider returns when its own rate limiter
// suppressed a lookup before any network call was made.
//
// Correlate recognises it and accounts for it apart from a failed query:
// nothing was consulted, so the result is not marked Queried, no latency is
// recorded, and the check lands on raven_global_check_rate_limited_total
// rather than raven_global_check_total. A local policy decision and a
// provider RAVEN could not reach are different operational problems and must
// not share a metric.
//
// It lives here, not in a provider package, so Correlate can test for it
// without importing any provider.
var ErrRateLimited = errors.New("suppressed by local rate limit")

// GlobalConsensus is the verdict of comparing the local BMP-observed origin
// against externally observed origins. The string values double as the
// `result` label on the raven_global_check_total metric.
type GlobalConsensus string

const (
	// ConsensusMatch means the local origin is the single most-observed
	// origin globally — the route looks the same from outside.
	ConsensusMatch GlobalConsensus = "match"
	// ConsensusDivergent means the world's majority origin is not the local
	// origin, or the local origin is only tied for most-observed (a MOAS
	// conflict). Both warrant operator attention.
	ConsensusDivergent GlobalConsensus = "divergent"
	// ConsensusLocalOnly means the provider has no observations at all for
	// this prefix. The route exists only in the local view, which points at
	// a leak or misconfiguration rather than a globally propagated hijack.
	ConsensusLocalOnly GlobalConsensus = "local_only"
	// ConsensusInconclusive means the correlation could not be performed:
	// the query failed, timed out, returned malformed data, was suppressed
	// by the rate limiter, or there was no local origin to compare against.
	ConsensusInconclusive GlobalConsensus = "inconclusive"
)

// String implements fmt.Stringer.
func (c GlobalConsensus) String() string { return string(c) }

// GlobalOriginObservation is one origin ASN and how widely it was seen.
type GlobalOriginObservation struct {
	ASN uint32 `json:"asn"`
	// CollectorCount is the number of distinct collector peers that reported
	// this ASN as the origin. A collector peer is one (route collector, peer
	// address) pair, so a single collector with many peering sessions
	// contributes more than one.
	CollectorCount int `json:"collector_count"`
}

// GlobalOriginSummary is a provider's raw answer for one prefix, before any
// comparison against local state.
type GlobalOriginSummary struct {
	// Origins is sorted by CollectorCount descending, then ASN ascending.
	// Empty means the provider has no observations for the prefix.
	Origins []GlobalOriginObservation
	// CollectorCount is the total number of distinct collector peers that
	// reported an observation, in the same unit as
	// GlobalOriginObservation.CollectorCount.
	CollectorCount int
}

// GlobalVisibilityResult is the annotation produced by a correlation. It is a
// standalone annotation type: it deliberately does not feed into
// types.SecurityPosture, which stays a pure local ROV x ASPA product.
type GlobalVisibilityResult struct {
	// Queried is true when a provider was actually consulted (including a
	// cache hit). It is false when no provider was configured, and when the
	// lookup was suppressed by the rate limiter before the provider was
	// reached — see ErrRateLimited.
	Queried bool `json:"queried"`
	// Source is the provider identifier, e.g. "ripestat".
	Source string `json:"source,omitempty"`
	// QueriedAt is when the correlation ran, not when the underlying
	// observation was collected.
	QueriedAt time.Time `json:"queried_at"`
	// LocalOrigin is the BMP-observed origin ASN used as the baseline.
	// Zero means no local baseline was available.
	LocalOrigin uint32 `json:"local_origin"`
	// GlobalOrigins is what the provider saw, sorted most-observed first.
	GlobalOrigins []GlobalOriginObservation `json:"global_origins,omitempty"`
	Consensus     GlobalConsensus           `json:"consensus"`
	// CollectorCount is the total distinct collector peers reporting.
	CollectorCount int `json:"collector_count"`
	// Latency is how long the correlation took, in nanoseconds on the wire.
	// Zero when nothing was consulted, including a rate-limited lookup:
	// the time spent rejecting a call is not a latency measurement.
	Latency time.Duration `json:"latency_ns"`
	// Error explains a ConsensusInconclusive verdict. Empty otherwise.
	Error string `json:"error,omitempty"`
}

// MajorityOrigin returns the most widely observed origin ASN and whether one
// was observed at all.
func (r GlobalVisibilityResult) MajorityOrigin() (uint32, bool) {
	if len(r.GlobalOrigins) == 0 {
		return 0, false
	}
	return r.GlobalOrigins[0].ASN, true
}

// GlobalVisibilityProvider resolves the externally observed origin ASNs for a
// prefix. Implementations are expected to cache and rate-limit internally.
//
// The interface exists so the RIPEstat implementation can be replaced by a
// fake in tests; nothing in the test suite may reach the real API.
type GlobalVisibilityProvider interface {
	// Name is the provider identifier recorded in results and metrics.
	Name() string
	// GlobalOrigins returns the observations for prefix.
	//
	// maxAge is the caller's freshness requirement: a cached answer younger
	// than maxAge may be returned without a network call. A maxAge of zero
	// or less means "use the provider's configured default".
	//
	// A prefix with no observations is not an error: implementations return
	// an empty summary and a nil error. Errors are reserved for query
	// failures, and callers translate them into ConsensusInconclusive.
	GlobalOrigins(ctx context.Context, prefix netip.Prefix, maxAge time.Duration) (GlobalOriginSummary, error)
}
