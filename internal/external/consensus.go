package external

import (
	"cmp"
	"slices"
)

// Reasons recorded in GlobalVisibilityResult.Error for inconclusive verdicts
// that are not provider failures.
const (
	reasonNoProvider    = "no global visibility provider configured"
	reasonNoLocalOrigin = "no local BMP-observed origin to compare against"
)

// SortObservations orders observations most-observed first, breaking ties by
// ascending ASN so output and consensus are deterministic.
func SortObservations(obs []GlobalOriginObservation) {
	slices.SortFunc(obs, func(a, b GlobalOriginObservation) int {
		if c := cmp.Compare(b.CollectorCount, a.CollectorCount); c != 0 {
			return c
		}
		return cmp.Compare(a.ASN, b.ASN)
	})
}

// Consensus compares a local BMP-observed origin against external
// observations and returns the verdict plus, for inconclusive verdicts, the
// reason. obs is expected to be sorted by SortObservations.
//
// The Match bar is a strict majority: the local origin must be the single
// most-observed origin. A tie between the local origin and another ASN is a
// MOAS conflict at equal global visibility, which is reported as Divergent
// rather than Match — the operator still needs to look at it.
func Consensus(localOrigin uint32, obs []GlobalOriginObservation) (GlobalConsensus, string) {
	// No external observations at all: the route is only in the local view.
	// This is checked before the local-origin guard because "the world has
	// never heard of this prefix" is a useful answer even without a baseline.
	if len(obs) == 0 {
		return ConsensusLocalOnly, ""
	}
	if localOrigin == 0 {
		return ConsensusInconclusive, reasonNoLocalOrigin
	}

	top := obs[0].CollectorCount
	tied := 0
	for _, o := range obs {
		if o.CollectorCount == top {
			tied++
		}
	}
	if tied == 1 && obs[0].ASN == localOrigin {
		return ConsensusMatch, ""
	}
	return ConsensusDivergent, ""
}
