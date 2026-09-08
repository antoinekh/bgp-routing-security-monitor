package external

import "testing"

// ─── TestConsensus ───

func TestConsensus(t *testing.T) {
	tests := []struct {
		name        string
		localOrigin uint32
		origins     []GlobalOriginObservation
		want        GlobalConsensus
		wantReason  bool
	}{
		{
			name:        "match — sole global origin is the local origin",
			localOrigin: 15169,
			origins:     []GlobalOriginObservation{{ASN: 15169, CollectorCount: 9}},
			want:        ConsensusMatch,
		},
		{
			name:        "match — local origin is the strict majority in a MOAS",
			localOrigin: 64511,
			origins: []GlobalOriginObservation{
				{ASN: 64511, CollectorCount: 30},
				{ASN: 65000, CollectorCount: 2},
			},
			want: ConsensusMatch,
		},
		{
			name:        "divergent — the world sees a different origin entirely",
			localOrigin: 64511,
			origins:     []GlobalOriginObservation{{ASN: 65000, CollectorCount: 20}},
			want:        ConsensusDivergent,
		},
		{
			name:        "divergent — local origin is present but in the minority",
			localOrigin: 64511,
			origins: []GlobalOriginObservation{
				{ASN: 65000, CollectorCount: 25},
				{ASN: 64511, CollectorCount: 3},
			},
			want: ConsensusDivergent,
		},
		{
			// A MOAS conflict at equal global visibility is not a clean
			// match: the operator still needs to look at it.
			name:        "divergent — local origin only tied for most-observed",
			localOrigin: 64511,
			origins: []GlobalOriginObservation{
				{ASN: 64511, CollectorCount: 10},
				{ASN: 65000, CollectorCount: 10},
			},
			want: ConsensusDivergent,
		},
		{
			name:        "local only — no external observations at all",
			localOrigin: 64511,
			origins:     nil,
			want:        ConsensusLocalOnly,
		},
		{
			name:        "local only — takes precedence over a missing local origin",
			localOrigin: 0,
			origins:     []GlobalOriginObservation{},
			want:        ConsensusLocalOnly,
		},
		{
			name:        "inconclusive — no local origin to compare against",
			localOrigin: 0,
			origins:     []GlobalOriginObservation{{ASN: 15169, CollectorCount: 9}},
			want:        ConsensusInconclusive,
			wantReason:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, reason := Consensus(tt.localOrigin, tt.origins)
			if got != tt.want {
				t.Errorf("Consensus = %q, want %q", got, tt.want)
			}
			if tt.wantReason && reason == "" {
				t.Error("Consensus: want a non-empty reason for an inconclusive verdict")
			}
			if !tt.wantReason && reason != "" {
				t.Errorf("Consensus reason = %q, want empty", reason)
			}
		})
	}
}

// ─── TestSortObservations ───

func TestSortObservations(t *testing.T) {
	obs := []GlobalOriginObservation{
		{ASN: 65000, CollectorCount: 2},
		{ASN: 64511, CollectorCount: 30},
		// Equal counts break ties by ascending ASN so output and the
		// majority pick are deterministic.
		{ASN: 65002, CollectorCount: 2},
		{ASN: 64999, CollectorCount: 2},
	}
	SortObservations(obs)

	want := []GlobalOriginObservation{
		{ASN: 64511, CollectorCount: 30},
		{ASN: 64999, CollectorCount: 2},
		{ASN: 65000, CollectorCount: 2},
		{ASN: 65002, CollectorCount: 2},
	}
	for i := range want {
		if obs[i] != want[i] {
			t.Errorf("obs[%d] = %+v, want %+v", i, obs[i], want[i])
		}
	}
}

func TestSortObservationsEmpty(t *testing.T) {
	SortObservations(nil)
	SortObservations([]GlobalOriginObservation{})
}

// ─── TestMajorityOrigin ───

func TestMajorityOrigin(t *testing.T) {
	r := GlobalVisibilityResult{GlobalOrigins: []GlobalOriginObservation{
		{ASN: 64511, CollectorCount: 30},
		{ASN: 65000, CollectorCount: 2},
	}}
	asn, ok := r.MajorityOrigin()
	if !ok || asn != 64511 {
		t.Errorf("MajorityOrigin = (%d, %v), want (64511, true)", asn, ok)
	}

	empty := GlobalVisibilityResult{}
	if asn, ok := empty.MajorityOrigin(); ok || asn != 0 {
		t.Errorf("MajorityOrigin on empty = (%d, %v), want (0, false)", asn, ok)
	}
}
