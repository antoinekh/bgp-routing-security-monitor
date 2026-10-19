package types

import "testing"

func TestComputePosture(t *testing.T) {
	tests := []struct {
		rov  ROVState
		aspa ASPAState
		want SecurityPosture
	}{
		{ROVValid, ASPAValid, PostureSecured},
		{ROVValid, ASPAUnknown, PostureOriginOnly},
		{ROVValid, ASPAUnverifiable, PostureOriginOnly},
		{ROVValid, ASPAInvalid, PosturePathSuspect},
		{ROVNotFound, ASPAValid, PosturePathOnly},
		{ROVNotFound, ASPAUnknown, PostureUnverified},
		{ROVNotFound, ASPAUnverifiable, PostureUnverified},
		{ROVNotFound, ASPAInvalid, PosturePathSuspect},
		{ROVInvalid, ASPAValid, PostureOriginInvalid},
		{ROVInvalid, ASPAInvalid, PostureOriginInvalid},
		{ROVInvalid, ASPAUnknown, PostureOriginInvalid},
	}
	for _, tt := range tests {
		got := ComputePosture(tt.rov, tt.aspa)
		if got != tt.want {
			t.Errorf("ComputePosture(%v, %v) = %v, want %v",
				tt.rov, tt.aspa, got, tt.want)
		}
	}
}

// The origin AS is the last AS of the final segment when that is an
// AS_SEQUENCE (RFC 6811 §2). Confederation segments never give it: after a
// final one the route originated inside the router's confederation, whose
// AS RAVEN does not know, so there is no origin, as for an empty path.
func TestOriginASNRFC6811(t *testing.T) {
	sq := func(a ...uint32) ASSegment { return ASSegment{Type: ASSegmentSequence, ASNs: a} }
	st := func(a ...uint32) ASSegment { return ASSegment{Type: ASSegmentSet, ASNs: a} }
	cs := func(a ...uint32) ASSegment { return ASSegment{Type: ASSegmentConfedSequence, ASNs: a} }
	cset := func(a ...uint32) ASSegment { return ASSegment{Type: ASSegmentConfedSet, ASNs: a} }
	for _, tc := range []struct {
		name string
		segs []ASSegment
		want uint32
	}{
		{"AS_SEQUENCE", []ASSegment{sq(64501, 13335)}, 13335},
		{"confederation then AS_SEQUENCE", []ASSegment{cs(65001, 65002), sq(64500, 13335)}, 13335},
		{"AS_CONFED_SEQUENCE only", []ASSegment{cs(65001, 65002)}, 0},
		{"AS_CONFED_SET only", []ASSegment{cset(65001, 65002)}, 0},
		{"AS_SEQUENCE then confederation (out of order)", []ASSegment{sq(64500), cs(65001)}, 0},
		{"final AS_SET: its last member", []ASSegment{sq(64501), st(64510, 64511)}, 64511},
		{"empty", nil, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Route{ASPathRaw: tc.segs}
			for _, s := range tc.segs {
				r.ASPath = append(r.ASPath, s.ASNs...)
			}
			if got := r.OriginASN(); got != tc.want {
				t.Errorf("OriginASN() = %d, want %d", got, tc.want)
			}
		})
	}
	// Without segments, the flattened path's last AS.
	if got := (&Route{ASPath: []uint32{64501, 13335}}).OriginASN(); got != 13335 {
		t.Errorf("ASPath only: %d, want 13335", got)
	}
}
