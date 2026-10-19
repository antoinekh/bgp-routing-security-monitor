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
// AS_SEQUENCE (RFC 6811 §2). With an empty AS_PATH, or after a final
// AS_CONFED_SEQUENCE or AS_CONFED_SET, it is the router's own AS: its
// confederation identifier if known, else LocalASN.
// Member ASes in the path never give it. After a final AS_SET it is NONE.
func TestOriginASNRFC6811(t *testing.T) {
	sq := func(a ...uint32) ASSegment { return ASSegment{Type: ASSegmentSequence, ASNs: a} }
	st := func(a ...uint32) ASSegment { return ASSegment{Type: ASSegmentSet, ASNs: a} }
	cs := func(a ...uint32) ASSegment { return ASSegment{Type: ASSegmentConfedSequence, ASNs: a} }
	cset := func(a ...uint32) ASSegment { return ASSegment{Type: ASSegmentConfedSet, ASNs: a} }
	for _, tc := range []struct {
		name            string
		segs            []ASSegment
		local, confedID uint32
		want            uint32
		src             OriginSource
	}{
		{"AS_SEQUENCE", []ASSegment{sq(64501, 13335)}, 64500, 64999, 13335, OriginFromPath},
		{"confederation then AS_SEQUENCE", []ASSegment{cs(65001, 65002), sq(64500, 13335)}, 65001, 64999, 13335, OriginFromPath},
		{"AS_CONFED_SEQUENCE only, identifier known", []ASSegment{cs(65001, 65002)}, 65001, 64999, 64999, OriginConfedID},
		{"AS_CONFED_SET only, identifier known", []ASSegment{cset(65001, 65002)}, 65001, 64999, 64999, OriginConfedID},
		{"AS_CONFED_SEQUENCE only, member AS", []ASSegment{cs(65001, 65002)}, 65001, 0, 65001, OriginConfedMember},
		{"AS_CONFED_SEQUENCE only, nothing known", []ASSegment{cs(65001, 65002)}, 0, 0, 0, OriginConfedMember},
		{"AS_SEQUENCE then confederation (out of order)", []ASSegment{sq(64500), cs(65001)}, 65001, 0, 65001, OriginConfedMember},
		{"final AS_SET: NONE", []ASSegment{sq(64501), st(64510, 64511)}, 64500, 0, 0, OriginNone},
		{"AS_SET then AS_SEQUENCE", []ASSegment{st(64510, 64511), sq(64501)}, 64500, 0, 64501, OriginFromPath},
		{"empty: local AS", nil, 64500, 0, 64500, OriginLocalAS},
		{"empty inside a confederation, identifier known", nil, 65001, 64999, 64999, OriginLocalConfedID},
		{"empty, local AS not known", nil, 0, 0, 0, OriginLocalAS},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Route{ASPathRaw: tc.segs, LocalASN: tc.local, ConfedID: tc.confedID}
			for _, s := range tc.segs {
				r.ASPath = append(r.ASPath, s.ASNs...)
			}
			if got, src := r.OriginAS(); got != tc.want || src != tc.src {
				t.Errorf("OriginAS() = %d, %d; want %d, %d", got, src, tc.want, tc.src)
			}
			if got := r.OriginASN(); got != tc.want {
				t.Errorf("OriginASN() = %d, want %d", got, tc.want)
			}
			wantNone := len(tc.segs) > 0 && tc.segs[len(tc.segs)-1].Type == ASSegmentSet
			if got := r.OriginIsNone(); got != wantNone {
				t.Errorf("OriginIsNone() = %v, want %v", got, wantNone)
			}
		})
	}
	// Without segments, the flattened path's last AS.
	if got := (&Route{ASPath: []uint32{64501, 13335}}).OriginASN(); got != 13335 {
		t.Errorf("ASPath only: %d, want 13335", got)
	}
}

// A Loc-RIB AS_PATH holding only the router's own AS (LocalASN), as FRR 10.2
// sends a locally originated route, is an empty path to the origin rule:
// origin the local AS, or the confederation identifier. Anything else in it,
// or any other RIB, and the path's own origin stands.
func TestOriginASLocRIBOnlyLocalAS(t *testing.T) {
	sq := func(a ...uint32) ASSegment { return ASSegment{Type: ASSegmentSequence, ASNs: a} }
	st := func(a ...uint32) ASSegment { return ASSegment{Type: ASSegmentSet, ASNs: a} }
	for _, tc := range []struct {
		name            string
		rib             RIBType
		segs            []ASSegment
		local, confedID uint32
		want            uint32
		src             OriginSource
		empty           bool
	}{
		{"[local AS]", LocRIB, []ASSegment{sq(65000)}, 65000, 0, 65000, OriginLocalAS, true},
		{"[local AS] prepended", LocRIB, []ASSegment{sq(65000, 65000)}, 65000, 0, 65000, OriginLocalAS, true},
		{"[local AS] in two segments", LocRIB, []ASSegment{sq(65000), sq(65000)}, 65000, 0, 65000, OriginLocalAS, true},
		{"[local AS], confederation identifier known", LocRIB, []ASSegment{sq(65001)}, 65001, 64999, 64999, OriginLocalConfedID, true},
		{"empty", LocRIB, nil, 65000, 0, 65000, OriginLocalAS, true},
		{"leading local AS", LocRIB, []ASSegment{sq(65000, 64510, 64500)}, 65000, 0, 64500, OriginFromPath, false},
		{"local AS last", LocRIB, []ASSegment{sq(64510, 65000)}, 65000, 0, 65000, OriginFromPath, false},
		{"AS_SET of the local AS", LocRIB, []ASSegment{st(65000)}, 65000, 0, 0, OriginNone, false},
		{"local AS not known", LocRIB, []ASSegment{sq(65000)}, 0, 0, 65000, OriginFromPath, false},
		{"Adj-RIB-In", AdjRIBInPre, []ASSegment{sq(65000)}, 65000, 64999, 65000, OriginFromPath, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := Route{RIBType: tc.rib, ASPathRaw: tc.segs, LocalASN: tc.local, ConfedID: tc.confedID}
			for _, s := range tc.segs {
				r.ASPath = append(r.ASPath, s.ASNs...)
			}
			if got, src := r.OriginAS(); got != tc.want || src != tc.src {
				t.Errorf("OriginAS() = %d, %d; want %d, %d", got, src, tc.want, tc.src)
			}
			if got := r.EmptyPath(); got != tc.empty {
				t.Errorf("EmptyPath() = %v, want %v", got, tc.empty)
			}
			// A route restored from a snapshot has the flattened path only.
			r.ASPathRaw = nil
			if tc.rib == LocRIB && tc.segs != nil && tc.segs[0].Type == ASSegmentSequence {
				if got, src := r.OriginAS(); got != tc.want || src != tc.src {
					t.Errorf("flattened path only: OriginAS() = %d, %d; want %d, %d", got, src, tc.want, tc.src)
				}
			}
		})
	}
}
