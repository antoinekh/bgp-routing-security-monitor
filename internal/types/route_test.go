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

func TestRIBTypeString(t *testing.T) {
	for rib, want := range map[RIBType]string{
		AdjRIBInPre:  "pre-policy",
		AdjRIBInPost: "post-policy",
		LocRIB:       "loc-rib",
	} {
		if got := rib.String(); got != want {
			t.Errorf("RIBType(%d).String() = %q, want %q", rib, got, want)
		}
	}
}

func TestParseRIBType(t *testing.T) {
	for _, rib := range RIBTypes {
		if got, err := ParseRIBType(rib.String()); err != nil || got != rib {
			t.Errorf("ParseRIBType(%q) = %v, %v, want %v", rib.String(), got, err, rib)
		}
	}
	if _, err := ParseRIBType("adj-rib-out"); err == nil {
		t.Error("ParseRIBType accepted an unknown RIB type")
	}
}
