package api

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// TestRouteToResponseCarriesROAData checks that the ROA behind a verdict reaches
// the API. Without it a consumer cannot tell a wrong origin AS from a prefix
// that is merely more specific than the ROA allows.
func TestRouteToResponseCarriesROAData(t *testing.T) {
	route := &types.Route{
		Prefix:   netip.MustParsePrefix("80.12.10.128/28"),
		PeerAddr: netip.MustParseAddr("193.251.127.50"),
		PeerASN:  3215,
		NextHop:  netip.MustParseAddr("193.251.127.50"),
		ASPath:   []uint32{28708},
		ROV: types.ROVResult{
			State:      types.ROVInvalid,
			Reason:     "origin AS28708 not authorized by any covering VRP",
			ReasonCode: types.ROVReasonInvalidASN,
			MatchedVRPs: []types.VRP{
				{Prefix: netip.MustParsePrefix("80.12.0.0/18"), ASN: 3215, MaxLength: 32},
			},
		},
		ASPA:            types.ASPAResult{State: types.ASPAUnknown},
		SecurityPosture: types.PostureOriginInvalid,
	}

	got := routeToResponse(route)

	if got.ROVReasonCode != string(types.ROVReasonInvalidASN) {
		t.Errorf("rov_reason_code: got %q, want %q", got.ROVReasonCode, types.ROVReasonInvalidASN)
	}
	if len(got.MatchedVRPs) != 1 {
		t.Fatalf("matched_vrps: got %d entries, want 1", len(got.MatchedVRPs))
	}
	want := VRPResponse{Prefix: "80.12.0.0/18", ASN: 3215, MaxLength: 32}
	if got.MatchedVRPs[0] != want {
		t.Errorf("matched_vrps[0]: got %+v, want %+v", got.MatchedVRPs[0], want)
	}
}

// TestRouteToResponseOmitsEmptyROAData checks the new fields stay out of the
// JSON for a NotFound route, so existing consumers see an unchanged payload.
func TestRouteToResponseOmitsEmptyROAData(t *testing.T) {
	route := &types.Route{
		Prefix:   netip.MustParsePrefix("86.192.204.0/31"),
		PeerAddr: netip.MustParseAddr("193.251.127.167"),
		NextHop:  netip.MustParseAddr("193.251.127.167"),
		ROV: types.ROVResult{
			State:      types.ROVNotFound,
			Reason:     "no origin ASN in AS_PATH",
			ReasonCode: types.ROVReasonNoOriginASN,
		},
		ASPA:            types.ASPAResult{State: types.ASPAUnknown},
		SecurityPosture: types.PostureUnverified,
	}

	body, err := json.Marshal(routeToResponse(route))
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if _, present := decoded["matched_vrps"]; present {
		t.Errorf("matched_vrps must be omitted when there is no covering VRP, got %s", body)
	}
}

// TestVRPsToResponseNilForEmpty pins the nil return, which is what makes
// omitempty drop the field rather than emit an empty array.
func TestVRPsToResponseNilForEmpty(t *testing.T) {
	if out := vrpsToResponse(nil); out != nil {
		t.Errorf("got %v, want nil", out)
	}
	if out := vrpsToResponse([]types.VRP{}); out != nil {
		t.Errorf("got %v, want nil", out)
	}
}
