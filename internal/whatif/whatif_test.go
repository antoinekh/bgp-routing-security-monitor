package whatif

import (
	"context"
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// What an import policy would drop is a pre-policy question: a prefix the
// router reports both pre-policy and in its Loc-RIB is one route received,
// counted once, and the Loc-RIB instance is not a peer.
func TestSimulationsCountPrePolicyOnly(t *testing.T) {
	router := netip.MustParseAddr("192.0.2.1")
	bgp := netip.MustParseAddr("192.0.2.9")
	p := netip.MustParsePrefix("203.0.113.0/24")
	invalid := types.ROVResult{State: types.ROVInvalid, Reason: "origin AS mismatch"}
	table := routetable.New()
	table.Insert(&types.Route{Router: router, PeerAddr: bgp, PeerASN: 64501, Prefix: p,
		ASPath: []uint32{64501, 64666}, RIBType: types.AdjRIBInPre, ROV: invalid,
		SecurityPosture: types.PostureOriginInvalid})
	table.Insert(&types.Route{Router: router, PeerType: types.PeerTypeLocRIB, PeerAddr: netip.IPv4Unspecified(),
		PeerASN: 65000, LocalASN: 65000, Prefix: p, ASPath: []uint32{64501, 64666}, RIBType: types.LocRIB,
		ROV: invalid, SecurityPosture: types.PostureOriginInvalid})
	s := NewSimulator(table)

	res, err := s.SimulateRejectInvalid(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if res.TotalRoutes != 1 || res.RejectedRoutes != 1 {
		t.Errorf("reject-invalid: total %d, rejected %d, want 1 and 1", res.TotalRoutes, res.RejectedRoutes)
	}
	if len(res.ByPeer) != 1 || res.ByPeer[0].PeerAddr != bgp.String() {
		t.Errorf("reject-invalid: by peer %+v, want %s only", res.ByPeer, bgp)
	}
	if len(res.RejectedRouteList) != 1 || res.RejectedRouteList[0].RIBType != types.AdjRIBInPre {
		t.Errorf("reject-invalid: rejected list %+v, want the adj-rib-in-pre route only", res.RejectedRouteList)
	}

	aspa, err := s.SimulateASPAEnforce(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if aspa.TotalRoutes != 1 {
		t.Errorf("aspa-enforce: total %d, want 1", aspa.TotalRoutes)
	}
}
