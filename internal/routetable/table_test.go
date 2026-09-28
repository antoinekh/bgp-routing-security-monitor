package routetable

import (
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

func makeRoute(peer string, prefix string, asPath []uint32) *types.Route {
	return &types.Route{
		PeerAddr: netip.MustParseAddr(peer),
		Prefix:   netip.MustParsePrefix(prefix),
		ASPath:   asPath,
		RIBType:  types.AdjRIBInPre,
	}
}

func TestInsertAndGetByPrefix(t *testing.T) {
	tbl := New()

	r := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	tbl.Insert(r)

	if tbl.Count() != 1 {
		t.Fatalf("count = %d, want 1", tbl.Count())
	}

	routes := tbl.GetByPrefix(netip.MustParsePrefix("1.0.0.0/24"))
	if len(routes) != 1 {
		t.Fatalf("GetByPrefix returned %d routes, want 1", len(routes))
	}
	if routes[0].Prefix != r.Prefix {
		t.Errorf("prefix = %s, want %s", routes[0].Prefix, r.Prefix)
	}
}

func TestMultiplePeersSamePrefix(t *testing.T) {
	tbl := New()

	r1 := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	r2 := makeRoute("192.0.2.2", "1.0.0.0/24", []uint32{64502, 13335})
	tbl.Insert(r1)
	tbl.Insert(r2)

	if tbl.Count() != 2 {
		t.Fatalf("count = %d, want 2", tbl.Count())
	}

	routes := tbl.GetByPrefix(netip.MustParsePrefix("1.0.0.0/24"))
	if len(routes) != 2 {
		t.Fatalf("GetByPrefix returned %d routes, want 2", len(routes))
	}
}

func TestGetByOriginASN(t *testing.T) {
	tbl := New()

	r1 := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	r2 := makeRoute("192.0.2.1", "8.8.8.0/24", []uint32{64501, 15169})
	tbl.Insert(r1)
	tbl.Insert(r2)

	routes := tbl.GetByOriginASN(13335)
	if len(routes) != 1 {
		t.Fatalf("GetByOriginASN(13335) returned %d routes, want 1", len(routes))
	}
	if routes[0].Prefix.String() != "1.0.0.0/24" {
		t.Errorf("prefix = %s, want 1.0.0.0/24", routes[0].Prefix)
	}
}

func TestGetByPeer(t *testing.T) {
	tbl := New()

	r1 := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	r2 := makeRoute("192.0.2.2", "8.8.8.0/24", []uint32{64502, 15169})
	tbl.Insert(r1)
	tbl.Insert(r2)

	routes := tbl.GetByPeer(netip.MustParseAddr("192.0.2.1"))
	if len(routes) != 1 {
		t.Fatalf("GetByPeer returned %d routes, want 1", len(routes))
	}
}

func TestWithdraw(t *testing.T) {
	tbl := New()

	r := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	tbl.Insert(r)

	if tbl.Count() != 1 {
		t.Fatalf("count before withdraw = %d, want 1", tbl.Count())
	}

	tbl.Withdraw(netip.MustParseAddr("192.0.2.1"), netip.MustParsePrefix("1.0.0.0/24"))

	if tbl.Count() != 0 {
		t.Fatalf("count after withdraw = %d, want 0", tbl.Count())
	}

	routes := tbl.GetByPrefix(netip.MustParsePrefix("1.0.0.0/24"))
	if len(routes) != 0 {
		t.Errorf("GetByPrefix after withdraw returned %d routes, want 0", len(routes))
	}
}

func TestWithdrawAllFromPeer(t *testing.T) {
	tbl := New()

	tbl.Insert(makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335}))
	tbl.Insert(makeRoute("192.0.2.1", "8.8.8.0/24", []uint32{64501, 15169}))
	tbl.Insert(makeRoute("192.0.2.2", "10.0.0.0/8", []uint32{64502, 3356}))

	if tbl.Count() != 3 {
		t.Fatalf("count = %d, want 3", tbl.Count())
	}

	removed := tbl.WithdrawAllFromPeer(netip.MustParseAddr("192.0.2.1"))
	if removed != 2 {
		t.Errorf("removed = %d, want 2", removed)
	}
	if tbl.Count() != 1 {
		t.Errorf("count after withdraw = %d, want 1", tbl.Count())
	}
}

// A peer going down must leave no trace of its routes anywhere: not in the
// primary map, and not in the prefix, origin-ASN or posture indexes. The
// public Get* queries skip index keys whose route is gone from the primary
// map, so a stale index entry would be invisible through them; this test
// inspects the indexes directly.
func TestWithdrawAllFromPeerCleansAllIndexes(t *testing.T) {
	tbl := New()
	down := netip.MustParseAddr("192.0.2.1")
	other := netip.MustParseAddr("192.0.2.2")

	const n = 50
	for i := 0; i < n; i++ {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 1, byte(i), 0}), 24).String()
		for _, rib := range []types.RIBType{types.AdjRIBInPre, types.AdjRIBInPost} {
			r := makeRoute(down.String(), prefix, []uint32{64501, 65000 + uint32(i%5)})
			r.RIBType = rib
			r.SecurityPosture = types.PostureOriginOnly
			if i%2 == 0 {
				r.SecurityPosture = types.PostureOriginInvalid
			}
			tbl.Insert(r)
		}
	}
	// The other peer shares one prefix and one origin ASN with the downed peer.
	shared := makeRoute(other.String(), "10.1.0.0/24", []uint32{64502, 65000})
	shared.SecurityPosture = types.PostureOriginInvalid
	tbl.Insert(shared)
	tbl.Insert(makeRoute(other.String(), "8.8.8.0/24", []uint32{64502, 15169}))

	if got := tbl.Count(); got != 2*n+2 {
		t.Fatalf("count before peer down = %d, want %d", got, 2*n+2)
	}

	if removed := tbl.WithdrawAllFromPeer(down); removed != 2*n {
		t.Errorf("removed = %d, want %d", removed, 2*n)
	}

	if got := tbl.Count(); got != 2 {
		t.Errorf("count after peer down = %d, want 2 (the other peer's routes)", got)
	}
	if got := tbl.GetByPeer(down); len(got) != 0 {
		t.Errorf("GetByPeer(down) returned %d routes, want 0", len(got))
	}

	// Prefix (BART) index: the downed peer's own prefixes are gone entirely;
	// the shared prefix keeps only the other peer's key.
	for i := 0; i < n; i++ {
		p := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 1, byte(i), 0}), 24)
		keys, ok := tbl.prefixIdx.Get(p)
		for _, k := range keys {
			if k.PeerAddr == down {
				t.Errorf("prefix index still holds %v", k)
			}
		}
		if i != 0 && ok {
			t.Errorf("prefix index still has an entry for %s, want it deleted", p)
		}
	}
	if keys, _ := tbl.prefixIdx.Get(netip.MustParsePrefix("10.1.0.0/24")); len(keys) != 1 || keys[0].PeerAddr != other {
		t.Errorf("shared prefix keys = %v, want only the other peer's", keys)
	}

	// Origin-ASN and posture indexes hold no key for the downed peer.
	for asn, keys := range tbl.asnIdx {
		for _, k := range keys {
			if k.PeerAddr == down {
				t.Errorf("ASN index AS%d still holds %v", asn, k)
			}
		}
	}
	for posture, keys := range tbl.postureIdx {
		for _, k := range keys {
			if k.PeerAddr == down {
				t.Errorf("posture index %q still holds %v", posture, k)
			}
		}
	}
	if got := tbl.CountByPosture()[types.PostureOriginInvalid]; got != 1 {
		t.Errorf("origin-invalid count after peer down = %d, want 1 (the other peer's shared route)", got)
	}
	if got := tbl.CountByPosture()[types.PostureOriginOnly]; got != 0 {
		t.Errorf("origin-only count after peer down = %d, want 0", got)
	}
}

func TestGetByPosture(t *testing.T) {
	tbl := New()

	r1 := makeRoute("192.0.2.1", "1.0.0.0/24", []uint32{64501, 13335})
	r1.SecurityPosture = types.PostureSecured
	tbl.Insert(r1)

	r2 := makeRoute("192.0.2.1", "10.0.0.0/8", []uint32{64501, 64666})
	r2.SecurityPosture = types.PostureOriginInvalid
	tbl.Insert(r2)

	secured := tbl.GetByPosture(types.PostureSecured)
	if len(secured) != 1 {
		t.Errorf("secured routes = %d, want 1", len(secured))
	}

	invalid := tbl.GetByPosture(types.PostureOriginInvalid)
	if len(invalid) != 1 {
		t.Errorf("origin-invalid routes = %d, want 1", len(invalid))
	}
}
