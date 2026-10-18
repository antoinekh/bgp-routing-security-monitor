package routetable

import (
	"math/rand/v2"
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// checkPeerCounts asserts the per-peer counts are exactly the table's routes
// grouped by peer (IPv4 peers in either form counted together), and sum to
// the table's total.
func checkPeerCounts(t *testing.T, tbl *Table, step string) {
	t.Helper()
	actual := map[netip.Addr]uint64{}
	for _, r := range tbl.All() {
		actual[r.PeerAddr.Unmap()]++
	}
	got := tbl.PeerRouteCounts()
	var sum uint64
	for p, n := range got {
		sum += n
		if actual[p] != n {
			t.Fatalf("%s: peer %s counted %d, holds %d", step, p, n, actual[p])
		}
	}
	for p, n := range actual {
		if got[p] != n {
			t.Fatalf("%s: peer %s holds %d, counted %d", step, p, n, got[p])
		}
	}
	if total := tbl.Count(); sum != total {
		t.Fatalf("%s: per-peer counts sum to %d, table holds %d", step, sum, total)
	}
}

// Property: through random announcements, re-announcements (same session or
// a newer one taking over), withdrawals, peer-downs, session ends after a
// supersede, and stale evictions, applied whole or a step at a time, each
// peer's count is the number of its routes in the table.
func TestPeerRouteCountsInvariant(t *testing.T) {
	peers := []netip.Addr{
		netip.MustParseAddr("46.18.174.241"),
		netip.MustParseAddr("206.82.106.254"),
		netip.MustParseAddr("::ffff:80.81.194.180"), // stored mapped
		netip.MustParseAddr("2001:db8::1"),
	}
	for seed := uint64(1); seed <= 30; seed++ {
		rng := rand.New(rand.NewPCG(seed, 3))
		tbl := New()
		session := map[netip.Addr]uint64{} // each peer's current BMP session
		for _, p := range peers {
			session[p] = 1
		}
		prefix := func() netip.Prefix {
			return netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 0, byte(rng.IntN(40)), 0}), 24)
		}
		announce := func(peer netip.Addr, stale bool) {
			owner := session[peer]
			if stale {
				owner = 0 // restored from a snapshot: no session owns it yet
			}
			tbl.Insert(&types.Route{
				PeerAddr: peer, Prefix: prefix(), ASPath: []uint32{64500, uint32(64501 + rng.IntN(3))},
				RIBType: types.AdjRIBInPre, OwnerSession: owner, Stale: stale,
			})
		}
		apply := func(rm *Removal) {
			if rng.IntN(2) == 0 {
				rm.Apply()
				return
			}
			for {
				_, done := rm.Step(1 + rng.IntN(5))
				checkPeerCounts(t, tbl, "mid-removal")
				if done {
					return
				}
			}
		}
		for step := 0; step < 400; step++ {
			peer := peers[rng.IntN(len(peers))]
			var op string
			switch r := rng.IntN(20); {
			case r < 9:
				op = "announce or re-announce"
				announce(peer, false)
			case r < 13:
				op = "withdraw"
				tbl.WithdrawFromSession(peer, prefix(), session[peer])
			case r < 14:
				op = "peer down"
				apply(tbl.DetachPeer(peer, session[peer]))
			case r < 16:
				// A new BMP session supersedes the old one, re-announces some
				// routes, then the old session ends: its routes the new one
				// did not take over go.
				op = "session supersede"
				old := session[peer]
				session[peer] = old + 100
				for n := rng.IntN(10); n > 0; n-- {
					announce(peer, false)
				}
				apply(tbl.DetachSession(old))
			case r < 18:
				op = "snapshot restore (stale)"
				announce(peer, true)
			default:
				op = "stale eviction"
				apply(tbl.DetachUnowned())
			}
			checkPeerCounts(t, tbl, op)
		}
	}
}
