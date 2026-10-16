package validation

import (
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// revalidateAll runs one revalidation pass to completion, in small chunks.
func revalidateAll(e *Engine) *Revalidation {
	rv := e.NewRevalidation()
	for !rv.Step(7) {
	}
	return rv
}

// Revalidation replaces a route whose posture changed with a revalidated
// copy. The posture index must follow: the route is listed under its current
// posture only, however many times it flips, and nothing is left behind once
// the route is withdrawn. Leaked keys here grow memory with every RTR-driven
// posture change and inflate the per-posture counts. The route objects the
// table held before are never changed: readers may still hold them.
func TestRevalidationPostureFlipsLeaveNoStaleIndexKeys(t *testing.T) {
	prefix := netip.MustParsePrefix("192.0.2.0/24")
	matching := []types.VRP{{Prefix: prefix, ASN: 65000, MaxLength: 24}} // → origin-only
	other := []types.VRP{{Prefix: prefix, ASN: 65999, MaxLength: 24}}    // → origin-invalid

	vrps := store.NewVRPStore()
	vrps.ReplaceAll(matching, 1, 1)
	table := routetable.New()
	e := NewEngine(vrps, store.NewASPAStore(), table, slog.New(slog.NewTextHandler(io.Discard, nil)))

	route := &types.Route{
		PeerAddr: netip.MustParseAddr("198.51.100.1"),
		Prefix:   prefix,
		ASPath:   []uint32{64500, 65000},
		RIBType:  types.AdjRIBInPre,
	}
	e.ValidateRoute(route)
	table.Insert(route)
	if route.SecurityPosture != types.PostureOriginOnly {
		t.Fatalf("initial posture = %s, want %s", route.SecurityPosture, types.PostureOriginOnly)
	}

	checkIndexed := func(step string, want types.SecurityPosture) {
		t.Helper()
		var total uint64
		for posture, n := range table.CountByPosture() {
			total += n
			if posture != want && n != 0 {
				t.Errorf("%s: posture index %q still counts %d route(s); the route is %s", step, posture, n, want)
			}
		}
		if total != 1 {
			t.Errorf("%s: posture index counts %d entries in total, want 1 (one route)", step, total)
		}
		for _, r := range table.GetByPosture(want) {
			if r.SecurityPosture != want {
				t.Errorf("%s: GetByPosture(%s) returned a route whose posture is %s", step, want, r.SecurityPosture)
			}
		}
	}

	key := types.RouteKey{PeerAddr: route.PeerAddr, Prefix: route.Prefix, RIBType: route.RIBType}
	flip := func(step string, want types.SecurityPosture) {
		t.Helper()
		before := table.Get(key)
		beforePosture := before.SecurityPosture
		if rv := revalidateAll(e); rv.Changed != 1 {
			t.Errorf("%s: pass changed %d routes, want 1", step, rv.Changed)
		}
		checkIndexed(step, want)
		if after := table.Get(key); after == before || after.SecurityPosture != want {
			t.Errorf("%s: table holds %p with posture %s, want a new route with %s", step, after, after.SecurityPosture, want)
		}
		if before.SecurityPosture != beforePosture {
			t.Errorf("%s: the replaced route was changed in place to %s", step, before.SecurityPosture)
		}
	}
	for i := 0; i < 4; i++ {
		vrps.ReplaceAll(other, uint32(2*i+2), 1)
		flip("flip to origin-invalid", types.PostureOriginInvalid)

		vrps.ReplaceAll(matching, uint32(2*i+3), 1)
		flip("flip back to origin-only", types.PostureOriginOnly)
	}
	if rv := revalidateAll(e); rv.Changed != 0 {
		t.Errorf("a pass with no store change replaced %d routes, want 0", rv.Changed)
	}

	table.Withdraw(route.PeerAddr, route.Prefix)
	for posture, n := range table.CountByPosture() {
		if n != 0 {
			t.Errorf("after withdrawal: posture index %q still counts %d route(s), want 0", posture, n)
		}
	}
}

// midPassFixture is a table of n routes owned by session 1, validated
// against VRPs they match, and a revalidation pass that has made its first
// step after the VRPs changed so every route's posture changes. The pass has
// read part of the table and not yet applied it.
func midPassFixture(t *testing.T, n int) (*Engine, *routetable.Table, *store.VRPStore, []*types.Route, *Revalidation) {
	t.Helper()
	vrps := store.NewVRPStore()
	vrps.ReplaceAll([]types.VRP{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), ASN: 65000, MaxLength: 24}}, 1, 1)
	table := routetable.New()
	e := NewEngine(vrps, store.NewASPAStore(), table, slog.New(slog.NewTextHandler(io.Discard, nil)))
	routes := make([]*types.Route, n)
	for i := range routes {
		r := &types.Route{
			PeerAddr:     netip.MustParseAddr("198.51.100.1"),
			Prefix:       netip.PrefixFrom(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 0}), 24),
			ASPath:       []uint32{64500, 65000},
			NextHop:      netip.MustParseAddr("198.51.100.1"),
			RIBType:      types.AdjRIBInPre,
			OwnerSession: 1,
		}
		e.ValidateRoute(r)
		table.Insert(r)
		routes[i] = r
	}
	vrps.ReplaceAll([]types.VRP{{Prefix: netip.MustParsePrefix("10.0.0.0/8"), ASN: 65999, MaxLength: 24}}, 2, 1)
	rv := e.NewRevalidation()
	if rv.Step(1) {
		t.Fatal("pass finished after one route")
	}
	return e, table, vrps, routes, rv
}

// Routes withdrawn while a revalidation pass is in progress stay withdrawn,
// including those the pass had already read.
func TestRevalidationKeepsMidPassWithdrawalsWithdrawn(t *testing.T) {
	const n = 3000
	_, table, _, routes, rv := midPassFixture(t, n)
	for _, r := range routes {
		table.Withdraw(r.PeerAddr, r.Prefix)
	}
	for !rv.Step(64) {
	}
	if got := table.Count(); got != 0 {
		t.Errorf("table holds %d routes after the pass, want 0: withdrawn routes were brought back", got)
	}
	if rv.Skipped == 0 {
		t.Error("no read-then-withdrawn route was skipped; the test did not exercise that case")
	}
	if got := table.WithdrawSession(1); got != 0 {
		t.Errorf("owner index still held %d withdrawn routes", got)
	}
}

// Routes re-announced by a newer session while a pass is in progress keep
// the newer announcement: its owner, its attributes, and a route object
// that is not the old one.
func TestRevalidationKeepsMidPassReannouncements(t *testing.T) {
	const n = 3000
	e, table, _, routes, rv := midPassFixture(t, n)
	newHop := netip.MustParseAddr("198.51.100.2")
	for _, r := range routes {
		cp := *r
		cp.OwnerSession = 2
		cp.NextHop = newHop
		e.ValidateRoute(&cp) // as ingest does, against the current stores
		table.Insert(&cp)
	}
	for !rv.Step(64) {
	}
	for i, old := range routes {
		cur := table.Get(types.RouteKey{PeerAddr: old.PeerAddr, Prefix: old.Prefix, RIBType: old.RIBType})
		if cur == nil || cur == old || cur.OwnerSession != 2 || cur.NextHop != newHop {
			t.Fatalf("route %d = %+v after the pass, want session 2's announcement", i, cur)
		}
		if cur.SecurityPosture != types.PostureOriginInvalid {
			t.Fatalf("route %d posture = %s, want %s from the current VRPs", i, cur.SecurityPosture, types.PostureOriginInvalid)
		}
	}
	if rv.Skipped == 0 {
		t.Error("no read-then-replaced route was skipped; the test did not exercise that case")
	}
	if got := table.WithdrawSession(1); got != 0 {
		t.Errorf("session 1 still owns %d routes, want 0", got)
	}
	if got := table.WithdrawSession(2); got != n {
		t.Errorf("session 2's end removed %d routes, want %d", got, n)
	}
}
