package rtr

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/rtrtest"
	"github.com/nokia/bgp-routing-security-monitor/internal/rtr/store"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// Each sync that changes the data hands onUpdate a Delta: Full when the
// stores were rebuilt (Reset Query, Cache Reset, a new session ID), and
// otherwise exactly the VRPs announced and withdrawn and the ASPA customers
// whose provider set changed.
func TestSyncDeltas(t *testing.T) {
	cache := rtrtest.NewCache(t)
	tc := newTestClient(t, cache, 2)
	deltas := make(chan *store.Delta, 16)
	tc.SetOnUpdate(func(d *store.Delta) { deltas <- d })
	tc.start(t)
	next := func(what string) *store.Delta {
		t.Helper()
		select {
		case d := <-deltas:
			return d
		case <-time.After(5 * time.Second):
			t.Fatalf("no delta for %s", what)
			return nil
		}
	}
	serialQuery := func(conn *rtrtest.Conn, serial uint32) {
		t.Helper()
		conn.Send(rtrtest.SerialNotify(2, 7, serial))
		if q := cache.Next(5 * time.Second); q.Type != rtrtest.PDUSerialQuery {
			t.Fatalf("query type %d after Serial Notify, want a Serial Query", q.Type)
		}
	}

	conn, _ := fullSync(t, cache, 2, 1, 600, 600, 7200)
	if d := next("the first sync"); !d.Full {
		t.Fatalf("first sync (Reset Query) delta = %+v, want Full", d)
	}

	added := netip.MustParsePrefix("198.51.100.0/24")
	serialQuery(conn, 2)
	conn.Send(rtrtest.CacheResponse(2, 7),
		rtrtest.IPv4Prefix(2, true, added, 24, 65001),
		rtrtest.IPv4Prefix(2, false, testPrefix, 24, 65000),
		rtrtest.ASPA(true, 64500, 64501, 64502),
		rtrtest.EndOfData(2, 7, 2, 600, 600, 7200))
	d := next("the incremental sync")
	wantAdd := []types.VRP{{Prefix: added, MaxLength: 24, ASN: 65001}}
	wantDel := []types.VRP{{Prefix: testPrefix, MaxLength: 24, ASN: 65000}}
	if d.Full || !slices.Equal(d.VRPAnnounced, wantAdd) || !slices.Equal(d.VRPWithdrawn, wantDel) ||
		!slices.Equal(d.ASPACustomers, []uint32{64500}) {
		t.Fatalf("incremental delta = %+v, want announced %v, withdrawn %v, ASPA [64500]", d, wantAdd, wantDel)
	}

	// Re-announcing providers the record already has changes nothing.
	serialQuery(conn, 3)
	conn.Send(rtrtest.CacheResponse(2, 7), rtrtest.ASPA(true, 64500, 64501),
		rtrtest.EndOfData(2, 7, 3, 600, 600, 7200))
	if d := next("the no-op ASPA sync"); !d.Empty() {
		t.Fatalf("delta for an unchanged ASPA record = %+v, want empty", d)
	}

	// A provider withdrawn from the record is a change to its customer.
	serialQuery(conn, 4)
	conn.Send(rtrtest.CacheResponse(2, 7), rtrtest.ASPA(false, 64500, 64502),
		rtrtest.EndOfData(2, 7, 4, 600, 600, 7200))
	if d := next("the ASPA withdrawal"); d.Full || !slices.Equal(d.ASPACustomers, []uint32{64500}) {
		t.Fatalf("delta for a withdrawn provider = %+v, want ASPA [64500]", d)
	}

	// A different session ID: the stores no longer match what the delta
	// would describe.
	serialQuery(conn, 5)
	conn.Send(rtrtest.CacheResponse(2, 8), rtrtest.IPv4Prefix(2, true, testPrefix, 24, 65000),
		rtrtest.EndOfData(2, 8, 5, 600, 600, 7200))
	if d := next("the session-ID change"); !d.Full {
		t.Fatalf("delta after a session-ID change = %+v, want Full", d)
	}

	// Cache Reset: the client re-syncs from scratch.
	serialQuery(conn, 6)
	conn.Send(rtrtest.CacheReset(2))
	if q := cache.Next(5 * time.Second); q.Type != rtrtest.PDUResetQuery {
		t.Fatalf("query type %d after Cache Reset, want a Reset Query", q.Type)
	}
	conn.Send(rtrtest.CacheResponse(2, 8), rtrtest.IPv4Prefix(2, true, testPrefix, 24, 65000),
		rtrtest.EndOfData(2, 8, 6, 600, 600, 7200))
	if d := next("the Cache Reset sync"); !d.Full {
		t.Fatalf("delta after Cache Reset = %+v, want Full", d)
	}
}

func TestDeltaMerge(t *testing.T) {
	v := func(p string, asn uint32) types.VRP {
		return types.VRP{Prefix: netip.MustParsePrefix(p), MaxLength: 24, ASN: asn}
	}
	d := &store.Delta{VRPAnnounced: []types.VRP{v("192.0.2.0/24", 1)}, ASPACustomers: []uint32{5, 9}}
	d.Merge(&store.Delta{VRPWithdrawn: []types.VRP{v("198.51.100.0/24", 2)}, ASPACustomers: []uint32{3, 9}})
	if d.Full || len(d.VRPAnnounced) != 1 || len(d.VRPWithdrawn) != 1 || !slices.Equal(d.ASPACustomers, []uint32{3, 5, 9}) {
		t.Fatalf("merged delta = %+v", d)
	}
	if got := d.VRPPrefixes(); len(got) != 2 {
		t.Fatalf("VRPPrefixes = %v, want 2 distinct prefixes", got)
	}
	d.Merge(store.FullDelta())
	if !d.Full || len(d.VRPAnnounced) != 0 || len(d.ASPACustomers) != 0 {
		t.Fatalf("merging a Full delta gave %+v, want Full with no detail", d)
	}
	d.Merge(&store.Delta{ASPACustomers: []uint32{1}})
	if !d.Full || len(d.ASPACustomers) != 0 {
		t.Fatalf("merging into a Full delta gave %+v, want it to stay Full", d)
	}
}
