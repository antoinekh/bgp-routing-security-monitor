package routetable

import (
	"context"
	"fmt"
	"hash/fnv"
	"net/netip"
	"sync"

	"github.com/gaissmai/bart"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

const defaultShards = 256

// Table is RAVEN's internal route table — an annotated Adj-RIB-In.
// It stores every route from every peer with validation annotations.
//
// Architecture: hybrid BART prefix index + sharded flat map (see ARCHITECTURE.md §2.3).
type Table struct {
	// Primary store: sharded flat map keyed by (PeerAddr, Prefix)
	shards []shard

	// Prefix index: BART trie mapping prefix -> route keys. A prefix's list
	// holds at most one key per peer carrying it, so it stays short and a
	// linear scan is cheap; a map per prefix would roughly triple the index's
	// memory when most prefixes have a single route.
	prefixMu  sync.RWMutex
	prefixIdx bart.Table[[]types.RouteKey]

	// Secondary index: origin ASN -> route keys
	asnMu  sync.RWMutex
	asnIdx map[uint32]keySet

	// Secondary index: security posture -> route keys
	postureMu  sync.RWMutex
	postureIdx map[types.SecurityPosture]keySet
}

// keySet is the set of route keys under one ASN or posture index entry.
// These entries used to be slices, scanned linearly on every insert and
// removal; with about a million keys under a single posture that made index
// maintenance quadratic.
type keySet map[types.RouteKey]struct{}

// keys copies the set's members. Callers hold the index's lock: a map must
// not be read while another goroutine writes it.
func (s keySet) keys() []types.RouteKey {
	out := make([]types.RouteKey, 0, len(s))
	for k := range s {
		out = append(out, k)
	}
	return out
}

type shard struct {
	mu     sync.RWMutex
	routes map[types.RouteKey]*types.Route

	// owned indexes the shard's routes by owning BMP session and peer, so a
	// withdraw-all finds the routes it removes without scanning the table.
	// A route is indexed under the OwnerSession and PeerAddr it had when
	// inserted; neither may change while it is in the table.
	owned map[ownerKey]routeSet
}

type ownerKey struct {
	session uint64
	peer    netip.Addr
}

// routeSet is keyed by pointer rather than RouteKey: 8 bytes per route
// instead of 64, and a pointer also tells a route apart from a later
// announcement stored under the same key.
type routeSet map[*types.Route]struct{}

// own indexes r under its owner. The caller holds s.mu.
func (s *shard) own(r *types.Route) {
	k := ownerKey{session: r.OwnerSession, peer: r.PeerAddr}
	set := s.owned[k]
	if set == nil {
		set = make(routeSet)
		s.owned[k] = set
	}
	set[r] = struct{}{}
}

// disown drops r from the owner index. It is a no-op for a route a Removal
// has already detached. The caller holds s.mu.
func (s *shard) disown(r *types.Route) {
	k := ownerKey{session: r.OwnerSession, peer: r.PeerAddr}
	if set, ok := s.owned[k]; ok {
		delete(set, r)
		if len(set) == 0 {
			delete(s.owned, k)
		}
	}
}

// Filter holds query parameters for ListRoutes.
type Filter struct {
	PeerAddr  string
	Prefix    string
	OriginASN uint32
	Posture   string
	AFI       string // "ipv4" | "ipv6" | ""
}

// ListRoutes returns routes matching the given filter.
// Used by the what-if simulator and ASPA recommender.
func (t *Table) ListRoutes(ctx context.Context, f Filter) ([]types.Route, error) {
	var ptrs []*types.Route

	switch {
	case f.PeerAddr != "":
		addr, err := netip.ParseAddr(f.PeerAddr)
		if err != nil {
			return nil, fmt.Errorf("invalid peer addr: %w", err)
		}
		ptrs = t.GetByPeer(addr)
	case f.Prefix != "":
		p, err := netip.ParsePrefix(f.Prefix)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix: %w", err)
		}
		ptrs = t.GetByPrefix(p)
	case f.OriginASN != 0:
		ptrs = t.GetByOriginASN(f.OriginASN)
	case f.Posture != "":
		ptrs = t.GetByPosture(types.SecurityPosture(f.Posture))
	default:
		ptrs = t.All()
	}

	// Apply AFI filter
	routes := make([]types.Route, 0, len(ptrs))
	for _, r := range ptrs {
		if f.AFI == "ipv4" && !r.Prefix.Addr().Is4() {
			continue
		}
		if f.AFI == "ipv6" && !r.Prefix.Addr().Is6() {
			continue
		}
		routes = append(routes, *r)
	}
	return routes, nil
}

// New creates a new Route Table.
func New() *Table {
	t := &Table{
		shards:     make([]shard, defaultShards),
		asnIdx:     make(map[uint32]keySet),
		postureIdx: make(map[types.SecurityPosture]keySet),
	}
	for i := range t.shards {
		t.shards[i].routes = make(map[types.RouteKey]*types.Route)
		t.shards[i].owned = make(map[ownerKey]routeSet)
	}
	return t
}

// Insert adds or updates a route in the table.
func (t *Table) Insert(route *types.Route) {
	key := types.RouteKey{
		PeerAddr: route.PeerAddr,
		Prefix:   route.Prefix,
		RIBType:  route.RIBType,
	}

	// Write to primary store
	s := t.getShard(key)
	s.mu.Lock()
	old := s.routes[key]
	s.routes[key] = route
	// RevalidateAll re-inserts the stored pointer itself; its owner is
	// unchanged.
	if old != route {
		if old != nil {
			s.disown(old)
		}
		s.own(route)
	}
	s.mu.Unlock()

	// Update prefix index
	t.prefixMu.Lock()
	existing, _ := t.prefixIdx.Get(route.Prefix)
	if !containsKey(existing, key) {
		t.prefixIdx.Insert(route.Prefix, append(existing, key))
	}
	t.prefixMu.Unlock()

	// Update ASN index. A re-announcement with a new origin arrives as a new
	// route for the same key, so the old origin's entry must be dropped.
	originASN := route.OriginASN()
	t.asnMu.Lock()
	if old != nil {
		if oldASN := old.OriginASN(); oldASN != 0 && oldASN != originASN {
			t.unindexASN(oldASN, key)
		}
	}
	if originASN != 0 {
		addKey(t.asnIdx, originASN, key)
	}
	t.asnMu.Unlock()

	// Update posture index
	t.postureMu.Lock()
	t.unindexPostureExcept(key, route.SecurityPosture)
	if route.SecurityPosture != "" {
		addKey(t.postureIdx, route.SecurityPosture, key)
	}
	t.postureMu.Unlock()
}

// unindexPostureExcept removes key from every posture index entry other than
// keep. The caller holds postureMu.
//
// The old posture cannot be read off the stored route: RevalidateAll changes
// a route's posture in place and re-inserts the same pointer, so by the time
// Insert runs the stored route already carries the new posture. Checking the
// old route's posture left the key listed under every posture it had ever
// had. There are only a handful of postures, so clear them all.
func (t *Table) unindexPostureExcept(key types.RouteKey, keep types.SecurityPosture) {
	for posture, set := range t.postureIdx {
		if posture != keep {
			delete(set, key)
			if len(set) == 0 {
				delete(t.postureIdx, posture)
			}
		}
	}
}

// unindexASN removes key from asn's index entry, dropping the entry once it
// is empty so the map does not keep one per origin ever seen. The caller
// holds asnMu.
func (t *Table) unindexASN(asn uint32, key types.RouteKey) {
	if set, ok := t.asnIdx[asn]; ok {
		delete(set, key)
		if len(set) == 0 {
			delete(t.asnIdx, asn)
		}
	}
}

// addKey adds key to idx[k], creating the entry if needed.
func addKey[K comparable](idx map[K]keySet, k K, key types.RouteKey) {
	set, ok := idx[k]
	if !ok {
		set = keySet{}
		idx[k] = set
	}
	set[key] = struct{}{}
}

var allRIBTypes = []types.RIBType{types.AdjRIBInPre, types.AdjRIBInPost, types.LocRIB}

// Withdraw removes a route from the table, whichever session owns it.
func (t *Table) Withdraw(peerAddr netip.Addr, prefix netip.Prefix) {
	// Withdraw across all RIB types
	for _, rib := range allRIBTypes {
		t.withdrawOne(types.RouteKey{PeerAddr: peerAddr, Prefix: prefix, RIBType: rib}, nil)
	}
}

// WithdrawFromSession removes a route withdrawn by BMP session session,
// unless a newer session has since re-announced it: a late withdrawal from a
// superseded session must not remove the newer session's route. It returns
// the number of routes removed (one per RIB type at most).
func (t *Table) WithdrawFromSession(peerAddr netip.Addr, prefix netip.Prefix, session uint64) int {
	count := 0
	for _, rib := range allRIBTypes {
		if t.withdrawOne(types.RouteKey{PeerAddr: peerAddr, Prefix: prefix, RIBType: rib},
			func(r *types.Route) bool { return r.OwnerSession <= session }) {
			count++
		}
	}
	return count
}

// withdrawOne removes the route under key. If pred is non-nil the route is
// only removed when pred reports true; it is checked under the shard lock, so
// a concurrent Insert cannot slip in between the check and the delete.
func (t *Table) withdrawOne(key types.RouteKey, pred func(*types.Route) bool) bool {
	s := t.getShard(key)
	s.mu.Lock()
	route, exists := s.routes[key]
	if exists && pred != nil && !pred(route) {
		exists = false
	}
	if exists {
		delete(s.routes, key)
		s.disown(route)
	}
	s.mu.Unlock()

	if !exists {
		return false
	}

	// Clean up prefix index
	t.prefixMu.Lock()
	existing, _ := t.prefixIdx.Get(key.Prefix)
	updated := removeKey(existing, key)
	if len(updated) == 0 {
		t.prefixIdx.Delete(key.Prefix)
	} else {
		t.prefixIdx.Insert(key.Prefix, updated)
	}
	t.prefixMu.Unlock()

	// Clean up ASN index
	originASN := route.OriginASN()
	if originASN != 0 {
		t.asnMu.Lock()
		t.unindexASN(originASN, key)
		t.asnMu.Unlock()
	}

	// Clean up posture index. Every entry, not just route.SecurityPosture's:
	// a revalidation may have changed the posture in place before this ran.
	t.postureMu.Lock()
	t.unindexPostureExcept(key, "")
	t.postureMu.Unlock()
	return true
}

// WithdrawAllFromPeer removes, at once, what a peer-down from BMP session
// session removes; see DetachPeer.
func (t *Table) WithdrawAllFromPeer(peerAddr netip.Addr, session uint64) int {
	return t.DetachPeer(peerAddr, session).Apply()
}

// WithdrawSession removes, at once, what the end of BMP session session
// removes; see DetachSession.
func (t *Table) WithdrawSession(session uint64) int {
	return t.DetachSession(session).Apply()
}

// DetachPeer starts the withdraw-all for a peer-down of peerAddr seen by BMP
// session session. It removes the peer's routes that session owns, and its
// routes no session owns (restored from a snapshot and not yet confirmed):
// the peer is down, so those are gone too. Routes of the peer that another
// session owns, such as a newer session from the same router, are kept.
//
// It costs O(shards); the routes themselves are removed by the Removal.
func (t *Table) DetachPeer(peerAddr netip.Addr, session uint64) *Removal {
	keys := []ownerKey{{session: session, peer: peerAddr}}
	if session != 0 {
		keys = append(keys, ownerKey{peer: peerAddr})
	}
	rm := &Removal{t: t}
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for _, k := range keys {
			if set, ok := s.owned[k]; ok {
				rm.add(set)
				delete(s.owned, k)
			}
		}
		s.mu.Unlock()
	}
	return rm
}

// DetachSession starts the withdraw-all for the end of BMP session session:
// every route, from any peer, that the session owns. Routes no session owns
// are left to stale eviction, since the session never confirmed them.
//
// It costs O(owner index entries), one per (session, peer) pair per shard;
// the routes themselves are removed by the Removal.
func (t *Table) DetachSession(session uint64) *Removal {
	rm := &Removal{t: t}
	if session == 0 {
		return rm // never a live session; nothing to end
	}
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.Lock()
		for k, set := range s.owned {
			if k.session == session {
				rm.add(set)
				delete(s.owned, k)
			}
		}
		s.mu.Unlock()
	}
	return rm
}

// Removal is a withdraw-all that has been taken out of the owner index but
// not yet applied. Its routes stay readable until Step removes them, in
// bounded chunks so a large withdraw-all does not stall ingest. A route that
// was replaced or withdrawn in the meantime is skipped, so a later
// announcement under the same key survives.
//
// A Removal is not safe for concurrent use.
type Removal struct {
	t    *Table
	sets []routeSet
	cur  []*types.Route
	n    int
}

func (rm *Removal) add(set routeSet) {
	rm.sets = append(rm.sets, set)
	rm.n += len(set)
}

// Len returns the number of routes detached, including any since replaced.
func (rm *Removal) Len() int { return rm.n }

// Step removes up to budget routes and reports how many it removed and
// whether the Removal is finished.
func (rm *Removal) Step(budget int) (removed int, done bool) {
	for budget > 0 {
		if len(rm.cur) == 0 {
			if len(rm.sets) == 0 {
				break
			}
			// One shard's routes for one (session, peer); copied so the
			// next Step can resume where this one stopped.
			set := rm.sets[len(rm.sets)-1]
			rm.sets = rm.sets[:len(rm.sets)-1]
			rm.cur = make([]*types.Route, 0, len(set))
			for r := range set {
				rm.cur = append(rm.cur, r)
			}
			continue
		}
		r := rm.cur[len(rm.cur)-1]
		rm.cur = rm.cur[:len(rm.cur)-1]
		budget--
		if rm.t.removeIfCurrent(r) {
			removed++
		}
	}
	return removed, len(rm.cur) == 0 && len(rm.sets) == 0
}

// Apply removes all of the Removal's routes and returns how many it removed.
func (rm *Removal) Apply() int {
	total := 0
	for {
		n, done := rm.Step(1 << 16)
		total += n
		if done {
			return total
		}
	}
}

// removeIfCurrent removes r if the table still holds this very route.
func (t *Table) removeIfCurrent(r *types.Route) bool {
	key := types.RouteKey{PeerAddr: r.PeerAddr, Prefix: r.Prefix, RIBType: r.RIBType}
	return t.withdrawOne(key, func(cur *types.Route) bool { return cur == r })
}

// ─── Query Methods ───

// Get returns the route stored under the given key, or nil if not found.
func (t *Table) Get(key types.RouteKey) *types.Route {
	s := t.getShard(key)
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.routes[key]
}

func (t *Table) GetByPrefix(prefix netip.Prefix) []*types.Route {
	t.prefixMu.RLock()
	keys, _ := t.prefixIdx.Get(prefix)
	t.prefixMu.RUnlock()
	return t.resolveKeys(keys)
}

func (t *Table) GetByOriginASN(asn uint32) []*types.Route {
	t.asnMu.RLock()
	keys := t.asnIdx[asn].keys()
	t.asnMu.RUnlock()
	return t.resolveKeys(keys)
}

func (t *Table) GetByPosture(posture types.SecurityPosture) []*types.Route {
	t.postureMu.RLock()
	keys := t.postureIdx[posture].keys()
	t.postureMu.RUnlock()
	return t.resolveKeys(keys)
}

func (t *Table) GetByPeer(peerAddr netip.Addr) []*types.Route {
	var routes []*types.Route
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for key, route := range s.routes {
			if key.PeerAddr == peerAddr && route.RIBType == types.AdjRIBInPre {
				routes = append(routes, route)
			}
		}
		s.mu.RUnlock()
	}
	return routes
}

// All returns every route in the table regardless of RIB type.
func (t *Table) All() []*types.Route {
	var routes []*types.Route
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for _, route := range s.routes {
			routes = append(routes, route)
		}
		s.mu.RUnlock()
	}
	return routes
}

// AllPrePolicy returns only Adj-RIB-In Pre-Policy routes — the default
// operator view showing what routers received before import filtering.
func (t *Table) AllPrePolicy() []*types.Route {
	var routes []*types.Route
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for _, route := range s.routes {
			if route.RIBType == types.AdjRIBInPre {
				routes = append(routes, route)
			}
		}
		s.mu.RUnlock()
	}
	return routes
}

// Count returns the total number of routes.
func (t *Table) Count() uint64 {
	var total uint64
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		total += uint64(len(s.routes))
		s.mu.RUnlock()
	}
	return total
}

// Snapshot returns all routes currently in the table.
// Called by the serve shutdown sequence to persist state.
func (t *Table) Snapshot() []*types.Route {
	return t.All()
}

// Restore populates the table from a snapshot.
// All restored routes have Stale=true so that the Event Engine
// ignores them until a live BMP message confirms each one.
func (t *Table) Restore(routes []*types.Route) {
	for _, r := range routes {
		cp := *r
		cp.Stale = true
		t.Insert(&cp)
	}
}

// EvictStale removes all routes still marked Stale from the table.
// Returns the number of routes evicted. Called once after
// stale_eviction_timeout to purge unconfirmed snapshot entries.
func (t *Table) EvictStale() int {
	var toEvict []types.RouteKey
	for i := range t.shards {
		s := &t.shards[i]
		s.mu.RLock()
		for key, route := range s.routes {
			if route.Stale {
				toEvict = append(toEvict, key)
			}
		}
		s.mu.RUnlock()
	}
	for _, key := range toEvict {
		t.withdrawOne(key, nil)
	}
	return len(toEvict)
}

// CountByPosture returns route counts grouped by security posture.
func (t *Table) CountByPosture() map[types.SecurityPosture]uint64 {
	t.postureMu.RLock()
	defer t.postureMu.RUnlock()

	result := make(map[types.SecurityPosture]uint64)
	for posture, set := range t.postureIdx {
		result[posture] = uint64(len(set))
	}
	return result
}

// ─── Internal helpers ───

func (t *Table) getShard(key types.RouteKey) *shard {
	h := fnv.New32a()
	b := key.PeerAddr.As16()
	h.Write(b[:])
	pb, _ := key.Prefix.MarshalBinary()
	h.Write(pb)
	return &t.shards[h.Sum32()%uint32(len(t.shards))]
}

func (t *Table) resolveKeys(keys []types.RouteKey) []*types.Route {
	routes := make([]*types.Route, 0, len(keys))
	for _, key := range keys {
		if key.RIBType != types.AdjRIBInPre {
			continue // only return pre-policy routes by default
		}
		s := t.getShard(key)
		s.mu.RLock()
		if r, ok := s.routes[key]; ok {
			routes = append(routes, r)
		}
		s.mu.RUnlock()
	}
	return routes
}

// containsKey and removeKey maintain a prefix's key list. It holds at most
// one key per peer, so a linear scan is bounded by the peer count, not the
// table size.
func containsKey(keys []types.RouteKey, key types.RouteKey) bool {
	for _, k := range keys {
		if k == key {
			return true
		}
	}
	return false
}

func removeKey(keys []types.RouteKey, key types.RouteKey) []types.RouteKey {
	for i, k := range keys {
		if k == key {
			return append(keys[:i], keys[i+1:]...)
		}
	}
	return keys
}
