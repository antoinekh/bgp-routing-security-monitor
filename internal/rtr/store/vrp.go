package store

import (
	"cmp"
	"net/netip"
	"slices"
	"sync"
	"sync/atomic"

	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// VRPStore holds Validated ROA Payloads indexed for efficient
// Route Origin Validation lookups (RFC 6811).
//
// The RTR client changes the VRP set as a sync's PDUs arrive (AddVRP,
// RemoveVRP, Clear) and publishes it at End of Data (RebuildIndex), or
// replaces it whole (ReplaceAll). Lookups (FindCovering) see only published
// sets: until End of Data they see the previous one, whole and consistent,
// as RTR intends. They take no lock and never wait for a rebuild, which is
// built off to the side and swapped in.
type VRPStore struct {
	// mu guards the VRP set being built up and the serial and session ID.
	mu sync.RWMutex
	// The VRP multiset: each distinct VRP's live copies, by the order they
	// were added in (store order), oldest first. Most VRPs have one copy;
	// extra holds the rest.
	first map[types.VRP]uint64
	extra map[types.VRP][]uint64
	next  uint64 // order of the next VRP added
	count uint64

	serial    uint32
	sessionID uint16

	// idx is the published covering-prefix index (see vrpIndex): built
	// whole and never modified after, so the slices FindCovering hands out
	// stay valid and unchanged. buildMu orders rebuilds, so a slower
	// rebuild of an older set can never replace a newer one.
	idx      atomic.Pointer[vrpIndex]
	buildMu  sync.Mutex
	rebuilds atomic.Uint64
}

// NewVRPStore creates an empty VRP store.
func NewVRPStore() *VRPStore {
	s := &VRPStore{first: make(map[types.VRP]uint64), extra: make(map[types.VRP][]uint64)}
	s.idx.Store(newVRPIndex(nil, nil))
	return s
}

// Count returns the number of VRPs in the store, including changes not yet
// published.
func (s *VRPStore) Count() uint64 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.count
}

// Serial returns the current RTR serial number.
func (s *VRPStore) Serial() uint32 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.serial
}

// SessionID returns the current RTR session ID.
func (s *VRPStore) SessionID() uint16 {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.sessionID
}

// SetSerial updates the serial and session ID after an RTR sync.
func (s *VRPStore) SetSerial(serial uint32, sessionID uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.serial = serial
	s.sessionID = sessionID
}

// Rebuilds returns how many times the index has been rebuilt and published.
func (s *VRPStore) Rebuilds() uint64 { return s.rebuilds.Load() }

// Clear empties the VRP set. Called at the start of a full RTR sync so the
// incoming snapshot replaces rather than appends to the previous one. The
// serial and session ID are also reset; they are repopulated on EndOfData.
// Lookups go on seeing the previous set until the sync's End of Data.
func (s *VRPStore) Clear() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.first = make(map[types.VRP]uint64)
	s.extra = make(map[types.VRP][]uint64)
	s.count = 0
	s.serial = 0
	s.sessionID = 0
}

// ReplaceAll replaces the entire VRP set and publishes it (used on RTR cache
// reset and snapshot restore).
func (s *VRPStore) ReplaceAll(vrps []types.VRP, serial uint32, sessionID uint16) {
	s.buildMu.Lock()
	defer s.buildMu.Unlock()

	s.mu.Lock()
	s.first = make(map[types.VRP]uint64, len(vrps))
	s.extra = make(map[types.VRP][]uint64)
	s.count = 0
	order := make([]uint64, len(vrps))
	for i, v := range vrps {
		order[i] = s.addLocked(v)
	}
	s.serial = serial
	s.sessionID = sessionID
	s.mu.Unlock()

	s.publish(newVRPIndex(vrps, order))
}

// AddVRP adds a single VRP (used during incremental RTR updates). Lookups see
// it from the next RebuildIndex.
func (s *VRPStore) AddVRP(vrp types.VRP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addLocked(vrp)
}

func (s *VRPStore) addLocked(vrp types.VRP) uint64 {
	o := s.next
	s.next++
	if _, ok := s.first[vrp]; ok {
		s.extra[vrp] = append(s.extra[vrp], o)
	} else {
		s.first[vrp] = o
	}
	s.count++
	return o
}

// RemoveVRP removes a single VRP (used during incremental RTR updates): the
// oldest copy, if there are several. Lookups stop seeing it from the next
// RebuildIndex.
func (s *VRPStore) RemoveVRP(vrp types.VRP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.first[vrp]; !ok {
		return
	}
	if more := s.extra[vrp]; len(more) > 0 {
		s.first[vrp] = more[0]
		if len(more) == 1 {
			delete(s.extra, vrp)
		} else {
			s.extra[vrp] = more[1:]
		}
	} else {
		delete(s.first, vrp)
	}
	s.count--
}

// FindCovering returns all VRPs that cover the given prefix.
// A VRP covers a route prefix if the VRP prefix is equal to or
// less specific than the route prefix (RFC 6811 §2). They come shortest
// VRP prefix first and, within a prefix, in the order they were added;
// nil if there are none.
//
// It reads the last published index without locking. The returned slice is
// shared with other callers and must not be modified. In steady state
// FindCovering does not allocate.
func (s *VRPStore) FindCovering(prefix netip.Prefix) []types.VRP {
	return s.idx.Load().covering(prefix)
}

// All returns a copy of all VRPs, in store order, including changes not yet
// published. Used for diagnostics.
func (s *VRPStore) All() []types.VRP {
	s.mu.RLock()
	vrps, order := s.collectLocked()
	s.mu.RUnlock()
	idx := make([]int, len(vrps))
	for i := range idx {
		idx[i] = i
	}
	slices.SortFunc(idx, func(a, b int) int { return cmp.Compare(order[a], order[b]) })
	out := make([]types.VRP, len(vrps))
	for i, j := range idx {
		out[i] = vrps[j]
	}
	return out
}

// collectLocked lists the VRP set's copies and their store order, in no
// particular order. The caller holds mu.
func (s *VRPStore) collectLocked() ([]types.VRP, []uint64) {
	vrps := make([]types.VRP, 0, s.count)
	order := make([]uint64, 0, s.count)
	for v, o := range s.first {
		vrps = append(vrps, v)
		order = append(order, o)
	}
	for v, os := range s.extra {
		for _, o := range os {
			vrps = append(vrps, v)
			order = append(order, o)
		}
	}
	return vrps, order
}

// Snapshot returns a copy of all VRPs for persistence.
func (s *VRPStore) Snapshot() []types.VRP {
	return s.All()
}

// Restore replaces the store contents from a snapshot.
// The serial is reset to 0 so the next RTR connection performs a full sync.
func (s *VRPStore) Restore(vrps []types.VRP) {
	s.ReplaceAll(vrps, 0, 0)
}

// RebuildIndex publishes the current VRP set to lookups. The RTR client calls
// it once per sync, at End of Data. The index is built without holding any
// lock lookups take, then swapped in.
func (s *VRPStore) RebuildIndex() {
	s.buildMu.Lock()
	defer s.buildMu.Unlock()
	s.mu.RLock()
	vrps, order := s.collectLocked()
	s.mu.RUnlock()
	s.publish(newVRPIndex(vrps, order))
}

// publish makes idx the index lookups use. The caller holds buildMu.
func (s *VRPStore) publish(idx *vrpIndex) {
	s.idx.Store(idx)
	s.rebuilds.Add(1)
}
