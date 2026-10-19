package api

import (
	"fmt"
	"net/netip"
	"net/url"
	"slices"
	"strconv"

	"github.com/nokia/bgp-routing-security-monitor/internal/routetable"
	"github.com/nokia/bgp-routing-security-monitor/internal/types"
)

// routeFilter is the route query of /api/v1/routes and /api/v1/watch: every
// filter given must match. Each used to be honoured only when no filter
// before it in a fixed order was given, so --prefix with --peer returned the
// prefix from every peer.
type routeFilter struct {
	prefix  netip.Prefix // exact prefix; invalid = any
	origin  uint32       // origin ASN; 0 = any
	peer    netip.Addr   // BMP peer, unmapped; invalid = any
	posture types.SecurityPosture
	// routers, when byRouter, are the monitored routers a route must come
	// from: the one router address given, or the routers whose sysName is
	// the name given (none, if no router has it).
	byRouter bool
	routers  []netip.Addr
	// rib is the RIB to list: Adj-RIB-In pre-policy unless the rib
	// parameter names another. A watch is filtered by RIB only when the
	// parameter is given (ribGiven).
	rib      types.RIBType
	ribGiven bool
}

// parseRIB returns the RIB type a name (types.RIBType.String) gives.
func parseRIB(name string) (types.RIBType, bool) {
	for _, r := range types.AllRIBTypes {
		if r.String() == name {
			return r, true
		}
	}
	return 0, false
}

// parseRouteFilter reads the prefix, origin-asn, peer, posture, router and
// rib query parameters. router is a router address or a BMP sysName; named
// resolves a sysName to the routers that have it.
func parseRouteFilter(q url.Values, named func(string) []netip.Addr) (routeFilter, error) {
	var f routeFilter
	if v := q.Get("router"); v != "" {
		f.byRouter = true
		if a, err := netip.ParseAddr(v); err == nil {
			f.routers = []netip.Addr{a.Unmap()}
		} else if named != nil {
			f.routers = named(v)
		}
	}
	if v := q.Get("prefix"); v != "" {
		p, err := netip.ParsePrefix(v)
		if err != nil {
			return f, fmt.Errorf("invalid prefix: %w", err)
		}
		f.prefix = p
	}
	if v := q.Get("origin-asn"); v != "" {
		asn, err := strconv.ParseUint(v, 10, 32)
		if err != nil {
			return f, fmt.Errorf("invalid ASN: %w", err)
		}
		f.origin = uint32(asn)
	}
	if v := q.Get("peer"); v != "" {
		a, err := netip.ParseAddr(v)
		if err != nil {
			return f, fmt.Errorf("invalid peer address: %w", err)
		}
		f.peer = a.Unmap()
	}
	f.posture = types.SecurityPosture(q.Get("posture"))
	if v := q.Get("rib"); v != "" {
		rib, ok := parseRIB(v)
		if !ok {
			return f, fmt.Errorf("invalid rib %q: want adj-rib-in-pre, adj-rib-in-post, loc-rib, adj-rib-out-pre or adj-rib-out-post", v)
		}
		f.rib, f.ribGiven = rib, true
	}
	return f, nil
}

// match reports whether r passes every filter. A peer matches in either its
// plain IPv4 or its IPv4-mapped IPv6 form.
func (f *routeFilter) match(r *types.Route) bool {
	return (!f.prefix.IsValid() || r.Prefix == f.prefix) &&
		(f.origin == 0 || r.OriginASN() == f.origin) &&
		(!f.peer.IsValid() || r.PeerAddr.Unmap() == f.peer) &&
		(f.posture == "" || r.SecurityPosture == f.posture) &&
		(!f.byRouter || slices.Contains(f.routers, r.Router.Unmap())) &&
		(!f.ribGiven || r.RIBType == f.rib)
}

// routes returns the table's routes of the filter's RIB (Adj-RIB-In
// pre-policy by default) that pass the filter. For Adj-RIB-In pre-policy it
// starts from the most selective index the filter allows; the indexes
// return only that RIB, so any other is scanned whole.
func (f *routeFilter) routes(t *routetable.Table) []*types.Route {
	var candidates []*types.Route
	switch {
	case f.rib != types.AdjRIBInPre:
		candidates = t.AllOfRIB(f.rib)
	case f.prefix.IsValid():
		candidates = t.GetByPrefix(f.prefix)
	case f.origin != 0:
		candidates = t.GetByOriginASN(f.origin)
	case f.peer.IsValid():
		candidates = t.GetByPeer(f.peer)
	case f.posture != "":
		candidates = t.GetByPosture(f.posture)
	case f.byRouter:
		candidates = t.AllPrePolicy()
	default:
		return t.AllPrePolicy()
	}
	out := candidates[:0]
	for _, r := range candidates {
		if r.RIBType == f.rib && f.match(r) {
			out = append(out, r)
		}
	}
	return out
}
