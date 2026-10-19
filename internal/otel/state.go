package otel

// StateReader provides read-only access to RAVEN's current runtime state.
// It is implemented by internal/server.Server and defined here so that
// internal/otel never imports internal/server (which would be circular).
type StateReader interface {
	// RouteCounts returns the current route counts by RIB, security
	// posture and address family: the RIBs raven_routes_total counts
	// (adj-rib-in-pre, adj-rib-in-post, loc-rib), each apart.
	RouteCounts() []RouteCount

	// PeerRouteCounts returns per-peer route counts.
	PeerRouteCounts() []PeerRouteCount

	// BMPSessionStates returns the up/down state for each connected router.
	BMPSessionStates() []BMPSessionState

	// BMPMessageCounts returns cumulative BMP message counts per router and
	// message type.
	BMPMessageCounts() []BMPMessageCount

	// RTRSessionStates returns the connection state of each RTR cache.
	RTRSessionStates() []RTRSessionState

	// RTRCacheCounts returns VRP/ASPA counts and last-sync time per cache.
	RTRCacheCounts() []RTRCacheCount
}

// RouteCount is the number of routes of one RIB with one posture and
// address family.
type RouteCount struct {
	RIB     string // adj-rib-in-pre, adj-rib-in-post or loc-rib
	Posture string
	AFI     string // ipv4 or ipv6
	Count   int64
}

// PeerRouteCount holds the route count for a single BGP peer on one
// monitored router (Router, its BMP session address) and in one instance
// (PeerDistinguisher, "" for a global-instance peer).
type PeerRouteCount struct {
	Router            string
	PeerDistinguisher string
	PeerAddr          string
	RIB               string // the RIB counted, e.g. adj-rib-in-pre; inbound and outbound apart
	PeerASN           uint32
	Posture           string
	Count             int64
}

// BMPSessionState holds the up/down state for one router's BMP session.
type BMPSessionState struct {
	RouterID string
	State    int64 // 1 = up, 0 = down
}

// BMPMessageCount holds a cumulative message count for one router+type pair.
type BMPMessageCount struct {
	RouterID string
	MsgType  string
	Count    int64
}

// RTRSessionState holds the connection state for one RTR cache.
type RTRSessionState struct {
	CacheName string
	State     int64 // 1 = connected, 0 = disconnected
}

// RTRCacheCount holds VRP/ASPA counts and last-sync timestamp for one cache.
type RTRCacheCount struct {
	CacheName string
	VRPCount  int64
	ASPACount int64
	LastSync  int64 // unix seconds; 0 if never synced
}
