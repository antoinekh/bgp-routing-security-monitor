# Data Model

This page describes how RAVEN turns BMP messages into routes, and how it
identifies and stores them. Knowing the route key explains why RAVEN shows
the same prefix from the same peer address more than once, and why its
counts match what your routers report.

## From BMP to routes

RAVEN decodes BMP and BGP itself. Its decoder in `internal/bmp` reads the
BMP messages your routers send and the BGP UPDATE and OPEN messages carried
inside them. RAVEN does not use GoBGP to parse UPDATEs; GoBGP appears in
RAVEN only as the Flowspec injection target for
[Active Response](../user-guide/active-response.md).

BMP input is untrusted: anything that reaches the BMP port can send it
bytes, so the decoder is written to fail safe and is fuzzed. `make fuzz` in
the code repository runs three fuzz targets, `FuzzBMPMessage`,
`FuzzPeerUpOpen` and `FuzzDecodeUpdate`, and every failing input found is
kept and replayed by the regular test suite. A BMP message longer than
1 MiB closes the session, Statistics Report entries are sized from the bytes
present rather than from the count the message claims, and the UPDATE's
Withdrawn Routes Length is checked against the message length.

The decoder handles:

- **Peer Up**: both the sent and received OPEN messages, including RFC 9072
  extended optional parameters. RAVEN reads the ADD-PATH capability from
  both OPENs to learn, per address family and direction, whether the peer's
  UPDATEs carry path identifiers.
- **Route Monitoring**: withdrawn routes, path attributes and NLRI in the
  UPDATE body (IPv4 unicast), and `MP_REACH_NLRI` / `MP_UNREACH_NLRI` for
  IPv4 and IPv6 unicast, including IPv6 next hops for IPv4 routes
  (RFC 8950). Other address families are counted in
  `raven_bmp_unsupported_nlri_total` and not stored.
- **AS_PATH**: two-octet AS_PATHs, as sent by a peer whose per-peer header
  has the A flag set, are merged with `AS4_PATH` (RFC 6793 §4.2.3), so the
  route carries the real four-octet path.
- **RIB type**: the per-peer header tells RAVEN whether a route is
  Adj-RIB-In pre-policy, Adj-RIB-In post-policy, or Adj-RIB-Out
  pre- or post-policy (RFC 8671).

A malformed UPDATE is handled the way RFC 7606 tells your router to handle
it (attribute discard, treat-as-withdraw or session reset), so RAVEN's
table keeps matching the router's Adj-RIB-In; see
[Malformed BGP Input](../troubleshooting.md#malformed-bgp-input). Each
route also carries the BMP per-peer header's timestamp, the time the router
received it.

Routes and withdrawals from all BMP sessions go to the route table over one
channel, in the order each router sent them, so a peer-down is never
applied before routes from that peer that were still queued.

## The route

Each route RAVEN stores carries:

| Field group | Contents |
|---|---|
| Where it was learned | The monitored router, the peer distinguisher and peer type from the BMP per-peer header, the peer's address and ASN, the ADD-PATH path ID, the RIB type |
| What was announced | Prefix, AS_PATH (flattened, and with its segment types kept for ASPA), ORIGIN, next hop, communities, large communities |
| What RAVEN concluded | ROV result, ASPA result (state, procedure, procedure source, failing hop, reason), security posture |
| Bookkeeping | Whether the route was restored from a snapshot and not yet confirmed live, and which BMP session owns it |

The **router** is the source address of the router's BMP session. The BMP
Initiation sysName, when the router sends one, is kept as a display name:
that is what the CLI's `ROUTER` column and the `router_name` JSON field
show.

## The route key

A route is identified by six parts:

| Part | Why it is part of the key |
|---|---|
| **Router** | Two routers can have a peer with the same address, such as the same exchange route server. Without the router in the key, each router's routes overwrote the other's |
| **Peer distinguisher** | A router can have peers with the same address in different VRFs. The BMP per-peer header's Peer Distinguisher (the VRF's route distinguisher, zero for the global instance) keeps them apart |
| **Peer address** | The BGP neighbor the route came from |
| **Prefix** | The announced prefix |
| **Path ID** | With ADD-PATH (RFC 7911), one peer can send several paths for the same prefix. Each path ID is a separate route; without ADD-PATH the path ID is 0 |
| **RIB type** | The same route in Adj-RIB-In pre-policy and post-policy, for example, is two entries, so a post-policy withdrawal does not remove the pre-policy route |

The first three parts together identify a **peer** as one monitored router
sees it. RAVEN normalizes IPv4-mapped IPv6 addresses to plain IPv4 in the
router and peer address, so an IPv4 router or peer is one peer however its
address arrived.

Withdrawals carry the same six parts, so a withdrawal removes exactly the
route it names.

## The route table

The route table is in memory. Routes live in a 256-shard map keyed by the
route key, so lookups and updates for different routes rarely contend for
the same lock. Beside it RAVEN keeps:

- a prefix index (a BART trie), which answers exact-prefix queries and finds
  every route at or more specific than a prefix, as revalidation needs;
- an origin-ASN index;
- a posture index, holding Adj-RIB-In pre-policy routes only;
- per-peer route counts by RIB type, updated where routes are added and
  removed, which feed `raven status`, `raven peers` and the OpenTelemetry
  gauges.

Counts that RAVEN reports as "routes" (the route-table total and posture
breakdown in `raven status`, `ROUTES` in `raven peers`,
`raven_routes_total` and `raven_route_table_size`) are Adj-RIB-In
pre-policy: what your routers received from their peers before import
policy, comparable to the received-routes count on the router. Adj-RIB-Out
routes are counted separately, in the `OUT` column and in
`raven_adj_rib_out_routes_total`, so received and sent routes never add up
into one number.

## Snapshots

With persistence enabled, RAVEN writes the route table to a snapshot and
restores it at startup, marking restored routes stale until a live BMP
message confirms them. Snapshots use `format_version` 2, which stores the
full route key. A snapshot from an older RAVEN, keyed without router, peer
distinguisher and path ID, is not restored: RAVEN starts with an empty
route table and rebuilds it from the routers' BMP table dumps.
