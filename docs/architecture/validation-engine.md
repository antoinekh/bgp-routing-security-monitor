# Validation Engine

The validation engine annotates every route with an ROV result, an ASPA
result and a security posture, and keeps those annotations current as your
RPKI data changes. This page explains how it does both without stalling BMP
ingest.

## Validating a route

RAVEN validates each route once on ingest:

1. **ROV** (RFC 6811): RAVEN looks up the VRPs covering the route's prefix
   and compares the origin AS and prefix length against them, giving
   `Valid`, `Invalid` or `NotFound`.
2. **ASPA**: RAVEN picks the verification procedure from the peer the route
   came from (an `aspa-peers` entry by address, then by ASN, then
   `aspa-default-procedure`) and verifies the AS_PATH as described in
   [ASPA Path Verification](../getting-started/concepts.md#aspa-path-verification).
   Picking the procedure costs two map lookups and no allocations; RAVEN
   builds the lookup tables once at startup.
3. **Posture**: RAVEN combines the two results into one of the
   [security postures](../user-guide/security-postures.md).

### The origin AS

ROV compares VRPs against the route's origin AS, and RFC 6811 §2 defines
which AS that is. RAVEN follows it:

| AS_PATH ends in | Origin | ROV result |
|---|---|---|
| An AS_SEQUENCE | The last AS of that sequence | Compared against the covering VRPs as usual |
| An AS_SET | NONE, which no VRP can match | `Invalid` if any VRP covers the prefix, `NotFound` otherwise |
| A confederation segment (AS_CONFED_SEQUENCE or AS_CONFED_SET) | The route originated inside your router's own AS confederation | `NotFound` |
| Nothing (empty AS_PATH) | None | `NotFound` |

Confederation segments never supply the origin, wherever they appear: a
path with a confederation segment followed by an AS_SEQUENCE takes its
origin from the sequence. When the path ends in a confederation segment,
RFC 6811 makes the origin your router's own AS, but the BMP session only
tells RAVEN the member AS, not the confederation's AS, so RAVEN reports no
origin.

An AS_SET hides which of its members originated the route, so a VRP can
never confirm it. Earlier releases took the set's last member as the
origin, which let a VRP for that AS mark an aggregate `Valid`. In each case
without an origin, `origin_asn` is `0`, the CLI shows `-`, and `rov_reason`
says why, for example (from RAVEN's validator, on a route
`64500 {64502 64503}` under a VRP for `203.0.113.0/24`):

```text
origin is NONE: AS_PATH ends in an AS_SET (RFC 6811 §2), which no covering VRP can match
```

### Routes RAVEN does not ASPA-verify

Two kinds of route get ASPA state `Unverifiable` with an `aspa_reason`
instead of a verified result:

- **Routes from inside an AS confederation.** A route whose AS_PATH has a
  confederation segment came over an eBGP session between members of your
  own confederation: routers strip those segments before a route leaves the
  confederation (RFC 5065). draft-ietf-sidrops-aspa-verification-24 §6.2
  says ASPA verification is not recommended on those sessions, and
  verifying the path anyway would treat member ASes as hops. The reason
  reads `not ASPA-verified: learned over a session internal to an AS
  confederation (draft-ietf-sidrops-aspa-verification-24 §6.2)`.
- **Adj-RIB-Out routes** (below).

A route whose AS_PATH contains an AS_SET is also `Unverifiable`, because
an AS_SET has no single order to walk.

### Adj-RIB-Out routes

Adj-RIB-Out routes, the routes your router sends rather than receives, get
ROV only. ASPA verification is defined for routes received from a neighbor,
by that neighbor's relationship to you, so RAVEN marks their ASPA state
`Unverifiable` with a reason saying why. The Event Engine does not evaluate
Adj-RIB-Out routes.

## VRP lookups

RAVEN keeps VRPs in a longest-prefix-match index (a BART trie). For each
VRP prefix the index holds the list of VRPs covering it, built once and
shared by every lookup, so finding the VRPs for a route takes no lock and
allocates nothing.

### Changes publish at End of Data

The RTR client applies a sync's VRP announcements and withdrawals to a
working set as the PDUs arrive. Lookups do not see that working set. When
the cache sends End of Data, RAVEN rebuilds the index from the working set
off to the side, outside any lock, and swaps the new index in atomically.

This follows RTR's model (RFC 8210): a sync is complete at End of Data, and
until then the previous data set is the valid one. It has two practical
effects:

- **Lookups never wait for a sync.** Earlier releases rebuilt the whole
  index under the write lock for every withdrawn VRP, which blocked ROV
  lookups and therefore BMP ingest. One large withdrawal held ingest for
  over an hour in production; RAVEN now does one rebuild per sync.
- **Routes never see a half-applied sync.** At the start of a full sync,
  clearing the working set no longer empties lookups. Routes keep
  validating against the previous VRP set until End of Data instead of
  briefly reading `NotFound`.

## Incremental revalidation

When an RTR sync changes the VRP or ASPA data, some routes' results change.
Revalidating the whole table after every serial change is expensive on a
full table, and a typical delta changes only tens of VRPs, so RAVEN
revalidates only the routes a change can affect.

For each Cache Response, the RTR client records a **delta**: the VRPs
announced and withdrawn, and the customer ASNs whose ASPA record was added,
removed or changed. RAVEN then picks candidate routes from it:

- **ROV candidates**: routes whose prefix is at or more specific than the
  prefix of a changed VRP, found through the route table's prefix trie.
  Only those routes can be covered by the changed VRP.
- **ASPA candidates**: routes whose AS_PATH contains a changed customer
  ASN, found by scanning the table shard by shard. RAVEN runs this scan only
  when the delta has ASPA changes.

A delta that changes nothing triggers no work. Some syncs carry no usable
delta: a Cache Reset, a Reset Query, a new RTR session or a session-ID
change replaces the data wholesale, so RAVEN revalidates every route (a
**full** pass).

Revalidation runs inside the ingest loop, between chunks of BMP work, so
the route table keeps a single writer and ingest keeps flowing during a
pass. A route whose results did not change is left as it is; RAVEN copies
and replaces only the routes whose ROV, ASPA or posture changed. A property
test in the code repository checks that an incremental pass always reaches
the same results as a full pass.

Each pass logs `re-validation complete` with its `mode` (`incremental` or
`full`), `candidates`, `checked`, `changed` and `took`, and records
`raven_revalidation_duration_seconds` and `raven_revalidation_routes_total`
(see [Observability & Metrics](../user-guide/observability.md#revalidation)).
